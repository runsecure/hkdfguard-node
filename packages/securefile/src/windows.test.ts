import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import { InvalidArgumentError } from '@runsecure/hkdfguard-abstractions';
import { KeyFileError } from './errors.js';
import { windowsAddon } from './native.js';
import { KeyFileTrust } from './trust.js';
import {
  AceType, ADMINISTRATORS, describeRights, DriveType, driveTypeName, FILE_ATTRIBUTE_REPARSE_POINT, GUARDED_RIGHTS, GUARDED_ROOT_RIGHTS, INHERIT_ONLY_ACE,
  INVALID_FILE_ATTRIBUTES, Rights, SYSTEM, TRUSTED_INSTALLER, trustedPrincipals, verifyFinalPath, verifyNotReparsePoint, verifyPathForm, verifyTrustedOnly,
  type WinAce, type WinSecurity,
} from './windows.js';

/*
 * The Windows key-file location rules. The rules themselves run on every platform, against security
 * descriptors built here; the tests that need Windows to parse SDDL, canonicalize a SID or name an
 * account run on Windows only. trustedkeyfile.test.ts runs the rules against real files.
 */

const isWindows = process.platform === 'win32';

const KEY_FILE = 'C:\\HkdfGuardKeys\\myapp\\v1.key';
const USERS = 'S-1-5-32-545';
const AUTHENTICATED_USERS = 'S-1-5-11';
const DEPLOYERS = 'S-1-5-21-1111111111-2222222222-3333333333-1005';

// FileSystemRights values.
const FULL_CONTROL = 0x1f01ff;
const MODIFY = 0x1301bf;
const WRITE = 0x116;
const READ_AND_EXECUTE_SYNCHRONIZE = 0x1200a9;

const ACCOUNTS = new Map([[SYSTEM, 'NT AUTHORITY\\SYSTEM'], [ADMINISTRATORS, 'BUILTIN\\Administrators'], [USERS, 'BUILTIN\\Users']]);
const accountName = (sid: string) => ACCOUNTS.get(sid) ?? null;

/** A stand-in for ConvertStringSidToSidW: a well-formed SID string is its own canonical form. */
const canonical = (sid: string) => (sid.startsWith('S-1-') ? sid : null);

const trusted = (...extra: string[]) => trustedPrincipals(new KeyFileTrust({ windowsPrincipals: extra }), canonical, accountName);
const allow = (sid: string | null, mask: number, flags = 0): WinAce => ({ type: AceType.allowed, flags, mask, sid });
const locked = (owner: string | null, ...extra: WinAce[]): WinSecurity => ({
  owner,
  daclAbsent: false,
  aces: [allow(SYSTEM, FULL_CONTROL), allow(ADMINISTRATORS, FULL_CONTROL), allow(TRUSTED_INSTALLER, FULL_CONTROL), allow(USERS, READ_AND_EXECUTE_SYNCHRONIZE), ...extra],
});
const verify = (security: WinSecurity, item = KEY_FILE, guarded = GUARDED_RIGHTS, trust = trusted()) =>
  verifyTrustedOnly(security, KEY_FILE, item, guarded, trust, accountName);

/** Asserts `fn` throws a KeyFileError 'EACCES' whose message holds every one of `contains`. */
function untrusted(fn: () => unknown, ...contains: string[]): void {
  assert.throws(fn, (e: unknown) => {
    assert.ok(e instanceof KeyFileError, String(e));
    assert.equal(e.code, 'EACCES');
    assert.ok(e.message.includes('is not trusted'), e.message);
    for (const s of contains) assert.ok(e.message.includes(s), `"${e.message}" lacks "${s}"`);
    return true;
  });
}

function invalidArgument(fn: () => unknown, contains: string): void {
  assert.throws(fn, (e: unknown) => e instanceof InvalidArgumentError && e.message.includes(contains));
}

describe('Windows trusted principals', () => {
  it('always include SYSTEM, Administrators and TrustedInstaller', () => {
    assert.deepEqual(trusted(), [SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER]);
  });

  it('add the listed deployers', () => {
    assert.ok(trusted(DEPLOYERS).includes(DEPLOYERS));
  });

  it('refuse groups everyone is in', () => {
    for (const sid of ['S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-4', 'S-1-5-7']) invalidArgument(() => trusted(sid), 'every account');
  });

  it('refuse what is not a SID', () => {
    for (const value of ['HkdfGuardDeployers', '']) invalidArgument(() => trusted(value), 'not a security identifier');
  });
});

describe('Windows path form, final path and reparse points', () => {
  it('pass a path on a local fixed drive', () => {
    assert.doesNotThrow(() => verifyPathForm(KEY_FILE, DriveType.fixed));
  });

  it('refuse UNC and device paths', () => {
    for (const path of ['\\\\server\\share\\v1.key', '\\\\?\\C:\\HkdfGuardKeys\\v1.key', '\\\\.\\PhysicalDrive0', '//server/share/v1.key']) {
      untrusted(() => verifyPathForm(path, DriveType.fixed), 'UNC or device path');
    }
  });

  it('refuse every other kind of drive, named as .NET names it', () => {
    for (const type of Object.values(DriveType).filter((t) => t !== DriveType.fixed)) {
      untrusted(() => verifyPathForm(KEY_FILE, type), `${driveTypeName(type)} drive`);
    }
    assert.deepEqual([0, 1, 2, 3, 4, 5, 6, 7, -1].map(driveTypeName),
      ['Unknown', 'NoRootDirectory', 'Removable', 'Fixed', 'Network', 'CDRom', 'Ram', 'Unknown', 'Unknown']);
  });

  it('pass the same final path, whatever its case', () => {
    assert.doesNotThrow(() => verifyFinalPath(KEY_FILE, '\\\\?\\C:\\HkdfGuardKeys\\myapp\\v1.key'));
    assert.doesNotThrow(() => verifyFinalPath(KEY_FILE, '\\\\?\\c:\\hkdfguardkeys\\MYAPP\\v1.KEY'));
  });

  it('refuse a final path elsewhere, or remote', () => {
    for (const finalPath of [
      '\\\\?\\D:\\elsewhere\\v1.key', // a junction or symbolic link on the path
      '\\\\?\\C:\\real\\HkdfGuardKeys\\myapp\\v1.key', // a substituted drive
      '\\\\?\\UNC\\server\\share\\myapp\\v1.key', // a mapped network drive
      '\\\\?\\unc\\server\\share\\myapp\\v1.key',
      'C:\\HkdfGuardKeys\\myapp\\v1.key', // not the form GetFinalPathNameByHandleW returns
    ]) {
      untrusted(() => verifyFinalPath(KEY_FILE, finalPath), finalPath);
    }
  });

  it('refuse a short name that was asked for', () => {
    untrusted(() => verifyFinalPath('C:\\PROGRA~1\\HkdfGuard\\v1.key', '\\\\?\\C:\\Program Files\\HkdfGuard\\v1.key'));
  });

  it('compare case as NTFS does, never expanding one character into several', () => {
    verifyFinalPath('C:\\Schlüssel\\v1.key', '\\\\?\\C:\\SCHLÜSSEL\\V1.KEY');
    untrusted(() => verifyFinalPath('C:\\Straße\\v1.key', '\\\\?\\C:\\STRASSE\\v1.key'));
  });

  it('pass a real folder, and refuse a junction, link, or a folder that cannot be examined', () => {
    verifyNotReparsePoint(0x10, KEY_FILE, 'C:\\HkdfGuardKeys'); // FILE_ATTRIBUTE_DIRECTORY
    untrusted(() => verifyNotReparsePoint(0x10 | FILE_ATTRIBUTE_REPARSE_POINT, KEY_FILE, 'C:\\HkdfGuardKeys'), 'reparse point');
    untrusted(() => verifyNotReparsePoint(INVALID_FILE_ATTRIBUTES, KEY_FILE, 'C:\\HkdfGuardKeys'));
  });
});

describe('Windows owner and DACL', () => {
  it('pass a trusted owner, read-only for everyone else', () => {
    assert.doesNotThrow(() => verify(locked(ADMINISTRATORS)));
  });

  it('refuse an untrusted owner, naming it', () => {
    untrusted(() => verify(locked(USERS)), 'is owned by BUILTIN\\Users (S-1-5-32-545)');
  });

  it('refuse no owner', () => {
    untrusted(() => verify(locked(null)), 'an unknown principal');
  });

  it('refuse no DACL, which grants everyone everything', () => {
    untrusted(() => verify({ owner: ADMINISTRATORS, daclAbsent: true, aces: [] }), 'no DACL');
  });

  it('refuse any write right for an untrusted principal', () => {
    for (const rights of [Rights.writeData, Rights.appendData, Rights.writeExtendedAttributes, Rights.deleteSubdirectoriesAndFiles, Rights.delete,
      Rights.changePermissions, Rights.takeOwnership, MODIFY, FULL_CONTROL, Rights.genericAll, Rights.genericWrite]) {
      untrusted(() => verify(locked(ADMINISTRATORS, allow(USERS, rights))), 'grants');
    }
  });

  it('refuse a write right for an allow entry with no readable SID', () => {
    untrusted(() => verify(locked(ADMINISTRATORS, allow(null, Rights.writeData))), 'an unknown principal');
  });

  it('let a trusted deployer own and modify', () => {
    const security = locked(DEPLOYERS, allow(DEPLOYERS, MODIFY));
    verify(security, KEY_FILE, GUARDED_RIGHTS, trusted(DEPLOYERS));
    untrusted(() => verify(security));
  });

  it('ignore deny and inherit-only entries', () => {
    // A folder's: only a folder carries entries meant for what's created inside it.
    assert.doesNotThrow(() => verify({
      owner: ADMINISTRATORS,
      daclAbsent: false,
      aces: [allow(ADMINISTRATORS, FULL_CONTROL), { type: AceType.denied, flags: 0, mask: FULL_CONTROL, sid: USERS },
        allow(AUTHENTICATED_USERS, MODIFY, INHERIT_ONLY_ACE | 0x3)],
    }, 'C:\\HkdfGuardKeys'));
  });

  it('refuse an entry it cannot evaluate', () => {
    for (const type of [AceType.allowedObject, AceType.allowedCallbackObject, 0x11]) {
      untrusted(() => verify(locked(ADMINISTRATORS, { type, flags: 0, mask: Rights.writeData, sid: null })),
        `type 0x${type.toString(16).toUpperCase().padStart(2, '0')}, which this check can't evaluate`);
    }
  });

  it('ignore every kind of deny entry', () => {
    for (const type of [AceType.deniedObject, AceType.deniedCallback, AceType.deniedCallbackObject]) {
      assert.doesNotThrow(() => verify(locked(ADMINISTRATORS, { type, flags: 0, mask: FULL_CONTROL, sid: null })), `type ${type}`);
    }
  });

  it('check callback allow entries like plain ones', () => {
    untrusted(() => verify(locked(ADMINISTRATORS, { type: AceType.allowedCallback, flags: 0, mask: Rights.writeData, sid: USERS })), 'grants');
  });

  it('let the drive root allow creating folders, but not renaming them', () => {
    // A default C:\: Authenticated Users may create folders (AppendData) in the root itself.
    const root = locked(TRUSTED_INSTALLER, allow(AUTHENTICATED_USERS, Rights.appendData));
    verify(root, 'C:\\', GUARDED_ROOT_RIGHTS);

    // The same entry on any folder below the root is refused: they could create files there.
    untrusted(() => verify(root, 'C:\\HkdfGuardKeys'));

    const renamable = locked(TRUSTED_INSTALLER, allow(AUTHENTICATED_USERS, Rights.appendData), allow(AUTHENTICATED_USERS, Rights.deleteSubdirectoriesAndFiles));
    untrusted(() => verify(renamable, 'C:\\', GUARDED_ROOT_RIGHTS));
  });

  it('describe an unmappable SID by its value, and name the rights', () => {
    untrusted(() => verify(locked(ADMINISTRATORS, allow(DEPLOYERS, WRITE))), `to ${DEPLOYERS}.`,
      'grants 0x00000116 (WriteData, AppendData, WriteExtendedAttributes, WriteAttributes)');
  });

  it('name generic and unnamed bits', () => {
    assert.equal(describeRights(0), '0x00000000');
    assert.equal(describeRights(0x10000200), '0x10000200 (0x00000200, GenericAll)');
    assert.equal(describeRights(0x80000000), '0x80000000 (GenericRead)');
  });
});

describe('Windows rules against Windows itself', { skip: !isWindows && 'Windows only: Windows parses the SDDL and SIDs.' }, () => {
  it('canonicalizes SIDs and accepts SDDL aliases', () => {
    const addon = windowsAddon();
    const principals = trustedPrincipals(new KeyFileTrust({ windowsPrincipals: ['BA', 's-1-5-21-1111111111-2222222222-3333333333-1005'] }),
      addon.canonicalSid, addon.accountName);
    assert.deepEqual(principals.slice(3), [ADMINISTRATORS, DEPLOYERS]);
    invalidArgument(() => trustedPrincipals(new KeyFileTrust({ windowsPrincipals: ['HkdfGuardDeployers'] }), addon.canonicalSid, addon.accountName),
      'not a security identifier');
    invalidArgument(() => trustedPrincipals(new KeyFileTrust({ windowsPrincipals: ['WD'] }), addon.canonicalSid, addon.accountName), 'Everyone');
  });

  it('parses SDDL descriptors as the rules expect', () => {
    const addon = windowsAddon();
    const sddl = (text: string) => {
      const security = addon.sddlSecurity(text);
      assert.ok(security !== null, text);
      verifyTrustedOnly(security, KEY_FILE, KEY_FILE, GUARDED_RIGHTS, trusted(), addon.accountName);
    };

    sddl('O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200A9;;;BU)');
    sddl('O:BAD:(A;;FA;;;BA)(D;;FA;;;BU)(A;OICIIO;0x1301BF;;;AU)');
    for (const [refusedSddl, why] of [
      ['O:BUD:(A;;FA;;;SY)', 'is owned by'],
      ['D:(A;;FA;;;SY)', 'an unknown principal'],
      ['O:BAD:NO_ACCESS_CONTROL', 'no DACL'],
      ['O:BAD:(A;;FA;;;SY)(A;;GA;;;BU)', 'grants'], // unmapped generic rights
      ['O:BAD:(A;;FA;;;SY)(A;;GW;;;BU)', 'grants'],
      ['O:BAD:(A;;FA;;;SY)(OA;;0x2;bf967aba-0de6-11d0-a285-00aa003049e2;;BU)', "can't evaluate"], // an allow-object ACE
    ] as const) {
      untrusted(() => sddl(refusedSddl), why);
    }
  });

  it('describes an unmappable SID by its value, and names a mappable one', () => {
    const addon = windowsAddon();
    const security = addon.sddlSecurity(`O:BAD:(A;;FA;;;SY)(A;;0x116;;;${DEPLOYERS})`);
    assert.ok(security !== null);
    untrusted(() => verifyTrustedOnly(security, KEY_FILE, KEY_FILE, GUARDED_RIGHTS, trusted(), addon.accountName), `to ${DEPLOYERS}.`);
    assert.notEqual(addon.accountName(ADMINISTRATORS), null);
    assert.equal(addon.accountName('not a SID'), null);
  });

  it('reports invalid SDDL as null, and refuses a NUL in a string', () => {
    const addon = windowsAddon();
    assert.equal(addon.sddlSecurity('not SDDL'), null);
    assert.throws(() => addon.canonicalSid('S-1-5-18\0'), TypeError);
  });
});
