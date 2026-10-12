import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import { UntrustedError } from './errors.js';
import {
  ACE_FLAG_INHERIT_ONLY, AceType, PE_FILE_DLL, PeMachine, Rights, WIN_CODE_SIGNING_EKU, WIN_EXPECTED_PROFILE_EKU, WIN_EXPECTED_PUBLISHER,
  WIN_EXPECTED_ROOT_SHA256, WIN_GUARDED_RIGHTS, WIN_GUARDED_ROOT_RIGHTS, winReadPeHeader, winVerifyImageKind, winVerifySignerIdentity,
  winVerifyTrustedOnly, type WinAce, type WinSecurity,
} from './windowspolicy.js';

const SYSTEM = 'S-1-5-18', ADMINISTRATORS = 'S-1-5-32-544', TRUSTED_INSTALLER = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464';
const USERS = 'S-1-5-32-545', AUTHENTICATED_USERS = 'S-1-5-11';
const ARTIFACT_SIGNING_EKU = '1.3.6.1.4.1.311.97.1.0';
const FILE_ALL_ACCESS = 0x001f01ff, FILE_READ_AND_EXECUTE = 0x001200a9, FILE_WRITE = 0x00120116;
const GENUINE_EKUS = [ARTIFACT_SIGNING_EKU, WIN_CODE_SIGNING_EKU, WIN_EXPECTED_PROFILE_EKU];

const allow = (sid: string, mask: number): WinAce => ({ type: AceType.allowed, flags: 0, mask, sid });
const security = (owner: string, ...aces: WinAce[]): WinSecurity => ({ owner, daclAbsent: false, aces });
const verifyTrustedOnly = (s: WinSecurity) => winVerifyTrustedOnly(s, 'test', WIN_GUARDED_RIGHTS, (sid) => sid);
const verifyDriveRoot = (s: WinSecurity) => winVerifyTrustedOnly(s, 'C:\\', WIN_GUARDED_ROOT_RIGHTS, (sid) => sid);

function untrusted(fn: () => unknown, ...contains: string[]): void {
  assert.throws(fn, (e: unknown) => e instanceof UntrustedError && contains.every((s) => e.message.includes(s)));
}

describe('Windows ACLs', () => {
  it('pass a trusted owner with read-only access for everyone else', () => {
    verifyTrustedOnly(security(SYSTEM, allow(SYSTEM, FILE_ALL_ACCESS), allow(ADMINISTRATORS, FILE_ALL_ACCESS), allow(TRUSTED_INSTALLER, FILE_ALL_ACCESS), allow(USERS, FILE_READ_AND_EXECUTE)));
  });

  it('refuse any write right for an untrusted principal', () => {
    for (const right of [Rights.writeData, Rights.appendData, Rights.writeExtendedAttributes, Rights.deleteChild, Rights.delete, Rights.writeDac, Rights.writeOwner, 0x001301bf, Rights.genericAll, Rights.genericWrite]) {
      untrusted(() => verifyTrustedOnly(security(ADMINISTRATORS, allow(USERS, right))), USERS);
    }
  });

  it('refuse an untrusted, orphaned, or missing owner, and a NULL DACL', () => {
    untrusted(() => verifyTrustedOnly(security(USERS, allow(SYSTEM, FILE_ALL_ACCESS))));
    untrusted(() => verifyTrustedOnly(security('S-1-5-21-1-2-3-4242', allow(SYSTEM, FILE_ALL_ACCESS))), 'S-1-5-21-1-2-3-4242');
    untrusted(() => verifyTrustedOnly(security('', allow(SYSTEM, FILE_ALL_ACCESS))), 'an unknown principal');
    untrusted(() => verifyTrustedOnly({ owner: SYSTEM, daclAbsent: true, aces: [] }), 'no DACL');
  });

  it('ignore inherit-only and deny entries, check callback allows, and refuse unknown types', () => {
    verifyTrustedOnly(security(SYSTEM,
      { type: AceType.denied, flags: 0, mask: FILE_WRITE, sid: USERS },
      allow(SYSTEM, FILE_ALL_ACCESS),
      { type: AceType.allowed, flags: ACE_FLAG_INHERIT_ONLY | 0x3, mask: FILE_ALL_ACCESS, sid: USERS },
      allow(USERS, FILE_READ_AND_EXECUTE)));
    untrusted(() => verifyTrustedOnly(security(SYSTEM, { type: AceType.allowedCallback, flags: 0, mask: Rights.writeData, sid: USERS })), USERS);
    untrusted(() => verifyTrustedOnly(security(SYSTEM, { type: 0x5, flags: 0, mask: Rights.writeData, sid: '' })), 'type 0x5');
  });

  it('hold the drive root only to what could rename a folder beneath it', () => {
    verifyDriveRoot(security(SYSTEM, allow(ADMINISTRATORS, FILE_ALL_ACCESS), allow(SYSTEM, FILE_ALL_ACCESS), allow(USERS, FILE_READ_AND_EXECUTE),
      { type: AceType.allowed, flags: ACE_FLAG_INHERIT_ONLY | 0x3, mask: 0xe0010000, sid: AUTHENTICATED_USERS }, allow(AUTHENTICATED_USERS, 0x4)));
    for (const right of [Rights.deleteChild, Rights.writeDac, Rights.writeOwner, Rights.genericAll, FILE_ALL_ACCESS]) {
      untrusted(() => verifyDriveRoot(security(SYSTEM, allow(SYSTEM, FILE_ALL_ACCESS), allow(USERS, right))), USERS);
    }
    for (const right of [Rights.writeData, Rights.appendData, Rights.genericWrite]) {
      verifyDriveRoot(security(SYSTEM, allow(SYSTEM, FILE_ALL_ACCESS), allow(USERS, right)));
    }
    untrusted(() => verifyDriveRoot(security(USERS, allow(SYSTEM, FILE_ALL_ACCESS))));
  });
});

describe('Windows signer', () => {
  const verifySigner = (ekus: string[], subject = WIN_EXPECTED_PUBLISHER, root = WIN_EXPECTED_ROOT_SHA256) =>
    winVerifySignerIdentity('test', subject, ekus, root, WIN_EXPECTED_PUBLISHER);

  it('passes the pinned root, profile and publisher, whatever the hash case', () => {
    verifySigner(GENUINE_EKUS);
    verifySigner(GENUINE_EKUS, WIN_EXPECTED_PUBLISHER, WIN_EXPECTED_ROOT_SHA256.toLowerCase());
  });

  it('refuses another root, profile, missing EKUs, or another subject', () => {
    untrusted(() => verifySigner(GENUINE_EKUS, WIN_EXPECTED_PUBLISHER, 'A'.repeat(64)), 'A'.repeat(64));
    untrusted(() => verifySigner([WIN_CODE_SIGNING_EKU, ARTIFACT_SIGNING_EKU]), WIN_EXPECTED_PROFILE_EKU);
    untrusted(() => verifySigner([ARTIFACT_SIGNING_EKU, WIN_CODE_SIGNING_EKU, '1.3.6.1.4.1.311.97.1.2.3.4']), WIN_EXPECTED_PROFILE_EKU);
    untrusted(() => verifySigner([ARTIFACT_SIGNING_EKU, WIN_EXPECTED_PROFILE_EKU]), WIN_CODE_SIGNING_EKU);
    untrusted(() => verifySigner([]));
    untrusted(() => verifySigner(GENUINE_EKUS, 'CN=Someone Else'), 'not the expected HkdfGuard publisher');
  });
});

describe('Windows image kind', () => {
  it("passes a DLL for this process's architecture", () => {
    for (const [arch, machine] of [['x64', PeMachine.amd64], ['arm64', PeMachine.arm64], ['ia32', PeMachine.i386]] as const) {
      winVerifyImageKind('test', PE_FILE_DLL | 0x2, machine, arch);
    }
  });

  it('refuses an executable, or a DLL for another architecture', () => {
    untrusted(() => winVerifyImageKind('test', 0x2, PeMachine.amd64, 'x64'), 'not a DLL');
    for (const [arch, machine] of [['x64', PeMachine.arm64], ['arm64', PeMachine.amd64], ['x64', PeMachine.i386], ['wasm', 0]] as const) {
      untrusted(() => winVerifyImageKind('test', PE_FILE_DLL, machine, arch));
    }
  });

  it('reads the COFF header, refusing anything that is not a PE image', () => {
    const image = new Uint8Array(512);
    const view = new DataView(image.buffer);
    view.setUint16(0, 0x5a4d, true);
    view.setUint32(0x3c, 0x80, true);
    view.setUint32(0x80, 0x00004550, true);
    view.setUint16(0x84, PeMachine.amd64, true);
    view.setUint16(0x80 + 22, PE_FILE_DLL | 0x2, true);
    assert.deepEqual(winReadPeHeader('test', image), { machine: PeMachine.amd64, characteristics: PE_FILE_DLL | 0x2 });
    untrusted(() => winReadPeHeader('test', new Uint8Array([0x4d, 0x5a, 0x90, 0])), 'PE header');
    view.setUint32(0x3c, 0x1000, true);
    untrusted(() => winReadPeHeader('test', image), 'PE header');
  });
});
