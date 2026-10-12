import { UntrustedError } from './errors.js';

/*
 * The Windows loader's decisions, kept free of system calls (a security descriptor and signer are
 * passed in as plain data) so they can be checked on any platform. The loader (windows.ts) loads the
 * library from its one installed location and nowhere else, after five checks:
 *
 *  1. The file exists at %ProgramFiles%\HkdfGuard\v1\HkdfGuardV1.dll, the Program Files location
 *     coming from the known-folder setting only an administrator can change.
 *  2. No component of that path, below the drive root, is a reparse point (symlink or junction).
 *  3. Every one of those components is owned by, and writable only by, SYSTEM, Administrators, or
 *     TrustedInstaller; the drive root is held only to what could rename the folder beneath it.
 *  4. The file carries a valid Authenticode signature issued to WIN_EXPECTED_PUBLISHER under
 *     HkdfGuard's Artifact Signing profile, whose chain - as WinVerifyTrust validated it - ends at
 *     the pinned root.
 *  5. Its PE header marks it a DLL for this process's architecture.
 */

export const WIN_FILE_NAME = 'HkdfGuardV1.dll';

/** The Authenticode signer subject, as Windows renders it (X.500, reversed). */
export const WIN_EXPECTED_PUBLISHER = 'CN=Torin Blair, O=Torin Blair, L=Littleton, S=co, C=US';

/** SHA-256 of Microsoft Identity Verification Root Certificate Authority 2020, the root of Azure Artifact Signing. */
export const WIN_EXPECTED_ROOT_SHA256 = '5367F20C7ADE0E2BCA790915056D086B720C33C1FA2A2661ACF787E3292E1270';

/** The EKU identifying HkdfGuard's Artifact Signing certificate profile. */
export const WIN_EXPECTED_PROFILE_EKU = '1.3.6.1.4.1.311.97.492781510.305179978.413069662.611988563';

/** id-kp-codeSigning, required of the leaf. */
export const WIN_CODE_SIGNING_EKU = '1.3.6.1.5.5.7.3.3';

const SID_LOCAL_SYSTEM = 'S-1-5-18';
const SID_ADMINISTRATORS = 'S-1-5-32-544';
const SID_TRUSTED_INSTALLER = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464';
const TRUSTED_PRINCIPALS = [SID_LOCAL_SYSTEM, SID_ADMINISTRATORS, SID_TRUSTED_INSTALLER];

/** Access-mask bits. */
export const Rights = {
  writeData: 0x00000002,
  appendData: 0x00000004,
  writeExtendedAttributes: 0x00000010,
  deleteChild: 0x00000040,
  delete: 0x00010000,
  writeDac: 0x00040000,
  writeOwner: 0x00080000,
  genericAll: 0x10000000,
  genericWrite: 0x40000000,
} as const;

/** Any right that lets a principal change what this path loads; generic bits too, since an ACE can carry them unmapped. */
export const WIN_GUARDED_RIGHTS = Rights.writeData | Rights.appendData | Rights.writeExtendedAttributes | Rights.deleteChild
  | Rights.delete | Rights.writeDac | Rights.writeOwner | Rights.genericAll | Rights.genericWrite;

/** On the drive root, only what lets a principal rename or delete an entry directly beneath it. */
export const WIN_GUARDED_ROOT_RIGHTS = Rights.deleteChild | Rights.writeDac | Rights.writeOwner | Rights.genericAll;

export const AceType = { allowed: 0x0, denied: 0x1, allowedCallback: 0x9, deniedCallback: 0xa } as const;
export const ACE_FLAG_INHERIT_ONLY = 0x8;

/** One DACL entry. */
export interface WinAce {
  type: number;
  flags: number;
  mask: number;
  /** "" for ACE types whose SID isn't read (they are refused before it matters). */
  sid: string;
}

/** The parts of a security descriptor the checks read. */
export interface WinSecurity {
  /** "" when the descriptor has no owner. */
  owner: string;
  /** A NULL DACL: everyone has full control. */
  daclAbsent: boolean;
  aces: WinAce[];
}

/**
 * Requires a trusted owner and no allow entry granting any of `guardedRights` to anyone else.
 * Inherit-only and deny entries are ignored; any other kind of ACE is refused rather than
 * interpreted. `describe` renders a SID for messages.
 */
export function winVerifyTrustedOnly(security: WinSecurity, displayPath: string, guardedRights: number, describe: (sid: string) => string): void {
  if (security.owner === '' || !TRUSTED_PRINCIPALS.includes(security.owner)) {
    const owner = security.owner === '' ? 'an unknown principal' : describe(security.owner);
    throw new UntrustedError(`'${displayPath}' is owned by ${owner}; the HkdfGuard native library is only loaded from a location owned by SYSTEM, Administrators, or TrustedInstaller.`);
  }
  if (security.daclAbsent) {
    throw new UntrustedError(`'${displayPath}' has no DACL, which grants everyone full control; the HkdfGuard native library is only loaded from a location that only SYSTEM, Administrators, or TrustedInstaller can modify.`);
  }
  for (const ace of security.aces) {
    if ((ace.flags & ACE_FLAG_INHERIT_ONLY) !== 0) continue;
    switch (ace.type) {
      case AceType.denied:
      case AceType.deniedCallback:
        continue;
      case AceType.allowed:
      case AceType.allowedCallback:
        if ((ace.mask & guardedRights) !== 0 && !TRUSTED_PRINCIPALS.includes(ace.sid)) {
          throw new UntrustedError(`'${displayPath}' grants 0x${(ace.mask >>> 0).toString(16).toUpperCase().padStart(8, '0')} to ${describe(ace.sid)}; the HkdfGuard native library is only loaded from a location that only SYSTEM, Administrators, or TrustedInstaller can modify.`);
        }
        continue;
      default:
        throw new UntrustedError(`'${displayPath}' has an access control entry of type 0x${ace.type.toString(16).toUpperCase()}, which is not checked; refusing to load the HkdfGuard native library from there.`);
    }
  }
}

/** The signer policy: the expected publisher, the Code Signing and profile EKUs, and the pinned root. */
export function winVerifySignerIdentity(path: string, leafSubject: string, leafEkus: readonly string[], rootSha256: string, expectedPublisher: string): void {
  if (leafSubject !== expectedPublisher) {
    throw new UntrustedError(`'${path}' is signed by '${leafSubject}', not the expected HkdfGuard publisher '${expectedPublisher}'.`);
  }
  if (rootSha256.toUpperCase() !== WIN_EXPECTED_ROOT_SHA256) {
    throw new UntrustedError(`'${path}' is signed under a root with SHA-256 ${rootSha256}, not Microsoft Identity Verification Root Certificate Authority 2020 (${WIN_EXPECTED_ROOT_SHA256}), which HkdfGuard is signed under.`);
  }
  if (!leafEkus.includes(WIN_CODE_SIGNING_EKU)) {
    throw new UntrustedError(`'${path}' is signed with a certificate not issued for code signing (no EKU ${WIN_CODE_SIGNING_EKU}).`);
  }
  if (!leafEkus.includes(WIN_EXPECTED_PROFILE_EKU)) {
    throw new UntrustedError(`'${path}' is signed with a certificate not issued under HkdfGuard's Artifact Signing profile (no EKU ${WIN_EXPECTED_PROFILE_EKU}).`);
  }
}

export const PE_FILE_DLL = 0x2000;
export const PeMachine = { i386: 0x014c, amd64: 0x8664, arm64: 0xaa64 } as const;
const machineForArch: Record<string, number> = { x64: PeMachine.amd64, arm64: PeMachine.arm64, ia32: PeMachine.i386 };

/** Requires the PE header to mark the file a DLL built for `arch`. Run after the signature check, which covers the header. */
export function winVerifyImageKind(path: string, characteristics: number, machine: number, arch: string): void {
  if ((characteristics & PE_FILE_DLL) === 0) {
    throw new UntrustedError(`'${path}' is signed by the HkdfGuard publisher but is not a DLL (an executable renamed into place?); refusing to load it.`);
  }
  if (machineForArch[arch] !== machine) {
    const name = Object.entries(PeMachine).find(([, value]) => value === machine)?.[0].toUpperCase() ?? `0x${machine.toString(16).toUpperCase().padStart(4, '0')}`;
    throw new UntrustedError(`'${path}' is built for machine ${name}, but this is a ${arch} process; refusing to load it.`);
  }
}

/**
 * Reads a PE file's COFF header - machine and characteristics - from its first bytes, bounded.
 * @throws UntrustedError the file is not a PE image.
 */
export function winReadPeHeader(path: string, image: Uint8Array): { machine: number; characteristics: number } {
  const view = new DataView(image.buffer, image.byteOffset, image.byteLength);
  if (image.length < 0x40 || view.getUint16(0, true) !== 0x5a4d) {
    throw new UntrustedError(`Could not read the PE header of '${path}'; refusing to load it.`);
  }
  const peOffset = view.getUint32(0x3c, true);
  if (peOffset + 24 > image.length || view.getUint32(peOffset, true) !== 0x00004550) {
    throw new UntrustedError(`Could not read the PE header of '${path}'; refusing to load it.`);
  }
  return { machine: view.getUint16(peOffset + 4, true), characteristics: view.getUint16(peOffset + 22, true) };
}
