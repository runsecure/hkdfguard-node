import { spawn } from 'node:child_process';
import { MAX_WRAPPED_KEY_BYTES } from '@runsecure/hkdfguard-abstractions';

/*
 * macOS: in the native library's legacy keychain mode a KEK's access list names the binary that
 * created it (the provisioning tool), so the first call under a service from any other binary - node
 * - is answered with a keychain authorization dialog in a logged-in session, or with KEK access
 * denied (-18) without one. A dialog nobody answers would block that call, and the test run, forever.
 *
 * awaitNativeAccess makes that first call under a service with a deadline, and turns a dialog nobody
 * answers into a failure that says what to do - the Node counterpart of the Go tests'
 * awaitNativeAccess. The add-on runs the call on libuv's thread pool, so a timer could notice the
 * deadline from inside this process, but nothing can cancel the blocked call there: the worker it
 * holds keeps the event loop alive, and the test file's process would hang at its end anyway. So the
 * call is made in a short-lived child process - the same node executable, so the same keychain
 * access list entry; "Always Allow" there answers for this process too - which is killed at the
 * deadline. What the call answers is left to the tests. Elsewhere there is no dialog, and this
 * resolves at once.
 */

/** How long the first native call under a service may take on macOS. */
export const NATIVE_ACCESS_TIMEOUT_MS = 60_000;

// The child: loads the package from its entry module, and makes one generateAndWrap under the service.
const PROBE = `
const [entry, service, capacity] = process.argv.slice(1);
const { NativeKeyWrapperV1 } = require(entry);
NativeKeyWrapperV1.create(service).generateAndWrap(new Uint8Array(Number(capacity))).then(() => process.exit(0), () => process.exit(0));
`;

const checked = new Map<string, Promise<void>>();

/**
 * Resolves once a native call under `service` has returned - on macOS, from a child process that
 * loads @runsecure/hkdfguard-keywrapping-native-v1 from `packageEntry` (its main module) - and
 * rejects, explaining the unanswered keychain dialog, when it has not after `timeoutMs`. Once per
 * service per process. Resolves at once off macOS.
 */
export function awaitNativeAccess(service: string, packageEntry: string, timeoutMs = NATIVE_ACCESS_TIMEOUT_MS): Promise<void> {
  if (process.platform !== 'darwin') return Promise.resolve();
  let pending = checked.get(service);
  if (pending === undefined) {
    pending = probeNativeAccess(service, packageEntry, timeoutMs);
    checked.set(service, pending);
  }
  return pending;
}

/** The probe itself, on any platform and uncached: one generateAndWrap in a child process, with a deadline. */
export function probeNativeAccess(service: string, packageEntry: string, timeoutMs = NATIVE_ACCESS_TIMEOUT_MS): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    const child = spawn(process.execPath, ['-e', PROBE, packageEntry, service, String(MAX_WRAPPED_KEY_BYTES)], { stdio: 'ignore' });
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`The first native call under service '${service}' has not returned after ${timeoutMs / 1000}s. `
        + 'On macOS the KEK\'s keychain item is asking for access in a dialog: click "Always Allow" (each node executable asks once). '
        + 'In a session with no UI the library reports KEK access denied (-18) instead; run the tests from a logged-in session.'));
    }, timeoutMs);
    const done = () => {
      clearTimeout(timer);
      resolve(); // whatever the call answered: the tests report it
    };
    child.on('exit', done);
    child.on('error', done); // couldn't start it: the tests' own calls report what is wrong
  });
}
