/**
 * Runs application code (its logger, its tracer) so that an exception from it can never decide
 * whether the key stays in use, nor fail an encryption or a refresh. Shared by the provider and the
 * session. Never exported from the package index.
 */
export function quietly(action: () => void): void {
  try {
    action();
  } catch {
    // Deliberately ignored: see above.
  }
}
