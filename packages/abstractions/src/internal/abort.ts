// Waiting that an AbortSignal cuts short, for the network-backed packages' retries.

/** Resolves after `ms`, or rejects with `signal`'s reason once it is aborted - at once if it already is. */
export function delay(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    if (signal?.aborted === true) {
      reject(abortReason(signal));
      return;
    }
    const onAbort = () => {
      clearTimeout(timer);
      reject(abortReason(signal!));
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

/** `promise`, or `signal`'s reason once it is aborted, whichever comes first; `promise` itself without a signal. */
export function untilAborted<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (signal === undefined) return promise;
  return new Promise<T>((resolve, reject) => {
    if (signal.aborted) {
      reject(abortReason(signal));
      return;
    }
    const onAbort = () => reject(abortReason(signal));
    signal.addEventListener('abort', onAbort, { once: true });
    promise.then(
      (value) => { signal.removeEventListener('abort', onAbort); resolve(value); },
      (error: unknown) => { signal.removeEventListener('abort', onAbort); reject(error); });
  });
}

/**
 * What an aborted `signal` rejects with: its reason, as it is. Typed as an Error, which it is unless
 * the caller aborted with something else - and then that something is what they asked to be thrown.
 */
export function abortReason(signal: AbortSignal): Error {
  return signal.reason as Error;
}
