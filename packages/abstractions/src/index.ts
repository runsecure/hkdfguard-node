/**
 * The abstractions every HkdfGuard package is built against - the Node port of the .NET
 * HkdfGuard.Abstractions library: the interfaces implementations satisfy, the rules every port
 * applies identically, the shared errors, and the limits and defaults.
 *
 * Implementation packages (key wrappers, crypto providers, caches) depend on this package and never
 * on each other, so any one can be swapped for another implementation of the same interface.
 */
export * from './errors.js';
export * from './rules.js';
export * from './policy.js';
export type * from './interfaces.js';
