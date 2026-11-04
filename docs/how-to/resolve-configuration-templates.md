# Resolve configuration templates from protected caches

This page fills the `${name}` items in a template, such as a connection string or a configuration
file, with secrets from HkdfGuard's protected caches. Everything it uses is in one package,
`@runsecure/hkdfguard-integration-configurationresolver`. That package is the Node port of .NET's
`HkdfGuard.Integration.ConfigurationResolver`, together with the parts of
[ConfigurationResolver](https://github.com/runsecure/configurationresolver-dotnet) that it needs:
the token, the reader, the resolver and the value-provider contract.

Any `ProtectedReadOnlyCache` can supply the values:

- a `ProtectedCache`, a `ProtectedCacheCollection` or a `FilePerSecretCache`
- a remote secret store's cache: `AwsSecretsManagerSecretCache`, `AzureKeyVaultSecretCache`,
  `GoogleSecretManagerSecretCache` or `HashiCorpVaultSecretCache`

## 1. Install

```sh
npm install @runsecure/hkdfguard-integration-configurationresolver
```

Add the package for your cache too, such as `@runsecure/hkdfguard-cache-hashicorpvault`. Everything
below is imported from `@runsecure/hkdfguard-integration-configurationresolver`.

## 2. Resolve a template

A template's key is the cache's name for the value, unchanged. For a remote cache that includes the
`secret#key` form, so `${app-config#password}` is the `password` key of the secret `app-config`.

```ts
import { wipe } from '@runsecure/hkdfguard-abstractions';
import { ConfigurationItemReader, ConfigurationResolverBuilder, DefaultToken } from '@runsecure/hkdfguard-integration-configurationresolver';

// secrets is any ProtectedReadOnlyCache, such as a HashiCorpVaultSecretCache.
const template = 'Host=db.internal;Username=${app-config#user};Password=${app-config#password}';

const token = new DefaultToken();
const reader = new ConfigurationItemReader(token);
reader.readKeys(template);

const resolver = new ConfigurationResolverBuilder().withToken(token).withReader(reader).addProtectedCache(secrets).build();

const connectionString = new Uint8Array(1024);
try {
  const length = await resolver.resolve(template, connectionString);
  // use connectionString.subarray(0, length)
} finally {
  wipe(connectionString);
}
```

The resolver looks up only the keys the reader read from the template. Read the template from a
trusted source, since it decides which secrets are revealed. Write `$${name}` for the literal text
`${name}`.

A missing value rejects with `ConfigurationKeyError`, whose `error` is `ConfigurationKeyErrorCode.notFound`,
and a destination that is too small rejects with `DestinationTooSmallError`. A cache's own error, such
as a remote store refusing access, propagates unchanged. Pass an `AbortSignal` as `resolve`'s third
argument to cancel; it reaches every cache lookup.

> **Security:** Each value is decrypted straight into the destination, or into a buffer that is
> zeroed once the value is copied out. It never becomes a string. If resolving fails, the resolver
> zeroes the whole destination. The template itself, when you pass a string, is immutable and can't
> be zeroed; pass a `Uint8Array` for a template that holds secrets.

### Prefetching

Every lookup is asynchronous, so a remote cache fetching a secret it hasn't cached yet never blocks
`resolve`. To fetch everything a template needs ahead of time, such as at startup, so a missing
secret or a refused credential shows up then, call `prefetch` with the reader. The cache keeps every
value it fetches, encrypted, so `resolve` then reads only from memory:

```ts
import { ConfigurationItemResolver, ProtectedCacheValueProvider } from '@runsecure/hkdfguard-integration-configurationresolver';

const provider = new ProtectedCacheValueProvider(secrets);
await provider.prefetch(reader);
const resolver = new ConfigurationItemResolver(token, reader, [provider]);
```

Prefetching asks for each key once. A key the cache doesn't have is skipped then, and reported by
`resolve`. `prefetchKeys` takes the keys themselves.

## 3. Combine it with other providers

Pass several providers, highest priority first. The first one that has a key supplies its value.
Any `ValueProvider` works. For one over your own settings that aren't secret, extend
`ValueProviderBase` and implement `tryGetBytes` and `tryGetByteCount`:

```ts
const resolver = new ConfigurationItemResolver(token, reader, [new ProtectedCacheValueProvider(secrets), mySettingsProvider]);
```

## 4. Keep templates in the caches themselves

`ResolvingProtectedCacheCollection` resolves templates for you, on lookup. It works like
`ProtectedCacheCollection`: you add sources, and it checks them in order. When the value it finds
holds items, it resolves them from the same sources, encrypts the result under your key ring, and
caches it. Later lookups only decrypt the cached result. A value without items is answered by its
source, unchanged.

Because the collection is itself a `ProtectedReadOnlyCache`, anything that reads a cache can read
resolved templates without knowing they were templates:

```ts
import { ResolvingProtectedCacheCollection } from '@runsecure/hkdfguard-integration-configurationresolver';

// ring is your application's key ring. local holds, say, the encrypted value
// "Host=db.internal;Username=${app-config#user};Password=${app-config#password}"
// under the name "orders.connection-string"; vault is a HashiCorpVaultSecretCache.
const secrets = new ResolvingProtectedCacheCollection(ring).add(local).add(vault);

const connectionString = new Uint8Array((await secrets.maxDecryptedLength('orders.connection-string')) ?? 0);
const length = await secrets.decrypt('orders.connection-string', connectionString);
```

Items can also come from value providers that are asked after every source, for values that aren't
secret:

```ts
const secrets = new ResolvingProtectedCacheCollection(ring).add(local).add(vault).addValueProvider(mySettingsProvider);
```

> **Security:** Any value in any source that holds `${...}` is a template, and a template can name
> any value in any source. Add only sources you trust as much as the secrets they can reach.

Some things to know:

- **Resolved values are kept until you invalidate them.** A value a template uses can change, for
  example through an `addOrUpdate` or a rotated remote secret. When it does, call
  `invalidate(name)` with the template's name, or `clear()`. The next lookup resolves it again. A
  resolution already under way when you call either doesn't cache its result.
- **A resolved value expires with its key,** as every protected cache's values do: once the ring
  retires the key version it was encrypted under, the next lookup resolves it again under the
  current key.
- **Items are resolved one level deep.** An item whose value is itself a template inserts that
  template's text unresolved.
- **A template that names a missing value rejects** with `ConfigurationKeyError` on lookup, rather
  than reporting the template's name missing. A template that resolves to nothing is reported
  missing, as an empty value can't be cached.
- **Names match exactly**, as the sources' own names may. The collection keeps `Db` and `db` apart,
  even though HkdfGuard's caches otherwise ignore ASCII case.
- **Resolved values are capped** at `maxResolvedLength` bytes, 1 MiB by default. A longer one rejects
  with `ResolvedValueTooLongError`. Set it, and the token, with the options
  `new ResolvingProtectedCacheCollection(ring, { token, maxResolvedLength })`.

## Values as strings

`ValueProvider.tryGetValue` returns a value as a string, which can't be zeroed. The resolver never
calls it, and `ProtectedCacheValueProvider` rejects with `StringValuesNotAllowedError` if anything
else does. When a caller truly needs strings, opt in:

```ts
const provider = new ProtectedCacheValueProvider(secrets, { allowStringValues: true });
```

## Differences from .NET

- **UTF-8 only.** Node has no mutable string to resolve into, so values are written as UTF-8 into a
  `Uint8Array`, and there is one `resolve`. A source may be a string, which is encoded, or UTF-8
  bytes. `TryGetChar` is `tryGetBytes`, and an item's `sourceIndex` is a byte index into the UTF-8
  source.
- **Asynchronous.** Every HkdfGuard cache's lookups are asynchronous in Node, so value providers and
  `resolve` return promises and take an optional `AbortSignal`. There are no synchronous members, and
  nothing blocks: `PrefetchAsync` is `prefetch` (a reader) and `prefetchKeys` (the keys), and it is
  needed only to fetch ahead of time.
- **Results, not out parameters.** `tryGetBytes` resolves to `{ status, written }`, and `tryGetValue`
  to `{ status, value }`. `ValueProviderBase`'s `TryGetByteCount` is `tryGetByteCount`, resolving to
  the count or `undefined`.
- **Errors are Node's.** Each has a stable `code`, as every HkdfGuard error does.
  `ConfigurationKeyException` is `ConfigurationKeyError` (`ERR_HKDFGUARD_CONFIGURATION_KEY`), and its
  `ConfigurationKeyError` enum is `ConfigurationKeyErrorCode`, whose values are the .NET names, so
  messages read as .NET's do. The destination's `ArgumentException` is `DestinationTooSmallError`, an
  `InvalidArgumentError`. The `InvalidOperationException`s are `StringValuesNotAllowedError`,
  `ResolvedValueTooLongError` and, from the builder, `InvalidOperationError`. `ArgumentNullException`
  is `TypeError`, and other argument errors are `InvalidArgumentError`.
- **Node names.** Members are camelCase, and `init` properties are an options object. The resolver
  needs only a reader's keys, the `KeyReader` interface; `ConfigurationItemReader` reads them with
  `readKeys`, `readKeysFrom` (a Node `Readable` or any iterable of `Uint8Array` chunks, with an
  optional encoding and byte order mark detection) and `readKeysAll`. `AddProtectedCache` is a method
  of the builder. `ConfigurationItemResolver` takes its providers as an array.
- Only the parts of ConfigurationResolver this integration uses are ported. The file-secret,
  environment-variable and dictionary providers, `StringValueProviderBase`, `SecretBuffer`, and the
  Microsoft.Extensions.Configuration support are not.
