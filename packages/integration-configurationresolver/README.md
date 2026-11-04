# @runsecure/hkdfguard-integration-configurationresolver

Resolves configuration templates - `Host=db;Password=${db-password}` - from HkdfGuard's protected
caches. The Node port of .NET's `HkdfGuard.Integration.ConfigurationResolver`, with the parts of
[ConfigurationResolver](https://github.com/runsecure/configurationresolver-dotnet) it needs (the
token, the reader, the resolver and the value-provider contract) in this one package.

- `ProtectedCacheValueProvider`: a value provider over any `ProtectedReadOnlyCache` - a
  `ProtectedCache`, a `FilePerSecretCache`, a collection or a remote secret store's cache. Each value
  is decrypted straight into the resolver's destination, or into a buffer that is zeroed, and never
  becomes a string.
- `ResolvingProtectedCacheCollection`: a `ProtectedCacheCollection` that resolves the templates its
  sources hold on their first lookup, from those same sources, and caches each result encrypted
  under the key ring.
- `ConfigurationResolverBuilder.addProtectedCache`: .NET's `AddProtectedCache` extension method.

```ts
import { ConfigurationItemReader, ConfigurationResolverBuilder, DefaultToken } from '@runsecure/hkdfguard-integration-configurationresolver';

const template = 'Host=db.internal;Password=${db-password}';
const token = new DefaultToken();
const reader = new ConfigurationItemReader(token);
reader.readKeys(template);

const resolver = new ConfigurationResolverBuilder().withToken(token).withReader(reader).addProtectedCache(secrets).build();
const destination = new Uint8Array(1024);
const length = await resolver.resolve(template, destination);
```

Values are UTF-8 bytes, and every lookup is asynchronous, as every HkdfGuard cache's is. See
[Resolve configuration templates](https://github.com/runsecure/hkdfguard-node/blob/main/docs/how-to/resolve-configuration-templates.md)
for the collection, prefetching and the differences from .NET.
