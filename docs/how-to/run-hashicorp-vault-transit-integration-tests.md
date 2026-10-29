# Run the HashiCorp Vault transit integration tests

`integration.test.ts` in `packages/keywrapping-hashicorpvault` makes real calls to a Vault transit
secrets engine through `HashiCorpVaultTransitKeyWrapper`. This page runs a Vault dev server in
Docker, provisions two transit keys and a token that may use only them, and runs the tests from the
command line.

The package's other tests serve a fake transit engine from `node:http` on 127.0.0.1, called through
the wrapper's real http client, and run without any of this. The integration tests are reported as
**skipped**, never passed, until a key is configured.

They check that:

- a DEK survives a wrap and unwrap round trip;
- `generateAndWrap` produces a wrapped DEK that reveals to 32 non-zero bytes, both generated in
  Vault (no context) and generated locally and encrypted (with one);
- a DEK wrapped under one context is refused under another, and under none;
- a DEK wrapped under one key is refused by another;
- a tampered wrapped DEK, and an invalid token, are refused;
- a crypto provider can generate and reveal its DEK through the wrapper.

The tests never create, rotate, read or delete a key.

If you already run hkdfguard-dotnet's, hkdfguard-java's or hkdfguard-python's Vault transit
integration tests, you have a Vault, the keys and a token: skip to
[step 3](#3-point-the-tests-at-the-key) and use the same values.

## What you need

- [Docker](https://docs.docker.com/get-docker/).
- Git Bash (on Windows) or any bash with `curl`, for the provisioning script.
- Node.js 22 or later, and this repository installed (`npm install`). The wrapper itself needs no
  HTTP library: it uses Node's own `node:http` and `node:https`.

## 1. Start a Vault dev server

```bash
docker run -d --name hkdfguard-vault --cap-add=IPC_LOCK -p 127.0.0.1:8200:8200 hashicorp/vault:1.19.0
```

The image's default command is `server -dev`: unsealed, in memory, listening on plain http. Bind it
to `127.0.0.1` as above, never to every interface. The wrapper allows http only on a loopback
address. If port 8200 is taken (another Vault, say), pick another host port, such as
`-p 127.0.0.1:18200:8200`, and use it in every address below.

Read the root token the server printed:

```bash
docker logs hkdfguard-vault 2>&1 | grep 'Root Token:'
```

A dev server keeps everything in memory, so a restarted container starts empty, with a new root
token. Repeat step 2 after every restart.

> The Vault cache's integration tests (`packages/cache-hashicorpvault`) can use the same server;
> they read the same `HKDFGUARD_TEST_VAULT_ADDR`, `HKDFGUARD_TEST_VAULT_TOKEN` and
> `HKDFGUARD_TEST_VAULT_CACERT`, but need a token that can read their KV secret.

## 2. Provision the keys and a token

From the repository root:

```bash
VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=<root token> scripts/provision-vault-transit-test-key.sh
```

The script uses the root token only to provision. It:

1. enables a transit engine at `transit` if nothing is mounted there;
2. creates two `aes256-gcm96` keys, `hkdfguard-test` and `hkdfguard-test-other`;
3. writes the policy `hkdfguard-transit-test`, granting `update` (not `create`) on `encrypt`,
   `decrypt` and `datakey/wrapped` for those two keys only;
4. creates a 24-hour token with only that policy, and prints it.

So the tests run with what a real application would get, not root: they can't create a key by
naming one that doesn't exist, list keys, or touch anything else. Re-running the script is safe; it
keeps the keys and prints a new token. It is the same script as hkdfguard-dotnet's.

To put the token straight into the environment without printing it:

```bash
export HKDFGUARD_TEST_VAULT_TOKEN=$(VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=<root token> scripts/provision-vault-transit-test-key.sh)
```

Point the script only at a dev server. If yours was started with `-dev-tls`, set `VAULT_CACERT` to
its CA first, and use https below.

> **Security:** the token goes in the environment of the shell you run the tests from, and nowhere
> else. Never put it in `vault.test.properties`, `package.json`, a `.env` file in the repository, or
> an IDE run configuration that is committed, and don't echo it.

## 3. Point the tests at the key

The tests read these variables - the same ones the .NET, Java and Python integration tests read - in
the Node process:

| Variable | Needed | Meaning |
|---|---|---|
| `HKDFGUARD_TEST_VAULT_TRANSIT_KEY` | Yes | The transit key to wrap under, `hkdfguard-test`; without it every test is skipped |
| `HKDFGUARD_TEST_VAULT_TOKEN` | Yes | A token allowed `update` on that key's `encrypt`, `decrypt` and `datakey/wrapped`; environment only |
| `HKDFGUARD_TEST_VAULT_ADDR` | No | Vault's address; default `http://127.0.0.1:8200` |
| `HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY` | No | A second key, `hkdfguard-test-other`, for the cross-key test; that test is skipped without it |
| `HKDFGUARD_TEST_VAULT_TRANSIT_MOUNT` | No | The transit mount; default `transit` |
| `HKDFGUARD_TEST_VAULT_CACERT` | No | The path of a CA to trust, for a server started with TLS; then it is the only CA trusted |

Everything but the token can also go in `vault.test.properties` in the repository root, next to
`package-lock.json` - the file the Vault cache's integration tests read, and the same file
hkdfguard-java and hkdfguard-python read, so you can copy theirs:

```properties
# The transit keys the Vault transit integration tests use.
HKDFGUARD_TEST_VAULT_ADDR=http://127.0.0.1:8200
HKDFGUARD_TEST_VAULT_TRANSIT_KEY=hkdfguard-test
HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY=hkdfguard-test-other
```

- **No token goes in the file.** The token is a secret, so it is read from the environment only.
- **The file stays on your machine.** `.gitignore` excludes `*.test.properties`.
- **An environment variable of the same name wins.** Set one for a single command, or on a CI runner,
  to override the file, or to run the tests without it.

The tests find `vault.test.properties` whatever the working directory: they look in the nearest
directory above the compiled test file that holds `package-lock.json`.

## 4. Run the tests

From the repository root, in Git Bash, macOS or Linux, with the token from step 2 in the environment:

```bash
HKDFGUARD_TEST_VAULT_ADDR=http://127.0.0.1:8200 HKDFGUARD_TEST_VAULT_TRANSIT_KEY=hkdfguard-test \
HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY=hkdfguard-test-other \
npm test --workspace packages/keywrapping-hashicorpvault
```

In PowerShell:

```powershell
$env:HKDFGUARD_TEST_VAULT_TOKEN = "<token the script printed>"
$env:HKDFGUARD_TEST_VAULT_ADDR = "http://127.0.0.1:8200"
$env:HKDFGUARD_TEST_VAULT_TRANSIT_KEY = "hkdfguard-test"
$env:HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY = "hkdfguard-test-other"
npm test --workspace packages/keywrapping-hashicorpvault
Remove-Item Env:HKDFGUARD_TEST_VAULT_TOKEN, Env:HKDFGUARD_TEST_VAULT_ADDR, Env:HKDFGUARD_TEST_VAULT_TRANSIT_KEY, Env:HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY
```

`npm test` in the package runs what is already built; build it first with
`npx tsc --build packages/keywrapping-hashicorpvault` (or every package with `npm run build`). To run
the integration tests alone:

```bash
node --test packages/keywrapping-hashicorpvault/dist/integration.test.js
```

Every test in the suite should pass with none skipped:

```text
# Subtest: HashiCorp Vault transit integration
    ok 1 - round-trips a 32-byte DEK through wrap and unwrap
    ok 2 - generates in Vault, with no context, a wrapped DEK that reveals
    ok 3 - generates, with a context, a wrapped DEK that reveals
    ok 4 - refuses to unwrap under another context, or none
    ok 5 - refuses to unwrap a tampered DEK with 400
    ok 6 - refuses to unwrap under another key
    ok 7 - refuses a token Vault doesn't know with 403
    ok 8 - lets a crypto provider generate and reveal its DEK through Vault
```

On a CI runner, start the same container as a service, run the provisioning script with the root
token you gave it (`-e VAULT_DEV_ROOT_TOKEN_ID=...`), and pass the printed token to the test step
through the job's environment, masked.

## If something goes wrong

| You see | Cause | Fix |
|---|---|---|
| `HashiCorp Vault transit integration # SKIP` | `HKDFGUARD_TEST_VAULT_TRANSIT_KEY` isn't set in the Node process or `vault.test.properties` | Set it in the same command, or the file in the repository root, next to `package-lock.json` |
| `refuses to unwrap under another key # SKIP` | `HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY` isn't set | Set it to `hkdfguard-test-other` |
| `Set HKDFGUARD_TEST_VAULT_TOKEN in the environment` | The token isn't in the Node process's environment | Step 2, in the same shell; it is never read from the file |
| `403 Forbidden` ... `permission denied` | The token expired (24 hours), or the container restarted and the token is gone | Step 2 again |
| `400 BadRequest` ... `encryption key not found` | The container restarted and the keys are gone, or the key name is wrong | Step 2 again |
| `no answer within`, or `ECONNREFUSED` | The container isn't running, or isn't on the address's port | `docker ps`; `docker start hkdfguard-vault`, then step 2 |
| `Vault's address ... must be https` | The address isn't loopback and isn't https | Use `127.0.0.1`, or https with `HKDFGUARD_TEST_VAULT_CACERT` |
| `EPROTO` or `wrong version number` | An https address for a dev server listening on http | Use `http://127.0.0.1:8200`, or start the server with `-dev-tls` |
| `SELF_SIGNED_CERT_IN_CHAIN` or `UNABLE_TO_VERIFY_LEAF_SIGNATURE` | Vault's certificate isn't trusted | Set `HKDFGUARD_TEST_VAULT_CACERT` to the CA's PEM file |

## When you're done

```bash
docker rm -f hkdfguard-vault
unset HKDFGUARD_TEST_VAULT_TOKEN
```

Nothing survives: the server kept its keys, policy and tokens in memory.
