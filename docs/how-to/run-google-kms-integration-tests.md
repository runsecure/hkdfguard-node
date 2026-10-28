# Run the Google Cloud KMS integration tests

`integration.test.ts` in `packages/keywrapping-googlekms` makes real calls to Google Cloud KMS
through `GoogleKmsKeyWrapper`. This page sets up a test key, and runs the tests from the command
line.

The package's other tests use a fake Cloud KMS, a gRPC server on the loopback address called through
the real `KeyManagementServiceClient`, and run without any of this. The integration tests are
reported as **skipped**, never passed, until the key is configured.

They check that:

- a DEK survives a wrap and unwrap round trip;
- `generateAndWrap` produces a wrapped DEK that reveals to 32 non-zero bytes;
- a wrapped DEK made under one context is refused under another;
- a tampered wrapped DEK is refused.

The tests never create, change or destroy a key.

If you already run hkdfguard-dotnet's, hkdfguard-java's or hkdfguard-python's Cloud KMS integration
tests, you have a key and access: skip to [step 5](#5-fill-in-googletestproperties) and use the same
resource name.

## What you need

- A Google Cloud project with billing enabled. Cloud KMS charges a small monthly fee per active key
  version and a fraction of a cent per test run; see [Cloud KMS pricing](https://cloud.google.com/kms/pricing).
- The [Google Cloud CLI](https://cloud.google.com/sdk/docs/install) (`gcloud`).
- Node.js 22 or later, and this repository installed (`npm install`).

## 1. Sign in

Sign in twice: once for `gcloud` itself, and once for Application Default Credentials (ADC),
which the tests use:

```bash
gcloud auth login
gcloud auth application-default login
```

## 2. Choose the project

```bash
project=<project id>
loc=us-east1
ring=<key ring name>
key=<key name>

gcloud config set project $project
gcloud auth application-default set-quota-project $project
gcloud services enable cloudkms.googleapis.com
```

Use a project for tests only, never one that protects real data. The quota project tells Google
which project to bill your ADC's API calls to; without it, calls can fail with `PERMISSION_DENIED`.

## 3. Create the key ring and key

```bash
gcloud kms keyrings create $ring --location $loc
gcloud kms keys create $key --keyring $ring --location $loc --purpose encryption --protection-level software
```

A software key is enough for tests. Key rings can't be deleted, so pick a name you don't mind
keeping.

## 4. Give yourself access

As the project's owner you can manage the key, but owner doesn't include using it. Grant yourself
**Cloud KMS CryptoKey Encrypter/Decrypter** on the test key:

```bash
me=$(gcloud config get-value account)

gcloud kms keys add-iam-policy-binding $key --keyring $ring --location $loc \
  --member "user:$me" --role roles/cloudkms.cryptoKeyEncrypterDecrypter
```

> **Security:** encrypt and decrypt together are fine for your own identity on a test key. A
> deployed application must have decrypt only; see the role table in
> [Wrap keys with Google Cloud KMS](use-google-kms.md#2-grant-each-identity-only-what-it-calls).

## 5. Fill in google.test.properties

The tests read the key's resource name as `HKDFGUARD_TEST_GOOGLE_KMS_KEY_NAME`. Rather than set it
for every command, create `google.test.properties` in the repository root, next to
`package-lock.json` - this repository's counterpart of hkdfguard-dotnet's `google.runsettings`, and
the same file as hkdfguard-java's and hkdfguard-python's, so you can copy either:

```properties
# The symmetric key that wraps DEKs: its resource name, without a key version.
HKDFGUARD_TEST_GOOGLE_KMS_KEY_NAME=projects/[project id]/locations/us-east1/keyRings/[key ring name]/cryptoKeys/[key name]
```

Replace `[project id]`, `[key ring name]` and `[key name]`, brackets included, with the names from
steps 2 and 3, and `us-east1` if you chose another location.

- **Name the key, not a version.** The wrapper refuses `.../cryptoKeyVersions/1`.
- **No credentials go in the file.** ADC signs in with your `gcloud auth application-default login`.
- **The file stays on your machine.** `.gitignore` excludes `*.test.properties`.
- **An environment variable of the same name wins.** Set one for a single command, or on a CI runner,
  to override the file, or to run the tests without it.

Check the name before running the tests:

```bash
gcloud kms keys describe "projects/$project/locations/$loc/keyRings/$ring/cryptoKeys/$key" --format "value(purpose)"
```

It must print `ENCRYPT_DECRYPT`.

## 6. Run the tests

From the repository root:

```bash
npm test --workspace packages/keywrapping-googlekms
```

`npm test` builds every package first; to run the integration tests alone after a build
(`npx tsc --build`):

```bash
node --test packages/keywrapping-googlekms/dist/integration.test.js
```

Without the file, set the variable for the one command instead, in Git Bash, macOS or Linux:

```bash
HKDFGUARD_TEST_GOOGLE_KMS_KEY_NAME=projects/$project/locations/$loc/keyRings/$ring/cryptoKeys/$key \
npm test --workspace packages/keywrapping-googlekms
```

Every test in the suite should pass with none skipped:

```text
# Subtest: Google Cloud KMS integration
    ok 1 - round-trips a 32-byte DEK through wrap and unwrap
    ok 2 - generates a wrapped DEK that reveals
    ok 3 - refuses to unwrap under another context
    ok 4 - refuses to unwrap a tampered DEK
```

The tests find `google.test.properties` whatever the working directory: they look in the nearest
directory above the compiled test file that holds `package-lock.json`.

On a CI runner, set the variable in the job and sign in with Workload Identity Federation (for
example GitHub's OIDC provider and `google-github-actions/auth`) rather than storing a service
account key.

## If something goes wrong

| You see | Cause | Fix |
|---|---|---|
| `Google Cloud KMS integration # SKIP` | Neither `google.test.properties` nor the environment names the key | Step 5: the file must be in the repository root, next to `package-lock.json` |
| `... isn't a key's resource name. Replace the placeholders in google.test.properties` | A placeholder is still in the file, or the name is malformed | Step 5 |
| `PERMISSION_DENIED` naming `useToEncrypt` or `useToDecrypt` | The role binding is missing or on another key | Step 4; check with `gcloud kms keys get-iam-policy $key --keyring $ring --location $loc` |
| `PERMISSION_DENIED` naming a quota project, or the API | No quota project, or the API isn't enabled | Step 2 |
| `NOT_FOUND` | A name in the file is wrong | Step 5's check command |
| `Could not load the default credentials` | ADC isn't set up | `gcloud auth application-default login` |

## When you're done

Key rings and keys can't be deleted, but a key with no active versions costs nothing. Destroy the
test key's versions:

```bash
gcloud kms keys versions list --key $key --keyring $ring --location $loc
gcloud kms keys versions destroy 1 --key $key --keyring $ring --location $loc
```

A destroyed version is kept, restorable, for its scheduled-destruction period (30 days by default),
then destroyed for good.
