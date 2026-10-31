# Run the Google Secret Manager cache integration tests

`integration.test.ts` in `packages/cache-googlesecretmanager` makes real calls to Google Cloud
Secret Manager through `GoogleSecretManagerSecretCache`. This page sets up a test secret, and runs
the tests from the command line.

The package's other tests use a fake Secret Manager, a gRPC server on the loopback address called
through the real `SecretManagerServiceClient`, and run without any of this. The integration tests
are reported as **skipped**, never passed, until the secret is configured.

They check that:

- the secret's latest version is revealed, through a client the cache creates
  (`GoogleSecretManagerSecretCache.create`) and through the application's own
  `SecretManagerServiceClient`;
- a secret that doesn't exist returns 0;
- with the expected JSON set (step 5), the whole value is that JSON object, every member reads back
  as `secret#key`, and a key the secret doesn't hold returns 0 - reading the whole value first, and
  the keys first.

No secret value is ever printed, whether it matches or not. The tests only read: they never list,
create, change or delete a secret.

If you already run hkdfguard-dotnet's, hkdfguard-java's or hkdfguard-python's Secret Manager cache
integration tests, you have a secret and access: skip to [step 5](#5-fill-in-googletestproperties)
and use the same resource name.

## What you need

- A Google Cloud project with billing enabled. Secret Manager charges a few cents a month per active
  secret version and a fraction of a cent per test run; see
  [Secret Manager pricing](https://cloud.google.com/secret-manager/pricing).
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
secret=hkdfguard-integration-secret

gcloud config set project $project
gcloud auth application-default set-quota-project $project
gcloud services enable secretmanager.googleapis.com
```

Use a project for tests only, never one that holds real secrets. The quota project tells Google
which project to bill your ADC's API calls to; without it, calls can fail with `PERMISSION_DENIED`.

## 3. Create the secret

Give it a JSON object as its value, so the per-key checks have something to read:

```bash
printf '%s' '{"username":"hkdfguard","password":"not-a-real-password","port":5432}' > secret.json
gcloud secrets create $secret --replication-policy automatic --data-file secret.json
rm secret.json
```

Secret Manager returns a payload's CRC32C with every read when the payload was added with one (recent
`gcloud` releases add one), and the cache then checks it; a payload added without one is accepted
unchecked. Use made-up values: the tests compare the secret with a copy you put in a local file.

## 4. Give yourself access

As the project's owner you can already read the secret. To test with exactly what a deployed
application gets, grant **Secret Manager Secret Accessor** on this one secret to the identity that
runs the tests:

```bash
me=$(gcloud config get-value account)

gcloud secrets add-iam-policy-binding $secret --member "user:$me" --role roles/secretmanager.secretAccessor
```

> **Security:** an application needs only this role (`secretmanager.versions.access`), on just the
> secrets it reads. The cache never lists secrets, so never grant `secretmanager.secrets.list` or
> a project-wide role for it.

## 5. Fill in google.test.properties

The tests read the secret's resource name as `HKDFGUARD_TEST_GOOGLE_SECRET_NAME` and, optionally,
the JSON object it holds as `HKDFGUARD_TEST_GOOGLE_SECRET_JSON`. Rather than set them for every
command, add them to `google.test.properties` in the repository root, next to `package-lock.json` -
the file the Cloud KMS integration tests read too
([Run the Google Cloud KMS integration tests](run-google-kms-integration-tests.md)), this
repository's counterpart of hkdfguard-dotnet's `google.runsettings`, and the same file as
hkdfguard-java's and hkdfguard-python's, so you can copy either:

```properties
# The secret the cache tests read: its resource name, without a version (the cache reads "latest").
HKDFGUARD_TEST_GOOGLE_SECRET_NAME=projects/[project id]/secrets/hkdfguard-integration-secret

# Optional: the JSON object the secret's latest version holds, on one line.
HKDFGUARD_TEST_GOOGLE_SECRET_JSON={"username":"hkdfguard","password":"not-a-real-password","port":5432}
```

Replace `[project id]`, brackets included, with the project from step 2 (its ID or number).

- **Name the secret, not a version.** The tests read `projects/{project}/secrets/{secret}` only; the
  cache always reads the `latest` version.
- **The JSON is compared as JSON.** Whitespace and member order don't matter for the whole value.
  Each string member must match exactly; a number, `true` or `false` must be written as in the secret
  (`5432`, not `5432.0`), since the cache caches it as its JSON text. `null`, objects and arrays
  aren't checked by key. Without the variable, the two content tests are skipped and the rest run.
- **No credentials go in the file.** ADC signs in with your `gcloud auth application-default login`.
- **The file stays on your machine.** `.gitignore` excludes `*.test.properties`.
- **An environment variable of the same name wins.** Set one for a single command, or on a CI runner,
  to override the file, or to run the tests without it.

Check the name, and what the secret holds, before running the tests:

```bash
gcloud secrets versions access latest --secret $secret --project $project
```

It must print the same JSON object as `HKDFGUARD_TEST_GOOGLE_SECRET_JSON`.

## 6. Run the tests

From the repository root:

```bash
npm test --workspace packages/cache-googlesecretmanager
```

`npm test` runs the compiled tests; build first (`npx tsc --build packages/cache-googlesecretmanager`,
or `npx tsc --build` for everything). To run the integration tests alone after a build:

```bash
node --test packages/cache-googlesecretmanager/dist/integration.test.js
```

Without the file, set the variables for the one command instead, in Git Bash, macOS or Linux:

```bash
HKDFGUARD_TEST_GOOGLE_SECRET_NAME=projects/$project/secrets/$secret \
HKDFGUARD_TEST_GOOGLE_SECRET_JSON='{"username":"hkdfguard","password":"not-a-real-password","port":5432}' \
npm test --workspace packages/cache-googlesecretmanager
```

Every test in the suite should pass with none skipped:

```text
# Subtest: Google Secret Manager cache integration
    ok 1 - reveals the secret through a client of its own
    ok 2 - reveals the secret through the application's own client
    ok 3 - reveals the expected whole value, then every key
    ok 4 - reveals every key, then the expected whole value
    ok 5 - reports a secret that doesn't exist missing
```

The tests find `google.test.properties` whatever the working directory: they look in the nearest
directory above the compiled test file that holds `package-lock.json`.

On a CI runner, set the variables in the job and sign in with Workload Identity Federation (for
example GitHub's OIDC provider and `google-github-actions/auth`) rather than storing a service
account key.

## If something goes wrong

A Secret Manager refusal fails a test with the gRPC error as `@grpc/grpc-js` reports it: the numeric
status, its name, and Google's description (`7 PERMISSION_DENIED: Permission 'secretmanager.versions.access' denied ...`).

| You see | Cause | Fix |
|---|---|---|
| `Google Secret Manager cache integration # SKIP` | Neither `google.test.properties` nor the environment names the secret | Step 5: the file must be in the repository root, next to `package-lock.json` |
| `# SKIP Set HKDFGUARD_TEST_GOOGLE_SECRET_NAME and HKDFGUARD_TEST_GOOGLE_SECRET_JSON to check a secret's contents.` on two tests | `HKDFGUARD_TEST_GOOGLE_SECRET_JSON` isn't set | Step 5, or leave it unset to skip the content checks |
| `... isn't a secret's resource name. Replace the placeholders in google.test.properties` | A placeholder is still in the file, or the name is malformed | Step 5 |
| `HKDFGUARD_TEST_GOOGLE_SECRET_JSON isn't a JSON object.`, or a `SyntaxError` from `JSON.parse` | The value is an array, a string, or not JSON | Step 5: one JSON object, on one line |
| `The secret's whole value isn't the expected JSON object.`, or `... isn't the expected value` | The secret's latest version holds something else | Step 5's check command; update the file or add a new version |
| `Nothing is stored under '<secret>'` | The secret doesn't exist under that name, or its latest version is empty | Step 3; check the name in step 5 |
| `7 PERMISSION_DENIED: Permission 'secretmanager.versions.access' denied` | The role binding is missing or on another secret | Step 4; check with `gcloud secrets get-iam-policy $secret` |
| `7 PERMISSION_DENIED` naming a quota project, or the API | No quota project, or the API isn't enabled | Step 2 |
| `9 FAILED_PRECONDITION` | The latest version is disabled or destroyed | Enable it, or add a new version |
| `Could not load the default credentials` | ADC isn't set up | `gcloud auth application-default login` |

## When you're done

Delete the test secret, and its versions with it:

```bash
gcloud secrets delete $secret --project $project
```

Or keep it for the next run: a secret with one active version costs a few cents a month.
