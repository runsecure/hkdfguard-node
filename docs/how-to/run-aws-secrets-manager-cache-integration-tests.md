# Run the AWS Secrets Manager cache integration tests

`src/integration.test.ts` in `packages/cache-awssecretsmanager` makes real calls to AWS Secrets
Manager through `AwsSecretsManagerSecretCache`. This page sets up a test secret and a
low-privilege identity for them, and runs them from the command line and the IDE.

The package's other tests run a real `SecretsManagerClient` - its serializer, middleware stack,
retries, deserializer and logger - whose HTTP handler is an in-process fake Secrets Manager, and
need none of this. The integration tests are reported as **skipped**, never passed, until a secret
is configured.

They check that:

- `decrypt` reveals the secret, whether `maxDecryptedLength` finds it first or `decrypt` is the
  first lookup;
- a secret that doesn't exist, beside the configured one, returns 0 rather than failing;
- if you also give the secret's expected JSON content: the whole value is that JSON object, every
  key reads back as `name#key` with its expected value, and a key it doesn't hold returns 0 -
  looking up the whole value first, and a key first.

The tests only read: they never list, create, change or delete a secret.

## What you need

- An AWS account. A secret costs $0.40 a month (new secrets are free for the first 30 days); the
  requests the tests make cost a fraction of a cent.
- The [AWS CLI](https://aws.amazon.com/cli/), for setting up and checking credentials.
- Node.js 22 or later, and the repository installed (`npm install` at its root; on Windows that
  needs Python 3 and Visual Studio Build Tools for the add-ons).

## 1. Create a test secret

In the console, open **Secrets Manager**, then **Store a new secret**:

1. Choose **Other type of secret**.
2. Under **Key/value pairs**, add a few keys, for example `username` = `hkdfguard-test` and
   `port` = `5432`. Use values only for tests, never real credentials.
3. Keep the **Encryption key** as `aws/secretsmanager` (the AWS managed key), so the identity needs
   no KMS permission.
4. Name it under a folder of its own, such as `hkdfguard-test/key-value`. The folder matters: the
   policy in step 2 grants access to everything under it, which the missing-secret test relies on.
5. Leave rotation off and store the secret.

Or with the CLI, signed in as an administrator:

```bash
aws secretsmanager create-secret --name hkdfguard-test/key-value \
  --secret-string '{"username":"hkdfguard-test","port":"5432"}'
```

Copy the secret's **ARN** from its details page; you need it for the policy, not for the tests.

If you set up the .NET, Java or Python integration tests, the same secret and IAM user serve here:
skip to step 4.

## 2. Create an IAM user for the tests

Don't run the tests as the root user, and don't create an access key for root. Create an IAM user
that can read only the test folder:

1. In the console, open **IAM**, then **Users**, then **Create user**. Name it, for example,
   `hkdfguard-dev` (the user from the [AWS KMS integration tests](run-aws-kms-integration-tests.md)
   will do).
2. Leave **Provide user access to the AWS Management Console** cleared. The tests need only an
   access key.
3. Create the user without attaching any policies.
4. Open the user, choose **Add permissions**, then **Create inline policy**. Switch to **JSON**,
   paste the policy below, and name it `HkdfGuardSecretsManagerIntegrationTest`:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Action": "secretsmanager:GetSecretValue",
       "Resource": "arn:aws:secretsmanager:us-east-2:[account id]:secret:hkdfguard-test/*"
     }]
   }
   ```

   Replace the region and account ID with your secret's (the fourth and fifth fields of its ARN)
   and leave no placeholders. The `/*` covers every secret in the folder - including the random
   name the missing-secret test asks for: without permission on a name, Secrets Manager answers
   `AccessDeniedException` even for a secret that doesn't exist, rather than
   `ResourceNotFoundException`.
5. On the user's **Security credentials** tab, choose **Create access key**, then **Command Line
   Interface (CLI)**. Copy the access key ID and the secret access key. The secret is shown only
   once; if you lose it, delete the access key and create another.

If the secret uses a customer managed KMS key instead of `aws/secretsmanager`, also allow
`kms:Decrypt` on that key.

## 3. Store the credentials

Run `aws configure` and enter the IAM user's access key:

```text
AWS Access Key ID [None]: AKIA...
AWS Secret Access Key [None]: ...
Default region name [None]: us-east-2
Default output format [None]: json
```

- **Access key ID** is the shorter value starting with `AKIA`. **Secret access key** is the longer one.
- **Region** is the secret's region: the fourth field of its ARN.

This writes the `default` profile to `~/.aws/credentials` and `config` (`%USERPROFILE%\.aws\` on
Windows).

The tests take the access key from `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` (and
`AWS_SESSION_TOKEN`, if set) when both are in the environment, and otherwise **only** from the
credentials file - the profile named by `AWS_PROFILE`, or `default`, in `~/.aws/credentials` (or the
file `AWS_SHARED_CREDENTIALS_FILE` names). They deliberately don't use the SDK's default credential
chain, as the AWS KMS tests do: it merges the `config` file into the profile, and a `login_session`
there (left by `aws login`) would take precedence over the access key, running the tests as whoever
signed in - perhaps root - rather than as the test user. The region still comes from the SDK's usual
chain: `AWS_REGION`, or the profile's `region` in `config`.

Check that the CLI uses the IAM user and can read the secret:

```bash
aws sts get-caller-identity
aws secretsmanager get-secret-value --secret-id hkdfguard-test/key-value --query Name
```

The first command's `Arn` must end in `:user/hkdfguard-dev`. If it ends in `:root`, root
credentials are configured on this machine: run `aws configure` again with the IAM user's keys, and
remove any `login_session` line naming `:root` from the `config` file. The second command must print
the secret's name (`--query Name` keeps the value itself off your screen).

> **Security:** keep the access key only in the credentials file (or the environment of the one
> command). Never put it in `aws.test.properties`, `package.json`, a `.env` file, an IDE run
> configuration that is committed, or anything else in the repository. The tests never print it.

## 4. Point the tests at the secret

The tests read two settings - the same names the .NET, Java and Python integration tests read -
each from the environment of the test process, else from `aws.test.properties` in the repository
root, next to `package-lock.json`:

| Setting | Value | Needed for |
|---|---|---|
| `HKDFGUARD_TEST_AWS_SECRET_NAME` | The secret's **name**, such as `hkdfguard-test/key-value` - not its ARN | Every test |
| `HKDFGUARD_TEST_AWS_SECRET_JSON` | The JSON object the secret's `SecretString` holds, on one line | The two content tests |

`aws.test.properties` is ignored by git (`*.test.properties`), so the settings needn't be set for
every command. It is the same file the Java and Python tests read, with one `NAME=value` per line
and `#` starting a comment; if you have one there, copy it as it is:

```properties
HKDFGUARD_TEST_AWS_SECRET_NAME=hkdfguard-test/key-value
HKDFGUARD_TEST_AWS_SECRET_JSON={"username":"hkdfguard-test","port":"5432"}
```

The whole value is compared as JSON, so whitespace doesn't matter; each key is compared as the
cache caches it: a string as its text, a number, `true` or `false` as its JSON text (`5432` written
as a number reads back as `5432`, exactly as written). `null`, objects and arrays aren't keys. A name
that isn't a secret name - a placeholder, or an ARN - fails the tests with a message naming the
setting.

## 5. Run the tests

From the repository root, in Git Bash, macOS or Linux:

```bash
npm run build
npm test --workspace packages/cache-awssecretsmanager
```

with the settings in `aws.test.properties`, or for one command:

```bash
npm run build
HKDFGUARD_TEST_AWS_SECRET_NAME=hkdfguard-test/key-value \
HKDFGUARD_TEST_AWS_SECRET_JSON='{"username":"hkdfguard-test","port":"5432"}' \
npm test --workspace packages/cache-awssecretsmanager
```

In PowerShell:

```powershell
npm run build
$env:HKDFGUARD_TEST_AWS_SECRET_NAME = "hkdfguard-test/key-value"
$env:HKDFGUARD_TEST_AWS_SECRET_JSON = '{"username":"hkdfguard-test","port":"5432"}'
npm test --workspace packages/cache-awssecretsmanager
Remove-Item Env:HKDFGUARD_TEST_AWS_SECRET_NAME, Env:HKDFGUARD_TEST_AWS_SECRET_JSON
```

Add `AWS_PROFILE=hkdfguard-dev` only if the credentials are in a named profile rather than
`[default]`. To run just the integration tests, name the file, from
`packages/cache-awssecretsmanager`: `node --test dist/integration.test.js`.

Every test in the suite should pass with none skipped:

```text
▶ AWS Secrets Manager cache integration
  ✔ reveals the secret through decrypt, after finding it through maxDecryptedLength
  ✔ reveals the secret through a first lookup that is decrypt
  ✔ reveals the expected whole value, and every key
  ✔ reveals every key, and the expected whole value, when a key is looked up first
  ✔ returns 0 for a secret that doesn't exist
✔ AWS Secrets Manager cache integration
```

Without `HKDFGUARD_TEST_AWS_SECRET_JSON` the two content tests are skipped and the other three run.
Without `HKDFGUARD_TEST_AWS_SECRET_NAME` the whole suite is reported as skipped, with the reason:

```text
﹣ AWS Secrets Manager cache integration (0.3ms) # Set HKDFGUARD_TEST_AWS_SECRET_NAME to a secret's name, in the environment or aws.test.properties, to run AWS Secrets Manager cache integration tests.
```

The tests find `aws.test.properties` whatever the working directory, so it works from an IDE too.
To use environment variables instead: in **VS Code**, put them in a `.env` file outside the
repository and point the test runner's `envFile` at it in your user settings, not the workspace's;
in **WebStorm**, add them under **Environment variables** in the Node.js test run configuration
(keep the configuration out of version control).

On a CI runner, set `HKDFGUARD_TEST_AWS_SECRET_NAME` in the job and give it `AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN` from a role, for example through GitHub's OIDC
provider and `aws-actions/configure-aws-credentials`, rather than storing an access key. The
repository's own CI does neither, so there the suite is skipped.

## If something goes wrong

| You see | Cause | Fix |
|---|---|---|
| `﹣ AWS Secrets Manager cache integration ... # Set HKDFGUARD_TEST_AWS_SECRET_NAME ...` | `HKDFGUARD_TEST_AWS_SECRET_NAME` isn't set in the test process or `aws.test.properties` | Step 4: the file must be in the repository root, next to `package-lock.json` |
| 2 tests skipped | `HKDFGUARD_TEST_AWS_SECRET_JSON` isn't set | Set it to check the content, or ignore |
| `... which isn't a secret's name` | The setting is a placeholder or an ARN | Use the secret's name, such as `hkdfguard-test/key-value` |
| `There is no AWS credentials file` | Neither the environment nor `~/.aws/credentials` has an access key | Step 3 |
| `The [name] profile ... has no aws_access_key_id` | `AWS_PROFILE` names a profile that isn't in the credentials file, or holds no access key (an SSO or `login_session` profile) | Step 3; unset `AWS_PROFILE` or name the profile `aws configure` wrote |
| `AccessDeniedException` | The policy doesn't cover the secret's folder, or the tests use other credentials | Step 2's `Resource` (keep the `/*`); `aws sts get-caller-identity` |
| `AccessDeniedException` only in the missing-secret test | The policy names the one secret's ARN rather than its folder | Step 2: grant `.../secret:hkdfguard-test/*` |
| `Nothing is stored under ...`, or the first tests fail with nothing found | The name is wrong, or the region isn't the secret's | Copy the name again; set the region in step 3 (or `AWS_REGION`) |
| `Region is missing` | No region in the profile or environment | Step 3, or set `AWS_REGION` |
| `InvalidRequestException` | The secret is scheduled for deletion | Restore it (`aws secretsmanager restore-secret`), signed in as an administrator |
| `The secret's whole value isn't the expected JSON object`, or `Key "..." isn't the expected value` | `HKDFGUARD_TEST_AWS_SECRET_JSON` differs from the secret | Compare it with the secret in the console's **Retrieve secret value** |

## When you're done

- **Deactivate the access key** on the IAM user's **Security credentials** tab when you're not
  running the tests, and delete it when you no longer need it.
- **To stop the secret's monthly charge**, delete it, signed in as an administrator. Secrets Manager
  waits 7 to 30 days before deleting it, and you can restore it during that time.
- **Set a budget.** **Billing**, then **Budgets**, then a zero-spend or small monthly budget emails
  you if anything starts to cost money.
