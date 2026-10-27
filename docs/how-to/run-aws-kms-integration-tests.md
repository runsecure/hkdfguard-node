# Run the AWS KMS integration tests

`src/integration.test.ts` in `packages/keywrapping-awskms` makes real calls to AWS KMS through
`AwsKmsKeyWrapper`. This page sets up a KMS key and a low-privilege identity for them, and runs
them from the command line and the IDE.

The package's other tests use an in-process fake KMS (which really encrypts, with AES-GCM, so a
wrong key, a wrong encryption context and tampering are refused), or a real `KMSClient` whose HTTP
handler answers in-process, and run without any of this. The integration tests are reported as
**skipped**, never passed, until a key is configured.

They check that:

- a DEK survives a wrap and unwrap round trip;
- `generateAndWrap` produces a wrapped DEK that reveals to 32 non-zero bytes;
- a DEK wrapped under one encryption context is refused under another;
- a tampered wrapped DEK is refused.

The tests never create, change, disable or delete a key.

## What you need

- An AWS account. The free tier covers the requests; the key itself costs about $1 a month.
- The [AWS CLI](https://aws.amazon.com/cli/), for setting up and checking credentials.
- Node.js 22 or later, and the repository installed (`npm install` at its root; on Windows that
  needs Python 3 and Visual Studio Build Tools for the add-ons).

## 1. Create a test key

Create a symmetric, encrypt-and-decrypt KMS key as in
[Wrap keys with AWS KMS, step 1](use-aws-kms.md#1-create-the-kms-key). Use a key only for tests,
never one that protects real data, and give it an alias such as `alias/hkdfguard-integration-test`
so it's easy to find.

Copy its key ARN.

## 2. Create an IAM user for the tests

Don't run the tests as the root user, and don't create an access key for root. Create an IAM user
that can use only this key:

1. In the console, open **IAM**, then **Users**, then **Create user**. Name it, for example,
   `hkdfguard-dev`.
2. Leave **Provide user access to the AWS Management Console** cleared. The tests need only an
   access key.
3. Create the user without attaching any policies.
4. Open the user, choose **Add permissions**, then **Create inline policy**. Switch to **JSON**,
   paste the policy below with your key's ARN as `Resource`, and name it `HkdfGuardKmsIntegrationTest`:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Action": ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKeyWithoutPlaintext"],
       "Resource": "arn:aws:kms:us-east-2:[account id]:key/[key id]"
     }]
   }
   ```

   Replace the whole ARN with your own and leave no placeholders. Use the key ARN, not the alias
   ARN: an alias in `Resource` doesn't grant access to the key.
5. On the user's **Security credentials** tab, choose **Create access key**, then **Command Line
   Interface (CLI)**. Copy the access key ID and the secret access key. The secret is shown only
   once; if you lose it, delete the access key and create another.

## 3. Store the credentials

Run `aws configure` and enter the IAM user's access key:

```text
AWS Access Key ID [None]: AKIA...
AWS Secret Access Key [None]: ...
Default region name [None]: us-east-2
Default output format [None]: json
```

- **Access key ID** is the shorter value starting with `AKIA`. **Secret access key** is the longer one.
- **Region** is the key's region: the fourth field of its ARN.

This writes the `default` profile to `~/.aws/credentials` and `config` (`%USERPROFILE%\.aws\` on
Windows). The AWS SDK for JavaScript reads both files, so neither the credentials nor the region
needs to be in an environment variable.

Check that the CLI uses the IAM user and can reach the key:

```bash
aws sts get-caller-identity
aws kms generate-data-key-without-plaintext --key-id <your-key-arn> --key-spec AES_256
```

The first command's `Arn` must end in `:user/hkdfguard-dev`. If it ends in `:root`, root
credentials are configured on this machine: run `aws configure` again with the IAM user's keys, and
remove any `login_session` line naming `:root` from the `config` file. The second command must
return a `CiphertextBlob`.

> **Security:** keep the access key only in the credentials file. Never put it in `package.json`,
> a `.env` file, an IDE run configuration that is committed, or anything else in the repository.

## 4. Point the tests at the key

The tests read the key ARN from the `HKDFGUARD_TEST_AWS_KMS_KEY_ID` environment variable - the same
variable the .NET, Java and Python integration tests read - in the test process. Set it for the one
command rather than in your shell profile.

## 5. Run the tests

From the repository root, in Git Bash, macOS or Linux:

```bash
npm run build
HKDFGUARD_TEST_AWS_KMS_KEY_ID=arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab \
npm test --workspace packages/keywrapping-awskms
```

In PowerShell:

```powershell
npm run build
$env:HKDFGUARD_TEST_AWS_KMS_KEY_ID = "arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
npm test --workspace packages/keywrapping-awskms
Remove-Item Env:HKDFGUARD_TEST_AWS_KMS_KEY_ID
```

Add `AWS_PROFILE=hkdfguard-dev` only if the credentials are in a named profile rather than
`[default]`. To run just the integration tests, name the file, from `packages/keywrapping-awskms`:
`node --test dist/integration.test.js`.

Every test in the suite should pass with none skipped:

```text
▶ AWS KMS integration
  ✔ round-trips a 32-byte DEK through wrap and unwrap
  ✔ generates a wrapped DEK that reveals
  ✔ refuses to unwrap under another encryption context
  ✔ refuses to unwrap a tampered DEK
✔ AWS KMS integration
```

Without the variable the whole suite is reported as skipped, with the reason:

```text
﹣ AWS KMS integration (0.3ms) # Set HKDFGUARD_TEST_AWS_KMS_KEY_ID to a symmetric KMS key to run the AWS KMS integration tests.
```

In **VS Code**, put the variable in a `.env` file outside the repository and point the test runner's
`envFile` at it in your user settings, not the workspace's. In **WebStorm**, add it under
**Environment variables** in the Node.js test run configuration (keep the configuration out of
version control).

On a CI runner, set `HKDFGUARD_TEST_AWS_KMS_KEY_ID` in the job and give the job a role, for example
through GitHub's OIDC provider and `aws-actions/configure-aws-credentials`, rather than storing an
access key. The repository's own CI does neither, so there the suite is skipped.

## If something goes wrong

| You see | Cause | Fix |
|---|---|---|
| `﹣ AWS KMS integration ... # Set HKDFGUARD_TEST_AWS_KMS_KEY_ID ...` | `HKDFGUARD_TEST_AWS_KMS_KEY_ID` isn't set in the test process | Set it in the same command, or in the IDE's run configuration |
| `AccessDeniedException` | The IAM user's policy doesn't name this key, or the tests are using other credentials | Step 2's `Resource`; `aws sts get-caller-identity` |
| `NotFoundException` | The ARN is wrong, or the profile's region isn't the key's | Copy the ARN again; set the region in step 3 (or `AWS_REGION`) |
| `Could not load credentials from any providers` | The SDK found no credentials | Step 3; set `AWS_PROFILE` if you used a named profile |
| `Region is missing` | No region in the profile or environment | Step 3, or set `AWS_REGION` |
| `DisabledException` or `KMSInvalidStateException` | The key is disabled or pending deletion | Re-enable it, or cancel its deletion |

## When you're done

- **Deactivate the access key** on the IAM user's **Security credentials** tab when you're not
  running the tests, and delete it when you no longer need it.
- **To stop the key's monthly charge**, schedule it for deletion, signed in as an administrator.
  KMS waits 7 to 30 days before deleting it, and you can cancel during that time. Don't schedule a
  key that wrapped anything you still need.
- **Set a budget.** **Billing**, then **Budgets**, then a zero-spend or small monthly budget emails
  you if anything starts to cost money.
