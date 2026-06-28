# Configuring aws-xfa with AWS IAM Identity Center (SSO) and a FIDO security key

This guide sets up `aws-xfa` to obtain credentials through **AWS IAM Identity
Center** (formerly AWS SSO) using a **FIDO2 security key** (e.g. a hardware
security key) as your authenticator. It is the **phishing-resistant** path and
the one to use where a TOTP code is not acceptable (for example, environments
that mandate phishing-resistant MFA).

All names below are placeholders — replace `<…>` with your own values.

---

## Which path is this?

`aws-xfa` supports two credential models:

| Model | How MFA works | aws-xfa config |
|-------|---------------|----------------|
| **IAM user + STS** | A 6-digit **TOTP** (from 1Password or a YubiKey's OATH app via `ykman`) passed to `sts get-session-token`. | `mfa_source` / `ykman_account` |
| **IAM Identity Center (SSO)** | A **FIDO security key** tapped in the browser during `aws sso login`. No code is typed. | auto-detected, or `auth_type = sso` |

**This document is the SSO + FIDO path.** You do **not** need `ykman` or an OATH
secret for it — the security key is used directly by the browser.

> **Why a security key can't be used by the CLI directly:** AWS STS only accepts
> a typed TOTP, and a FIDO security key produces a cryptographic, origin-bound
> assertion, not a code. AWS therefore supports security keys **only for browser
> sign-in**. Identity Center bridges this: `aws sso login` performs the FIDO
> challenge **in a browser** and returns an SSO session token; the CLI then
> exchanges that token for short-lived role credentials. `aws-xfa` materializes
> those into `~/.aws/credentials` so any tool that reads static credentials keeps
> working.

---

## Prerequisites

1. **AWS CLI v2** on your `PATH` (`aws --version` shows `aws-cli/2.x`). The SSO
   path uses `aws configure export-credentials` and `aws sso login`, both v2-only.
2. **`aws-xfa`** installed (`pip install -e '.[dev]'` for development).
3. **IAM Identity Center enabled** in your AWS organization, with a **permission
   set assigned to you** for the target account. (If you sign in to an access
   portal at a `*.awsapps.com/start` URL, it's enabled.)
4. A **FIDO2 security key** registered as your MFA in the Identity Center portal
   (see Step 1).

---

## Step 1 — Register your security key in the access portal

This is the "FIDO" part: the key is registered with Identity Center and used in
the browser during login.

1. Sign in to your Identity Center **access portal**. The URL is the one your
   administrator gave you — typically `https://<your-subdomain>.awsapps.com/start`
   or `https://d-xxxxxxxxxx.awsapps.com/start`. (AWS GovCloud uses a different
   domain — see the GovCloud notes below.)
2. Open **MFA devices** (under your user / security settings) and **register a
   security key**. Follow the browser prompt and **touch the key** when asked.
3. If your administrator controls the policy, ask them to **require security
   keys** for your account — that is what makes the sign-in phishing-resistant
   (otherwise a weaker factor could be used as a fallback).

> A single security key can hold credentials for multiple users/accounts; you do
> not need a separate key per profile.

---

## Step 2 — Configure the CLI profile

Use the AWS CLI's interactive wizard, which discovers the accounts and roles you
have access to and writes the config for you. It opens a browser and requires a
**security-key tap**, so run it in your own terminal:

```sh
aws configure sso
```

Answer the prompts (example values shown):

| Prompt | Enter |
|--------|-------|
| `SSO session name` | `<session-name>` (e.g. `my-sso`) |
| `SSO start URL` | `https://<your-portal>.awsapps.com/start` |
| `SSO region` | `<sso-region>` (e.g. `us-east-1`) |
| `SSO registration scopes` | press Enter for the default (`sso:account:access`) |

A browser opens → authenticate and **tap your security key** → then:

| Prompt | Enter |
|--------|-------|
| (account list) | choose the **target account** |
| (role list) | choose your **permission set** |
| `CLI default client Region` | `<region>` |
| `CLI default output format` | `json` (recommended; only affects normal `aws` commands) |
| **`CLI profile name`** | **`<base-profile>`** — the name you will pass to `aws-xfa` |

The wizard writes something like this to `~/.aws/config`:

```ini
[sso-session <session-name>]
sso_start_url = https://<your-portal>.awsapps.com/start
sso_region = <sso-region>
sso_registration_scopes = sso:account:access

[profile <base-profile>]
sso_session = <session-name>
sso_account_id = <ACCOUNT_ID>
sso_role_name = <PERMISSION_SET>
region = <region>
output = json
```

> **Tip — reuse an existing profile name.** If you already have a `[profile
> <base-profile>]` (e.g. an old IAM-user profile) and want `aws-xfa <base-profile>`
> to switch to SSO, name the CLI profile the same. The wizard adds the `sso_*`
> keys to that section. Any old `[<base-profile>-long-term]` / `[<base-profile>]`
> entries in `~/.aws/credentials` are then unused and can be deleted.

If you prefer to edit `~/.aws/config` by hand instead of running the wizard:
`aws-xfa` detects SSO from just **two** keys on the profile — `sso_account_id`
and `sso_role_name`. The SSO flow itself also needs a **source** — either a
`sso_session` that refers to an `[sso-session …]` block, or the legacy
`sso_start_url` + `sso_region` written directly on the profile. You still need to
run `aws sso login` once before credentials can be resolved.

---

## Step 3 — Get credentials with aws-xfa

```sh
aws-xfa <base-profile>
```

What happens:

1. `aws-xfa` detects the profile is SSO (it has `sso_account_id` + `sso_role_name`).
2. If the SSO session token is missing or expired, it runs `aws sso login`,
   which opens a browser → **tap your security key**.
3. It resolves the short-lived role credentials and **writes them into
   `~/.aws/credentials [<base-profile>]`** — `aws_access_key_id`,
   `aws_secret_access_key`, `aws_session_token`, `aws_security_token` (a
   boto2-compatible mirror), and an `expiration` marker that `aws-xfa` uses to
   track freshness (the AWS CLI/SDK does not read `expiration`).
4. Re-running while the credentials are still valid does nothing (a freshness
   margin re-fetches a few minutes before expiry); `--force` re-fetches now.

Verify:

```sh
aws --profile <base-profile> sts get-caller-identity
```

---

## Step 4 — (Optional) Assume-role sub-profiles

A common pattern is one SSO "base" profile plus role-assumption profiles into
other accounts. Those are plain AWS CLI assume-role profiles in `~/.aws/config`:

```ini
[profile <sub-profile>]
source_profile = <base-profile>
role_arn = arn:aws:iam::<TARGET_ACCOUNT_ID>:role/<TARGET_ROLE>
region = <region>
output = json
```

Once `aws-xfa <base-profile>` has written the base credentials, the AWS CLI/SDK
assumes the target role automatically using them — no extra `aws-xfa` command:

```sh
aws --profile <sub-profile> sts get-caller-identity
```

> **Trust-policy requirement (AWS side, not aws-xfa):** your **SSO permission-set
> role is a different principal** than any IAM user you used before. The target
> role's **trust policy** must allow your SSO role to assume it, and your
> permission set must allow `sts:AssumeRole`. If `--profile <sub-profile>` fails
> with **`AccessDenied`** on `AssumeRole`, that is the trust policy — an
> administrator change, not a tooling problem.

---

## How aws-xfa chooses SSO vs IAM-user STS

For each profile, `aws-xfa` decides the method with this precedence:

1. An explicit per-profile override in `~/.config/aws-xfa/config.json`:
   `"auth_type": "sso"` or `"sts"`.
2. Otherwise, **SSO** if `~/.aws/config` has **both** `sso_account_id` and
   `sso_role_name` for the profile.
3. Otherwise, **IAM-user STS**.

A profile with only `sso_session` (no role target) is treated as STS, since it
isn't directly assumable.

---

## Daily workflow

```sh
aws-xfa <base-profile>          # run when credentials expire; tap the key if it triggers login
aws --profile <base-profile> ...
aws --profile <sub-profile> ... # assumes the target role using the base creds
```

There is no unattended option for SSO: `aws sso login` needs a browser and a
key tap, so the **background daemon refuses SSO profiles**. Re-run
`aws-xfa <base-profile>` when the session expires.

---

## Notes for AWS GovCloud (US) / FIPS environments

- The access-portal URL uses the GovCloud domain
  (`https://start.us-gov-home.awsapps.com/directory/<id>`); `sso_region` is a
  GovCloud region (e.g. `us-gov-west-1`).
- For FIPS-validated endpoints, set `AWS_USE_FIPS_ENDPOINT=true` (and/or
  `AWS_CA_BUNDLE` as required). `aws-xfa` inherits your environment when it calls
  the AWS CLI, so these knobs continue to apply.
- In GovCloud an IAM **user** has historically been limited to **one** MFA device
  (verify the current limit for your partition) — which is part of why the SSO
  path (your one device is the security key, used in the browser) is the clean
  way to keep a phishing-resistant key while still getting CLI credentials.

---

## Troubleshooting

**`MFA device [arn:…:u2f/…] is a FIDO/U2F security key … needs a virtual MFA …`**
You ran `aws-xfa <profile>` on a profile that is **not** SSO-configured, so it
took the IAM-user STS path and rejected the FIDO device. Configure SSO on that
profile name (Step 2), or pass the SSO profile name.

**`AWS CLI v2 is required for SSO profiles`**
Install/upgrade to AWS CLI v2; the SSO path depends on it.

**`Your AWS CLI does not support 'configure export-credentials'`**
Your AWS CLI v2 is too old. Upgrade to a recent v2 release.

**A browser opens every run / "token expired"**
The Identity Center session token expired (these last hours, not minutes). Tap
your key to re-authenticate. The materialized role credentials themselves are
short-lived (often ~1 hour); re-run `aws-xfa <base-profile>` to refresh them.

**`AccessDenied` when using a sub-profile**
The target role's trust policy or your permission set doesn't allow the assume —
see the trust-policy note in Step 4.

**It used stale credentials / didn't seem to refresh**
`aws-xfa` resolves SSO with `AWS_SHARED_CREDENTIALS_FILE` pointed at the null
device so its own previously-written static credentials can't shadow SSO
resolution. If you run `aws configure export-credentials` **yourself** while a
stale `[<profile>]` block exists in `~/.aws/credentials`, the CLI may resolve
those static keys instead — let `aws-xfa` do it, or clear the stale block.

---

## Security notes

- `aws-xfa` never reads or stores your FIDO key material; the key is used only by
  the browser during `aws sso login`.
- Materialized SSO credentials are short-lived and written to
  `~/.aws/credentials` (user-readable, like any AWS CLI credential file). Treat
  that file as sensitive.
- Prefer requiring security keys in your Identity Center policy so the sign-in is
  phishing-resistant end to end.
