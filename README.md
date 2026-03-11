<p align="center">
  <img src="https://raw.githubusercontent.com/karmazin-me/aws-xfa/main/assets/banner.png" alt="aws-xfa" />
</p>

# aws-xfa

Exchange long-term AWS credentials for temporary STS tokens — handles MFA automatically, integrates with 1Password, and can run as a background daemon that keeps credentials fresh without any manual steps.

## Install

```sh
pip install aws-xfa
```

## First run

If you don't have `~/.aws/credentials` yet, just run:

```sh
aws-xfa          # sets up the "default" profile
aws-xfa main     # sets up a profile named "main"
```

The profile name you pass (or `default` when omitted) determines all section names in your credentials file. aws-xfa will prompt you for everything:

```
AWS Access Key ID: AKIA...
AWS Secret Access Key: ************
MFA device ARN (e.g. arn:aws:iam::123456789012:mfa/username): arn:aws:iam::...
AWS region (e.g. us-east-1): us-east-1
Would you like to add sub-profiles? [y/N]:
Use 1Password CLI to automatically fetch MFA codes? [y/N]:
```

Then it calls AWS STS and writes your temporary credentials to `~/.aws/credentials`.

## Existing credentials file

If you already have `~/.aws/credentials` with a `[default]` section, aws-xfa will migrate it automatically — creating `[default-long-term]` for your permanent keys, and using `[default]` for the temporary STS credentials.

**How profile names map to sections:**

| Command | Profile | Long-term section | Short-term section |
|---------|---------|-------------------|--------------------|
| `aws-xfa` | `default` | `[default-long-term]` | `[default]` |
| `aws-xfa main` | `main` | `[main-long-term]` | `[main]` |

Your credentials file structure after setup (using the `default` profile):

```ini
[default-long-term]
aws_access_key_id     = AKIA...          # your permanent keys — never exposed to AWS CLI
aws_secret_access_key = ...
aws_mfa_device        = arn:aws:iam::123456789012:mfa/username

[default]
aws_access_key_id     = ASIA...          # temporary — written by aws-xfa after each STS call
aws_secret_access_key = ...
aws_session_token     = ...
aws_security_token    = ...
expiration            = 2026-03-04 22:00:00
```

## Daily usage

```sh
aws-xfa
# Enter AWS MFA code for device [...]: 123456
# Success! Your credentials will expire in 12h 0m 0s at: 2026-03-05 10:00:00 UTC
```

Running again while credentials are still valid does nothing:

```sh
aws-xfa
# Your credentials are still valid for 11h 55m 34s, they will expire at ...
```

For a named profile (`[main-long-term]` → `[main]`):

```sh
aws-xfa main
```

Force refresh before expiry:

```sh
aws-xfa --force
aws-xfa main --force
```

## Sub-profiles

If you use AWS role assumption (e.g. separate prod/stage accounts), aws-xfa can create sub-profiles that reference your parent profile as `source_profile`.

Sub-profiles are named **`{profile}-{name}`** — for example, profile `main` with sub-profile `prod` becomes `main-prod`. Profile `default` with sub-profile `staging` becomes `default-staging`.

During first-run setup, aws-xfa asks if you want to add sub-profiles. You can also add them at any time:

```sh
aws-xfa add-subprofile main       # add sub-profiles under the "main" profile
aws-xfa add-subprofile default    # add sub-profiles under the "default" profile
```

The interactive prompt:

```
Sub-profile name (e.g. prod, stage): prod
Role ARN to assume (e.g. arn:aws:iam::123456789012:role/role-name): arn:aws:iam::263649228919:role/role-name
Region [us-west-1]:
Added sub-profile 'main-prod'
Add another sub-profile? [y/N]: n
```

This writes to `~/.aws/config` only (no credentials changes):

```ini
[profile main-prod]
source_profile = main
region = us-west-1
role_arn = arn:aws:iam::263649228919:role/role-name
output = json
```

## 1Password integration

Skip manual OTP entry entirely. If you answered `y` during setup, you're already configured. To enable it later:

```sh
aws-xfa --1pass
# Enter 1Password item name for profile 'default': AWS MFA
```

The item name is saved to `~/.config/aws-xfa/config.json`. **From then on, aws-xfa fetches the OTP automatically on every run** — no `--1pass` flag needed.

```sh
aws-xfa           # OTP fetched from 1Password silently (default profile)
aws-xfa main      # same for named profile
```

Requires the [`op` CLI](https://developer.1password.com/docs/cli/) to be installed and signed in. If `op` fails, aws-xfa falls back to prompting you manually.

## Auto-refresh daemon

Keep credentials fresh in the background — no manual intervention ever. The daemon wakes 5 minutes before expiry and renews automatically.

**Requires 1Password** to be configured for the profile first (the daemon runs unattended).

```sh
aws-xfa daemon install default   # configure 1Password if needed, then install and start
aws-xfa daemon status default    # show running status
aws-xfa daemon stop default      # stop without removing config
aws-xfa daemon delete default    # stop and remove all artifacts and logs
```

What gets installed per platform:

| Platform | Persistence method |
|----------|--------------------|
| macOS    | LaunchAgent plist (`~/Library/LaunchAgents/com.user.aws-xfa-daemon-PROFILE.plist`) |
| Linux    | systemd user unit (falls back to double-fork on systems without systemd) |
| Windows  | detached process + `schtasks` on-logon scheduled task |

Error logs: `~/.config/aws-xfa/errors-PROFILE.log`

On Linux without systemd (Alpine, OpenRC, WSL), the daemon won't survive reboot automatically. The install command prints the command to add to your init scripts.

## Options

| Flag | Description |
|------|-------------|
| `--force` | Refresh even if credentials are still valid |
| `--1pass` | Configure 1Password for this profile (one-time setup) |
| `--duration SECONDS` | Session duration (default: 43200 = 12 h, min: 900, max: 129600) |
| `--log-level debug` | Verbose output |

Environment variables:

| Variable | Effect |
|----------|--------|
| `MFA_STS_DURATION` | Session duration (same as `--duration`) |
| `AWS_REGION` / `AWS_DEFAULT_REGION` | Region used for the STS endpoint |
| `AWS_SHARED_CREDENTIALS_FILE` | Override the default `~/.aws/credentials` path |
| `AWS_CONFIG_FILE` | Override the default `~/.aws/config` path |

CLI flags take precedence over environment variables.

## Before you use this tool

Please read these before deploying aws-xfa in any environment:

- [DISCLAIMER.md](DISCLAIMER.md) — no warranty; you are responsible for your AWS credentials and account security
- [SECURITY.md](SECURITY.md) — how to report vulnerabilities
- [LICENSE](LICENSE) — Zero-Clause BSD (0BSD)
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute
