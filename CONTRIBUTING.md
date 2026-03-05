# Contributing to aws-xfa

## License

By contributing to this project, you agree that your contributions will be
licensed under the [BSD Zero Clause License (0BSD)](LICENSE).

## Developer Certificate of Origin (DCO)

All contributions must be signed off under the [Developer Certificate of
Origin](DCO) (DCO 1.1). This certifies that you have the right to submit
the contribution under the project's open source license.

### How to sign off

Add a `Signed-off-by` line to every commit message:

```
Signed-off-by: Your Name <your.email@example.com>
```

The easiest way is to use the `-s` flag when committing:

```bash
git commit -s -m "your commit message"
```

### Fixing unsigned commits

If you forgot to sign off, amend the most recent commit:

```bash
git commit --amend -s --no-edit
```

For multiple commits, use interactive rebase:

```bash
git rebase -i HEAD~N  # N = number of commits to fix
# Change 'pick' to 'edit' for each commit, then:
git commit --amend -s --no-edit
git rebase --continue
```

## Pull Request Requirements

1. All commits must be signed off (DCO).
2. All source files must include `# SPDX-License-Identifier: 0BSD` as the
   first comment line.
3. Do not introduce dependencies with copyleft licenses (GPL, AGPL, etc.)
   without discussion.

## Security Vulnerabilities

Do **not** open a public issue for security vulnerabilities. See
[SECURITY.md](SECURITY.md) for reporting instructions.
