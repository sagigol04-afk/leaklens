# LeakLens 🔍

A command-line security scanner that finds exposed API keys and secrets in local projects and remote git repos, including secrets that were deleted but still live in git history.

## Why

Developers building fast (especially with AI coding tools) often leave API keys hardcoded in source files or forget to protect `.env` files.

Deleting a key from the code is **not enough**. Git keeps every version of every file, so anyone who clones the repo can still find it in old commits. LeakLens catches both cases.

## Features

- Detects **12 types of secrets** (see the table below)
- Finds `.env` files and checks whether they are protected by `.gitignore`
- **Scans the full git history** on all branches, and reports the exact commit where a secret was first added
- **Scans remote repos by URL**: clones into a temporary folder and always deletes it afterwards
- **Smart detection** that skips public keys and example values, to keep false positives low
- Ranks every finding by severity
- Masks secrets in the output, so the scanner never leaks what it finds

## Detected secrets

| Category | Secret |
|---|---|
| AI providers | Anthropic API key, OpenAI API key |
| Cloud | AWS access key, Google API key, Google service account JSON |
| Dev platforms | GitHub token, Stripe live key |
| Supabase | `service_role` key (JWT), `sb_secret_` key |
| Bots | Telegram bot token |
| Databases | Postgres / MySQL / MongoDB / Redis / AMQP URLs with a password |
| Crypto | RSA / EC / OpenSSH private keys |

## Smart detection

Not everything that looks like a key is a secret:

- **Supabase JWTs are decoded.** The `anon` key is public by design, so it is skipped. Only a token whose payload says `"role": "service_role"` is reported, because that key bypasses all database permissions.
- **Example database URLs are skipped.** URLs like `postgresql://user:password@localhost` or `postgresql://admin:${DB_PASSWORD}@host` appear in countless tutorials and templates, so placeholder passwords are ignored.

## Severity levels

| Level | Meaning |
|---|---|
| **CRITICAL** | The secret exists in git history, or a `.env` file is not ignored |
| **HIGH** | A secret is hardcoded in source code |
| **MEDIUM** | Not a git repo, so protection cannot be verified |
| **LOW** | The secret is in an ignored file that was never committed |

## Usage

```bash
python scanner.py                                  # scan current folder
python scanner.py path/to/project                  # scan another folder
python scanner.py https://github.com/user/repo     # scan a remote repo
```

Exit codes:

| Code | Meaning |
|---|---|
| `0` | No CRITICAL or HIGH findings |
| `1` | CRITICAL or HIGH findings exist (useful for CI pipelines) |
| `2` | Error: bad path, bad URL, or git missing |

## Example: catching a deleted key

A developer commits a key, notices the mistake, and deletes it in the next commit. The current code looks clean, but the key is still in history:

```
Scanning: C:\projects\leak-test
Git repo: yes

[CRITICAL] OpenAI API Key  (git history)
    File:   config.py
    Commit: cd949c7  (2026-11-27)
    Value:  sk-pro...0abc
    Reason: Deleted from code but still in git history - rotate this key NOW

----------------------------------------
Files scanned:   1
Commits scanned: 2
  CRITICAL  1
  HIGH      0
  MEDIUM    0
  LOW       0
```

Version 0.2 missed this case (a **false negative**), because it only read the current files. Version 0.3 fixes it by parsing `git log -p --all` and scanning every line ever added.

## How it works

1. **Clone** (remote only): `git clone` into a temporary folder, with full history
2. **Walk** the folder with `os.walk`, skipping folders like `node_modules` and `.git`
3. **Match** each line against regex signatures of known key formats
4. **Validate** matches: decode JWTs, skip placeholder passwords
5. **Mask** every secret before printing it
6. **Ask git** whether each file is ignored or was ever committed
7. **Scan history**: read every added line in every commit
8. **Rank** each finding by severity and print a report
9. **Clean up**: the temporary clone is deleted in a `finally` block, even if the scan fails

All detection logic lives in one function, `find_secrets()`, which is shared by the file scan and the history scan.

## Security notes

- The repo URL is passed to git after `--`, so a malicious "URL" such as `--upload-pack=...` can never be read as a git option (argument injection).
- Git is run with interactive prompts disabled, so the scanner never hangs waiting for a password.
- Secrets are masked in every line of output.

## Roadmap

- [x] Local folder scanning
- [x] Git-aware severity levels
- [x] Full git history scanning
- [x] Scan remote repos by URL
- [x] More secret types (Supabase, Telegram bots, database URLs, service accounts)
- [ ] Check Supabase / Firebase databases for missing access rules
- [ ] Scan live websites' JavaScript bundles for leaked keys
- [ ] Install with `pip install` and run as `leaklens .`
- [ ] Web dashboard (FastAPI + Next.js) with AI-generated fix explanations

## Ethical use

Only scan code and websites you own or have explicit permission to test. If you find someone else's exposed key, report it to them privately (responsible disclosure).
