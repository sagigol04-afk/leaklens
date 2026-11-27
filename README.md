# LeakLens 🔍

A command-line security scanner that finds exposed API keys and secrets in local projects and remote git repos, including secrets that were deleted but still live in git history.

## Why

Developers building fast (especially with AI coding tools) often leave API keys hardcoded in source files or forget to protect `.env` files.

Deleting a key from the code is **not enough**. Git keeps every version of every file, so anyone who clones the repo can still find it in old commits. LeakLens catches both cases.

## Features

- Detects 7 types of secrets: Anthropic, OpenAI, AWS, GitHub, Stripe, Google API keys, and private keys
- Finds `.env` files and checks whether they are protected by `.gitignore`
- **Scans the full git history** on all branches, and reports the exact commit where a secret was first added
- **Scans remote repos by URL**: clones into a temporary folder and always deletes it afterwards
- Ranks every finding by severity
- Masks secrets in the output, so the scanner never leaks what it finds

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
4. **Mask** every secret before printing it
5. **Ask git** whether each file is ignored or was ever committed
6. **Scan history**: read every added line in every commit
7. **Rank** each finding by severity and print a report
8. **Clean up**: the temporary clone is deleted in a `finally` block, even if the scan fails

## Security notes

- The repo URL is passed to git after `--`, so a malicious "URL" such as `--upload-pack=...` can never be read as a git option (argument injection).
- Git is run with interactive prompts disabled, so the scanner never hangs waiting for a password.
- Secrets are masked in every line of output.

## Roadmap

- [x] Local folder scanning
- [x] Git-aware severity levels
- [x] Full git history scanning
- [x] Scan remote repos by URL
- [ ] More secret types (Supabase, Firebase, Telegram bots, database URLs)
- [ ] Scan live websites' JavaScript bundles for leaked keys
- [ ] Web dashboard (FastAPI + Next.js) with AI-generated fix explanations

## Ethical use

Only scan code and websites you own or have explicit permission to test. If you find someone else's exposed key, report it to them privately (responsible disclosure).