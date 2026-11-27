# LeakLens 🔍

A command-line security scanner that finds exposed API keys and secrets in your code, including secrets that were deleted but still live in git history.

## Why

Developers building fast (especially with AI coding tools) often leave API keys hardcoded in source files or forget to protect `.env` files.

Deleting a key from the code is **not enough**. Git keeps every version of every file, so anyone who clones the repo can still find it in old commits. LeakLens catches both cases.

## Features

- Detects 7 types of secrets: Anthropic, OpenAI, AWS, GitHub, Stripe, Google API keys, and private keys
- Finds `.env` files and checks whether they are protected by `.gitignore`
- **Scans the full git history** on all branches, and reports the exact commit where a secret was first added
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
python scanner.py                  # scan current folder
python scanner.py path/to/project  # scan another folder
```

The exit code is `1` when CRITICAL or HIGH findings exist, so LeakLens can be used in CI pipelines.

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

Version 0.2 of LeakLens missed this case (a **false negative**), because it only read the current files. Version 0.3 fixes it by parsing `git log -p --all` and scanning every line ever added.

## How it works

1. **Walk** the folder with `os.walk`, skipping folders like `node_modules` and `.git`
2. **Match** each line against regex signatures of known key formats
3. **Mask** every secret before printing it
4. **Ask git** whether each file is ignored or was ever committed
5. **Scan history**: read every added line in every commit
6. **Rank** each finding by severity and print a report

## Roadmap

- [x] Local folder scanning
- [x] Git-aware severity levels
- [x] Full git history scanning
- [ ] Scan remote GitHub repos by URL
- [ ] More secret types (Supabase, Firebase, Telegram bots, database URLs)
- [ ] Scan live websites' JavaScript bundles for leaked keys
- [ ] Web dashboard (FastAPI + Next.js) with AI-generated fix explanations

## Ethical use

Only scan code and websites you own or have explicit permission to test.