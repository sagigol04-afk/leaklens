# LeakLens 🔍

A command-line security scanner that finds exposed API keys and secrets in your code, and checks whether they were ever pushed to git.

## Why

Developers building fast (especially with AI coding tools) often leave API keys hardcoded in source files or forget to protect `.env` files. A single leaked key can cost thousands of dollars or expose user data. LeakLens catches these mistakes before they reach GitHub.

## Features

- Detects 7 types of secrets: Anthropic, OpenAI, AWS, GitHub, Stripe, Google API keys, and private keys
- Finds `.env` files and checks whether they are protected by `.gitignore`
- Searches **git history**, because a key deleted from the code can still be leaked through old commits
- Ranks every finding by severity
- Masks secrets in the output, so the scanner never leaks what it finds

## Severity levels

| Level | Meaning |
|---|---|
| **CRITICAL** | The secret is already in git history, or a `.env` file is not ignored |
| **HIGH** | A secret is hardcoded in source code |
| **MEDIUM** | Not a git repo, so protection cannot be verified |
| **LOW** | The secret is in an ignored file that was never committed |

## Usage

```bash
python scanner.py                  # scan current folder
python scanner.py path/to/project  # scan another folder
```

The exit code is `1` when CRITICAL or HIGH findings exist, so LeakLens can be used in CI pipelines.

## Example output

```
Scanning: C:\projects\my-app
Git repo: yes

[HIGH] OpenAI API Key
    File:   config.py  (line 7)
    Value:  sk-pro...fXYZ
    Reason: Hardcoded secret in source code - move it to .env

----------------------------------------
Files scanned: 58
  CRITICAL  0
  HIGH      1
  MEDIUM    0
  LOW       0
```

## Roadmap

- [ ] Scan remote GitHub repos by URL
- [ ] Scan live websites' JavaScript bundles for leaked keys
- [ ] Detect misconfigured Supabase / Firebase databases
- [ ] Web dashboard (FastAPI + Next.js) with AI-generated fix explanations

## Ethical use

Only scan code and websites you own or have explicit permission to test.