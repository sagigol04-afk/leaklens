"""
LeakLens - Step 2: Secret scanner with git awareness and severity levels
Usage: python scanner.py [folder]
"""

import os
import re
import subprocess
import sys

PATTERNS = {
    "Anthropic API Key": re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),
    "OpenAI API Key": re.compile(r"sk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}"),
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "GitHub Token": re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    "Stripe Live Key": re.compile(r"sk_live_[A-Za-z0-9]{20,}"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "Private Key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", ".next", "dist", "build"}

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".exe",
    ".dll", ".mp4", ".mp3", ".woff", ".woff2", ".ttf", ".pyc",
}

ENV_FILE_NAMES = {".env", ".env.local", ".env.production", ".env.development"}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def mask(secret):
    """Hide most of the secret so we never print it in full."""
    if len(secret) <= 12:
        return secret[:3] + "..."
    return secret[:6] + "..." + secret[-4:]


# ---------- git helpers ----------

def run_git(root, args):
    """Run a git command inside root. Returns None if git is not installed."""
    try:
        return subprocess.run(
            ["git", "-C", root] + args,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return None


def is_git_repo(root):
    result = run_git(root, ["rev-parse", "--is-inside-work-tree"])
    return result is not None and result.stdout.strip() == "true"


def is_ignored(root, git_path):
    """True if .gitignore protects this file."""
    result = run_git(root, ["check-ignore", "-q", git_path])
    return result is not None and result.returncode == 0


def was_committed(root, git_path):
    """True if this file appears anywhere in git history."""
    result = run_git(root, ["log", "--all", "--oneline", "--", git_path])
    return result is not None and result.stdout.strip() != ""


def classify(root, rel_path, in_git, cache):
    """Decide how dangerous a file is. Results are cached per file."""
    if rel_path in cache:
        return cache[rel_path]

    is_env = os.path.basename(rel_path) in ENV_FILE_NAMES
    git_path = rel_path.replace("\\", "/")

    if not in_git:
        if is_env:
            status = ("MEDIUM", "Not a git repo - cannot verify this file is protected")
        else:
            status = ("HIGH", "Hardcoded secret in source code - move it to .env")
    elif was_committed(root, git_path):
        status = ("CRITICAL", "Already in git history - rotate this key NOW")
    elif not is_ignored(root, git_path):
        if is_env:
            status = ("CRITICAL", "Not in .gitignore - will be uploaded on next commit")
        else:
            status = ("HIGH", "Hardcoded secret in source code - move it to .env")
    else:
        status = ("LOW", "Ignored by git and never committed - OK")

    cache[rel_path] = status
    return status


# ---------- scanning ----------

def scan_file(path):
    """Scan one file line by line and return all findings."""
    findings = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):
                for name, pattern in PATTERNS.items():
                    for match in pattern.finditer(line):
                        findings.append((name, line_number, mask(match.group())))
    except OSError:
        pass
    return findings


def scan_folder(root):
    """Walk through every folder and file under root."""
    findings = []
    env_files = []
    files_scanned = 0

    for current_dir, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for file_name in files:
            path = os.path.join(current_dir, file_name)
            rel_path = os.path.relpath(path, root)

            if file_name in ENV_FILE_NAMES:
                env_files.append(rel_path)

            ext = os.path.splitext(file_name)[1].lower()
            if ext in SKIP_EXTENSIONS:
                continue

            files_scanned += 1
            for name, line_number, masked in scan_file(path):
                findings.append({
                    "file": rel_path,
                    "type": name,
                    "line": line_number,
                    "value": masked,
                })

    return findings, env_files, files_scanned


# ---------- report ----------

def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."

    if not os.path.isdir(root):
        print(f"Error: '{root}' is not a folder")
        sys.exit(1)

    in_git = is_git_repo(root)
    print(f"Scanning: {os.path.abspath(root)}")
    print(f"Git repo: {'yes' if in_git else 'no'}\n")

    findings, env_files, files_scanned = scan_folder(root)
    cache = {}

    for f in findings:
        f["severity"], f["reason"] = classify(root, f["file"], in_git, cache)

    env_report = []
    for rel_path in env_files:
        severity, reason = classify(root, rel_path, in_git, cache)
        env_report.append({"file": rel_path, "severity": severity, "reason": reason})

    findings.sort(key=lambda f: SEVERITY_ORDER.index(f["severity"]))
    env_report.sort(key=lambda e: SEVERITY_ORDER.index(e["severity"]))

    for f in findings:
        print(f"[{f['severity']}] {f['type']}")
        print(f"    File:   {f['file']}  (line {f['line']})")
        print(f"    Value:  {f['value']}")
        print(f"    Reason: {f['reason']}\n")

    for e in env_report:
        print(f"[{e['severity']}] .env file: {e['file']}")
        print(f"    Reason: {e['reason']}\n")

    counts = {level: 0 for level in SEVERITY_ORDER}
    for item in findings + env_report:
        counts[item["severity"]] += 1

    print("-" * 40)
    print(f"Files scanned: {files_scanned}")
    for level in SEVERITY_ORDER:
        print(f"  {level:<9} {counts[level]}")

    # Exit code 1 = problems found (useful later for automation / CI)
    if counts["CRITICAL"] or counts["HIGH"]:
        sys.exit(1)


if __name__ == "__main__":
    main()