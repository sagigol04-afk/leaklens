"""
LeakLens v0.5 - Secret scanner for local folders and remote git repos
Usage:
    python scanner.py [folder]
    python scanner.py https://github.com/user/repo
"""

import base64
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile

PATTERNS = {
    # AI providers
    "Anthropic API Key": re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),
    "OpenAI API Key": re.compile(r"sk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}"),
    # Cloud and dev platforms
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "GitHub Token": re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    "Stripe Live Key": re.compile(r"sk_live_[A-Za-z0-9]{20,}"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "Google Service Account": re.compile(r"\"type\"\s*:\s*\"service_account\""),
    "Private Key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    # Supabase
    "Supabase Secret Key": re.compile(r"sb_secret_[A-Za-z0-9_-]{20,}"),
    "JWT": re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    # Bots
    "Telegram Bot Token": re.compile(r"[0-9]{8,10}:AA[A-Za-z0-9_-]{33}"),
    # Databases (only URLs that contain a password)
    "Database URL": re.compile(
        r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://"
        r"[^\s:@/\"']+:(?P<password>[^\s@/\"']+)@[^\s/\"']+"
    ),
}

# Passwords that are examples, not real secrets
PLACEHOLDER_PASSWORDS = {
    "password", "pass", "passwd", "secret", "changeme", "example",
    "xxx", "xxxx", "your_password", "yourpassword", "123456", "postgres", "root",
}

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", ".next", "dist", "build"}

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".exe",
    ".dll", ".mp4", ".mp3", ".woff", ".woff2", ".ttf", ".pyc",
}

ENV_FILE_NAMES = {".env", ".env.local", ".env.production", ".env.development"}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

# Never let git stop and wait for a username/password
GIT_ENV = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never"}


def mask(secret):
    """Hide most of the secret so we never print it in full."""
    if len(secret) <= 12:
        return secret[:3] + "..."
    return secret[:6] + "..." + secret[-4:]


# ---------- detection ----------

def jwt_role(token):
    """Read the 'role' field from inside a JWT, without verifying it."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)  # base64 needs padding
        data = json.loads(base64.urlsafe_b64decode(payload))
        return data.get("role")
    except (ValueError, IndexError):
        return None


def is_placeholder_password(password):
    p = password.lower()
    return p in PLACEHOLDER_PASSWORDS or p.startswith("$") or "<" in p or "{" in p


def find_secrets(line):
    """Return (name, secret) for every real secret in one line of text."""
    results = []
    for name, pattern in PATTERNS.items():
        for match in pattern.finditer(line):
            secret = match.group()

            if name == "JWT":
                # The anon key is public by design. Only service_role is dangerous.
                if jwt_role(secret) != "service_role":
                    continue
                name = "Supabase Service Role Key"

            elif name == "Database URL":
                if is_placeholder_password(match.group("password")):
                    continue

            results.append((name, secret))
    return results


# ---------- git helpers ----------

def run_git(root, args):
    """Run a git command inside root. Returns None if git is not installed."""
    try:
        return subprocess.run(
            ["git", "-C", root] + args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            env=GIT_ENV,
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


# ---------- remote repos ----------

def is_url(target):
    return target.startswith("https://") or target.startswith("http://")


def force_remove(func, path, _error):
    """Windows marks some git files read-only. Make them writable and retry."""
    os.chmod(path, stat.S_IWRITE)
    func(path)


def remove_folder(path):
    """Delete a folder and everything inside it."""
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=force_remove)
    else:
        shutil.rmtree(path, onerror=force_remove)


def clone_repo(url):
    """Clone a repo with full history into a new temporary folder."""
    temp_dir = tempfile.mkdtemp(prefix="leaklens_")
    print(f"Cloning {url} ...")

    try:
        # "--" means: everything after this is a URL/path, never an option.
        result = subprocess.run(
            ["git", "clone", "--quiet", "--", url, temp_dir],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            env=GIT_ENV,
        )
    except FileNotFoundError:
        remove_folder(temp_dir)
        print("Error: git is not installed")
        sys.exit(2)

    if result.returncode != 0:
        remove_folder(temp_dir)
        print("Error: could not clone the repo (wrong URL, or it is private)")
        print(result.stderr.strip())
        sys.exit(2)

    return temp_dir


# ---------- scanning current files ----------

def scan_file(path):
    """Scan one file line by line and return all findings."""
    findings = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):
                for name, secret in find_secrets(line):
                    findings.append((name, line_number, secret))
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
            for name, line_number, secret in scan_file(path):
                findings.append({
                    "file": rel_path,
                    "type": name,
                    "line": line_number,
                    "value": mask(secret),
                    "raw": secret,
                })

    return findings, env_files, files_scanned


# ---------- scanning git history ----------

def scan_git_history(root):
    """Scan every line that was ever ADDED in any commit, on all branches."""
    result = run_git(root, [
        "log", "-p", "--all", "--no-color",
        "--date=short", "--format=COMMIT %h %ad",
    ])
    if result is None or result.returncode != 0:
        return [], 0

    found = {}
    commits_scanned = 0
    commit, date, current_file = "?", "?", "?"

    for line in result.stdout.splitlines():
        if line.startswith("COMMIT "):
            parts = line.split()
            commit = parts[1]
            date = parts[2] if len(parts) > 2 else "?"
            commits_scanned += 1

        elif line.startswith("+++ "):
            current_file = line[6:] if line.startswith("+++ b/") else line[4:]

        elif line.startswith("+"):
            for name, secret in find_secrets(line):
                # git log shows newest first, so the LAST time we see
                # a secret is the commit where it was first added.
                found[secret] = {
                    "file": current_file,
                    "type": name,
                    "commit": commit,
                    "date": date,
                    "value": mask(secret),
                    "raw": secret,
                }

    return list(found.values()), commits_scanned


# ---------- report ----------

def run_scan(root, label):
    """Scan one folder, print the report, and return the exit code."""
    in_git = is_git_repo(root)
    print(f"Scanning: {label}")
    print(f"Git repo: {'yes' if in_git else 'no'}\n")

    # 1. Current files
    findings, env_files, files_scanned = scan_folder(root)
    cache = {}

    for f in findings:
        f["severity"], f["reason"] = classify(root, f["file"], in_git, cache)

    env_report = []
    for rel_path in env_files:
        severity, reason = classify(root, rel_path, in_git, cache)
        env_report.append({"file": rel_path, "severity": severity, "reason": reason})

    # 2. Git history - only secrets that are NOT in the current files
    history_report = []
    commits_scanned = 0
    if in_git:
        history, commits_scanned = scan_git_history(root)
        current_secrets = {f["raw"] for f in findings}
        for h in history:
            if h["raw"] in current_secrets:
                continue
            h["severity"] = "CRITICAL"
            h["reason"] = "Deleted from code but still in git history - rotate this key NOW"
            history_report.append(h)

    findings.sort(key=lambda f: SEVERITY_ORDER.index(f["severity"]))
    env_report.sort(key=lambda e: SEVERITY_ORDER.index(e["severity"]))

    # 3. Print
    for h in history_report:
        print(f"[{h['severity']}] {h['type']}  (git history)")
        print(f"    File:   {h['file']}")
        print(f"    Commit: {h['commit']}  ({h['date']})")
        print(f"    Value:  {h['value']}")
        print(f"    Reason: {h['reason']}\n")

    for f in findings:
        print(f"[{f['severity']}] {f['type']}")
        print(f"    File:   {f['file']}  (line {f['line']})")
        print(f"    Value:  {f['value']}")
        print(f"    Reason: {f['reason']}\n")

    for e in env_report:
        print(f"[{e['severity']}] .env file: {e['file']}")
        print(f"    Reason: {e['reason']}\n")

    counts = {level: 0 for level in SEVERITY_ORDER}
    for item in history_report + findings + env_report:
        counts[item["severity"]] += 1

    print("-" * 40)
    print(f"Files scanned:   {files_scanned}")
    print(f"Commits scanned: {commits_scanned}")
    for level in SEVERITY_ORDER:
        print(f"  {level:<9} {counts[level]}")

    # Exit code 1 = problems found (useful later for automation / CI)
    return 1 if counts["CRITICAL"] or counts["HIGH"] else 0


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "."

    # Remote repo: clone -> scan -> always delete the clone
    if is_url(target):
        temp_dir = clone_repo(target)
        try:
            exit_code = run_scan(temp_dir, label=target)
        finally:
            remove_folder(temp_dir)
            print("Temporary clone deleted.")
        sys.exit(exit_code)

    # Local folder
    if not os.path.isdir(target):
        print(f"Error: '{target}' is not a folder or a URL")
        sys.exit(2)

    sys.exit(run_scan(target, label=os.path.abspath(target)))


if __name__ == "__main__":
    main()
