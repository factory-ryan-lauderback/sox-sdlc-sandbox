"""PreToolUse guardrail for the coding agents (Dev and QA stories) in GitHub Actions.

A guardrail only: it stops obvious mistakes early with a reason the model can act on. It is not a
control and never evidence. The push job re-checks every changed path, and the review agent and the
gate judge the pushed head regardless of what happened here.

Blocks: edits outside SOX_ALLOWED_PATHS (comma-separated prefixes relative to SOX_WORK_DIR) or to a
control path; shell commands that push, talk to GitHub or the network, escalate privileges, or read
the process environment.
"""
import json
import os
import re
import sys

CONTROL = (".github/", ".sox/", ".factory/", "tools/", "CODEOWNERS")
BLOCKED_COMMANDS = [
    (r"\bgit\s+(push|remote|credential|config\s+--(global|system))\b", "git push/remote/credential changes are done by the workflow"),
    (r"\bgit\s+(commit|reset\s+--hard|checkout\s+-[bB]|switch|rebase|fetch|pull|clone)\b", "leave changes in the working tree; the workflow commits them"),
    (r"(^|[\s;&|(])(gh|curl|wget|nc|ncat|ssh|scp|rsync|ftp|telnet)(\s|$)", "no network or GitHub access from the coding agent"),
    (r"(^|[\s;&|(])(sudo|su|doas)(\s|$)", "no privilege escalation"),
    (r"(^|[\s;&|(])(env|printenv|set|export\s+-p)(\s*$|\s*[;&|])", "do not read the process environment"),
    (r"/proc/[^\s]*/environ|\$\{?(FACTORY_API_KEY|GITHUB_TOKEN|ACTIONS_[A-Z_]+|APP_TOKEN)\b", "do not read credentials"),
    (r"\bpip3?\s+install\b|\bnpm\s+(i|install)\b", "the services use the standard library only"),
]


def deny(reason):
    sys.stderr.write(f"sox guardrail: {reason}\n")
    sys.exit(2)


def check_path(path, work, allowed):
    full = os.path.realpath(path if os.path.isabs(path) else os.path.join(work, path))
    rel = os.path.relpath(full, work)
    if rel == ".." or rel.startswith("../"):
        deny(f"{path} is outside the repository working tree")
    if any(rel == c.rstrip("/") or rel.startswith(c) for c in CONTROL):
        deny(f"{rel} is a control path; agents never change it")
    if allowed and not any(rel.startswith(a) for a in allowed):
        deny(f"{rel} is outside the story's allowed paths {allowed}")


def main():
    try:
        event = json.load(sys.stdin)
    except ValueError:
        deny("unreadable hook input")
    work = os.path.realpath(os.environ.get("SOX_WORK_DIR") or event.get("cwd") or os.getcwd())
    allowed = [a.strip() for a in os.environ.get("SOX_ALLOWED_PATHS", "").split(",") if a.strip()]
    tool, args = event.get("tool_name"), event.get("tool_input") or {}
    if tool == "Execute":
        cmd = str(args.get("command") or "")
        for pattern, reason in BLOCKED_COMMANDS:
            if re.search(pattern, cmd):
                deny(reason)
        return
    paths = [args[k] for k in ("file_path", "path") if isinstance(args.get(k), str)]
    for value in args.values():
        if isinstance(value, str):
            paths += re.findall(r"^\*\*\* (?:Add|Update|Delete) File: (.+)$", value, re.M)
            paths += re.findall(r"^\*\*\* Move to: (.+)$", value, re.M)
    for p in paths:
        check_path(p.strip(), work, allowed)


if __name__ == "__main__":
    main()
