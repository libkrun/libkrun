#!/usr/bin/env python3
"""Validate AI attribution trailers in PR commits.

- Co-authored-by for AI tools → error
- Non-standard AI junk attributions → error
- Malformed Assisted-by / Generated-by → error

Usage:  check-ai-trailers.py <base-ref>
        check-ai-trailers.py --test
"""

import re
import subprocess
import sys
from collections.abc import Iterator


def _re(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.I)

CO_AUTHOR_RE = _re(r"^co-authored-by:\s*(?P<name>.+?)\s*<(?P<email>.+?)>\s*$")


def co_authors(msg: str) -> Iterator[tuple[str, str]]:
    """Yield (name, email) for each Co-authored-by trailer in msg."""
    for line in msg.splitlines():
        m = CO_AUTHOR_RE.match(line)
        if m:
            yield m["name"], m["email"]


# AGENT:MODEL | AGENT: MODEL | AGENT / MODEL | AGENT (MODEL)
ASSISTED_BY_RE = re.compile(
    r"^(?P<key>Assisted-by|Generated-by):\s*"
    r"(?P<agent>[A-Za-z][A-Za-z0-9 -]*[A-Za-z0-9])"
    r"(?:"
    r":\s*(?P<model_colon>.+)"        # AGENT: MODEL or AGENT:MODEL
    r"| / (?P<model_slash>.+)"        # AGENT / MODEL
    r"| \((?P<model_paren>.+)\)"      # AGENT (MODEL)
    r")$"
)


def assisted_by(msg: str) -> Iterator[tuple[str, str | None, str | None]]:
    """Yield (key, agent, model) for each Assisted-by/Generated-by trailer.

    Yields (key, None, None) for lines that have the trailer prefix but fail
    the format check.
    """
    for line in msg.splitlines():
        if not re.match(r"^(Assisted-by|Generated-by):\s", line):
            continue
        m = ASSISTED_BY_RE.match(line)
        if m:
            model = m["model_colon"] or m["model_slash"] or m["model_paren"]
            yield m["key"], m["agent"], model
        else:
            yield line.split(":")[0], None, None


BANNED_CO_AUTHOR_EMAILS = [
    _re(r"^noreply@anthropic\.com$"),
    _re(r"^(\d+\+)?copilot@(github\.com|users\.noreply\.github\.com)$"),
]
NON_STANDARD_AI_ATRIBUTION = [
    _re(r"^[^\x00-\x7F]*\s*Generated with \[Claude Code\]"),
    _re(r"^Made-with:\s*Cursor"),
]

CLAUDE_MODEL_RE = _re(r"(?:Claude\s+)?(?P<variant>Opus|Sonnet|Haiku)\s+(?P<version>\d+(?:\.\d+)?)")


def suggest_assisted_by(name: str, email: str) -> str | None:
    """Given a banned Co-authored-by, suggest a corrected Assisted-by trailer."""
    if "anthropic" in email:
        m = CLAUDE_MODEL_RE.search(name)
        if m:
            model = f"claude-{m['variant'].lower()}-{m['version']}"
            return f"Assisted-by: Claude Code:{model}"
        return "Assisted-by: Claude Code:<model>"
    if "github" in email:
        return "Assisted-by: Copilot:<model>"
    return None


def check_message(msg: str) -> Iterator[tuple[str, str | None]]:
    """Yield (description, suggestion) for each problem found."""
    for name, email in co_authors(msg):
        for pat in BANNED_CO_AUTHOR_EMAILS:
            if pat.match(email):
                yield f"AI Co-authored-by: {name} <{email}>", suggest_assisted_by(name, email)
                break

    for key, agent, model in assisted_by(msg):
        if agent is None:
            yield f"Bad {key} format", None

    for line in msg.splitlines():
        for pat in NON_STANDARD_AI_ATRIBUTION:
            if pat.match(line):
                yield f"Non-standard AI attribution: {line}", None
                break


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], capture_output=True, text=True, check=True
    ).stdout


def main() -> None:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <base-ref>", file=sys.stderr)
        sys.exit(2)

    base = sys.argv[1]
    shas = git("rev-list", f"{base}..HEAD").split()
    errors: list[str] = []

    for sha in shas:
        msg = git("log", "-1", "--format=%B", sha)
        short = git("log", "-1", "--format=%h %s", sha).strip()
        for desc, suggestion in check_message(msg):
            print(f"::error title={desc}::{short}")
            detail = f"  commit: {short}\n  problem: {desc}"
            if suggestion:
                detail += f"\n  fix:     {suggestion}"
            errors.append(detail)

    if not errors:
        print("All AI trailers look good.")
        return

    print(f"\n{len(errors)} error(s):")
    for i, item in enumerate(errors):
        print(f"\n{item}")
        if i < len(errors) - 1:
            print("---")

    print()
    print("AI tools should use Assisted-by (not Co-authored-by).")
    print("Expected format:  Assisted-by: <agent>:<model>")
    print("  e.g.  Assisted-by: Claude Code:claude-opus-4.6")
    print()
    print("Use `git rebase -i` to edit the commit message, then force-push.")
    print("See CONTRIBUTING.md for the full AI attribution policy.")

    sys.exit(1)


def tests() -> None:
    fail = 0

    def expect(label: str, msg: str, *, errors: int = 0) -> None:
        nonlocal fail
        got = sum(1 for _ in check_message(msg))
        if got != errors:
            print(f"  FAIL: {label}: {msg!r}  (errors={got}/{errors})")
            fail += 1

    def expect_parsed(line: str, exp_agent: str, exp_model: str) -> None:
        nonlocal fail
        results = list(assisted_by(line))
        if len(results) != 1:
            print(f"  FAIL: parse {line!r}: expected 1 result, got {len(results)}")
            fail += 1
            return
        _, agent, model = results[0]
        if agent != exp_agent or model != exp_model:
            print(f"  FAIL: parse {line!r}: agent={agent!r} model={model!r}"
                  f" (expected {exp_agent!r}, {exp_model!r})")
            fail += 1

    # Valid Assisted-by — clean, with parsed agent/model assertions
    valid_cases = [
        ("Assisted-by: Cursor:claude-opus-4.6", "Cursor", "claude-opus-4.6"),
        ("Assisted-by: Claude Code:claude-opus-4.6", "Claude Code", "claude-opus-4.6"),
        ("Assisted-by: Claude Code: Claude Opus 4.7 (1M context)", "Claude Code", "Claude Opus 4.7 (1M context)"),
        ("Assisted-by: Claude Code / Claude Opus 4.7 (1M context)", "Claude Code", "Claude Opus 4.7 (1M context)"),
        ("Assisted-by: Copilot (GPT-5.4)", "Copilot", "GPT-5.4"),
        ("Assisted-by: Copilot (GPT 5.4)", "Copilot", "GPT 5.4"),
        ("Generated-by: OpenCode:claude-opus-4.6", "OpenCode", "claude-opus-4.6"),
        ("Assisted-by: Copilot:auto", "Copilot", "auto"),
        ("Assisted-by: Copilot:unknown", "Copilot", "unknown"),
    ]
    for line, exp_agent, exp_model in valid_cases:
        expect("valid assisted-by", line)
        expect_parsed(line, exp_agent, exp_model)

    # Bad Assisted-by format — error
    for v in [
        "Assisted-by: <anthropic/claude-opus-4.6>",
        "Assisted-by: Claude",
        "Assisted-by: Claude Code",
    ]:
        expect("bad assisted-by", v, errors=1)

    # Banned Co-authored-by - hard error
    for v in [
        "Co-authored-by: Claude <noreply@anthropic.com>",
        "Co-Authored-By: Claude 4.6 <noreply@anthropic.com>",
        "Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>",
        "Co-authored-by: Copilot <copilot@github.com>",
        "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>",
        "Co-authored-by: Copilot <999999+Copilot@users.noreply.github.com>",
        "Co-authored-by: 🤖 Claude <noreply@anthropic.com>",
        "Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>",
    ]:
        expect("banned co-author", v, errors=1)

    # Human Co-authored-by — clean
    for v in [
        "Co-authored-by: John Doe <john@example.com>",
        "Co-authored-by: Claude Bernard <claude.bernard@anthropic.com>",
        "Co-authored-by: Mike Copilot <mike.copilot@github.com>",
    ]:
        expect("human co-author", v)

    # Junk AI lines — error
    for v in [
        "🤖 Generated with [Claude Code](https://claude.ai/code)",
        "Generated with [Claude Code](https://claude.ai/code)",
        "🤖 Generated with [Claude Code](https://claude.com/claude-code)",
        "Made-with: Cursor",
    ]:
        expect("junk", v, errors=1)

    # Normal line — clean
    expect("normal", "Some random commit message")

    # Suggestions for banned Co-authored-by
    suggestion_cases = [
        ("Claude", "noreply@anthropic.com", "Assisted-by: Claude Code:<model>"),
        ("Claude 4.6", "noreply@anthropic.com", "Assisted-by: Claude Code:<model>"),
        ("Claude Sonnet 4.6", "noreply@anthropic.com", "Assisted-by: Claude Code:claude-sonnet-4.6"),
        ("Claude Opus 4.7 (1M context)", "noreply@anthropic.com", "Assisted-by: Claude Code:claude-opus-4.7"),
        ("\N{ROBOT FACE} Claude", "noreply@anthropic.com", "Assisted-by: Claude Code:<model>"),
        ("Copilot", "copilot@github.com", "Assisted-by: Copilot:<model>"),
        ("Copilot", "223556219+Copilot@users.noreply.github.com", "Assisted-by: Copilot:<model>"),
    ]
    for name, email, expected in suggestion_cases:
        got = suggest_assisted_by(name, email)
        if got != expected:
            print(f"  FAIL: suggest({name!r}, {email!r}) = {got!r}, expected {expected!r}")
            fail += 1

    if fail:
        print(f"\n{fail} test(s) FAILED")
        sys.exit(1)
    print("All tests passed.")


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--test":
        tests()
    else:
        main()
