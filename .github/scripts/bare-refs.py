"""Bare issue references in what a change brings to main (CONTRIBUTING.md, «Сообщения коммитов»).

GitHub links a bare #N in a commit message to an issue, and in a fork with its issues off to the parent's: Niko's
commits on its task 148 showed up in MatsuriDayo/NekoBoxForAndroid's issue 148. owner/repo#N links where it says,
and «задача N» links nowhere.

Usage: bare-refs.py BASE HEAD (the commits of BASE..HEAD), the pull request's title and description in PR_TITLE and
PR_BODY if set (a squash merge makes its commit of them). Prints each bare reference with where it is; exit status 1
if there is one.
"""

import os
import re
import subprocess
import sys

# a # and digits, not glued to what comes before (owner/repo#N, a URL's fragment, an HTML entity &#N; pass) and not
# going on into a word (#1a2b, a colour); GH-N is linked too
BARE = re.compile(r"(?<![\w/&#=.:@-])#\d{1,6}(?![\w-])|(?<![\w/-])GH-\d+(?![\w-])")


def bare(label, text):
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        for match in BARE.finditer(line):
            found.append(f"{label}, line {number}: {match.group(0)} in «{line.strip()}»")
    return found


def commits(base, head):
    out = subprocess.run(
        ["git", "log", "--format=%H%x00%B%x00", f"{base}..{head}"],
        check=True, capture_output=True, text=True,
    ).stdout
    fields = out.split("\0")
    for i in range(0, len(fields) - 1, 2):
        yield fields[i].strip(), fields[i + 1]


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: bare-refs.py BASE HEAD")
    found = []
    for sha, message in commits(sys.argv[1], sys.argv[2]):
        found += bare(f"commit {sha[:12]}", message)
    for name, label in (("PR_TITLE", "the pull request's title"), ("PR_BODY", "the pull request's description")):
        found += bare(label, os.environ.get(name, ""))
    for line in found:
        print(line)
    if found:
        print("bare references: write owner/repo#N, or «задача N» (CONTRIBUTING.md)", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
