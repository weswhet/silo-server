#!/usr/bin/env python3
"""Compares the activity rows activity-dump.sh saved from the reference and the candidate.

    activity-diff.py <reference file> <candidate file>

Generated ids are masked, so a row is its method, pattern, path shape, status, accounts, and audit action.
Prints each difference. Exits 1 on any.
"""
import collections
import re
import sys

MASKS = [
    (re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"), "<uuid>"),
    (re.compile(r"\b[0-9A-HJKMNP-TV-Z]{26}\b"), "<ulid>"),
    (re.compile(r"\b[0-9]{12,}\b"), "<long>"),
]


def stages(path):
    current = collections.Counter()
    out = [current]
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.rstrip("\n")
        if line == "--stage--":
            current = collections.Counter()
            out.append(current)
            continue
        parts = line.split("|")
        if len(parts) != 10:
            continue
        for i in (1, 2):
            for pattern, mask in MASKS:
                parts[i] = pattern.sub(mask, parts[i])
        current[tuple(parts[:9])] += int(parts[9])
    return out


def main():
    # The first dump comes before the run's first reset, so it holds what the previous run left.
    ref, cand = stages(sys.argv[1])[1:], stages(sys.argv[2])[1:]
    failed = 0
    for n in range(max(len(ref), len(cand))):
        a = ref[n] if n < len(ref) else collections.Counter()
        b = cand[n] if n < len(cand) else collections.Counter()
        for key in sorted(set(a) | set(b)):
            if a[key] != b[key]:
                failed += 1
                print(f"stage {n}: {'|'.join(key)}: reference {a[key]}, candidate {b[key]}")
    print(f"{failed} differences over {max(len(ref), len(cand))} stages")
    return 1 if failed else 0


sys.exit(main())
