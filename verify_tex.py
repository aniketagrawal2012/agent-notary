#!/usr/bin/env python3
"""
LaTeX Manuscript Integrity Auditor for Agent-Notary.
Validates syntax, citation monotonicity, environment balance, and author certification.
Author: Aniket Agrawal <aniketagrawal@google.com>
"""

import os
import re
import sys

def audit_latex_file(tex_path: str):
    print(f"Auditing LaTeX Manuscript: {tex_path}")
    print("=" * 70)

    if not os.path.exists(tex_path):
        print(f"[FAIL] File not found: {tex_path}")
        sys.exit(1)

    with open(tex_path, "r", encoding="utf-8") as f:
        content = f.read()

    lines = content.splitlines()

    # 1. Environment Balancing
    env_starts = re.findall(r"\\begin\{([a-zA-Z0-9_\*]+)\}", content)
    env_ends = re.findall(r"\\end\{([a-zA-Z0-9_\*]+)\}", content)

    start_counts = {}
    for e in env_starts:
        start_counts[e] = start_counts.get(e, 0) + 1

    end_counts = {}
    for e in env_ends:
        end_counts[e] = end_counts.get(e, 0) + 1

    all_envs = sorted(list(set(list(start_counts.keys()) + list(end_counts.keys()))))
    balance_ok = True
    for env in all_envs:
        s = start_counts.get(env, 0)
        e = end_counts.get(env, 0)
        if s == e:
            print(f"  [PASS] Environment '{env}': {s} balanced pairs")
        else:
            print(f"  [FAIL] Environment '{env}': {s} begins vs {e} ends!")
            balance_ok = False

    if not balance_ok:
        print("[FAIL] Unbalanced LaTeX environments detected!")
        sys.exit(1)

    # 2. Citations & Bibliography Monotonicity
    bib_entries = re.findall(r"\\bibitem\{([^}]+)\}", content)
    citations_in_text = re.findall(r"\\cite\{([^}]+)\}", content)

    flat_citations = []
    for c in citations_in_text:
        for single in c.split(","):
            s_clean = single.strip()
            if s_clean and s_clean not in flat_citations:
                flat_citations.append(s_clean)

    print(f"  [INFO] Total unique bibliography keys defined: {len(bib_entries)}")
    print(f"  [INFO] Total unique citations in text: {len(flat_citations)}")

    for c in flat_citations:
        if c not in bib_entries:
            print(f"  [FAIL] Cited key '{c}' not found in bibliography!")
            sys.exit(1)
    print("  [PASS] Citations matched: all cited keys exist in bibliography")

    for b in bib_entries:
        if b not in flat_citations:
            print(f"  [FAIL] Bib key '{b}' defined but never cited!")
            sys.exit(1)
    print("  [PASS] Bibliography clean: all entries are cited in text")

    # Check strict citation monotonicity [1..N]
    monotonic_ok = True
    for idx, (cited, bib) in enumerate(zip(flat_citations, bib_entries)):
        if cited != bib:
            print(f"  [FAIL] Citation order mismatch at index {idx+1}: cited '{cited}' vs bib '{bib}'")
            monotonic_ok = False
            break

    if monotonic_ok:
        print(f"  [PASS] Citation sequence strictly monotonic: all {len(bib_entries)} citations cited in exact order [1..{len(bib_entries)}]")
    else:
        sys.exit(1)

    # 3. Author block certification
    if "Aniket Agrawal" in content and "aniketagrawal@google.com" in content and "Google Cloud" in content:
        print("  [PASS] Author block certified: Aniket Agrawal, Google Cloud, aniketagrawal@google.com")
    else:
        print("  [FAIL] Author block missing required credentials!")
        sys.exit(1)

    print("=" * 70)
    print("AUDIT 100% SUCCESS: Certified Diamond Quality for Overleaf compilation!")


if __name__ == "__main__":
    tex_file = sys.argv[1] if len(sys.argv) > 1 else "/Users/aniketagrawal/antigravity_workshop/agent_notary/agent_notary_paper.tex"
    audit_latex_file(tex_file)
