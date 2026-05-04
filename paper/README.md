# Paper: Tool-Vector Sensitivity in Indirect-Prompt-Injection Compliance for MCP-Using Agents

This directory contains the LaTeX source for the workshop paper
draft accompanying the harness. The paper is in IEEE conference
format; submission targets are arxiv (cs.CR), USENIX Security WOOT,
NDSS BAR, and IEEE SaTML.

## Build

```bash
cd paper/
make all                    # produces main.pdf
```

Requires TeX Live (`apt install texlive-full` on Linux) or MiKTeX
on Windows. The first run takes a couple of minutes for the full
texlive bundle to extract; subsequent builds are seconds.

If you don't have TeX locally, the easiest alternative is
[Overleaf](https://www.overleaf.com/) — upload `main.tex` and it
builds a PDF in your browser.

## Submit to arxiv

1. Build the PDF locally (or in Overleaf).
2. Create an arxiv account at https://arxiv.org/user/.
3. Upload the .tex source (NOT just the PDF — arxiv requires
   source). The build environment is `pdflatex` 2024 by default.
4. Primary subject class: `cs.CR` (Computer Science > Cryptography
   and Security). Cross-list to `cs.AI` (Artificial Intelligence).
5. arxiv typically takes 1-2 days to release publicly.

For the workshop paper version, the same `main.tex` is the
submission body. Some venues (USENIX) want a different template;
adapt the document class as needed.

## Outline reference

The structural outline is in
[`PAPER_OUTLINE.md`](../PAPER_OUTLINE.md). Sections in `main.tex`
follow that outline.

## Status

- 2026-05-05: initial draft, ~3000 words, 8 references.
- Pre-print target: arxiv before any conference submission.
- Workshop targets: USENIX WOOT (CFP usually opens summer for
  August submission), NDSS BAR (CFP opens autumn for January
  submission), SaTML.

## What's NOT in this draft yet

- Figures (just tables for now). A diagram of the tool-vector-
  shape hypothesis would help — agent / MCP server / poisoned
  content boxes with arrows showing where compliance occurs.
- Reviewer-style related-work coverage (the bibliography has 8
  entries; a competitive workshop submission usually wants 15-25).
- A controlled experiment on the tool-vector-shape hypothesis
  (single-tool vs multi-tool variants). Currently flagged as
  future work.
