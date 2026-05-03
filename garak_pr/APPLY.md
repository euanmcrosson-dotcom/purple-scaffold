# How to turn this into an actual PR against NVIDIA/garak

Everything in `garak_pr/` is the proposed contribution. Here's the
mechanical sequence to get it into a real GitHub PR.

## 1. Fork and clone garak

```powershell
# Make sure gh CLI is set up
gh auth login

# Fork the upstream repo to your account
gh repo fork NVIDIA/garak --clone=true --remote=true
Set-Location garak

# Verify your fork is "origin" and upstream is "upstream"
git remote -v
```

## 2. Create a feature branch

```powershell
git checkout -b refusal-language-classifier
```

## 3. Copy in the patched files

From the scaffold (assumes scaffold is at `C:\Users\euanc\purple-scaffold`):

```powershell
$src = "C:\Users\euanc\purple-scaffold\garak_pr"
$dst = (Get-Location).Path

Copy-Item "$src\garak\detectors\refusal.py"      "$dst\garak\detectors\refusal.py"
Copy-Item "$src\garak\detectors\promptinject.py" "$dst\garak\detectors\promptinject.py" -Force
Copy-Item "$src\garak\detectors\divergence.py"   "$dst\garak\detectors\divergence.py"   -Force
Copy-Item "$src\garak\detectors\mitigation.py"   "$dst\garak\detectors\mitigation.py"   -Force

# Tests directory — match the upstream test layout (may differ by repo;
# adjust path if upstream uses tests/garak/detectors/ etc.)
$test_dst = "$dst\tests\detectors"
New-Item -ItemType Directory -Force -Path $test_dst | Out-Null
Copy-Item "$src\tests\detectors\test_refusal.py" "$test_dst\test_refusal.py"
```

## 4. Run upstream's full test suite

Critical — the patches modify two existing detectors. Make sure existing
tests still pass:

```powershell
pip install -e .[test]
pytest tests/ -x 2>&1 | tail -30
```

If anything fails that wasn't failing before your changes, fix before
opening the PR. Most likely break point: tests that exercise
`AttackRogueString` / `RepeatDiverges` / `MitigationBypass` with
specific configs — none of those should change since `refusal_filter`
defaults to False.

## 5. Run the new tests

```powershell
pytest tests/detectors/test_refusal.py -v
```

All 46 should pass.

## 6. Format / lint per upstream conventions

```powershell
# Check upstream's CONTRIBUTING.md for the right tooling
# Garak typically uses black + isort
pip install black isort
black garak/detectors/refusal.py garak/detectors/promptinject.py garak/detectors/divergence.py garak/detectors/mitigation.py tests/detectors/test_refusal.py
isort garak/detectors/refusal.py garak/detectors/promptinject.py garak/detectors/divergence.py garak/detectors/mitigation.py tests/detectors/test_refusal.py
```

## 7. Commit and push

```powershell
git add garak/detectors/refusal.py
git add garak/detectors/promptinject.py
git add garak/detectors/divergence.py
git add garak/detectors/mitigation.py
git add tests/detectors/test_refusal.py

git commit -m "Add RefusalLanguageClassifier post-filter for substring detectors

Adds an opt-in refusal_filter flag on AttackRogueString, RepeatDiverges,
and MitigationBypass. When enabled, suppresses false-positive hits where
the model output contains articulate refusal language not matched by the
legacy substring lists.

Default is False everywhere; backward-compatible. New helper class
RefusalLanguageClassifier in garak.detectors.refusal covers explicit
verb / identity / meta / polite-deflection / redirect / guideline
refusal patterns. 46 unit tests added."

git push -u origin refusal-language-classifier
```

## 8. Open the PR

```powershell
gh pr create `
  --repo NVIDIA/garak `
  --base main `
  --head "$(gh api user --jq .login):refusal-language-classifier" `
  --title "Add RefusalLanguageClassifier post-filter for substring detectors" `
  --body-file C:\Users\euanc\purple-scaffold\garak_pr\PR_DESCRIPTION.md
```

Or open https://github.com/NVIDIA/garak/compare in browser, point at
your fork's branch, and paste the body manually.

## 9. After opening the PR

- Watch GitHub Actions / CI. If any check fails, look at the logs and
  push fixes to the same branch (auto-updates the PR).
- Reply to maintainer comments within 24-48 hours. Be willing to:
  - Split into per-detector PRs if asked
  - Adjust pattern coverage based on their feedback
  - Add docs page entries if they request it
- If maintainer asks for changes, edit locally → commit → push to the
  same branch.

## 10. If this PR ends up landing — what you've gained

- A merged commit in NVIDIA's garak repo with your name on it
- A traceable contribution citation for your CV / portfolio
- Direct working relationship with garak maintainers
- The detector fix is now what every garak user gets by default once
  they opt in (and eventually as default after a deprecation cycle)

This is the highest-impact single artifact you can produce in the AI
security tooling space right now — the tool has 4k+ stars and is used
by frontier labs in their pre-deployment evaluations.

## If the PR doesn't land

If maintainers reject or ignore it:

- Document the analysis publicly anyway (your blog, the issue you filed)
- The scripts/cards in your repo demonstrate the same fix works
- Cite the rejected/stalled PR in your portfolio writeup as evidence of
  the contribution attempt — even rejected PRs show the work product

Good luck.
