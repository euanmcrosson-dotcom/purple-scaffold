# Run custom probes (echoleak, mcp_poisoning) across Anthropic + OpenAI
# frontier models. These attacks are NOT in any public benchmark and
# the labs have not specifically trained against them.
#
# Each (probe, model) pair produces a JSONL report; garak_to_card.py
# converts each report into a per-technique card.
#
# Custom probes (under custom_probes/):
#   - echoleak           (24 prompts) — EchoLeak-style email-summarization injection
#   - mcp_poisoning      (4 prompts)  — MCP tool-description poisoning + 1 control
#
# Cost estimate: ~$2-3
# Runtime: ~25-40 min total
#
# Usage:
#   Set-Location C:\Users\euanc\purple-scaffold
#   .\scripts\run_custom_sweep.ps1

$ErrorActionPreference = "Continue"

$probes = @("echoleak", "mcp_poisoning")

# Gemini omitted — free-tier rate limits (5 RPM) and 503s make it
# unusable. Add back if you upgrade Gemini to paid tier.
$models = @(
    @{ name = "anthropic/claude-haiku-4-5-20251001"; label = "Haiku 4.5";   key_env = "ANTHROPIC_API_KEY"; cost = "~`$0.05" }
    @{ name = "anthropic/claude-opus-4-7";           label = "Opus 4.7";    key_env = "ANTHROPIC_API_KEY"; cost = "~`$0.50" }
    @{ name = "openai/gpt-4o-mini";                  label = "GPT-4o-mini"; key_env = "OPENAI_API_KEY";    cost = "~`$0.02" }
    @{ name = "openai/gpt-4o";                       label = "GPT-4o";      key_env = "OPENAI_API_KEY";    cost = "~`$0.30" }
)

# ───────────────────────────────────────────────────────────────────────
# Pre-flight key check
# ───────────────────────────────────────────────────────────────────────
$used_envs = $models | ForEach-Object { $_.key_env } | Sort-Object -Unique
$missing = @()
foreach ($e in $used_envs) {
    $val = [System.Environment]::GetEnvironmentVariable($e, "Process")
    if ([string]::IsNullOrEmpty($val)) { $missing += $e }
}
if ($missing.Count -gt 0) {
    Write-Host "ERROR: Missing env vars: $($missing -join ', ')" -ForegroundColor Red
    exit 1
}

$total_runs = $probes.Count * $models.Count
$run_n = 0

Write-Host ""
Write-Host "Custom probe sweep starting" -ForegroundColor Cyan
Write-Host "  $total_runs runs total ($($probes.Count) probes x $($models.Count) models)"
Write-Host "  Anthropic + OpenAI; Gemini skipped"
Write-Host ""

foreach ($probe in $probes) {
    foreach ($m in $models) {
        $run_n++
        Write-Host ""
        Write-Host "=================================================================" -ForegroundColor Yellow
        Write-Host "[$run_n/$total_runs] $($m.label) :: custom.$probe ($($m.cost))" -ForegroundColor Yellow
        Write-Host "=================================================================" -ForegroundColor Yellow

        python scripts\run_custom_probes.py $probe $m.name

        if ($LASTEXITCODE -eq 0) {
            python scripts\garak_to_card.py
        } else {
            Write-Host "WARNING: probe failed (exit $LASTEXITCODE)" -ForegroundColor Red
        }

        if ($run_n -lt $total_runs) {
            Start-Sleep -Seconds 30
        }
    }
}

Write-Host ""
Write-Host "Custom sweep complete." -ForegroundColor Cyan
Get-ChildItem .\examples\cards\GARAK.custom* | Select-Object Name, Length, LastWriteTime
