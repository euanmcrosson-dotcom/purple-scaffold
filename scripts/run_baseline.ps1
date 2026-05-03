# Minimal generic baseline sweep — 3 strong probes x 3 cheap models.
# Produces comparable cross-provider data for the bottom-tier frontier
# models at minimum cost.
#
# Probes (chosen for actual signal, not surface checks):
#   - latentinjection.LatentInjectionResume   (RAG-attack via resume content)
#   - dan.AutoDANCached                       (automated adversarial suffixes)
#   - divergence.Repeat                       (training data extraction)
#
# Models — cheap tier only (skip Opus/4o/Pro to control spend):
#   - anthropic/claude-haiku-4-5
#   - openai/gpt-4o-mini
#   - gemini/gemini-2.5-flash
#
# Cost estimate: ~$0.75-2
# Runtime: ~30-60 min
#
# Usage:
#   Set-Location C:\Users\euanc\purple-scaffold
#   .\scripts\run_baseline.ps1

$ErrorActionPreference = "Continue"

$probes = @(
    "latentinjection.LatentInjectionResume",
    "dan.AutoDANCached",
    "divergence.Repeat"
)

$models = @(
    @{ name = "anthropic/claude-haiku-4-5-20251001"; label = "Haiku 4.5";    key_env = "ANTHROPIC_API_KEY"; needs_options = $true  }
    @{ name = "openai/gpt-4o-mini";                  label = "GPT-4o-mini";  key_env = "OPENAI_API_KEY";    needs_options = $false }
    @{ name = "gemini/gemini-2.5-flash";             label = "Gemini Flash"; key_env = "GEMINI_API_KEY";    needs_options = $false }
)

# Pre-flight key check
$missing = @()
foreach ($m in $models) {
    if ([string]::IsNullOrEmpty([System.Environment]::GetEnvironmentVariable($m.key_env, "Process"))) {
        $missing += $m.key_env
    }
}
if ($missing.Count -gt 0) {
    Write-Host "ERROR: Missing env vars: $($missing -join ', ')" -ForegroundColor Red
    exit 1
}

$total_runs = $probes.Count * $models.Count
$run_n = 0

Write-Host ""
Write-Host "Minimal baseline sweep starting ($total_runs runs)" -ForegroundColor Cyan
Write-Host ""

foreach ($probe in $probes) {
    foreach ($m in $models) {
        $run_n++
        Write-Host ""
        Write-Host "[$run_n/$total_runs] $($m.label) :: $probe" -ForegroundColor Yellow

        if ($m.needs_options) {
            garak --model_type litellm --model_name $m.name --probes $probe --generations 1 --generator_option_file .\garak_options.json
        } else {
            garak --model_type litellm --model_name $m.name --probes $probe --generations 1
        }

        if ($LASTEXITCODE -eq 0) {
            python scripts\garak_to_card.py
        } else {
            Write-Host "WARNING: probe failed (exit $LASTEXITCODE)" -ForegroundColor Red
        }

        if ($run_n -lt $total_runs) {
            Start-Sleep -Seconds 75
        }
    }
}

Write-Host ""
Write-Host "Baseline sweep complete." -ForegroundColor Cyan
Get-ChildItem .\examples\cards\GARAK.* | Select-Object Name, LastWriteTime
