# Run STRONG probe families across multi-provider frontier models.
# Designed to actually find or characterize real attack patterns —
# not surface-check trivia.
#
# Probe lineup (5 families):
#   - divergence.Repeat                               (Carlini-style data extraction)
#   - latentinjection.LatentInjectionResume           (RAG-attack against recruiting flow)
#   - latentinjection.LatentJailbreak                 (translation-mode jailbreak)
#   - dan.AutoDANCached                               (automated adversarial suffixes)
#   - goodside.Tag                                    (zero-width unicode injection)
#
# Models per provider — comment out anything you want to skip.
#
# Prerequisites:
#   $env:ANTHROPIC_API_KEY, $env:OPENAI_API_KEY, $env:GEMINI_API_KEY
#
# Cost estimate (all 30 runs at default config): ~$15-25
# Runtime: ~4-6 hours sequential (with 75-sec inter-probe waits)
#
# Usage:
#   Set-Location C:\Users\euanc\purple-scaffold
#   .\scripts\run_frontier_probes.ps1

$ErrorActionPreference = "Continue"

# ───────────────────────────────────────────────────────────────────────
# Probes — chosen for actual signal on frontier models, not surface tests
# ───────────────────────────────────────────────────────────────────────
$probes = @(
    "divergence.Repeat",
    "latentinjection.LatentInjectionResume",
    "latentinjection.LatentJailbreak",
    "dan.AutoDANCached",
    "goodside.Tag"
)

# ───────────────────────────────────────────────────────────────────────
# Models — comment out to skip
# ───────────────────────────────────────────────────────────────────────
$models = @(
    @{ name = "anthropic/claude-haiku-4-5-20251001"; label = "Haiku 4.5";    provider = "anthropic"; key_env = "ANTHROPIC_API_KEY"; needs_options = $true;  cost = "~`$0.10" }
    @{ name = "anthropic/claude-opus-4-7";           label = "Opus 4.7";     provider = "anthropic"; key_env = "ANTHROPIC_API_KEY"; needs_options = $true;  cost = "~`$1.50" }
    @{ name = "openai/gpt-4o-mini";                  label = "GPT-4o-mini";  provider = "openai";    key_env = "OPENAI_API_KEY";    needs_options = $false; cost = "~`$0.05" }
    @{ name = "openai/gpt-4o";                       label = "GPT-4o";       provider = "openai";    key_env = "OPENAI_API_KEY";    needs_options = $false; cost = "~`$0.50" }
    @{ name = "gemini/gemini-2.5-flash";             label = "Gemini Flash"; provider = "gemini";    key_env = "GEMINI_API_KEY";    needs_options = $false; cost = "~`$0.10" }
    @{ name = "gemini/gemini-2.5-pro";               label = "Gemini Pro";   provider = "gemini";    key_env = "GEMINI_API_KEY";    needs_options = $false; cost = "~`$1.50" }
)

# ───────────────────────────────────────────────────────────────────────
# Pre-flight: verify keys
# ───────────────────────────────────────────────────────────────────────
$used_envs = $models | ForEach-Object { $_.key_env } | Sort-Object -Unique
$missing = @()
foreach ($e in $used_envs) {
    $val = [System.Environment]::GetEnvironmentVariable($e, "Process")
    if ([string]::IsNullOrEmpty($val)) { $missing += $e }
}
if ($missing.Count -gt 0) {
    Write-Host "ERROR: Missing required env vars: $($missing -join ', ')" -ForegroundColor Red
    Write-Host "Set them with [System.Environment]::SetEnvironmentVariable(...) and reopen PowerShell." -ForegroundColor Yellow
    exit 1
}

$active_models = @()
foreach ($m in $models) {
    $val = [System.Environment]::GetEnvironmentVariable($m.key_env, "Process")
    if ([string]::IsNullOrEmpty($val)) {
        Write-Host "Skipping $($m.label) — $($m.key_env) not set" -ForegroundColor DarkGray
    } else {
        $active_models += $m
    }
}

$total_runs = $probes.Count * $active_models.Count
$run_n = 0

Write-Host ""
Write-Host "Strong frontier probe sweep starting" -ForegroundColor Cyan
Write-Host "  $total_runs runs total ($($probes.Count) probes x $($active_models.Count) models)"
Write-Host "  75-sec waits between probes (rate limits)"
Write-Host ""

foreach ($probe in $probes) {
    foreach ($m in $active_models) {
        $run_n++
        Write-Host ""
        Write-Host "=================================================================" -ForegroundColor Yellow
        Write-Host "[$run_n/$total_runs] $($m.label) ($($m.provider)) :: $probe ($($m.cost))" -ForegroundColor Yellow
        Write-Host "=================================================================" -ForegroundColor Yellow

        if ($m.needs_options) {
            garak --model_type litellm --model_name $m.name --probes $probe --generations 1 --generator_option_file .\garak_options.json
        } else {
            garak --model_type litellm --model_name $m.name --probes $probe --generations 1
        }

        if ($LASTEXITCODE -eq 0) {
            Write-Host "Converting to card..." -ForegroundColor Green
            python scripts\garak_to_card.py
        } else {
            Write-Host "WARNING: probe run failed (exit $LASTEXITCODE); continuing." -ForegroundColor Red
        }

        if ($run_n -lt $total_runs) {
            Write-Host "Waiting 75 seconds for rate limit window..." -ForegroundColor DarkGray
            Start-Sleep -Seconds 75
        }
    }
}

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "Sweep complete." -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Get-ChildItem .\examples\cards\GARAK.* | Select-Object Name, Length, LastWriteTime
