# Retry just the runs that failed in the first sweep:
#   1. latentinjection vs Haiku 4.5 (was rate-limited at 93%)
#   2. leakreplay.LiteratureCloze vs Haiku 4.5 (probe name was wrong)
#   3. leakreplay.LiteratureCloze vs Opus 4.7 (probe name was wrong)
#
# Adds 75-second waits between probes to let Anthropic's 50 req/min
# rate limit window reset between runs.
#
# Cost estimate: ~$2.50 (mostly Opus run)
# Runtime: ~25-35 min
#
# Usage:
#   Set-Location C:\Users\euanc\purple-scaffold
#   .\scripts\retry_failed_probes.ps1

$ErrorActionPreference = "Continue"

$runs = @(
    @{ probe = "latentinjection.LatentInjectionFactSnippetEiffel"; model = "anthropic/claude-haiku-4-5-20251001"; label = "Haiku 4.5"; cost = "~`$0.10" }
    @{ probe = "leakreplay.LiteratureCloze";                       model = "anthropic/claude-haiku-4-5-20251001"; label = "Haiku 4.5"; cost = "~`$0.05" }
    @{ probe = "leakreplay.LiteratureCloze";                       model = "anthropic/claude-opus-4-7";           label = "Opus 4.7";  cost = "~`$1.50" }
)

$total = $runs.Count
$n = 0

Write-Host ""
Write-Host "Retrying $total failed runs from previous sweep" -ForegroundColor Cyan
Write-Host "  Includes 75-sec waits between probes to respect 50 req/min rate limits" -ForegroundColor Cyan
Write-Host ""

foreach ($r in $runs) {
    $n++
    Write-Host ""
    Write-Host "=================================================================" -ForegroundColor Yellow
    Write-Host "[$n/$total] $($r.label) :: $($r.probe) ($($r.cost))" -ForegroundColor Yellow
    Write-Host "=================================================================" -ForegroundColor Yellow

    garak --model_type litellm `
          --model_name $r.model `
          --probes $r.probe `
          --generations 1 `
          --generator_option_file .\garak_options.json

    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "Converting to card..." -ForegroundColor Green
        python scripts\garak_to_card.py
    } else {
        Write-Host ""
        Write-Host "WARNING: probe run failed; check garak.log" -ForegroundColor Red
    }

    if ($n -lt $total) {
        Write-Host ""
        Write-Host "Waiting 75 seconds for rate limit window to reset..." -ForegroundColor DarkGray
        Start-Sleep -Seconds 75
    }
}

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "Retry sweep complete. All cards under examples\cards\" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Get-ChildItem .\examples\cards\GARAK.* | Select-Object Name, Length, LastWriteTime
