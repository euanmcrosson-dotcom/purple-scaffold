# Run dan.DanInTheWild (64 real-world jailbreak prompts) against the
# cheap-tier frontier models — replaces the N=3 AutoDANCached run with
# a statistically meaningful sample.
#
# Cost: ~$0.10 total
# Runtime: ~10-15 min
#
# Usage:
#   Set-Location C:\Users\euanc\purple-scaffold
#   .\scripts\run_dan_in_the_wild.ps1

$models = @(
    @{ name = "anthropic/claude-haiku-4-5-20251001"; label = "Haiku 4.5";   key_env = "ANTHROPIC_API_KEY"; needs_options = $true  }
    @{ name = "openai/gpt-4o-mini";                  label = "GPT-4o-mini"; key_env = "OPENAI_API_KEY";    needs_options = $false }
)

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

$n = 0
foreach ($m in $models) {
    $n++
    Write-Host ""
    Write-Host "[$n/$($models.Count)] $($m.label) :: dan.DanInTheWild" -ForegroundColor Yellow

    if ($m.needs_options) {
        garak --model_type litellm --model_name $m.name --probes dan.DanInTheWild --generations 1 --generator_option_file .\garak_options.json
    } else {
        garak --model_type litellm --model_name $m.name --probes dan.DanInTheWild --generations 1
    }

    if ($LASTEXITCODE -eq 0) {
        python scripts\garak_to_card.py
    } else {
        Write-Host "WARNING: probe failed (exit $LASTEXITCODE)" -ForegroundColor Red
    }

    if ($n -lt $models.Count) { Start-Sleep -Seconds 75 }
}

Write-Host ""
Write-Host "DanInTheWild sweep complete." -ForegroundColor Cyan
