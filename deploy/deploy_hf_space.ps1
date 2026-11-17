<#
  Deploy the PhishGuard-AI backend to the Hugging Face Space KunTheNoobie/phishguard-backend
  (SDK gradio, free CPU Basic). The access token is read from the HF_TOKEN environment
  variable and is sent only as an HTTP header: it is never written to any file.

    $env:HF_TOKEN = "hf_..."          # a WRITE token from https://huggingface.co/settings/tokens
    powershell -ExecutionPolicy Bypass -File deploy\deploy_hf_space.ps1

  After the build (5-10 minutes) the app answers at https://kunthenoobie-phishguard-backend.hf.space
#>
param(
  [string]$Space = "KunTheNoobie/phishguard-backend",
  [string]$User  = "KunTheNoobie"
)
$ErrorActionPreference = "Stop"
if (-not $env:HF_TOKEN) { throw "Set `$env:HF_TOKEN to a Hugging Face write token first." }
$repo = Split-Path -Parent $PSScriptRoot
$work = Join-Path $env:TEMP "phishguard-space"

# Send the token as a header for git and git-lfs (nothing is stored in a remote URL or config file).
$basic = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${User}:$($env:HF_TOKEN)"))
$env:GIT_CONFIG_COUNT = "1"
$env:GIT_CONFIG_KEY_0 = "http.https://huggingface.co/.extraHeader"
$env:GIT_CONFIG_VALUE_0 = "Authorization: Basic $basic"
$env:GIT_TERMINAL_PROMPT = "0"

$weights = Join-Path $repo "phishguard_custom_model\model.safetensors"
if (-not (Test-Path $weights) -or (Get-Item $weights).Length -lt 100MB) {
  throw "phishguard_custom_model\model.safetensors is missing or a Git LFS pointer. Run setup.bat (git lfs pull) first."
}

if (Test-Path $work) { Remove-Item -Recurse -Force $work }
git clone "https://huggingface.co/spaces/$Space" $work
if ($LASTEXITCODE -ne 0) { throw "Could not clone the Space. Check that it exists and that the token has write access." }

$items = @("main.py", "app.py", "requirements.txt", "packages.txt", "api", "core", "database", "schemas", "services", "dashboard",
           "phishguard_custom_model\config.json", "phishguard_custom_model\model.safetensors",
           "phishguard_custom_model\tokenizer.json", "phishguard_custom_model\tokenizer_config.json",
           "visual_identity\models", "visual_identity\classes.txt")
foreach ($item in $items) {
  $source = Join-Path $repo $item
  $target = Join-Path $work $item
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
  Copy-Item -Recurse -Force $source $target
}
Get-ChildItem -Path $work -Recurse -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force
Copy-Item -Force (Join-Path $PSScriptRoot "hf_space_README.txt") (Join-Path $work "README.md")

Push-Location $work
git lfs install --local
git lfs track "*.safetensors" "*.pt" "phishguard_custom_model/tokenizer.json"
git add -A
git -c user.name="$User" -c user.email="$User@users.noreply.huggingface.co" commit -m "Deploy PhishGuard-AI backend"
git push
Pop-Location
Remove-Item Env:GIT_CONFIG_COUNT, Env:GIT_CONFIG_KEY_0, Env:GIT_CONFIG_VALUE_0
Write-Host "Pushed. Build log: https://huggingface.co/spaces/$Space"
Write-Host "Live URL:  https://kunthenoobie-phishguard-backend.hf.space/health"

