<#
  Deploy the PhishGuard-AI backend to a Hugging Face Space (Docker, free CPU).

  One-time preparation (in a browser):
    1. Sign in at https://huggingface.co and open https://huggingface.co/new-space
    2. Owner: your account, Space name: phishguard-backend, SDK: Docker (Blank),
       Hardware: CPU basic (free), Visibility: Public.  Create the Space.
    3. Create a WRITE access token at https://huggingface.co/settings/tokens

  Then, from the PhishGuard-AI-Complete folder:
    powershell -ExecutionPolicy Bypass -File deploy\deploy_hf_space.ps1
  When git asks for a password, paste the access token (user name = your HF user name).

  The Space builds for 5-10 minutes, then answers at
    https://<user>-phishguard-backend.hf.space/health
#>
param(
  [string]$Space = "KunTheNoobie/phishguard-backend"
)
$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$work = Join-Path $env:TEMP "phishguard-space"

Write-Host "Preparing a clean copy of the Space in $work"
if (Test-Path $work) { Remove-Item -Recurse -Force $work }
git clone "https://huggingface.co/spaces/$Space" $work
if ($LASTEXITCODE -ne 0) { throw "Could not clone the Space. Create it first (see the notes at the top of this script)." }

# Make sure the model files are real weights, not Git LFS pointers.
git -C $repo lfs pull

$items = @("main.py", "requirements.txt", "Dockerfile", "api", "core", "database", "schemas", "services",
           "dashboard", "phishguard_custom_model\config.json", "phishguard_custom_model\model.safetensors",
           "phishguard_custom_model\tokenizer.json", "phishguard_custom_model\tokenizer_config.json",
           "visual_identity\models", "visual_identity\classes.txt")
foreach ($item in $items) {
  $source = Join-Path $repo $item
  $target = Join-Path $work $item
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
  Copy-Item -Recurse -Force $source $target
}
Get-ChildItem -Path $work -Recurse -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force
Copy-Item -Force (Join-Path $PSScriptRoot "space_readme.txt") (Join-Path $work "README.md")

Push-Location $work
git lfs install
git lfs track "*.safetensors" "*.pt" "phishguard_custom_model/tokenizer.json"
git add -A
git commit -m "Deploy PhishGuard-AI backend"
git push
Pop-Location
Write-Host "Pushed. Watch the build log on https://huggingface.co/spaces/$Space"
