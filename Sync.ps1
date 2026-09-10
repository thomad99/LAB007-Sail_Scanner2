# Always run from this repo folder (where Sync.ps1 lives)
Set-Location $PSScriptRoot

# Set GitHub repo URL (just in case)
git remote set-url origin https://github.com/thomad99/LAB007-Sail_Scanner2.git

# Ensure Images folder is tracked even if gitignored
if (Test-Path "Images") {
    git add Images/ -f
    Write-Output "Images folder staged"
}

# Stage all local changes
git add .

# Check for changes
$changes = git status --porcelain

if ($changes) {
    Write-Output "🔄 Files to be committed:"
    $changes

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    git commit -m "Auto-sync $timestamp"

    Write-Output "⬆️ Pushing local changes to GitHub..."
    git push origin main
    Write-Output "✅ Sync complete at $timestamp"
}
else {
    Write-Output "🟢 No changes to sync."
}
