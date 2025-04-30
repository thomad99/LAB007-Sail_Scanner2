cd "C:\Users\david\OneDrive\My Pet Projects\AI\3.1-ScanImage"

# Set GitHub repo URL (just in case)
git remote set-url origin https://github.com/thomad99/LAB007-Sail_Scanner2.git

# Pull latest changes first
Write-Output "⬇️ Pulling latest changes..."
git pull origin main

# Stage all changes
git add .

# Check for changes
$changes = git status --porcelain

if ($changes) {
    Write-Output "🔄 Files to be committed:"
    $changes

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    git commit -m "Auto-sync $timestamp"

    Write-Output "⬆️ Pushing changes to GitHub..."
    git push origin main
    Write-Output "✅ Sync complete at $timestamp"
}
else {
    Write-Output "🟢 No changes to sync."
}
