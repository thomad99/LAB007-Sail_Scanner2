cd "C:\Users\david\OneDrive\My Pet Projects\AI\3.1-ScanImage"

# Ensure correct GitHub repo is linked
# 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

git remote set-url origin https://github.com/thomad99/LAB007-Sail_Scanner2.git

# Stage all changes
git add .

# Only commit if there are actual changes
$changes = git status --porcelain
if ($changes) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    git commit -m "Auto-sync $timestamp"
    git push origin main
}
