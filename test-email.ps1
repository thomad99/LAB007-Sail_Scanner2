# Test Email Endpoint
$baseUrl = "https://lab007-sail-scanner2.onrender.com"  # Change to your Render URL for production
$endpoint = "$baseUrl/api/send-email"

$body = @{
    from = "info@lab007.ai"
    to = "david.thomas@thinworld.net"
    subject = "Test Email LAB007.AI "
    text = "This is a test email sent at $(Get-Date)."
} | ConvertTo-Json

try {
    Write-Host "Sending test email..." -ForegroundColor Yellow
    $response = Invoke-RestMethod -Uri $endpoint -Method POST -Body $body -ContentType "application/json"
    Write-Host "SUCCESS!" -ForegroundColor Green
    Write-Host ($response | ConvertTo-Json -Depth 5)
} catch {
    Write-Host "ERROR:" -ForegroundColor Red
    Write-Host $_.Exception.Message
    if ($_.ErrorDetails.Message) {
        Write-Host $_.ErrorDetails.Message
    }
}