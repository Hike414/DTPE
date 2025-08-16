# Add Go to PATH for this session
$env:Path += ";C:\Users\Cprtv\OneDrive\Desktop\DTPE\Go\bin"

# Verify Go is accessible
go version

# Navigate to the project directory
Set-Location "C:\Users\Cprtv\OneDrive\Desktop\DTPE\dtpe-framework\dtpe-framework\client-go"

# Run the Go client
go run main.go

# Keep the window open
Write-Host "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
