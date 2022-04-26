# Copy exe to c:\opt
$currdir = Get-Location
New-Item -ItemType Directory -Path "C:\opt"
Copy-Item "$currdir\rdnssd.exe" "C:\opt\rdnssd.exe"

# Service parameters
$params = @{
  Name = "rdnssd"
  BinaryPathName = "C:\opt\rdnssd.exe -b"
  DisplayName = "RDNSS Daemon"
  StartupType = "Automatic"
  Description = "IPv6 recursive DNS server discovery daemon is an implementation of the RFC 5006 for Microsoft Windows. It parses the RDNSS options present in Router Advertisement (RA), get the DNS nameservers and write them in the registry."
}

# Delete existing service
Stop-Service rdnssd
# Remove-Service -Name rdnssd # Requires PowerShell 6.0+
& sc.exe delete rdnssd 1>$null # Will always work

# Create service
New-Service @params
Start-Service rdnssd
