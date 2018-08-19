rdnssd
======

#### Introduction
Recursive DNS Servers discovery daemon is an implementation of the RFC 5006 for Microsoft Windows. It parses the RDNSS options present in Router Advertisement (RA), get the DNS nameservers and write them in the registry.

#### Compilation
- To compile rdnssd you need Visual Studio 2017.
- Open rdnssd.sln.
- Go to project => Properties, select "Configuration properties" and be sure that platform is right for you (win32 or x64).
- Build the solution.

#### Configuration
- rdnssd listens on all network interfaces for RA.
- An optional parameter "-b" is used for the service mode, see next section.

#### Installation
On the target, you have to install the Microsoft Visual C++ 2015 Redistributable Package.

Install as service:
Copy `rdnssd.exe` to a directory (here `C:\Windows\System32\`) then in a console type:
```console
New-Service -Name rdnssd -BinaryPathName "C:\WINDOWS\System32\rdnssd.exe -b" -DisplayName "Recursive DNS Servers discovery daemon" -StartupType Manual -Description "IPv6 recursive DNS server discovery daemon is an implementation of the RFC 5006 for Microsoft Windows. It parses the RDNSS options present in Router Advertisement (RA), get the DNS nameservers and write them in the registry."
Set-Service rdnssd -StartupType Automatic
```

If you want to change ifname parameter after installation:
```console
Stop-Service rdnssd
sc.exe delete rdnssd 1>$null
```

#### Limitations
- rdnssd works only on Microsoft Windows >= Vista as well as Windows server >= 2003.
- On older versions such as Windows XP, IPv6 nameservers are written at the good place but could not be used because they do not provide a DNS resolver with IPv6 transport.

#### Credit
- [Sebastien Vincent](sebastien.vincent@cppextrem.com) for writing the software.
