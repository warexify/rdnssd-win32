Sebastien Vincent <sebastien.vincent@cppextrem.com>

-------------
rdnssd_win32
-------------

Introduction
------------

rdnssd_win32 is an implementation of the RFC 5006. It parse the RDNSS options present 
in Router Advertisement (RA), get the DNS nameservers and write them in the registry.

1) Compilation
--------------

To compile rdnssd_win32 you need :
- Visual Studio 2008 (should work with 2005)
- Microsoft SDKs and configure Visual Studio directory (include and lib)
- Install the "WinPcap developper's pack" and configure Visual Studio directory (include and lib)

Open the rdnssd_win32.sln and compile (F7).

2) Configuration
----------------

rdnssd_win32 needs at least one argument, it is the name of the interface that will catch the traffic.
If you don't know them, simply type rdnssd_win32 without arguments, it will show you all the interface name.

The second parameters is "b" and it is used for services, see next section.


3) Installation
----------------

On the target, you have to install the VC Runtime depending on which version you have compile rdnssd_win32 
(VC 2008 or VC 2005).

Install as service :

copy rdnssd_win32 to a directory then in a console type, 

sc create rdnssd binPath= "<YourDirectory>\rdnssd_win32.exe <ifname> b"

If you want to change the ifname after installation : 
sc delete rdnssd

Then type again the "sc create..." command with new ifname.

4) Limitations

- rdnssd_win32 works only on Microsoft Windows 2003 and higher.
On the other version, the IPv6 name servers are written at the good place but could not be used because 
they do not provide a DNS resolver with IPv6 transport.

- For the moment, only one interface could be configure to listen to RDNSS option. If you want to 
have more interfaces at a time, you need to launch one rdnssd_win32 per interface.
Future versions will take care of this problem.
