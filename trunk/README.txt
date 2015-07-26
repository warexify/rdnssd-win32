rdnssd_win32
============

Introduction
------------

rdnssd_win32 is an implementation of the RFC 5006 for Microsoft Windows. It
parses the RDNSS options present in Router Advertisement (RA), get the DNS
nameservers and write them in the registry.

Compilation
------------

To compile rdnssd_win32 you need:
- Visual Studio 2015.

Now open rdnssd_win32.sln
Go to project => Properties, select "Configuration properties" and be sure that platform is right for you (win32 or x64).
Compile (F7).

Configuration
--------------

rdnssd_win32 listens on all network interfaces for RA.

An optional parameter "-b" is used for the service mode, see next section.

Installation
-------------

On the target, you have to install the Microsoft Visual C++ 2013 Redistributable
Package.

Install as service:
Copy rdnssd_win32 to a directory (here c:\rdnssd\) then in a console type:
sc create rdnssd binPath= "c:\rdnssd\rdnssd_win32.exe -b"

If you want to change ifname parameter after installation:
sc delete rdnssd

Limitations
------------

- rdnssd_win32 works only on Microsoft Windows Vista/7/8 as well as Windows
server 2003 and 2008.

On older versions such as Windows XP, IPv6 nameservers are written at the good
place but could not be used because they do not provide a DNS resolver with
IPv6 transport.

Contact
--------

Sebastien Vincent <sebastien.vincent@cppextrem.com>

