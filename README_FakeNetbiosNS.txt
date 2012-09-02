
   --------------------------------------------------------------------------
  |                                                                          |
  |                         FakeNetbiosNS V. 0.91                            |
  |                                                                          |
  |  Simulation of NetBIOS hosts (Windows-like) on NetBIOS Name Service (NS) |
  |                                                                          |
   --------------------------------------------------------------------------


Copyright © Patrick Chambet 2004-2005



DISCLAMER
=========

This is provided as a simulation tool only for educational purposes 
and testing by authorized individuals with permission to do so.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.


INTRO
=====

FakeNetbiosNS is a NetBIOS Name Service daemon, listening on port UDP 137.
It can be used as a standalone tool or as a honeyd responder.

It responds to NetBIOS Name requests like real Windows computers:
for example 'ping -a', 'nbtstat -A' and 'nbtstat -a', etc.

- Note: when you use FakeNetbiosNS in daemon mode on Windows, you have to
disable NBT on the network adapter you listen on. 
To do that:
  - Open Network and Dial-up Connections
  - Open your network adpater properties
  - Select "Internet Protocol (TCP/IP)"
  - Click on "Properties", then on "Advanced"
  - Goto the "WINS" tab
  - Select the "Disable NetBIOS over TCP/IP" radio button
  - Click "OK" 3 times
  - You do not need to reboot usually. You should now be able to bind to port UDP 137.


COMPILE
=======

The source code compiles on Win32 AND on Linux. 
Yes, it is on purpose. No, it isn't always easy.


USAGE
=====

Usage: FakeNetbiosNS [options]

IP options:
  -s [source IP]          Source IP address (on which we also listen)
                          -Note 1: your system must support raw IP
                          -Note 2: Windows XP SP2 & Windows 2003 with Windows
                           Firewall enabled silently drop packets with
                           spoofed source address...
  -d [destination IP]     Broadcast IP address

NetBIOS options:
  -D [Domain/Workgroup]   Target Domain/Workgroup (default: WORKGROUP)
  -N [names prefix]       Host names prefix (default: HOST)
  -f [file path]          Use a configuration file (default: none)
  -r [NB svc hex code]    Send Release packet and quit

Misc. options:
  -H                      Activate Honeyd mode
  -v                      Verbose mode (do not use with Honeyd mode)
  -h                      This text


EXAMPLES
========

FakeNetbiosNS -s 192.168.0.1 -d 192.168.0.255 -D NTDOM -N ALLYOURBASE -v
FakeNetbiosNS -d 192.168.0.255 -f FakeNetbiosNS.ini -H


TO DO
=====

- Add more BROWSE and NETLOGON commands
- Add more Server types


WHO
===

Patrick Chambet <patrick@chambet.com>

Greetings to:
- Barzoc <barzoc@rstack.org>
- Francis Hauguet <francis.hauguet@eads.com>
- The French Honeynet Project (FHP) <http://www.frenchhoneynet.org>
- Rstack team <http://www.rstack.org>
