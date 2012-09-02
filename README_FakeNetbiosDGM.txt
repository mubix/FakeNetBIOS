
   -------------------------------------------------------------------------------
  |                                                                               |
  |                           FakeNetbiosDGM V. 0.91                              |
  |                                                                               |
  |  Simulation of NetBIOS hosts (Windows-like) on NetBIOS Datagram Service (DGM) |
  |                                                                               |
   -------------------------------------------------------------------------------


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

FakeNetbiosDGM sends NetBIOS Datagram service packets on port UDP 138 to simulate
Windows hosts bradcasts. It sends periodically NetBIOS announces over the network
to simulate Windows computers.
It fools the Computer Browser services running over the LAN and so on.

It can be used as a standalone tool or as a honeyd subsystem.
Note that it is an ACTIVE honeypot.


COMPILE
=======

- Note: the source code compiles on Win32 AND on Linux. 
Yes, it is on purpose. No, it isn't always easy.


USAGE
=====

Usage: FakeNetbiosDGM -d <destination_IP> [options]

IP options:
  -s [source IP]          Source IP address
                          -Note 1: your system must support raw IP
                          -Note 2: Windows XP SP2 & Windows 2003 with Windows
                           Firewall enabled silently drop packets with
                           spoofed source address...
  -u                      Do not use raw IP (Honeyd compatible) (default: off)
  -d [destination IP]     Broadcast IP address

NetBIOS options:
  -D [Domain/Workgroup]   Target Domain/Workgroup (default: WORKGROUP)
  -N [names prefix]       Host names prefix (default: HOST)
  -a [announcement]       Announcement type (default: 1)
                          1: Host, 2: Domain/Workgroup, 3: Local Master
  -n [host number]        Host number (default: 1)
  -c [comment]            Host description (default: "Windows XP Workstation")
  -f [file path]          Use a configuration file (default: none)

Misc. options:
  -t [time]               Time between successive packets in ms (default: 500)
  -T [time to wait]       Time before repeating same action in sec.
                          (Windows default: 720 [12 min])
  -H                      Activate Honeyd mode
  -v                      Verbose mode
  -h                      This text


EXAMPLES
========

FakeNetbiosDGM -s 192.168.0.1 -d 192.168.0.255 -D NTDOM -N ALLYOURBASE -n 100 
  -t 1000 -T 120 -c "Windows XP Workstation" -v
FakeNetbiosDGM -d 192.168.0.255 -D MYDOMAIN -N MYCOMPUTER -c "" -v
FakeNetbiosDGM -d 192.168.0.255 -f FakeNetbiosDGM.ini -H


SOME SAMPLE USAGES
==================

- Honeypot/net tool
  - Can simulate a huge LAN with one computer only
  - Can use a configuration file

- Messing tool...
  - Announce thousands of computers (up to 100 000 computers can appear 
    in Windows "Network Places" GUI !)
  - Announce yourself as the DC, the file server, etc. 
    -> man in the middle attacks
  - Release real NetBIOS services (DC, Computer Browser, IIS, etc.)
  - Etc. (you can have some imagination here: think about NetBIOS as
    an ARP-like protocol over UDP)


TO DO
=====

- Add more Release types


WHO
===

Patrick Chambet <patrick@chambet.com>

Greetings to:
- Barzoc <barzoc@rstack.org>
- Francis Hauguet <francis.hauguet@eads.com>
- The French Honeynet Project (FHP) <http://www.frenchhoneynet.org>
- Rstack team <http://www.rstack.org>
