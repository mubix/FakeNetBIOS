/*
* FakeNetbiosDGM 0.91
*
* Copyright 2004-2005 Patrick Chambet <patrick@chambet.com>
*
* Greetings to:
* - Barzoc <barzoc@rstack.org>
* - Francis Hauguet <francis.hauguet@eads.com>
* - The French Honeynet Project (FHP) <http://www.frenchhoneynet.org>
* - Rstack team <http://www.rstack.org>
*
---------------------------------------------------------------------
* Description:
* Simulation of NetBIOS hosts (Windows-like) on NetBIOS Datagram Service (DGM).
*
* NOTE: some sizes are hardcoded, careful if you hack the sources.
*
---------------------------------------------------------------------
* Compile:
* Win32/VC++ : cl -o FakeNetbiosDGM FakeNetbiosDGM.c
* Win32/cygwin: gcc -o FakeNetbiosDGM FakeNetbiosDGM.c -lws2_32.lib
* Linux : gcc -o FakeNetbiosDGM FakeNetbiosDGM.c -Wall
*
---------------------------------------------------------------------
*
* This is provided as a simulation tool only for educational
* purposes and testing by authorized individuals with permission to
* do so.
*
*/

#ifdef WIN32
#pragma comment(lib,"ws2_32")
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h> /* for IP_HDRINCL (Raw IP) */
#include <process.h>
#include "getopt.h"

#else
#include <sys/types.h>
#include <ctype.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/timeb.h>
#include <getopt.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <assert.h>

#define MAX_MESSAGE 4068
#define MAX_PACKET 4096

/* Structures definition */
#ifdef WIN32
#pragma pack(1) // Windows specific
#endif

typedef struct	// NBT DS Header
{
	unsigned char type;
	unsigned char flags;
	unsigned short id;
	unsigned long sourceip;
	unsigned short sourceport;
	unsigned short length;
	unsigned short offset;
	unsigned char sourcename[34]; // mangled
	unsigned char destinationname[34]; // mangled
}
#ifdef WIN32
nbt_header;
#else
__attribute__ ((packed)) nbt_header;
#endif

typedef struct	// SMB Header
{
	unsigned char server_component[4];	// Magic header
	unsigned char command;
	unsigned char error_class;
	unsigned char reserved;
	unsigned short error_code;
	unsigned char flags;
	unsigned short flags2;
	unsigned short proc_id_high;
	unsigned char signature[8];
	unsigned short reserved2;
	unsigned short tree_id;
	unsigned short proc_id;
	unsigned short user_id;
	unsigned short multiplex_id;

	/* Transaction request */
	unsigned char word_count;
	unsigned short total_param_count;
	unsigned short total_data_count;
	unsigned short max_param_count;
	unsigned short max_data_count;
	unsigned char max_setup_count;
	unsigned char reserved3;
	unsigned short flags_summary;
	unsigned long timeout;
	unsigned short reserved4;
	unsigned short param_count;
	unsigned short param_offset;
	unsigned short data_count;
	unsigned short data_offset;
	unsigned short setup_count;
	unsigned short mailslot_opcode;
	unsigned short trans_priority;
	unsigned short mailslot_class;
	unsigned short size;
	unsigned char file_name[17];
}
#ifdef WIN32
smb_header;
#else
__attribute__ ((packed)) smb_header;
#endif

typedef struct	// Browser announcement
{
	unsigned char command;
	unsigned char update_count;
	unsigned long announcement_interval;
	unsigned char name[16];					// Host name announced (not mangled)
	unsigned char major_version;
	unsigned char minor_version;
	unsigned long server_type;
	unsigned char browser_protocol_major_version;
	unsigned char browser_protocol_minor_version;
	unsigned short browser_constant;
}
#ifdef WIN32
browser_announcement;
#else
__attribute__ ((packed)) browser_announcement;
#endif

/* Define the IP header */
typedef struct ip_hdr
{
	unsigned char ip_verlen;		/* IP version & length */
	unsigned char ip_tos;			/* IP type of service */
	unsigned short ip_totallength;	/* Total length */
	unsigned short ip_id;			/* Unique identifier */
	unsigned short ip_offset;		/* Fragment offset field */
	unsigned char ip_ttl;			/* Time to live */
	unsigned char ip_protocol;		/* Protocol */
	unsigned short ip_checksum;		/* IP checksum */
	unsigned int ip_srcaddr;		/* Source address */
	unsigned int ip_destaddr;		/* Destination address */
#ifdef WIN32
} IP_HDR, * PIP_HDR, FAR* LPIP_HDR;
#else
} IP_HDR, * PIP_HDR, * LPIP_HDR;
#endif

/* Define the UDP header */
typedef struct udp_hdr
{
	unsigned short src_portno;		/* Source port number */
	unsigned short dst_portno;		/* Destination port number */
	unsigned short udp_length;		/* UDP packet length */
	unsigned short udp_checksum;	/* UDP checksum (optional) */
} UDP_HDR, *PUDP_HDR;


#ifdef WIN32
#pragma pack() // Windows specific
#endif


const unsigned char *global_scope = NULL;

/* Global vars */
unsigned char *appname = "FakeNetbiosDGM";
unsigned char *sourceIP = "127.0.0.1";
unsigned char *targetIP = "255.255.255.255";
unsigned char *domainname;
unsigned char *hostnameradix;
unsigned char *hostname;
signed   long hostnum = 1;
unsigned char *description;	// Host description
unsigned char *comment;
unsigned long timer = 720;	// Windows default: 720 s -> 12 min


/* Host name resolve */
unsigned long resolve(char *name)
{
    struct hostent *he;
    unsigned int ip;

    if((ip=inet_addr(name))==(-1))
    {
        if((he=gethostbyname(name))==0)
            return 0;
        memcpy(&ip,he->h_addr,4);
    }
    return ip;
}

/* Return the total storage length of a mangled name */
int name_len (char *s1)
{
	/* NOTE: this argument _must_ be unsigned */
	unsigned char *s = (unsigned char *) s1;
	int len;

	/* If the two high bits of the byte are set, return 2. */
	if (0xC0 == (*s & 0xC0))
	return (2);

	/* Add up the length bytes. */
	for (len = 1; (*s); s += (*s) + 1)
	{
	  len += *s + 1;
	  assert (len < 80);
	}

	return (len);
}

/* Mangle a name into NetBIOS format (NBT level one encoding)
 Note:  <Out> must be (33 + strlen(scope) + 2) bytes long, at minimum.
 <name_type> is the NetBIOS service code. */
int name_mangle (char *In, char *Out, char name_type)
{
	int i;
	int c;
	int len;
	char buf[20];
	char *p = Out;

	/* Safely copy the input string, In, into buf[]. */
	(void) memset (buf, 0, 20);
	if (strcmp (In, "*") == 0)
	buf[0] = '*';
	else
	(void)sprintf(buf, "%-15.15s%c", In, name_type);

	/* Place the length of the first field into the output buffer. */
	p[0] = 32;
	p++;

	/* Now convert the name to the rfc1001/1002 format. */
	for (i = 0; i < 16; i++)
	{
	  c = toupper (buf[i]);
	  p[i * 2] = ((c >> 4) & 0x000F) + 'A';
	  p[(i * 2) + 1] = (c & 0x000F) + 'A';
	}
	p += 32;
	p[0] = '\0';

	/* Add the scope string. */
	for (i = 0, len = 0; global_scope != NULL; i++, len++)
	{
	  switch (global_scope[i])
		{
		case '\0':
		  p[0] = len;
		  if (len > 0)
			p[len + 1] = 0;
		  return (name_len (Out));
		case '.':
		  p[0] = len;
		  p += (len + 1);
		  len = -1;
		  break;
		default:
		  p[len + 1] = global_scope[i];
		  break;
		}
	}

	return (name_len (Out));
}

/* Build the NBT DS header */
void build_nbt_header (nbt_header *hdr, unsigned char *sourceip, char *sourcename, char *destinationname, int type)
{
	unsigned long ip;
	char source[34];
	char dest[34];

	/* Params computation */
	ip = resolve(sourceip);
	if (type == 2) {
		/* Domain/Workgroup announcement */
		name_mangle(sourcename,source,0x00);
		name_mangle("\x01\x02__MSBROWSE__\x02",dest,0x01);
	}
	else {
		/* Default: Host/Master announcement */
		name_mangle (sourcename,source,0x00);		// 0x00 (Workstation svc) or 0x20 (Server svc)
		name_mangle (destinationname,dest,0x1e);	// 0x1d: Local Master Browser, 0x1e: Browser Service Elections
	}

	memset(hdr, 0, sizeof(nbt_header));

	/* NBT Header */
	hdr->type = 17;
	hdr->flags = 2; // or 10 (node type)
	hdr->id = htons((unsigned short)rand());
	hdr->sourceip = ip;
	hdr->sourceport = htons(138);
	hdr->length = htons(211);		// to compute if modified (but not really used)
	hdr->offset = 0;
	strcpy (hdr->sourcename, source);
	strcpy (hdr->destinationname, dest);
}

/* Build the SMB header */
void build_smb_header (smb_header *hdr, int comment_size)
{
	memset (hdr, 0, sizeof (smb_header));

	/* SMB Header */
	strcpy (hdr->server_component, "\xffSMB");	// SMB magic header
	hdr->command = 0x25;
	hdr->error_class = 0;
	hdr->reserved = 0;
	hdr->error_code = 0;
	hdr->flags = 0;
	hdr->flags2 = 2;
	hdr->proc_id_high = 0;
	strcpy(hdr->signature, "\0");
	hdr->reserved2 = 0;
	hdr->tree_id = 0;
	hdr->proc_id = 0;
	hdr->user_id = 0;
	hdr->multiplex_id = 0;

	/* Transaction request */
	hdr->word_count = 17;
	hdr->total_param_count = 0;
	hdr->total_data_count = 33 + comment_size;
	hdr->max_param_count = 0;
	hdr->max_data_count = 0;
	hdr->max_setup_count = 0;
	hdr->reserved3 = 0;
	hdr->flags_summary = 0;
	hdr->timeout = 1000;		// 1000 ms
	hdr->reserved4 = 0;
	hdr->param_count = 0;
	hdr->param_offset = 0;
	hdr->data_count = 33 + comment_size;
	hdr->data_offset = 86;
	hdr->setup_count = 3;
	hdr->mailslot_opcode = 1;
	hdr->trans_priority = 0;	// or 1
	hdr->mailslot_class = 2;
	hdr->size = 50 + comment_size;
	memcpy(hdr->file_name, "\\MAILSLOT\\BROWSE\x00", 17);
}

/* Build the Browser protocol packet content */
void build_browser_announcement (browser_announcement *announcement, char *comment, char *sourcename, char *destinationname, char *description, int type)
{
	memset(announcement, 0, sizeof(browser_announcement));

	/* Browser announcement */
	switch (type)
		{
		case 4:
			/* Get Backup List Request */
			announcement->command = 0x09;
			announcement->update_count = 4;				// Backup List Requested Count
			announcement->announcement_interval = 113;	// Backup Request Token
			strcpy(comment, "");
			break;

		case 3:
			/* Local Master Announcement */
			announcement->command = 0x0f;
			announcement->update_count = 0;
			announcement->announcement_interval = 720000;	// 720 000 sec = 12 min
			strcpy(announcement->name, sourcename);
			announcement->major_version = 5;
			announcement->minor_version = 0;
			announcement->server_type = 0x000c9b0b;
			announcement->browser_protocol_major_version = 15;
			announcement->browser_protocol_minor_version = 1;
			announcement->browser_constant = 0xaa55;
			if (description != NULL)
				strcpy(comment, description);
			break;

		case 2:
			/* Domain/Workgroup announcement */
			announcement->command = 0x0c;
			announcement->update_count = 0;
			announcement->announcement_interval = 300000;	// 300 000 sec = 5 min
			strcpy(announcement->name, destinationname);
			announcement->major_version = 3;
			announcement->minor_version = 10;
			announcement->server_type = 0x80001000;
			announcement->browser_protocol_major_version = (unsigned char) rand ();
			announcement->browser_protocol_minor_version = (unsigned char) rand ();
			announcement->browser_constant = htons((unsigned short) rand ());
			strcpy(comment, sourcename);
			break;

		case 1:
		default:
			/* Default case: Host announcement */
			announcement->command = 0x01;
			announcement->update_count = 0;
			announcement->announcement_interval = 720000;	// 720 000 sec = 12 min
			strcpy(announcement->name, sourcename);
			announcement->major_version = 5;
			announcement->minor_version = 0;
			announcement->server_type = 0x00001003;
			announcement->browser_protocol_major_version = 15;
			announcement->browser_protocol_minor_version = 1;
			announcement->browser_constant = 0xaa55;
			if (description != NULL)
				strcpy(comment, description);
			break;
		}

		/*	Possible BROWSE commands:
			0x01: Host Announcement
			0x02: Request Announcement
			0x08: Browser Election Request
			0x09: Get Backup List Request
			0x0a: Get Backup List Response
			0x0b: Become Backup Browser
			0x0c: Domain/Workgroup Announcement
			0x0d: Master Announcement
			0x0e: Reset Browser State Announcement
			0x0f: Local master Announcement

			Some NETLOGON commands:
			0x07: Query for PDC
			0x12: SAM Logon Request from Client
			etc.
		*/

		/*	Some classical server types (bits):
			0x00001003: Workstation, Server
			0x000c9b0b: Workstation, Server, DC and Master Browser
			0x0006120b: Workstation, Server, DC, Print Queue Server, Master Browser and Backup Browser
			0x80001000: Domain/Workgroup, Domain Enum
			etc.
		*/
}

/* Calculates the 16-bit one's complement sum for the supplied buffer */
unsigned short checksum(unsigned short *buffer, int size)
{
	unsigned long cksum=0;

	while (size > 1) {
	cksum += *buffer++;
	size -= sizeof(unsigned short);
	}
	if (size) {
	cksum += *(unsigned char *)buffer;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >>16);

	return (unsigned short)(~cksum);
}

/* Display a hex dump */
void hexdump(unsigned char *p, unsigned int len)
{
	unsigned char *line = p;
	unsigned int thisline, offset = 0;
	unsigned int i;

	while (offset < len)
	{
		printf("%04x ", offset);
		thisline = len - offset;
		if (thisline > 16)
			thisline = 16;

		for (i = 0; i < thisline; i++)
			printf("%02x ", line[i]);

		for (; i < 16; i++)
				printf("   ");

		for (i = 0; i < thisline; i++)
			printf("%c",
			       (line[i] >= 0x20
				&& line[i] < 0x7f) ? line[i] : '.');

		printf("\n");
		offset += thisline;
		line += thisline;
	}
}

/* Raw IP UDP connection */
int send_raw_ip_udp(unsigned long sourceIP, unsigned short sourceport, unsigned long destIP, unsigned short destport, char *udpmsg, int udpmsgLen)
{
	int s;	// socket
#ifdef WIN32
	BOOL bOpt;
#else
	int bOpt;
#endif
	struct sockaddr_in remote;
	IP_HDR ipHdr;
	UDP_HDR udpHdr;
	int ret;
	unsigned short iTotalSize,
		iUdpSize,
		iUdpChecksumSize,
		iIPVersion,
		iIPSize,
		cksum = 0;
	char buf[MAX_PACKET],
	*ptr = NULL;

	/* Create a raw socket */
	s = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
#ifdef WIN32
	if (s == INVALID_SOCKET) {
		printf("A raw socket couldn't be created: error [%d]\nYour system must support raw sockets, or port already bound.\n", WSAGetLastError());
		return -1;
	}
#endif

	/* Enable the IP header include option */
#ifdef WIN32
	bOpt = TRUE;
#else
	bOpt = 1;
#endif
	ret = setsockopt(s, IPPROTO_IP, IP_HDRINCL, (char *)&bOpt, sizeof(bOpt));

#ifdef WIN32
	if (ret == SOCKET_ERROR) {
		printf("setsockopt(IP_HDRINCL) failed: error [%d]\n", WSAGetLastError());
		return -1;
	}
#endif

	/* Enable the Broadcast option */
	ret = setsockopt(s, SOL_SOCKET, SO_BROADCAST, (char *)&bOpt, sizeof(bOpt));

#ifdef WIN32
	if (ret == SOCKET_ERROR) {
		printf("setsockopt(SO_BROADCAST) failed: error [%d]\n", WSAGetLastError());
		return -1;
	}
#endif

	/* Initalize the IP header */
	iTotalSize = sizeof(ipHdr) + sizeof(udpHdr) + udpmsgLen + 4;

	iIPVersion = 4;
	iIPSize = sizeof(ipHdr) / sizeof(unsigned long);

	iIPSize += 1;

	ipHdr.ip_verlen = (iIPVersion << 4) | iIPSize;
	ipHdr.ip_tos = 0;							/* IP type of service */
	ipHdr.ip_totallength = htons(iTotalSize);	/* Total packet len */
	ipHdr.ip_id = 0;							/* IP id: set to 0 (will be replaced by the network provider)
												   or htons(0xDEAD) (reverse bytes) or rand() */
	ipHdr.ip_offset = 0;						/* Fragment offset field */
	ipHdr.ip_ttl = 128;							/* Time to live */
	ipHdr.ip_protocol = 0x11;					/* Protocol(UDP) */
	ipHdr.ip_checksum = 0 ;						/* IP checksum */
	ipHdr.ip_srcaddr = sourceIP;				/* Source address */
	ipHdr.ip_destaddr = destIP;					/* Destination address */

	/* Initalize the UDP header */
	iUdpSize = sizeof(udpHdr) + udpmsgLen;

	udpHdr.src_portno = htons(sourceport);
	udpHdr.dst_portno = htons(destport);
	udpHdr.udp_length = htons(iUdpSize);
	udpHdr.udp_checksum = 0 ;

	iUdpChecksumSize = 0;
	ptr = buf;
	memset(buf, 0, MAX_PACKET);

	memcpy(ptr, &ipHdr.ip_srcaddr, sizeof(ipHdr.ip_srcaddr));
	ptr += sizeof(ipHdr.ip_srcaddr);
	iUdpChecksumSize += sizeof(ipHdr.ip_srcaddr);

	memcpy(ptr, &ipHdr.ip_destaddr, sizeof(ipHdr.ip_destaddr));
	ptr += sizeof(ipHdr.ip_destaddr);
	iUdpChecksumSize += sizeof(ipHdr.ip_destaddr);

	ptr++;
	iUdpChecksumSize += 1;

	memcpy(ptr, &ipHdr.ip_protocol, sizeof(ipHdr.ip_protocol));
	ptr += sizeof(ipHdr.ip_protocol);
	iUdpChecksumSize += sizeof(ipHdr.ip_protocol);

	memcpy(ptr, &udpHdr.udp_length, sizeof(udpHdr.udp_length));
	ptr += sizeof(udpHdr.udp_length);
	iUdpChecksumSize += sizeof(udpHdr.udp_length);

	memcpy(ptr, &udpHdr, sizeof(udpHdr));
	ptr += sizeof(udpHdr);
	iUdpChecksumSize += sizeof(udpHdr);

	// UDP payload
	memcpy(ptr, udpmsg, udpmsgLen);
	iUdpChecksumSize += udpmsgLen;

	cksum = checksum((unsigned short *)buf, iUdpChecksumSize);
	udpHdr.udp_checksum = cksum;

	/* Final buffer */
	memset(buf, 0, MAX_PACKET);
	ptr = buf;

	memcpy(ptr, &ipHdr, sizeof(ipHdr));
	ptr += sizeof(ipHdr);

	/* IP option (length = 0x00 or correctly computed: 4 [second byte]) */
	memcpy(ptr, "\x88\x04\x12\x34", 4);
	ptr += 4;

	memcpy(ptr, &udpHdr, sizeof(udpHdr));
	ptr += sizeof(udpHdr);

	memcpy(ptr, udpmsg, udpmsgLen);

	remote.sin_family = AF_INET;
	remote.sin_port = htons(destport);
	remote.sin_addr.s_addr = destIP;

	/* Send data */
#ifdef WIN32
	ret = sendto(s, buf, iTotalSize, 0, (SOCKADDR *)&remote, sizeof(remote));
	if (ret == SOCKET_ERROR) {
		printf("sendto() failed: %d\n", WSAGetLastError());
		return -2;
	} else
#else
	ret = sendto(s, buf, iTotalSize, 0, (struct sockaddr *)&remote, sizeof(remote));
#endif

	/* Close socket */
#ifdef WIN32
	closesocket(s);
#else
	close(s);
#endif

	return 0;
}


/* "Classic" UDP connection: in case raw IP is not supported on the system */
int send_udp(unsigned long sourceIP, unsigned short sourceport, unsigned long destIP, unsigned short destport, char *udpmsg, int udpmsgLen)
{
	unsigned int s;	// socket
    struct sockaddr_in local, remote;
    int i;
	int bf;
    fd_set wd;
    struct timeval tv;
#ifdef WIN32
	BOOL bOpt;
#else
	int bOpt;
#endif
	int ret;

	/* Create a socket */
    s = socket(AF_INET, SOCK_DGRAM, 0);
#ifdef WIN32
	if (s == INVALID_SOCKET) {
		printf("A socket couldn't be created: error [%d]\n", WSAGetLastError());
		return -1;
	}
#else
    if (s < 0) {
		printf("A socket couldn't be created: error [%d]\n", s);
        return -1;
    }
#endif

	/* Enable the Broadcast option */
#ifdef WIN32
	bOpt = TRUE;
#else
	bOpt = 1;
#endif
	ret = setsockopt(s, SOL_SOCKET, SO_BROADCAST, (char *)&bOpt, sizeof(bOpt));

#ifdef WIN32
	if (ret == SOCKET_ERROR) {
		printf("setsockopt(SO_BROADCAST) failed: error [%d]\n", WSAGetLastError());
		return -1;
	}
#endif

    memset((char *)&local, 0, sizeof(local));

	/* Bind source port */
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(sourceIP); // or htonl(INADDR_ANY)
    local.sin_port = htons(sourceport);

    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = destIP;
    if(remote.sin_addr.s_addr == 0) {
#ifdef WIN32
		closesocket(s);
#else
		close(s);
#endif
        return -2;
    }
    remote.sin_port = htons(destport);

    bf = 1;
#ifdef WIN32
    ioctlsocket(s, FIONBIO, (u_long *)&bf);
#endif

    tv.tv_sec = 10;
    tv.tv_usec = 0;
    FD_ZERO(&wd);
    FD_SET(s, &wd);

    connect(s, (struct sockaddr *)&remote, sizeof(remote));
	if ((i = select(s+1, 0, &wd, 0, &tv)) == (-1)) {
#ifdef WIN32
		closesocket(s);
#else
		close(s);
#endif
		return -3;
    }

	if (i == 0) {
#ifdef WIN32
		closesocket(s);
#else
		close(s);
#endif
		return -4;
    }

    i = sizeof(int);
    getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&bf, &i);
    if ((bf != 0) || (i != sizeof(int))) {
#ifdef WIN32
		closesocket(s);
#else
		close(s);
#endif
		errno = bf;
		return -5;
    }
#ifdef WIN32
    ioctlsocket(s, FIONBIO, (u_long *)&bf);
#endif

	/* Send data */
#ifdef WIN32
	ret = sendto(s, udpmsg, udpmsgLen, 0, (SOCKADDR *)&remote, sizeof(remote));
	if (ret == SOCKET_ERROR) {
		printf("sendto() failed: %d\n", WSAGetLastError());
		return -6;
	} else
#else
	ret = sendto(s, udpmsg, udpmsgLen, 0, (struct sockaddr *)&remote, sizeof(remote));
#endif

	/* Close socket */
#ifdef WIN32
	closesocket(s);
#else
	close(s);
#endif

	return 0;
}


void usage(char *name)
{
	printf("Simulation of NetBIOS hosts (Windows-like) on NetBIOS Datagram Service (DGM)\n");
	printf("\n");

	printf("Usage: %s -d <destination_IP> [options]\n\n", name);
	printf("IP options:\n");
	printf("  -s [source IP]          Source IP address\n");
	printf("                          -Note 1: your system must support raw IP\n");
	printf("                          -Note 2: Windows XP SP2 & Windows 2003 with Windows\n");
	printf("                           Firewall enabled silently drop packets with\n");
	printf("                           spoofed source address...\n");
	printf("  -u                      Do not use raw IP (Honeyd compatible) (default: off)\n");
	printf("  -d [destination IP]     Broadcast IP address\n");
	printf("\n");

	/*
	printf("Ethernet options:\n");
	printf("  -S [adapter MAC]        Ethernet address of source \n");
	printf("  -E [destination MAC]    Destination Ethernet address \n");
	printf("\n");
	*/

	printf("NetBIOS options:\n");
	printf("  -D [Domain/Workgroup]   Target Domain/Workgroup (default: WORKGROUP)\n");
	printf("  -N [names prefix]       Host names prefix (default: HOST)\n");
	printf("  -a [announcement]       Announcement type (default: 1)\n");
	printf("                          1: Host, 2: Domain/Workgroup, 3: Local Master\n");
	printf("  -n [host number]        Host number (default: 1)\n");
	printf("  -c [comment]            Host description (default: \"Windows XP Workstation\")\n");
	printf("  -f [file path]          Use a configuration file (default: none)\n");
	printf("\n");

	printf("Misc. options:\n");
	printf("  -t [time]               Time between successive packets in ms (default: 500)\n");
	printf("  -T [time to wait]       Time before repeating same action in sec.\n");
	printf("                          (Windows default: %lu [12 min])\n", timer);
	printf("  -H                      Activate Honeyd mode\n");
	printf("  -v                      Verbose mode\n");
	printf("  -h                      This text\n");
	printf("\n");

	printf("Example:\n");
	printf("%s -s 192.168.0.1 -d 192.168.0.255 -D NTDOM -N ALLYOURBASE -n 100 -T 120 -c \"Windows XP Workstation\" -v\n", name);
	printf ("\n");

	exit(1);
}


/* Main */
int main(int argc,char *argv[])
{
#ifdef WIN32
	WSADATA wsd;	// Winsock Data
#endif
	int c;	// command line switches
	int showusage = 0;
	int verbose_on = 0;
	int honeyd_mode = 0;
	int conffile_mode = 0;
	FILE *fp;				// config file
	char *confpath;
	char *tmpbuf = malloc(320);
	unsigned long int line_count = 0;
	char domains[1000][14];	// config params
	char hosts[1000][14];
	char ipaddr[1000][15];
	char desc[1000][256];
	int ann_type[1000];

	int raw_ip_on = 1;
    long int hostcount;
	int numlong = 1;
	char namemask[5];
	int timerset = 0;
	int rnddelay = 0;		// Pseudo-random delay between 2 announcements (ms)
	int meandelay = 500;	// Mean delay
	int announce_type = 1;
	nbt_header nbt_hdr;		// NetBIOS structures
	smb_header smb_hdr;
	browser_announcement announcement;
	char sendbuf[512];
	int bufLen;
	long int init_rnd;
	unsigned long int i;

	/* Program header */
    printf("\n-----------\n");
    printf("%s V.0.9\n", appname);
    printf("Patrick Chambet - patrick@chambet.com\n");
	printf("Simulation of NetBIOS hosts (Windows-like) on NetBIOS Datagram Service (DGM)\n");
	printf("Honeyd subsystem or standalone app mode\n");
	printf("This is provided as a simulation tool only for educational and\n");
	printf("testing purposes by authorized individuals with permission to do so.\n");
    printf("-----------\n\n");

	/* Init params */
	domainname = (unsigned char*)malloc(sizeof(unsigned char*)*15);
	strcpy(domainname, "WORKGROUP");
	hostnameradix = (unsigned char*)malloc(sizeof(unsigned char*)*15);
	strcpy(hostnameradix, "HOST");
	hostname = (unsigned char*)malloc(sizeof(unsigned char*)*15);
	description = (unsigned char*)malloc(sizeof(unsigned char*)*256);
	strcpy(description, "Windows XP Workstation");
	comment = (unsigned char*)malloc(sizeof(unsigned char*)*256);

	/* Get params */
	while ((c = getopt (argc, argv, "s:d:uD:N:f:a:n:c:t:T:vHh?")) != -1)
    {
      switch (c)
        {
        case 's':
          sourceIP = optarg;
          break;
        case 'd':
          targetIP = optarg;
          break;
        case 'u':
          raw_ip_on = 0;
          break;
        case 'D':
          strcpy(domainname, optarg); // Cut at 15 char ? Try yourself...
          break;
        case 'N':
          strcpy(hostnameradix, optarg); // Cut at 15 char ? Try yourself...
          break;
        case 'f':
		  confpath = (unsigned char*)malloc(sizeof(unsigned char)*strlen(optarg));
		  strcpy(confpath, optarg);
          conffile_mode = 1;
          break;
        case 'a':
          announce_type = atol(optarg);
          break;
        case 'n':
          hostnum = atol (optarg);
		  numlong = strlen(optarg);
          break;
        case 'c':
          strcpy(description, optarg);
          break;
        case 't':
          meandelay = atol(optarg);
          break;
        case 'T':
          timerset = 1;
          timer = atol(optarg);
          break;
        case 'v':
          verbose_on = 1;
          break;
        case 'H':
          honeyd_mode = 1;
          break;
        case 'h':
        case '?':
        default:
          showusage = 1;
          break;
        }
    }

	if (showusage || targetIP == (unsigned char*)"255.255.255.255")	// || argc<2
		usage(appname);

	/* Seed the random-number generator with current time */
	srand((unsigned)(time(NULL)*getpid()));

	/* Get conf file */
	if (conffile_mode) {
		fp = fopen(confpath, "rt");
		if (fp == NULL) {
			fprintf(stderr, "Config file '%s' not found.\n", confpath);
			return 1;
		}
		/* Read the file line by line */
		while(fgets(tmpbuf, 64, fp) != NULL) {
			sscanf(tmpbuf, "%s%s%s%d%255c", &domains[line_count], &hosts[line_count], &ipaddr[line_count], &ann_type[line_count], &desc[line_count]);
			for (i=0; i<strlen(desc[line_count]); i++)
				desc[line_count][i] = desc[line_count][i+1];
			desc[line_count][strlen(desc[line_count])-1] = '\0';
			line_count++;
		}
		fclose(fp);
		printf("Host number in config file: %lu\n", line_count);

		if (verbose_on) {
			for (i=0; i<line_count; i++)
				printf("Dom: '%s'\tHost: '%s'\tIP: '%s'\tAnn:'%d'\tDesc: '%s'\n", domains[i], hosts[i], ipaddr[i], ann_type[i], desc[i]);
		}
	}

#ifdef WIN32
	/* Winsock initialization */
	if (WSAStartup(MAKEWORD(2,2), &wsd) != 0) {
		printf("Winsock did not initialize properly: Winsock error [%d]\n", GetLastError());
		return -1;
	}
#endif

	/* Host name mask */
	sprintf(namemask, "%%s%%0%dd", numlong);

	/* If in honeyd, wait for a random delay between 0 and 'meandelay' in ms
	   to avoid simultaneous announcements when starting */
    if (honeyd_mode) {
#ifdef WIN32
		init_rnd = rand()*meandelay/RAND_MAX;
#else
		int rnd_seed = init_rnd;
		init_rnd = 1+(int)((meandelay/1000)*rand_r(&rnd_seed)/(RAND_MAX+1.0));
#endif
		printf("Honeyd mode: randomly sleeping to avoid simultaneous announcements: %lu\n", init_rnd);
#ifdef WIN32
			Sleep(init_rnd);	// milliseconds
#else
			sleep(init_rnd);	// seconds
#endif

		/* Compute the correct hostname tu use from the IP address */
		if ((!conffile_mode) && (sizeof(hostnameradix) < 11*sizeof(char))) {
		/* Get last number of IP address */
		char* tmp = strrchr(sourceIP, '.');
		tmp+=sizeof(char);
		init_rnd=atoi(tmp);
		strcat(hostnameradix, tmp);
		printf("Honeyd mode: hostname=radix+suffix(IP) = %s\n",hostnameradix);
		}
	}

	/* Main broadcast loop */
	while (1)
	{
		if (conffile_mode)
			hostnum = line_count;

		/* Host number loop */
		for (hostcount=1; hostcount<hostnum+1; hostcount++)
		{
			/* Params computation */
			if (conffile_mode) {
				// Get {domain, host name, IP, desc and announce type}
				domainname = domains[hostcount-1];
				hostname = hosts[hostcount-1];
				sourceIP = ipaddr[hostcount-1];
				announce_type = ann_type[hostcount-1];
				description = desc[hostcount-1];
			}
			else if ((hostnum > 1) && (!honeyd_mode))
				sprintf(hostname, namemask, hostnameradix, hostcount);
			else
				strcpy(hostname, hostnameradix);

			/* Build headers and Browser packet */
			build_nbt_header(&nbt_hdr, sourceIP, hostname, domainname, announce_type);
			build_browser_announcement(&announcement, comment, hostname, domainname, description, announce_type);
			build_smb_header(&smb_hdr, strlen(comment));

			/* Build final buffer */
			memcpy(sendbuf,&nbt_hdr,sizeof(nbt_hdr));
			bufLen = sizeof(nbt_hdr);
			memcpy(sendbuf+bufLen,&smb_hdr,sizeof(smb_hdr));
			bufLen += sizeof(smb_hdr);
			memcpy(sendbuf+bufLen,&announcement,sizeof(announcement));
			bufLen += sizeof(announcement);
			memcpy(sendbuf+bufLen, comment, strlen(comment));
			bufLen += strlen(comment);
			memcpy(sendbuf+bufLen, "\0", 1);
			bufLen += 1;

			/* Send packet */
			printf("Announcing '%s\\%s' (type %d) ", domainname, hostname, announce_type);
			if (raw_ip_on)
				send_raw_ip_udp(resolve(sourceIP), 138, resolve(targetIP), 138, sendbuf, bufLen);
			else
				send_udp(resolve(sourceIP), 138, resolve(targetIP), 138, sendbuf, bufLen);

			/* Verbose */
			if (verbose_on)
			{
				printf("\nBytes sent [%d]:\n", bufLen);
				hexdump(sendbuf, bufLen);
			}

			/* Host announcement interval */
			if (hostnum > 1) {
				rnddelay = rand() * meandelay / RAND_MAX;
				printf("- Waiting for %3d ms...\n", rnddelay);
#ifdef WIN32
				Sleep(rnddelay);
#else
				sleep(rnddelay/1000);
#endif
			}
		} /* for */

	/* Broadcast interval */
	if (timerset)
	{
		printf("\nWaiting for %lu s before repeating same action...\n", timer);
		printf("[CTRL+C to exit]\n\n");
#ifdef WIN32
		Sleep(timer*1000);	// Windows default: 720 s -> 12 min
#else
		sleep(timer);		// Windows default: 720 s -> 12 min
#endif
	}
	else
		break;
	} /* Main broadcast loop */

#ifdef WIN32
	/* Cleanup Winsock before leaving */
	WSACleanup();
#endif

	return 0;
}
