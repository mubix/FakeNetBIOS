/*
* FakeNetbiosNS 0.91
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
* Simulation of NetBIOS hosts (Windows-like) on NetBIOS Name Service (NS).
*
* NOTE: some sizes are hardcoded, careful if you hack the sources.
*
---------------------------------------------------------------------
* Compile:
* Win32/VC++ : cl -o FakeNetbiosNS FakeNetbiosNS.c
* Win32/cygwin: gcc -o FakeNetbiosNS FakeNetbiosNS.c -lws2_32.lib
* Linux : gcc -o FakeNetbiosNS FakeNetbiosNS.c -Wall
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
#include <io.h>
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
#include <unistd.h>
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

typedef struct	// Name query packet
{
	unsigned short trans_id;
	unsigned short flags;
	unsigned short questions;
	unsigned short answers;
	unsigned short authority_RRs;
	unsigned short additional_RRs;
	unsigned char name[34];			// mangled
	unsigned short query_type;
	unsigned short query_class;
}
#ifdef WIN32
ns_name_query;
#else
__attribute__ ((packed)) ns_name_query;
#endif

typedef struct	// NBT NS NB response packet
{
	unsigned short trans_id;
	unsigned short flags;
	unsigned short questions;
	unsigned short answers;
	unsigned short authority_RRs;
	unsigned short additional_RRs;
	unsigned char name[34];			// mangled
	unsigned short ans_type;
	unsigned short ans_class;
	unsigned long ttl;
	unsigned short length;
	unsigned short ans_flags;
	unsigned long IPaddr;
}
#ifdef WIN32
ns_nb_response;
#else
__attribute__ ((packed)) ns_nb_response;
#endif

typedef struct	// NBT NS NBTSTAT response packet header
{
	unsigned short trans_id;
	unsigned short flags;
	unsigned short questions;
	unsigned short answers;
	unsigned short authority_RRs;
	unsigned short additional_RRs;
	unsigned char name[34];			// mangled
	unsigned short ans_type;
	unsigned short ans_class;
	unsigned long ttl;
	unsigned short length;

	unsigned char name_num;
}
#ifdef WIN32
ns_nbtstat_response_hdr;
#else
__attribute__ ((packed)) ns_nbtstat_response_hdr;
#endif

typedef struct	// NBTSTAT name
{
	unsigned char name[16];		// not mangled
	unsigned short flags;
}
#ifdef WIN32
ns_nbtstat_name;
#else
__attribute__ ((packed)) ns_nbtstat_name;
#endif

typedef struct	// NBT NS NBTSTAT response packet end
{
	unsigned char unit_id[6];
	unsigned char jumpers;
	unsigned char test_result;
	unsigned short version;
	unsigned short stats;
	unsigned short crc_num;
	unsigned short errors;
	unsigned short collisions;
	unsigned short send_aborts;
	unsigned short good_sends;
	unsigned short good_rcvs;
	unsigned short retrans;
	unsigned short no_rsc_conditions;
	unsigned short cmd_blocks;
	unsigned short pending_sessions;
	unsigned short max_pending_sessions;
	unsigned short max_sessions;
	unsigned short packet_size;
	unsigned char end[22];		// some tail 0's
}
#ifdef WIN32
ns_nbtstat_response_end;
#else
__attribute__ ((packed)) ns_nbtstat_response_end;
#endif

typedef struct	// NBT NS Release packet
{
	unsigned short trans_id;
	unsigned short flags;
	unsigned short questions;
	unsigned short answers;
	unsigned short authority_RRs;
	unsigned short additional_RRs;
	unsigned char query_name[34];			// mangled
	unsigned short query_type;
	unsigned short query_class;
	unsigned short additional_name;
	unsigned short additional_type;
	unsigned short additional_class;
	unsigned long ttl;
	unsigned short length;
	unsigned short query_flags;
	unsigned long IPaddr;
}
#ifdef WIN32
ns_nb_release;
#else
__attribute__ ((packed)) ns_nb_release;
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
} UDP_HDR, * PUDP_HDR;

#ifdef WIN32
#pragma pack() // Windows specific
#endif


const unsigned char *global_scope = NULL;

/****** Global vars ******/
unsigned char *appname = "FakeNetbiosNS";
unsigned char *listen_sourceIP = "127.0.0.1";
unsigned char *send_sourceIP = "127.0.0.1";
unsigned char *targetIP = "255.255.255.255";
unsigned char *domainname;
signed   long hostnum = 1;
unsigned char *hostname;
unsigned char *interactive_usr;
int MAX_MSG = 512;
int verbose_on = 0;

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

/* Mangle a name into NetBIOS format (NBT Level One encoding)
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

/* Build the NBT DS NB response */
void build_ns_nb_response(ns_nb_response *resp, unsigned short trans_id, unsigned char *IPaddr, char *name)
{
	char mangled_name[34];

	/* Params computation */
	name_mangle(name, mangled_name, 0x00); // TO DO: case 0x20

	memset(resp, 0, sizeof(ns_nb_response));

	/* NBT DS NB response */
	resp->trans_id = htons(trans_id);
	resp->flags = htons(0x8500);
	resp->questions = 0;
	resp->answers = htons(1);
	resp->authority_RRs = 0;
	resp->additional_RRs = 0;
	strcpy(resp->name, mangled_name);
	resp->ans_type = htons(0x20);	// type: NB
	resp->ans_class = htons(1);		// class: inet
	resp->ttl = htonl((unsigned long)(871663*rand()*30000/RAND_MAX));	// real-life TTL (x days, y hours, ...)
	resp->length = htons(6);
	resp->ans_flags = 0;
	resp->IPaddr = inet_addr(IPaddr);
}

/* Build a NBTSTAT response packet header */
void build_ns_nbtstat_response_hdr(ns_nbtstat_response_hdr *nbtstat_response_hdr, unsigned short trans_id, char *name, int name_num, int size, int type)
{
	char mangled_name[34];

	/* Params computation */
	switch (type)
	{
	case 2:	// by IP address
		name_mangle("*\0\0\0\0\0\0\0\0\0\0\0\0\0\0", mangled_name, 0x00);
		break;

	case 1:	// by NetBIOS name (default)
	default:
		name_mangle(name, mangled_name, 0x00);
		break;
	}

	memset(nbtstat_response_hdr, 0, sizeof(ns_nbtstat_response_hdr));

	/* NBTSTAT header */
	nbtstat_response_hdr->trans_id = htons(trans_id);
	nbtstat_response_hdr->flags = htons(0x8400);
	nbtstat_response_hdr->questions = 0;
	nbtstat_response_hdr->answers = htons(1);
	nbtstat_response_hdr->authority_RRs = 0;
	nbtstat_response_hdr->additional_RRs = 0;
	strcpy(nbtstat_response_hdr->name, mangled_name);	// mangled
	nbtstat_response_hdr->ans_type= htons(0x21);	// NBTSTAT
	nbtstat_response_hdr->ans_class = htons(1);
	nbtstat_response_hdr->ttl = 0;
	nbtstat_response_hdr->length = htons((unsigned short)size);		// computed

	nbtstat_response_hdr->name_num = name_num;		// number of NetBIOS Services
}

/* Build a NBTSTAT name */
void build_ns_nbtstat_name(ns_nbtstat_name *nbtstat_name, char *name, unsigned char number, unsigned char type)
{
	char nb_name[16] = "                ";

	/* Params computation */
	memcpy(nb_name, name, strlen(name));
	nb_name[15] = number;

	memset(nbtstat_name, 0, sizeof(ns_nbtstat_name));

	/* NBTSTAT name */
	memcpy(nbtstat_name->name, nb_name, 16);
	nbtstat_name->flags = type;
}

/* Build a NBTSTAT response packet end */
void build_ns_nbtstat_response_end(ns_nbtstat_response_end *nbtstat_response_end)
{
	memset(nbtstat_response_end, 0, sizeof(ns_nbtstat_response_end));

	/* NBTSTAT end */
	memcpy(nbtstat_response_end->unit_id, "\x00\x01\x03\x31\x37\xAA", 8);
	nbtstat_response_end->jumpers = 0;
	nbtstat_response_end->test_result = 0;
	nbtstat_response_end->version = 0;
	nbtstat_response_end->stats = 0;
	nbtstat_response_end->crc_num = 0;
	nbtstat_response_end->errors = 0;
	nbtstat_response_end->collisions = 0;
	nbtstat_response_end->send_aborts = 0;
	nbtstat_response_end->good_sends = 0;
	nbtstat_response_end->good_rcvs = 0;
	nbtstat_response_end->retrans = 0;
	nbtstat_response_end->no_rsc_conditions = 0;
	nbtstat_response_end->cmd_blocks = 0;
	nbtstat_response_end->pending_sessions = 0;
	nbtstat_response_end->max_pending_sessions = 0;
	nbtstat_response_end->max_sessions = 0;
	nbtstat_response_end->packet_size = 0;
	memset(nbtstat_response_end->end, 0, 22);
}

/* Build the NS NB Release packet */
void build_ns_nb_release(ns_nb_release *release, unsigned char *IPaddr, char *name, char nbsvc)
{
	char mangled_name[34];

	/* Params computation */
	name_mangle(name, mangled_name, nbsvc);

	memset(release, 0, sizeof(ns_nb_release));

	/* NS NB release */
	release->trans_id = htons((unsigned short)rand());
	release->flags = htons(0x3010);
	release->questions = htons(1);
	release->answers = 0;
	release->authority_RRs = 0;
	release->additional_RRs = htons(1);
	strcpy(release->query_name, mangled_name);
	release->query_type = htons(0x20);		// type: NB
	release->query_class = htons(1);		// class: inet
	release->additional_name = htons(0xc00c);
	release->additional_type = htons(0x20);
	release->additional_class = htons(1);
	release->ttl = 0;
	release->length = htons(6);
	release->query_flags = 0;
	release->IPaddr = inet_addr(IPaddr);

	/* Complete release =
		Name, 0x00
		Name, 0x03
		Name, 0x20
		Domain, 0x00
		Domain, 0x1e
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

int udp_listen(char *msg, int *bytesreceived, unsigned long sourceIP, unsigned short lport) {

	int s, rc;
	struct sockaddr_in cliAddr, servAddr;
	int cliLen;

	/* Socket creation */
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if(s < 0) {
		printf("Cannot open socket \n");
		exit(1);
	}

	/* Bind local server port */
	servAddr.sin_family = AF_INET;
#ifdef WIN32
	// Listen only on sourceIP or on any local IP (INADDR_ANY)
	if (listen_sourceIP == (unsigned char*)"127.0.0.1")
		servAddr.sin_addr.s_addr = INADDR_ANY;
	else
		servAddr.sin_addr.s_addr = sourceIP;
#else
	// INADDR_ANY only, otherwise Linux doesn't get broadasts
	// (on Windows, broadcasts are received even if we listen on sourceIP only)
	servAddr.sin_addr.s_addr = INADDR_ANY;
#endif
	servAddr.sin_port = htons(lport);
	rc = bind(s, (struct sockaddr *)&servAddr, sizeof(servAddr));
	if(rc < 0) {
		printf("Cannot bind port number %d. Check that the source IP you listen on is correct ", lport);
		printf("and that NetBIOS over TCP/IP is disabled on your network interface.\n");
		exit(1);
	}

	if (verbose_on)
		printf("Waiting for data on port UDP %u...\n\n", lport);

	/* Init buffer */
	memset(msg, 0, MAX_MSG);

	/* Receive message */
	cliLen = sizeof(cliAddr);
	*bytesreceived = recvfrom(s, msg, MAX_MSG, 0, (struct sockaddr *) &cliAddr, &cliLen);

	if(*bytesreceived < 0) {
		printf("Cannot receive data \n");
	}
	else {
		targetIP = inet_ntoa(cliAddr.sin_addr);
		if (verbose_on)
			printf("Connection from %s:UDP%u :\n", targetIP, ntohs(cliAddr.sin_port));
	}

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
	/* Program header */
    printf("\n-----------\n");
    printf("%s V.0.9\n", name);
    printf("Patrick Chambet - patrick@chambet.com\n");
    printf("-----------\n\n");
	printf("Simulation of NetBIOS hosts (Windows-like) on NetBIOS Name Service (NS)\n");
	printf("Honeyd responder or full UDP server mode\n");
	printf("\n");

	/* Usage */
	printf("Usage: %s [options]\n\n", name);
	printf("IP options:\n");
	printf("  -s [source IP]          Source IP address (on which we also listen)\n");
	printf("                          -Note 1: your system must support raw IP\n");
	printf("                          -Note 2: Windows XP SP2 & Windows 2003 with Windows\n");
	printf("                           Firewall enabled silently drop packets with\n");
	printf("                           spoofed source address...\n");
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
	printf("  -f [file path]          Use a configuration file (default: none)\n");
	printf("  -r [NB svc hex code]    Send Release packet for the NB service and quit\n");
	printf("\n");

	printf("Misc. options:\n");
	printf("  -H                      Activate Honeyd mode\n");
	printf("  -v                      Verbose mode (do not use with Honeyd mode)\n");
	printf("  -h                      This text\n");
	printf("\n");

	printf("Example:\n");
	printf("%s -s 192.168.0.1 -d 192.168.0.255 -D NTDOM -N ALLYOURBASE -v\n", name);
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
	int honeyd_mode = 0;
	int conffile_mode = 0;
	FILE *fp;				// config file
	char *confpath;
	char *tmpbuf = malloc(96);
	long int line_count = 0;
	char domains[1000][14];	// config params
	char hosts[1000][14];
	char ipaddr[1000][15];
	char users[1000][20];

	int release_mode = 0;
	int nbsvc = 0;
	ns_name_query ns_query;	// NetBIOS structures
	ns_nb_response ns_nb_resp;
	ns_nbtstat_response_hdr ns_nbtstat_resp_hdr;
	ns_nbtstat_name nbtstat_name;
	ns_nbtstat_response_end ns_nbtstat_resp_end;
	ns_nb_release ns_release;
	char getbuf[512];
	int getLen;
	char tmpname[34];
	char sendbuf[512];
	int bufLen;
	int resp_required;
	int resp_size;
	int resp_type;
	long int i;
	int numsvc;

	/* Init params */
	domainname = (unsigned char*)malloc(sizeof(unsigned char)*15);
	strcpy(domainname, "WORKGROUP");
	hostname = (unsigned char*)malloc(sizeof(unsigned char)*15);
	strcpy(hostname, "HOST");
	interactive_usr = (unsigned char*)malloc(sizeof(unsigned char)*21);
	strcpy(interactive_usr, "ADMINISTRATOR");

	/* Get params */
	while ((c = getopt (argc, argv, "s:d:D:N:f:r:vHh?")) != -1)
    {
      switch (c)
        {
        case 's':
          listen_sourceIP = optarg;
		  send_sourceIP = optarg;
          break;
        case 'd':
          targetIP = optarg;
          break;
        case 'D':
          strcpy(domainname, optarg); // Cut at 15 char ? Try yourself...
          break;
        case 'N':
          strcpy(hostname, optarg); // Cut at 15 char ? Try yourself...
          break;
        case 'f':
		  confpath = (unsigned char*)malloc(sizeof(unsigned char)*strlen(optarg));
		  strcpy(confpath, optarg);
          conffile_mode = 1;
          break;
        case 'r':
          release_mode = 1;
		  sscanf(optarg, "%x", &nbsvc);
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

	if (showusage)
		usage(appname);

	/* Seed the random-number generator with current time */
	srand((unsigned)(time(NULL)*getpid()));

	/* Program header */
    if (!honeyd_mode) {
		printf("\n-----------\n");
		printf("%s V.0.9\n", appname);
		printf("Patrick Chambet - patrick@chambet.com\n");
		printf("-----------\n\n");
	}

	/* Get conf file */
	if (conffile_mode) {
		fp = fopen(confpath, "rt");
		if (fp == NULL) {
			fprintf(stderr, "Config file '%s' not found.\n", confpath);
			return 1;
		}
		/* Read the file line by line */
		while(fgets(tmpbuf, 64, fp) != NULL) {
			sscanf(tmpbuf, "%s%s%s%s", &domains[line_count], &hosts[line_count], &ipaddr[line_count], &users[line_count]);
			line_count++;
		}
		fclose(fp);

		if (!honeyd_mode)
			printf("Host number in config file: %lu\n", line_count);

		if (verbose_on) {
			for (i=0; i<line_count; i++)
				printf("Dom: '%s'\tHost: '%s'\tIP: '%s'\tUser: '%s'\n", domains[i], hosts[i], ipaddr[i], users[i]);
		}
	}
	else if (honeyd_mode) {
		/* If in honeyd, compute the correct hostname to use */
		if (sizeof(hostname) < 11*sizeof(char)) {
			/* Get last number of IP address */
			char *tmp = strrchr(listen_sourceIP, '.');
			tmp+=sizeof(char);
			strcat(hostname, tmp);
		}
	}

#ifdef WIN32
	/* Winsock initialization */
	if (!honeyd_mode) {
		if (WSAStartup(MAKEWORD(2,2), &wsd) != 0) {
			printf("Winsock did not initialize properly: Winsock error [%d]\n", GetLastError());
			return -1;
		}
	}
#endif

	/* Packet types:
		0x01: Find Name
		etc.
	*/

	/* Send mode */
	if (release_mode) {
		build_ns_nb_release(&ns_release, send_sourceIP, hostname, (char)nbsvc);
		memcpy(sendbuf,&ns_release,sizeof(ns_release));
		bufLen = sizeof(ns_release);

		/* Send packet */
		printf("Releasing '%s<%02x>'\n", hostname, nbsvc);
		send_raw_ip_udp(resolve(send_sourceIP), 137, resolve(targetIP), 137, sendbuf, bufLen);

#ifdef WIN32
		/* Cleanup Winsock before leaving */
		WSACleanup();
#endif

		return 0;
	}

	/* Listen mode */
	do // 'while (!honeyd mode)' loop: execute once only in honeyd
	{
		resp_required = 0;

		/* Get request */
		if (honeyd_mode) {
			// Get stdin
			getLen = read(0, getbuf, MAX_MSG);
		}
		else {
			// Get received data on UDP port
			udp_listen(getbuf, &getLen, resolve(listen_sourceIP), 137);
		}

		/* Display received data */
		if (verbose_on) {
			printf("Bytes received [%d]:\n", getLen);
			hexdump(getbuf, getLen);
			printf("\n");
		}

		/* Interpret data into an NS Query */
		memcpy(&ns_query, &getbuf, getLen);

		/* Build response depending on query type */
		switch (htons(ns_query.query_type))
		{
		// NBTSTAT response (unicast) to an NBTSTAT request (unicast)
		case 33:
			resp_required = 1;

			// Response to a generic query on IP address with a name (nbtstat -A)
			if (strcmp(ns_query.name, " CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") == 0) { // "*\0" query
				resp_type = 2;
				if (conffile_mode) {
					// Get {domain, host name, user} with the IP address
					for (i=0; i<line_count; i++) {
						if (strcmp(ipaddr[i], listen_sourceIP) == 0) {
							domainname = domains[i];
							hostname = hosts[i];
							send_sourceIP = ipaddr[i];
							interactive_usr = users[i];
						}
					}
				}
			}
			// Response to a name query with an IP address (nbtstat -a)
			else {
				resp_type = 1;
				if (conffile_mode) {
					// Get {domain, IP address, user} with the host name
					for (i=0; i<line_count; i++) {
						// Mangle each name of conf file
						// Why ? To be able to use special chars in our NetBIOS names and
						// services, and not only spaces. Test yourself... ;-)
						name_mangle(hosts[i], tmpname, 0x00);
						if (strncmp(tmpname, ns_query.name, 31) == 0) {	// 31 chars and not 32 to respond to all NB services
							domainname = domains[i];
							hostname = hosts[i];
							send_sourceIP = ipaddr[i];
							interactive_usr = users[i];
						}
					}
				}
			}

			numsvc = 5;
			resp_size = 47 + numsvc * sizeof(ns_nbtstat_name);

			// Response header
			build_ns_nbtstat_response_hdr(&ns_nbtstat_resp_hdr, htons(ns_query.trans_id), hostname, numsvc, resp_size, resp_type);
			memcpy(sendbuf,&ns_nbtstat_resp_hdr,sizeof(ns_nbtstat_resp_hdr));
			bufLen = sizeof(ns_nbtstat_resp_hdr);

			// NetBIOS Names
			// 0x44: Unique, 0xC4: Group
				// Workstation service
				build_ns_nbtstat_name(&nbtstat_name, hostname, 0x00, 0x44);
				memcpy(sendbuf+bufLen,&nbtstat_name,sizeof(nbtstat_name));
				bufLen += sizeof(nbtstat_name);

				// Server service
				build_ns_nbtstat_name(&nbtstat_name, hostname, 0x20, 0x44);
				memcpy(sendbuf+bufLen,&nbtstat_name,sizeof(nbtstat_name));
				bufLen += sizeof(nbtstat_name);

				// Workgroup/domain workstation redirector
				build_ns_nbtstat_name(&nbtstat_name, domainname, 0x00, 0xc4);
				memcpy(sendbuf+bufLen,&nbtstat_name,sizeof(nbtstat_name));
				bufLen += sizeof(nbtstat_name);

				// Messenger service / main name
				build_ns_nbtstat_name(&nbtstat_name, interactive_usr, 0x03, 0x44);
				memcpy(sendbuf+bufLen,&nbtstat_name,sizeof(nbtstat_name));
				bufLen += sizeof(nbtstat_name);

				// Browser service
				build_ns_nbtstat_name(&nbtstat_name, hostname, 0x01, 0x44);
				memcpy(sendbuf+bufLen,&nbtstat_name,sizeof(nbtstat_name));
				bufLen += sizeof(nbtstat_name);

				// Etc.

			// Response end
			build_ns_nbtstat_response_end(&ns_nbtstat_resp_end);
			memcpy(sendbuf+bufLen,&ns_nbtstat_resp_end,sizeof(ns_nbtstat_resp_end));
			bufLen += sizeof(ns_nbtstat_resp_end);

			break;

		// NB response: send IP address to a name request (broadcast)
		case 32:
			resp_required = 0;

			// Check if the name is in the config file
			if (conffile_mode) {
				for (i=0; i<line_count; i++) {
					name_mangle(hosts[i], tmpname, 0x00);
					if (strncmp(tmpname, ns_query.name, 31) == 0) {
						hostname = hosts[i];
						send_sourceIP = ipaddr[i];
						resp_required = 1;
					}
				}
			}
			else {
				// Check if the name is mine
				name_mangle(hostname, tmpname, 0x00);
				if (strncmp(ns_query.name, tmpname, 31) == 0) {	// 31 and not 32 to respond to all NB services
					send_sourceIP = listen_sourceIP;
					resp_required = 1;
				}
			}

			if (resp_required) {
				build_ns_nb_response(&ns_nb_resp, htons(ns_query.trans_id), send_sourceIP, hostname);

				memcpy(sendbuf,&ns_nb_resp,sizeof(ns_nb_resp));
				bufLen = sizeof(ns_nb_resp);
			}
			break;

		// Unknown or malformed query
		default:
			resp_required = 0;
			break;
		}

		/* Send response */
		if (resp_required) {
			if (honeyd_mode) {
				// Print on stdout
				for (i=0; i<bufLen; i++)
					fprintf(stdout, "%c", sendbuf[i]);
			}
			else {
				printf("Responding for host '%s' \n", hostname);
				send_raw_ip_udp(resolve(send_sourceIP), 137, resolve(targetIP), 137, sendbuf, bufLen);
				if (verbose_on) {
					printf("Bytes sent [%d]:\n", bufLen);
					hexdump(sendbuf, bufLen);
					printf("\n");
				}
			}
		}
		else {
			if (!honeyd_mode)
				printf("No response needed: nothing sent.\n\n");
		}
	} while (!honeyd_mode);

#ifdef WIN32
	/* Cleanup Winsock before leaving */
	if (!honeyd_mode)
		WSACleanup();
#endif

	return 0;
}
