/*
 *  This file is part of rdnssd_win32.
 *  Copyright (C) 2008-2012 Sebastien Vincent <sebastien.vincent@cppextrem.com>
 *
 *  rdnssd_win32 is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  rdnssd_win32 is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with rdnssd_win32.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * \file rdnssd.c
 * \brief Recursive DNS Server daemon for Microsoft Windows.
 * \author Sebastien Vincent
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <sys/utime.h>
#include <sys/types.h>

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <MSTcpIP.h>
#include <IPHlpApi.h>
#include <WinSvc.h>

#include "network.h"
#include "packet.h"
#include "utils.h"
#include "list.h"

/* disable "conditional expression is constant" warning due to 
 * do { ...}while(0); expression in macros in list.h
 */
#pragma warning(disable:4127)

/**
 * \def KEY_STR
 * \brief Beginning of the IPv6 nameservers registry key.
 * You have to add interface name (i.e {xxxx-xxxx-xxx...}).
 */
#define KEY_STR "SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\"

/**
 * \def MAX_RDNSS
 * \brief Maximum number of RDNSS option.
 */
#define MAX_RDNSS 16

/**
 * \struct rdnss_t
 * \brief Server information.
 */
typedef struct rdnss_t
{
    struct in6_addr addr; /**< \brief IPv6 address of the server. */
    unsigned int ifindex; /**< \brief Interface index. */
    time_t expiry; /**< \brief Expire time. */
}rdnss_t;

/**
 * \struct rdnss_servers
 * \brief The list of DNS servers.
 */
typedef struct rdnss_servers
{
    size_t count; /**< \brief Number of servers. */
    rdnss_t list[MAX_RDNSS]; /**< \brief Array of server information. */
}rdnss_servers;

/**
 * \struct socket_desc
 * \brief Socket descriptor element for list.
 */
struct socket_desc
{
	SOCKET sock; /**< \brief Socket descriptor. */
	struct in6_addr addr; /**< \brief Address of the socket. */
	char interface_guid[64]; /**< \brief Network interface GUID. */
	struct rdnss_servers servers; /**< \brief DNS servers. */
	struct list_head list; /**< \brief For list management. */
};

/**
 * \struct rdnssd
 * \brief The rdnssd main structure.
 */
struct rdnssd
{
	struct list_head sockets; /**< \brief Sockets list. */
};

/**
 * \var g_service_status
 * \brief Service status information.
 * Windows service related variable
 */
static SERVICE_STATUS g_service_status;

/**
 * \var g_status
 * \brief Service handle.
 * Windows service related variable
 */
static SERVICE_STATUS_HANDLE g_status = NULL;

/**
 * \var g_rdnssd
 * \brief Structure that contains sockets and DNS servers descriptors.
 */
static struct rdnssd g_rdnssd;

/**
 * \var g_run
 * \brief Running state of the program.
 */
static volatile sig_atomic_t g_run = 0;

/**
 * \brief Write name servers to the registry.
 * \param sock socket information
 */
static void rdnssd_write_registry(struct socket_desc* sock)
{
    HKEY key;
    char registry_key[sizeof(KEY_STR) + 64];
    char old[1024];
    char str[INET6_ADDRSTRLEN];
    char buf[1024];
    char* buf2 = NULL;
    DWORD bufsize = 0;

    size_t i = 0;

    if(!sock->servers.count)
    {
		fprintf(stdout, "no servers to write\n");
        return;
    }

	/* forge the key entry */
	memset(registry_key, 0x00, sizeof(registry_key));
	strncpy(registry_key, KEY_STR, sizeof(KEY_STR) + 1);
	snprintf(registry_key, sizeof(registry_key), "%s%s", KEY_STR, sock->interface_guid);
	registry_key[sizeof(registry_key) - 1] = 0x00;

	/* open the specified entry */
	if(RegOpenKeyExA(HKEY_LOCAL_MACHINE, registry_key, 0, 
		KEY_READ | KEY_WRITE, &key) != ERROR_SUCCESS)
	{
		/* create the key entry if not exists */
		if(RegCreateKeyExA(HKEY_LOCAL_MACHINE, registry_key, 0, NULL, 
			REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_READ, NULL, &key,
			&bufsize))
		{
			fprintf(stderr, "Error RegCreateKeyExA: cannot create key\n");
			return;
		}
	}

	bufsize = sizeof(buf);
	RegQueryValueExA(key, "NameServer", NULL, NULL, (unsigned char*)buf,
		&bufsize);

	/* in case it failed, buf is zeroed string */
	fprintf(stdout, "Current registry value is %s\n", buf);

	memcpy(old, buf, sizeof(buf));

	buf2 = buf;	
	bufsize = sizeof(buf);

    for(i = 0 ; i < sock->servers.count ; i++)
    {
		struct rdnss_t* rd = &sock->servers.list[i];
		DWORD str_len = 0;

        inet_ntop(AF_INET6, &rd->addr, str, INET6_ADDRSTRLEN);
		str_len = (DWORD)strlen(str);
		
		if (rd->expiry == 0)
		{
			fprintf(stdout, "Expired entry: %s", str);
			continue;
		}

		fprintf(stdout, "New entry: %s\n", str);

        if((str_len + 1) > bufsize)
        {
			fprintf(stderr, "Bufsize too small\n");
			break;
        }

        bufsize -= str_len;
        strncpy(buf2, str, str_len);
        buf2 += str_len;

        if(bufsize > 1)
        {
            *buf2 = ' ';
            buf2++;
            bufsize--;
            *buf2 = 0x00;
        }
		else /* bufsize == 1 */
		{
			*buf2 = 0x00;
			break;
		}
    }   
	
	buf[sizeof(buf) - 1] = 0x00;

	fprintf(stdout, "Old=%s New=%s\n", old, buf);
	if (!strncmp(buf, old, bufsize))
	{
		fprintf(stdout, "Same value, don't update\n");
		return;
	}

	/* write the value */
	if(RegSetValueExA(key, "NameServer", 0, REG_SZ, (unsigned char*)buf,
		bufsize) != ERROR_SUCCESS)
	{
		fprintf(stderr, "Failed to set value in registry\n");
		RegCloseKey(key);
		return;
	}

	/* close the registry */
	RegCloseKey(key);
	
	fprintf(stdout, "DNS server(s) written in the registry\n");
}

/**
 * \brief Remove an entry in the table if lifetime is expired.
 * \param sock socket information
 * \author Pierre Ynard
 */
static void rdnssd_trim_expired(struct socket_desc* sock)
{
	time_t now = 0;
    struct timespec ts;
    
    clock_gettime(CLOCK_MONOTONIC, &ts);
	now = ts.tv_sec;    

    while(sock->servers.count > 0
            && sock->servers.list[sock->servers.count - 1].expiry <= now)
	{
        sock->servers.count--;
	}
}

/**
 * \brief Compare function.
 * \param a first parameter
 * \param b second parameter
 * \return 0 if equal, 1 if "a" is lower than "b", -1 if "a" is greater than than "b"
 * \author Pierre Ynard
 */
static int rdnssd_is_older(const void *a, const void *b)
{
    time_t ta = ((const rdnss_t*)a)->expiry;
    time_t tb = ((const rdnss_t*)b)->expiry;

    if(ta < tb)
	{
        return 1;
	}
    if(ta > tb)
	{
        return -1;
	}
    return 0;
}

/**
 * \brief Update the name servers list.
 * \param sock socket information
 * \param addr IPv6 address of the name server
 * \param ifindex interface index on which we receive the RA
 * \param expiry lifetime of the entry
 * \author Pierre Ynard
 */
static void rdnssd_update(struct socket_desc* sock, struct in6_addr* addr,
	unsigned int ifindex, time_t expiry)
{
    size_t i = 0;

    /* Does this entry already exist? */
    for(i = 0 ; i < sock->servers.count ; i++)
    {
        if(memcmp(addr, &sock->servers.list[i].addr,
			sizeof(struct in6_addr)) == 0 && 
				(!IN6_IS_ADDR_LINKLOCAL(&sock->addr) || 
					ifindex == sock->servers.list[i].ifindex))
		{
            break;
		}
    }

    /* Add a new entry */
    if(i == sock->servers.count)
    {
        if(sock->servers.count < MAX_RDNSS)
		{
            i = sock->servers.count++;
		}
        else
        {
            /* No more room? replace the most obsolete entry */
            if((expiry - sock->servers.list[MAX_RDNSS - 1].expiry) >= 0)
			{
                i = MAX_RDNSS - 1;
			}
        }
    }

    memcpy(&sock->servers.list[i].addr, addr, sizeof(struct in6_addr));
    sock->servers.list[i].ifindex = ifindex;
    sock->servers.list[i].expiry = expiry;

    qsort(sock->servers.list, sock->servers.count, sizeof(rdnss_t),
		rdnssd_is_older);
	fprintf(stdout, "Update done\n");
}

/**
 * \brief Parse the Neighbor Discovery options, searching the RDNSS option.
 * \param sock socket information
 * \param opt pointer on the options
 * \param opts_len length of the options
 * \param ifindex interface index
 * \return 0 if success, -1 otherwise
 * \author Pierre Ynard
 * \author Sebastien Vincent
 */
int rdnssd_parse_nd_opts(struct socket_desc* sock,
	const struct nd_opt_hdr *opt, size_t opts_len, unsigned int ifindex)
{
    struct in6_addr *addr = NULL;

	fprintf(stdout, "rdnssd parse\n");
    for( ; opts_len >= sizeof(struct nd_opt_hdr) ; opts_len -= opt->nd_opt_len << 3,
            opt = (const struct nd_opt_hdr*)((const uint8_t*) opt + (opt->nd_opt_len << 3)))
    {
        struct nd_opt_rdnss *rdnss_opt = NULL;
        size_t nd_opt_len = opt->nd_opt_len;
        uint32_t lifetime = 0;
		time_t now = 0;
		struct timespec ts;

        if(nd_opt_len == 0 || opts_len < (nd_opt_len << 3))
        {
			return -1;
		}

        if(opt->nd_opt_type != ND_OPT_RDNSS)
		{
            continue;
		}

        if(nd_opt_len < 3 /* too short per RFC */
                || (nd_opt_len & 1) == 0) /* bad (even) length */
		{
            continue;
		}

        rdnss_opt = (struct nd_opt_rdnss*)opt;

        fprintf(stdout, "rdnss option found!\n");

        clock_gettime(CLOCK_MONOTONIC, &ts);
		now = ts.tv_sec;    

        lifetime = (uint32_t)(now + ntohl(rdnss_opt->nd_opt_rdnss_lifetime));

        for(addr = (struct in6_addr*)(rdnss_opt + 1) ; nd_opt_len >= 2 ; 
			addr++, nd_opt_len -= 2)
        {
			rdnssd_update(sock, addr, ifindex, (lifetime > now) ? lifetime : 0);
        }
    }

    return 0;
}

/**
 * \brief Callback for the frame analyze.
 * \param sock socket information
 * \param wsa_buf ICMPv6 packet received
 * \return 0
 */
static int rdnssd_decode_frame(struct socket_desc* sock, const WSABUF* wsa_buf)
{
	if(packet_decode_icmpv6(sock, wsa_buf->buf, wsa_buf->len) == 1)
    {
        /* if returns 1, the packet is a RA */
        rdnssd_trim_expired(sock);
        /* write to the registry */
        rdnssd_write_registry(sock);
    }
    return 0;
}

/**
 * \brief Function executed when the program receive a signal.
 * \param code code of the signal
 */
static void __cdecl signal_routine(int code)
{
    switch(code)
    {
    case SIGTERM:
    case SIGINT:
    case SIGABRT:
		/* break main loop */
		g_run = 0;
        break;
    case SIGSEGV:
        fprintf(stderr, "Receive SIGSEGV: oups, exiting now\n");
        _exit(EXIT_FAILURE); /* we just exit the program without cleanup */
        break;
    default:
        break;
    }
}

/**
 * \brief Wait ICMPv6 messages and process it.
 * \return 0 if success, -1 otherwise
 */
static int rdnssd_main()
{
	struct list_head* n = NULL;
	struct list_head* get = NULL;
	struct fd_set fdsr;
	int nsock = 0;
	struct timeval tv = {1, 0}; /* one second timeout */
	int ret = -1;
	WSABUF wsa_buf;
	DWORD flags = 0;
	char buf[1500];
	DWORD bytes_ret = 0;

	wsa_buf.buf = buf;
	wsa_buf.len = sizeof(buf);
	FD_ZERO(&fdsr);

	list_iterate_safe(get, n, &g_rdnssd.sockets)
	{
		/* add socket descriptors for select() */
		struct socket_desc* tmp = list_get(get, struct socket_desc, list);
		FD_SET(tmp->sock, &fdsr);
		/* nsock = tmp->sock > nsock ? tmp->sock : nsock; */
	}

	/* first parameters for select() _on_ Windows is ignored (see MSDN) */
	/* nsock++; */
	ret = select(nsock, &fdsr, NULL, NULL, &tv);
	
	if(ret > 0)
	{
		list_iterate_safe(get, n, &g_rdnssd.sockets)
		{
	
			struct socket_desc* tmp = list_get(get, struct socket_desc, list);

			if(FD_ISSET(tmp->sock, &fdsr))
			{
				SOCKADDR_STORAGE from;
				int from_len = sizeof(SOCKADDR_STORAGE);

				if(WSARecvFrom(tmp->sock, &wsa_buf, 1, &bytes_ret, 
					&flags, (struct sockaddr*)&from, &from_len, NULL, NULL) != SOCKET_ERROR)
				{
					struct sockaddr_in6* addrv6 = (struct sockaddr_in6*)&from;
					if(!memcmp(&tmp->addr, &addrv6->sin6_addr, sizeof(struct in6_addr)))
					{
						/* do not read and process packet coming from us */
						continue;
					}
					rdnssd_decode_frame(tmp, &wsa_buf);
					wsa_buf.len = 0;
				}
			}
		}
	}
	else if(ret == 0)
	{
		/* timeout */	
		return 0;
	}
	else if(ret == -1)
	{
		fprintf(stderr, "Error select() (%d)\n", GetLastError());
		return -1;
	}

    return 0;
}

/**
 * \brief Windows service controller.
 * \param Opcode opcode received
 * \param EventType event type received
 * \param pEventData auxiliary data
 * \param pContext context
 * \return ERROR_SUCCCESS
 */
DWORD WINAPI ctrl_handler(DWORD Opcode, DWORD EventType, PVOID pEventData,
	PVOID pContext)
{
    /* avoid compilation warnings */
    pContext = pContext;
    pEventData = pEventData;
    EventType = EventType;

    switch(Opcode)
    {
	case SERVICE_CONTROL_SHUTDOWN:
    case SERVICE_CONTROL_STOP:
		/* break main loop */
		g_run = 0;
        g_service_status.dwWin32ExitCode = ERROR_SUCCESS;
        g_service_status.dwCurrentState = SERVICE_STOPPED;
        g_service_status.dwCheckPoint= 1;
        g_service_status.dwWaitHint = 10000;
        break;
    default:
        break;
    }

    if(!SetServiceStatus(g_status, &g_service_status))
    {
        /* SvcDebugOut(TEXT("SetServiceStatus error - "), 
			GetLastError());
		*/
    }
    return ERROR_SUCCESS;
}

/**
 * \brief Init rdnssd internal structures.
 * \return 0 if success, -1 otherwise
 */
static int rdnssd_init(void)
{
	PIP_ADAPTER_ADDRESSES adapters = NULL;
	PIP_ADAPTER_ADDRESSES p = NULL;

	network_init();

	INIT_LIST(g_rdnssd.sockets);

	/* get all network interfaces and bind a socket to its
	 * IPv6 link-local address
	 */
	adapters = network_get_adapters(AF_INET6);

	if(!adapters)
	{
		return -1;
	}

	for(p = adapters ; p ; p = p->Next)
	{
		PIP_ADAPTER_UNICAST_ADDRESS p2 = NULL;
		struct sockaddr* addr = NULL;
		struct socket_desc* desc = NULL;

		for(p2 = p->FirstUnicastAddress ; p2 ; p2 = p2->Next)
		{
			addr = p2->Address.lpSockaddr;

			/* try directly to bind on link-local address, 
			 * in case an address has no link-local address, bind on global
			 * address
			 */
			if(IN6_IS_ADDR_LINKLOCAL(&((struct sockaddr_in6*)addr)->sin6_addr))
			{
				break;
			}
		}

		if(addr)
		{
			SOCKET sock = WSASocket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6, NULL, 0,
				WSA_FLAG_OVERLAPPED);
			unsigned long on = 0;
			DWORD bytes_ret = 0;

			if(sock == INVALID_SOCKET)
			{
				fprintf(stderr, "Error socket: %d\n", GetLastError());
				continue;
			}

			if(bind(sock, addr, sizeof(struct sockaddr_in6)) != 0)
			{
				fprintf(stderr, "Error bind: %d\n", GetLastError());
				closesocket(sock);
				continue;
			}

			/* enable mode to receive all ICMPv6 packets */
			on = RCVALL_IPLEVEL;
			if(WSAIoctl(sock, SIO_RCVALL, &on, sizeof(unsigned long), NULL, 0,
				&bytes_ret, NULL, NULL) == SOCKET_ERROR)
			{
				fprintf(stderr, "Error WSAIoctl: %d\n", GetLastError());
				closesocket(sock);
				continue;
			}

			desc = malloc(sizeof(struct socket_desc));

			if(!desc)
			{
				closesocket(sock);
				continue;
			}

			desc->sock = sock;
			memcpy(&desc->addr, addr, sizeof(struct sockaddr_in6));
			strncpy(desc->interface_guid, p->AdapterName, sizeof(desc->interface_guid));
			desc->interface_guid[sizeof(desc->interface_guid) - 1] = 0x00;
			INIT_LIST(desc->list);
			memset(&desc->servers, 0x00, sizeof(struct rdnss_servers));
			desc->servers.count = 0;
			
			fprintf(stdout, "Add socket to list: %s\n", desc->interface_guid);
			LIST_ADD(&desc->list, &g_rdnssd.sockets);
		}
	}

	free(adapters);

	return 0;
}

/**
 * \brief Cleanup all stuff from init_rdnssd().
 */
static void rdnssd_cleanup(void)
{
	struct list_head* n = NULL;
	struct list_head* get = NULL;

	/* close all sockets and do other cleanup */
	list_iterate_safe(get, n, &g_rdnssd.sockets)
	{
		struct socket_desc* tmp = list_get(get, struct socket_desc, list);
		LIST_DEL(&tmp->list);
		closesocket(tmp->sock);
		free(tmp);
	}

	network_cleanup();
}

/**
 * \brief The rdnssd service entry point.
 * \param argc number of arguments
 * \param argv array of arguments
 */
VOID WINAPI rdnssd_service(int argc, char** argv)
{
    /* avoid compilation warnings */
    (void)argc;
	(void)argv;

    g_service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP |
		SERVICE_ACCEPT_SHUTDOWN;
    g_service_status.dwCurrentState = SERVICE_RUNNING;
    g_service_status.dwServiceType = SERVICE_WIN32;
    g_service_status.dwCheckPoint = 0;
    g_service_status.dwServiceSpecificExitCode = 0;
    g_service_status.dwWaitHint = 0;
    g_service_status.dwWin32ExitCode = 0;

    g_status = RegisterServiceCtrlHandlerEx(TEXT("rdnssd"), ctrl_handler,
		NULL);

    if(!g_status)
    {
        fprintf(stderr, "RegisterServiceCtrlHandlerEx\n");
        return;
    }

    SetServiceStatus(g_status, &g_service_status);

	if(rdnssd_init() == -1)
	{
		/* TODO debug in log */
		return;
	}

	g_run = 1;
    while(g_service_status.dwCurrentState == SERVICE_RUNNING && g_run)
    {
        /* main loop to capture the packet */
		rdnssd_main();
    }
    
	rdnssd_cleanup();
}

/**
 * \brief Entry point of the program.
 * \param argc number of arguments
 * \param argv array of arguments
 * \return EXIT_SUCCESS or EXIT_FAILURE
 */
int main(int argc, char** argv)
{
	/* ensure the application is running with full privileges */
	if (is_run_as_administrator() == 0)
	{
		fprintf(stdout, "Run this application as administrator. Exiting...\n");
		exit(EXIT_FAILURE);
	}

    /* signals handling */

    /* On Windows x64, it is normal that the following
     * lines throw warnings (if compiled with /W4).
     * The reason is that SIG_ERR cast -1 to function pointer (8 bytes)
     * and -1 is interpreted as a 'int' (4 bytes on x64).
     */
    if(signal(SIGTERM, signal_routine) == SIG_ERR)
    {
        fprintf(stderr, "SIGTERM not handled\n");
    }

    if(signal(SIGINT, signal_routine) == SIG_ERR)
    {
        fprintf(stderr, "SIGINT not handled\n");
    }

    if(signal(SIGABRT, signal_routine) == SIG_ERR)
    {
        fprintf(stderr, "SIGABRT not handled\n");
    }

    if(signal(SIGSEGV, signal_routine) == SIG_ERR)
    {
        fprintf(stderr, "SIGSEGV not handled\n");
    }

	network_print_adapters_addresses();

	/* run in background (service) */
    if(argc > 1 && !strncmp(argv[1], "-b", strlen(argv[1])))
    {
        SERVICE_TABLE_ENTRY service_table[2];

        service_table[0].lpServiceName = TEXT("rdnssd");
        service_table[0].lpServiceProc = 
			(LPSERVICE_MAIN_FUNCTION)rdnssd_service;
        service_table[1].lpServiceName = NULL;
        service_table[1].lpServiceProc = NULL;
        StartServiceCtrlDispatcher(service_table);
    }
    else
    {
		if(rdnssd_init() == -1)
		{
			fprintf(stderr, "Error during rdnssd-win32 initialization\n");
			exit(EXIT_FAILURE);
		}

		g_run = 1;
		
		while(g_run)
		{
			rdnssd_main();
		}

		g_run = 0;
		rdnssd_cleanup();
    }

    return EXIT_SUCCESS;
}
