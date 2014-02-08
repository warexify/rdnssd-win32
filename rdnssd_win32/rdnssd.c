/*
    This file is part of rdnssd_win32.
    Copyright (C) 2008-2009 Sebastien Vincent <sebastien.vincent@cppextrem.com>

    rdnssd_win32 is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    rdnssd_win32 is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with rdnssd_win32.  If not, see <http://www.gnu.org/licenses/>.
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

#include <winsock2.h>
#include <winsvc.h>

/* include this before pcap.h for windows */
#define HAVE_REMOTE
#define WPCAP
#define PACKET_SIZE 65536

#include <pcap.h>

#include "inet_function.h"
#include "packet.h"

/**
 * \def PACKET_CAPTURE_LEN
 * \brief Captured packet len.
 */
#define PACKET_CAPTURE_LEN 1514

/**
 * \def PACKET_TIMEOUT
 * \brief Timeout (for pcap_open_live).
 */
#define PACKET_TIMEOUT 100

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
    struct in6_addr addr; /**< IPv6 address of the server */
    unsigned int ifindex; /**< Interface index */
    time_t expiry; /**< Expire time */
}rdnss_t;

/**
 * \struct rdnss_servers
 * \brief The list of dns servers.
 */
typedef struct rdnss_servers
{
    size_t count; /**< Number of servers */
    rdnss_t list[MAX_RDNSS]; /**< Array of server information */
}rdnss_servers;

/**
 * \enum clockid_t
 * \brief Different type of clock (used with clock_* function).
 */
typedef enum clockid_t
{
    CLOCK_REALTIME, /**< The realtime clock */
    CLOCK_MONOTONIC /**< The monotonic clock */
}clockid_t;

/**
 * \struct timespec
 * \brief The timespec structure for Windows.
 */
struct timespec
{
    time_t tv_sec; /**< Seconds */
    long tv_nsec; /**< Nanoseconds */
};

/**
 * \var now
 * \brief The current time.
 */
static time_t now;

/**
 * \var ifname
 * \brief Interface name (i.e {xxx-xxx-xxx...}.
 */
static char ifname[MAX_PATH];

/**
 * \var sock
 * \brief the interface sniffer.
 * Must be global if we want to cleanup when pcap_breakloop.
 */
static pcap_t* sock = NULL;

/**
 * \var service_status
 * \brief Service status information.
 * Windows service related variable
 */
static SERVICE_STATUS service_status;

/**
 * \var status
 * \brief Service handle.
 * Windows service related variable
 */
static SERVICE_STATUS_HANDLE status = NULL;

/**
 * \var servers
 * \brief DNS list information.
 */
static struct rdnss_servers servers;

/**
 * \brief An implementation of gettimeofday for Windows.
 * \param p the time will be filled in
 * \param tz timezone (it is ignored).
 * \return 0
 */
static inline int gettimeofday(struct timeval* p, void* tz /* IGNORED */)
{
    union
    {
        long long ns100; /* time since 1 Jan 1601 in 100ns units */
        FILETIME ft;
    } now;

    tz = tz; /* not used */

    GetSystemTimeAsFileTime(&(now.ft));
    p->tv_usec = (long)((now.ns100 / 10LL) % 1000000LL);
    p->tv_sec = (long)((now.ns100 - (116444736000000000LL)) / 10000000LL);
    return 0;
}

/**
 * \brief A clock_gettime function replacement.
 * \param clk_id the type of clock we want
 * \param tp structure that will be filled with the time
 * \return 0 if success, negative integer otherwise
 * \author Sebastien Vincent
 */
static int clock_gettime(clockid_t clk_id, struct timespec *tp)
{
    struct timeval tv;

    clk_id = clk_id; /* not used */

    if(gettimeofday(&tv, NULL)==-1)
    {
        return -1;
    }

    tp->tv_sec = tv.tv_sec;
    tp->tv_nsec = tv.tv_usec * 1000; /* convert microsecond to nanosecond */
    return 0;
}

/**
 * \brief Write name servers to the registry.
 */
static void rdnssd_write_registry(void)
{
    HKEY key;
    char registry_key[sizeof(KEY_STR) + 64];
    char old[1024];
    char str[INET6_ADDRSTRLEN];
    char buf[1024];
    char* buf2 = NULL;
    DWORD bufsize = 0;
    struct rdnss_t* rd = NULL;
    size_t i = 0;

    if(!servers.count)
    {
        return;
    }

    /* forge the key entry */
    memset(registry_key, 0x00, sizeof(registry_key));
    strncpy(registry_key, KEY_STR, sizeof(KEY_STR) + 1);
    strcat(registry_key, ifname /*"{792556BE-97C6-4AE0-8456-7C6566000B1D}"*/);
    registry_key[sizeof(registry_key) - 1] = 0x00;

    /* open the specified entry */
    if(RegOpenKeyExA(HKEY_LOCAL_MACHINE, registry_key, 0, KEY_READ | KEY_WRITE, &key) != ERROR_SUCCESS)
    {
        /* create the key entry if not exists */
        if(RegCreateKeyExA(HKEY_LOCAL_MACHINE, registry_key, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_READ, NULL, &key, &bufsize))
        {
            printf("Error RegCreateKeyExA: cannot create key\n");
            return;
        }
    }

    bufsize = sizeof(buf);
    RegQueryValueExA(key, "NameServer", NULL, NULL, (unsigned char*)buf, &bufsize);

    /* in case it failed, buf is zeroed string */
    printf("Old value is %s\n", buf);
    memcpy(old, buf, sizeof(buf));

    buf2 = buf;
    bufsize = sizeof(buf);

    for(i = 0 ; i < servers.count ; i++)
    {
        rd = &servers.list[i];

        inet_ntop2(AF_INET6, &rd->addr, str, INET6_ADDRSTRLEN);

        if((strlen(str) + 1) > (bufsize))
        {
            break;
        }

        bufsize -= (int)strlen(str);
        strncpy(buf2, str, strlen(str));
        buf2 += (int)strlen(str);

        if(bufsize > 1)
        {
            *buf2 = ' ';
            buf2++;
            bufsize--;
            *buf2 = 0x00;
        }
    }
    
    buf[sizeof(buf) - bufsize] = 0x00;
    printf("New value is %s\n", buf);
    bufsize = (int)strlen(buf);

    if(!strcmp(buf, old))
    {
        printf("Same value, don't update\n");
        RegCloseKey(key);
        return;
    }

    /* write the value */
    if(RegSetValueExA(key, "NameServer", 0, REG_SZ, (unsigned char*)buf, bufsize) != ERROR_SUCCESS)
    {
        RegCloseKey(key);
        return;
    }
    printf("DNS server(s) written in the registry\n");
    /* close the registry */
    RegCloseKey(key);
}

/**
 * \brief Remote a entry in the table if lifetime is expired.
 * \author Pierre Ynard
 */
static void rdnssd_trim_expired(void)
{
    while(servers.count > 0
            && servers.list[servers.count - 1].expiry <= now)
        servers.count--;
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
        return 1;
    if(ta > tb)
        return -1;
    return 0;
}

/**
 * \brief Update the name servers list.
 * \param addr IPv6 address of the name server
 * \param ifindex interface index on which we receive the RA
 * \param expiry lifetime of the entry
 * \author Pierre Ynard
 */
static void rdnssd_update(struct in6_addr* addr, unsigned int ifindex, time_t expiry)
{
    size_t i = 0;

    /* Does this entry already exist? */
    for(i = 0 ; i < servers.count ; i++)
    {
        if(memcmp(addr, &servers.list[i].addr, sizeof(*addr)) == 0
                && (!IN6_IS_ADDR_LINKLOCAL(addr)
                    || ifindex == servers.list[i].ifindex))
            break;
    }

    /* Add a new entry */
    if(i == servers.count)
    {
        if(expiry == now)
            return; /* Do not add already expired entry! */

        if(servers.count < MAX_RDNSS)
            i = servers.count++;
        else
        {
            /* No more room? replace the most obsolete entry */
            if((expiry - servers.list[MAX_RDNSS - 1].expiry) >= 0)
                i = MAX_RDNSS - 1;
        }

      memcpy(&servers.list[i].addr, addr, sizeof(*addr));
      servers.list[i].ifindex = ifindex;
      servers.list[i].expiry = expiry;

      qsort(servers.list, servers.count, sizeof(rdnss_t), rdnssd_is_older);
    }

    /*
    #ifndef NDEBUG
        for(unsigned i = 0; i < servers.count; i++)
        {
            char buf[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &servers.list[i].addr, buf,
                       sizeof(buf));
            syslog(LOG_DEBUG, "%u: %48s expires at %u\n", i, buf,
                    (unsigned)servers.list[i].expiry);
        }
    #endif
    */
}

/**
 * \brief Parse the Neighbor Discovery options, searching the RDNSS option.
 * \param opt pointer on the options
 * \param opts_len length of the options
 * \param ifindex interface index
 * \return 0 if success, -1 otherwise
 * \author Pierre Ynard
 * \author Sebastien Vincent
 */
int rdnssd_parse_nd_opts(const struct nd_opt_hdr *opt, size_t opts_len, unsigned int ifindex)
{
    struct in6_addr *addr = NULL;

    for( ; opts_len >= sizeof(struct nd_opt_hdr) ; opts_len -= opt->nd_opt_len << 3,
            opt = (const struct nd_opt_hdr*)((const uint8_t*) opt + (opt->nd_opt_len << 3)))
    {
        struct nd_opt_rdnss *rdnss_opt = NULL;
        size_t nd_opt_len = opt->nd_opt_len;
        uint32_t lifetime = 0;

        if(nd_opt_len == 0 || opts_len < (nd_opt_len << 3))
            return -1;

        if(opt->nd_opt_type != ND_OPT_RDNSS)
            continue;

        if(nd_opt_len < 3 /* too short per RFC */
                || (nd_opt_len & 1) == 0) /* bad (even) length */
            continue;

        rdnss_opt = (struct nd_opt_rdnss*)opt;

        printf("rdnss option found!\n");

        {
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            now = ts.tv_sec;
        }

        lifetime = (uint32_t)now + ntohl(rdnss_opt->nd_opt_rdnss_lifetime);

        for(addr = (struct in6_addr*)(rdnss_opt + 1) ; nd_opt_len >= 2 ; addr++, nd_opt_len -= 2)
        {
            rdnssd_update(addr, ifindex, lifetime);
        }
    }

    return 0;
}

/**
 * \brief Callback for the frame analyze.
 * \param args not used
 * \param header packet information (size, ...)
 * \param packet the packet
 * \return 0
 */
static int rdnssd_decode_frame(u_char* args, const struct pcap_pkthdr* header, const u_char* packet)
{
    args = NULL; /* not used */

    if(packet_decode_ethernet(packet, header->len) == 1)
    {
        /* if returns 1, the packet is a RA */
        rdnssd_trim_expired();
        /* write to the registry */
        rdnssd_write_registry();
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
        if(sock)
        {
            pcap_breakloop(sock);
        }
        break;
    case SIGSEGV:
        printf("Receive SIGSEGV: oups, exiting now\n");
        _exit(EXIT_FAILURE); /* we just exit the program without cleanup */
        break;
    default:
        break;
    }
}

/**
 * \brief rdnssd program.
 * \param argc number of argument
 * \param argv array of argument
 * \return EXIT_SUCCESS or EXIT_FAILURE
 */
static int rdnssd_main(int argc, char** argv)
{
    /* avoid compilation warnings */
    argc = argc;
    argv = argv;

    /* signals handling */

    /* On Windows x64, it is normal that the following
     * lines throw warnings (if compiled with /W4).
     * The reason is that SIG_ERR cast -1 to function pointer (8 bytes)
     * and -1 is interpreted as a 'int' (4 bytes on x64).
     */
    if(signal(SIGTERM, signal_routine) == SIG_ERR)
    {
        printf("SIGTERM not handled\n");
    }

    if(signal(SIGINT, signal_routine) == SIG_ERR)
    {
        printf("SIGINT not handled\n");
    }

    if(signal(SIGABRT, signal_routine) == SIG_ERR)
    {
        printf("SIGABRT not handled\n");
    }

    if(signal(SIGSEGV, signal_routine) == SIG_ERR)
    {
        printf("SIGSEGV not handled\n");
    }

    /* test only
    inet_pton2(AF_INET6, "2001:660:2402::1", (struct sockaddr*)&servers.list[0].addr);
    inet_pton2(AF_INET6, "2001:660:2402::2", (struct sockaddr*)&servers.list[1].addr);
    servers.count = 2;
    rdnssd_write_registry();
    */

    /* capture the packet */
    pcap_loop(sock, -1, rdnssd_decode_frame, NULL);

    pcap_close(sock);

    printf("Terminating program\n");

    return EXIT_SUCCESS;
}

/**
 * \brief Windows service controller.
 * \param Opcode opcode received
 * \param EventType event type received
 * \param pEventData auxiliary data
 * \param pContext context
 * \return ERROR_SUCCCESS
 */
DWORD WINAPI ctrl_handler(DWORD Opcode, DWORD EventType, PVOID pEventData, PVOID pContext)
{
    /* avoid compilation warnings */
    pContext = pContext;
    pEventData = pEventData;
    EventType = EventType;

    switch(Opcode)
    {
    case SERVICE_CONTROL_SHUTDOWN:
    case SERVICE_CONTROL_STOP:
        pcap_breakloop(sock);
        service_status.dwWin32ExitCode = ERROR_SUCCESS;
        service_status.dwCurrentState = SERVICE_STOPPED;
        service_status.dwCheckPoint= 1;
        service_status.dwWaitHint = 10000;
        break;
    default:
        break;
    }

    if(!SetServiceStatus(status, &service_status))
    {
        /* SvcDebugOut(TEXT("SetServiceStatus error - "), GetLastError()); */
    }
    return ERROR_SUCCESS;
}

/**
 * \brief rdnssd service.
 * \param argc number of argument
 * \param argv array of argument
 */
VOID WINAPI rdnssd_service(int argc, char** argv)
{
    /* avoid compilation warnings */
    argc = argc;
    argv = argv;

    service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    service_status.dwCurrentState = SERVICE_RUNNING;
    service_status.dwServiceType = SERVICE_WIN32;
    service_status.dwCheckPoint = 0;
    service_status.dwServiceSpecificExitCode = 0;
    service_status.dwWaitHint = 0;
    service_status.dwWin32ExitCode = 0;

    status = RegisterServiceCtrlHandlerEx(TEXT("rdnssd"), ctrl_handler, NULL);

    if(!status)
    {
        printf("RegisterServiceCtrlHandlerEx\n");
        return;
    }

    SetServiceStatus(status, &service_status);

    while(service_status.dwCurrentState == SERVICE_RUNNING)
    {
        /* capture the packet */
        pcap_loop(sock, -1, rdnssd_decode_frame, NULL);
    }
    pcap_close(sock);
}

/**
 * \brief Entry point of the program.
 * \param argc number of arguments
 * \param argv array of arguments
 * \return EXIT_SUCCESS or EXIT_FAILURE
 */
int main(int argc, char** argv)
{
    struct bpf_program bpf;
    char* filter = "icmp6";
    char* dev = NULL;
    char error[PCAP_ERRBUF_SIZE];

    /* init list */
    memset(&servers, 0x00, sizeof(servers));
    servers.count = 0;

    if(argc < 2)
    {
        pcap_if_t * devices = NULL;
        pcap_if_t* ifdev = NULL;

        printf("Usage: %s ifname [b]\n", argv[0]);

        if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &devices, error) == -1)
        {
            printf("Error: %s\n", error);
            exit(EXIT_FAILURE);
        }

        printf("Available ifname: \n");
        for(ifdev = devices ; ifdev ; ifdev = ifdev->next)
        {
            printf("- ifname: %s\n\t(%s)\n", ifdev->name, ifdev->description);
        }
        pcap_freealldevs(devices);
        exit(EXIT_FAILURE);
    }

    dev = argv[1];

    if(!strchr(dev, '{'))
    {
        printf("Error bad interface name\n");
        exit(EXIT_FAILURE);
    }

    /* copy the interface name (to retrieve it when we will write to the registry) */
    strncpy(ifname, strchr(dev, '{'), MAX_PATH - 1);
    ifname[MAX_PATH - 1] = 0x00;

    printf("Listening on %s\n", ifname);
    sock = pcap_open(dev, PACKET_CAPTURE_LEN, 0, PACKET_TIMEOUT, NULL, error);

    if(!sock)
    {
        printf("%s\n", error);
        exit(EXIT_FAILURE);
    }

    /* compile filter */
    if(pcap_compile(sock, &bpf, filter, 0, 0) == -1)
    {
        printf("Error pcap_compile\n");
        pcap_close(sock);
        exit(EXIT_FAILURE);
    }

    /* set filter */
    if(pcap_setfilter(sock, &bpf) == -1)
    {
        printf("Error pcap_setfilter\n");
        pcap_freecode(&bpf);
        pcap_close(sock);
        exit(EXIT_FAILURE);
    }

    pcap_freecode(&bpf);

    if(argv[2] && argv[2][0]=='b') /* run in background (service) */
    {
        SERVICE_TABLE_ENTRY service_table[2];

        service_table[0].lpServiceName = TEXT("rdnssd");
        service_table[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)rdnssd_service;
        service_table[1].lpServiceName = NULL;
        service_table[1].lpServiceProc = NULL;
        StartServiceCtrlDispatcher(service_table);
    }
    else
    {
        rdnssd_main(argc, argv);
    }
    return EXIT_SUCCESS;
}
