/*
 *  This file is part of rdnssd_win32.
 *  Copyright (C) 2012 Sebastien Vincent <sebastien.vincent@cppextrem.com>
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
 * \file network.c
 * \brief Network functions.
 * \author Sebastien Vincent
 * \date 2012
 */

#include <stdio.h>
#include <stdlib.h>

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <MSTcpIP.h>
#include <IPHlpApi.h>

/**
 * \var g_wsaData
 * \brief Winsock WSADATA.
 */
static WSADATA g_wsaData;

int network_init(void)
{
	if(WSAStartup(MAKEWORD(2, 2), &g_wsaData) != 0)
	{
		return -1;
	}

	return 0;
}

void network_cleanup(void)
{
	WSACleanup();
}

SOCKET network_create_socket(const char* addr, const char* service,
	int socktype, int protocol, struct sockaddr_storage* addrv6)
{
	SOCKET sock = INVALID_SOCKET;
	ADDRINFO hints;
	ADDRINFO* res = NULL;
	ADDRINFO* p = NULL;

	if(addr == NULL || addrv6 == NULL)
	{
		return INVALID_SOCKET;
	}

	memset(&hints, 0x00, sizeof(struct addrinfo));

	hints.ai_family = AF_INET6;
	hints.ai_socktype = socktype;
	hints.ai_protocol = protocol;
	hints.ai_flags = AI_PASSIVE;

	if(GetAddrInfoA(addr, service, &hints, &res) != 0)
	{
		return INVALID_SOCKET;
	}
	
	for(p = res ; p ; p = p->ai_next)
	{
		sock = WSASocket(p->ai_family, p->ai_socktype, p->ai_protocol, NULL, 0,
			WSA_FLAG_OVERLAPPED);

		if(sock == INVALID_SOCKET)
		{
			continue;
		}

		if(bind(sock, p->ai_addr, (int)p->ai_addrlen) != 0)
		{
			closesocket(sock);
			continue;
		}

		memcpy(addrv6, p->ai_addr, p->ai_addrlen);
	}

	FreeAddrInfoA(res);
	p = NULL;

	return sock;
}

PIP_ADAPTER_ADDRESSES network_get_adapters(unsigned long af_family)
{
	unsigned long ret = 0;
	unsigned long size = 0;
	PIP_ADAPTER_ADDRESSES adapters = NULL;
	
	/* set a high value to minimize calling GetAdaptersAddresses multiple
	 * times (which is slow) in case buffer is not big enough
	 */
	size = 15000;

	do
	{
		adapters = malloc(size);

		if(adapters == NULL)
		{
			break;
		}

		ret = GetAdaptersAddresses(af_family, GAA_FLAG_SKIP_MULTICAST, 
			NULL, adapters, &size);
	} while(ret == ERROR_BUFFER_OVERFLOW);

	if(ret != ERROR_SUCCESS || adapters == NULL)
	{
		if(adapters)
		{
			free(adapters);
		}
		return NULL;
	}

	return adapters;
}

void network_print_adapters_addresses(void)
{
	PIP_ADAPTER_ADDRESSES adapters = NULL;
	PIP_ADAPTER_ADDRESSES p = NULL;	
	
	adapters = network_get_adapters(AF_UNSPEC);
	if(adapters == NULL)
	{
		fprintf(stderr, "Problem retrieving adapters\n");
		return;
	}

	for(p = adapters ; p ; p = p->Next)
	{
		PIP_ADAPTER_UNICAST_ADDRESS p2 = NULL;
		char buf[64];

		fprintf(stdout, "----------\n");
		fprintf(stdout, "Adapter: %s (%ls)\n", p->AdapterName,
			p->FriendlyName);
		for(p2 = p->FirstUnicastAddress ; p2 ; p2 = p2->Next)
		{
			struct sockaddr* addr = p2->Address.lpSockaddr;

			memset(buf, 0x00, sizeof(buf));

			/* convert socket address to string */
			switch(addr->sa_family)
			{
			case AF_INET6:
				InetNtopA(addr->sa_family, 
					&((struct sockaddr_in6*)addr)->sin6_addr, buf,
					INET6_ADDRSTRLEN);
				break;
			case AF_INET:
				InetNtopA(addr->sa_family, 
					&((struct sockaddr_in*)addr)->sin_addr, buf,
					INET_ADDRSTRLEN);
				break;
			default:
				continue;
			}
			fprintf(stdout, "\t%s\n", buf);
		}
	}

	free(adapters);
}
