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
 * \file network.h
 * \brief Network functions.
 * \author Sebastien Vincent
 * \date 2012
 */

#ifndef NETWORK_H
#define NETWORK_H

#include <WinSock2.h>

/**
 * \brief Initialize network stuff.
 * It must be called once to access network API from Microsoft.
 * \return 0 if success, -1 otherwise
 */
int network_init(void);
	
/**
 * \brief Cleanup network stuff.
 * It must be called at the end of the program (prior to exit() 
 * or return from main()).
 */
void network_cleanup(void);

/**
 * \brief Create a bound socket.
 * \param addr IPv6 address
 * \param service port of the service
 * \param socktype socket type
 * \param protocol socket protocol 
 * \param addrv6 socket address that will be filled if call succeed
 * \return socket descriptor if success, INVALID_SOCKET otherwise
 */
SOCKET network_create_socket(const char* addr, const char* service,
	int socktype, int protocol, struct sockaddr_storage* addrv6);

/**
 * \brief Get adapters (and its associated addresses).
 * \param af_family AF_INET, AF_INET6 or AF_UNSPEC family
 * \return pointer of IP_ADAPTER_ADDRESSES (chain list)
 * \note the return pointer MUST be freed with free() once usage is done
 */
PIP_ADAPTER_ADDRESSES network_get_adapters(unsigned long af_family);

/**
 * \brief Print all adapters guid and all of its IPv4/IPv6 addresses.
 */
void network_print_adapters_addresses(void);

#endif /* NETWORK_H */
