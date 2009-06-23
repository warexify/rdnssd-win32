/*
    This file is part of rdnssd_win32.
    Copyright (C) 2008 Sebastien Vincent <sebastien.vincent@cppextrem.com>

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
 * \file packet.c
 * \brief Ethernet, IPv6 and ICMPv6 headers.
 * \author Sebastien Vincent
 */

#include <winsock2.h>
#include <in6addr.h>

#include "packet.h"

extern int rdnssd_parse_nd_opts(const struct nd_opt_hdr *opt, size_t opts_len, unsigned int ifindex);

int packet_decode_ethernet(const u_char* packet, size_t len)
{
    struct eth_hdr* hdr = (struct eth_hdr*)packet;

    if(len < sizeof(struct eth_hdr))
    {
        return -1;
    }

    switch(ntohs(hdr->ether_type))
    {
    case 0x86dd: /* IPv6 */
        return packet_decode_ipv6(packet + sizeof(struct eth_hdr), len - sizeof(struct eth_hdr));
        break;
    default: /* other */
        break;
    }
    return 0;
}

int packet_decode_ipv6(const u_char* packet, size_t len)
{
    struct ipv6_hdr* hdr = (struct ipv6_hdr*)packet;

    if(len < sizeof(struct ipv6_hdr))
    {
        return -1;
    }

    /* TODO : go to payload (bypass the option) */
    switch(hdr->ipv6_nexthdr)
    {
    case IPPROTO_ICMPV6:
        return packet_decode_icmpv6(packet + sizeof(struct ipv6_hdr), len += sizeof(struct ipv6_hdr));
        break;
    default:
        break;
    }
    return 0;
}

int packet_decode_icmpv6(const u_char* packet, size_t len)
{
    struct icmpv6_hdr* hdr = (struct icmpv6_hdr*)packet;
    size_t hdr_len = 0;

    if(len < sizeof(struct icmpv6_hdr))
    {
        return -1;
    }

    switch(hdr->icmp6_type)
    {
    case 134: /* RA */
        hdr_len = sizeof(struct nd_router_advert);
        hdr_len = hdr_len + (hdr_len % 8);
        /* printf("RA received (%d)!\n", hdr_len); */
        rdnssd_parse_nd_opts((const nd_opt_hdr*)(packet + hdr_len), (len - hdr_len), 0);
        return 1;
        break;
    default:
        break;
    }
    return 0;
}

