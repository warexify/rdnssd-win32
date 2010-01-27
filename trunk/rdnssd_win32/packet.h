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
 * \file packet.h
 * \brief Ethernet, IPv6 and ICMPv6 headers.
 * \author Sebastien Vincent
 */

#ifndef PACKET_H
#define PACKET_H

#include <in6addr.h>

/**
 * \def ND_OPT_RDNSS
 * \brief Option type number for RDNSS option.
 */
#define ND_OPT_RDNSS 25

/* replacement from stdint.h */
typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;

/* __attribute__((packed) */
#pragma pack(push, 1)

/**
 * \struct eth_hdr
 * \brief Ethernet protocol header 
 */
typedef struct eth_hdr
{
    unsigned char dst_addr[6]; /**< Destination address */
    unsigned char src_addr[6]; /**< Source address */
    unsigned __int16 ether_type; /**< Ethernet type of the payload */
}eth_hdr;

/**
 * \struct ipv6_hdr
 * \brief IPv6 protocol header
 */
typedef struct ipv6_hdr
{
    unsigned long ipv6_vertcflow; /**< 4 bit IPv6 version\n
                                       8 bit traffic prioriy\n
                                       20 bit flow label */
    unsigned short ipv6_payloadlen; /**< Payload length */
    unsigned char ipv6_nexthdr; /**< Next header protocol value */
    unsigned char ipv6_hoplimit; /**< TTL */
    struct in6_addr ipv6_srcaddr; /**< Source address */
    struct in6_addr ipv6_destaddr; /**< Destination address */
}ipv6_hdr;

/**
 * \struct ipv6_fragment_hdr
 * \brief IPv6 fragment header
 */
typedef struct ipv6_fragment_hdr
{
    unsigned char ipv6_frag_nexthdr; /**< Next header protocol value */
    unsigned char ipv6_frag_reserved; /**< Reserved */
    unsigned short ipv6_frag_offset; /**< Offset */
    unsigned long ipv6_frag_id; /**< Id of the fragment */
}ipv6_fragment_hdr;

/**
 * \struct icmpv6_hdr
 * \brief ICMPv6 header
 */
typedef struct icmpv6_hdr
{
    unsigned char icmp6_type; /**< ICMPv6 type */
    unsigned char icmp6_code; /**< ICMPv6 code */
    unsigned short icmp6_checksum; /**< ICMPv6 checksum */
}icmpv6_hdr;

/**
 * \struct nd_router_advert
 * \brief Router Advertisement message.
 */
struct nd_router_advert
{
    struct icmpv6_hdr nd_ra_hdr; /**< ICMPv6 header */
    uint32_t nd_ra_reachable; /**< Reachable time */
    uint32_t nd_ra_retransmit; /**< Retransmit timer */
    /* could be followed by options */
}nd_router_advert;

/**
 * \struct nd_opt_hdr
 * \brief ICMPv6 option header.
 */
typedef struct nd_opt_hdr
{
    uint8_t nd_opt_type; /**< ICMPv6 option type */
    uint8_t nd_opt_len; /**< Length of the option (multiple of 8 bytes) */
}nd_opt_hdr;

/**
 * \struct nd_opt_rdnss
 * \brief ICMPv6 RDNSS option header.
 */
struct nd_opt_rdnss
{
    uint8_t nd_opt_rdnss_type; /**< ICMPv6 RDNSS option type = 25 */
    uint8_t nd_opt_rdnss_len; /**< Length of the option (multiple of 8 bytes) */
    uint16_t nd_opt_rdnss_resserved1; /**< Reserved value */
    uint32_t nd_opt_rdnss_lifetime; /**< Lifetime of the entry */
    /* followed by one or more IPv6 addresses */
}nd_opt_rdnss;

#pragma pack(pop)

/**
 * \brief Decode an ethernet frame.
 * \param packet the packet
 * \param len length of the packet
 * \return 0 if success, -1 otherwise
 * \note It returns 1 in case the packet is a Router Advertisement.
 */
int packet_decode_ethernet(const u_char* packet, size_t len);

/**
 * \brief Decode an IPv6 packet.
 * \param packet the packet
 * \param len length of the packet
 * \return 0 if success, -1 otherwise
 * \note It returns 1 in case the packet is a Router Advertisement.
 */
int packet_decode_ipv6(const u_char* packet, size_t len);

/**
 * \brief Decode an ICMPv6 packet.
 * \param packet the packet
 * \param len length of the packet
 * \return 0 if success, -1 otherwise
 * \note It returns 1 in case the packet is a Router Advertisement.
 */
int packet_decode_icmpv6(const u_char* packet, size_t len);

#endif /* PACKET_H */

