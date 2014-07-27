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
 * \file packet.h
 * \brief ICMPv6 headers and parsing.
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

/* forward declaration (socket_desc is defined in rdnssd.c) */
struct socket_desc;

/**
 * \brief Decode an ICMPv6 packet.
 * \param sock socket information
 * \param packet the packet
 * \param len length of the packet
 * \return 0 if success, -1 otherwise
 * \note It returns 1 in case the packet is a Router Advertisement.
 */
int packet_decode_icmpv6(struct socket_desc* sock, const char* packet,
	size_t len);

#endif /* PACKET_H */
