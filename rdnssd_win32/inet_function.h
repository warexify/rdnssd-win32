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

/*
* Copyright (C) 2006 Sebastien Vincent.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
* REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
* AND FITNESS. IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
* INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
* LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
* OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
* PERFORMANCE OF THIS SOFTWARE.
*/

#ifndef INET_FUNCTION_H
#define INET_FUNCTION_H

#include <sys/types.h>

#include <errno.h>

#if defined (_WIN32)  || defined(_WIN64)
#include <winsock2.h>
#define EAFNOSUPPORT WSAEAFNOSUPPORT
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

int inet_aton2(const char *cp, struct in_addr *inp);

int inet_pton2(int af, const char *src, void *dst);

const char *inet_ntop2(int af, const void * src, char * dst, size_t cnt);

#endif /* INET_FUNCTION_H */

