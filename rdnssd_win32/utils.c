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
 * \file utils.c
 * \brief Utils functions.
 * \author Sebastien Vincent
 * \date 2012
 */

#include "utils.h"

int gettimeofday(struct timeval* p, void* tz)
{
	union
    {
        long long ns100; /* time since 1 Jan 1601 in 100ns units */
        FILETIME ft;
    } timeofday;

	(void)tz;

    GetSystemTimeAsFileTime(&(timeofday.ft));
    p->tv_usec = (long)((timeofday.ns100 / 10LL) % 1000000LL);
    p->tv_sec =
		(long)((timeofday.ns100 - (116444736000000000LL)) / 10000000LL);
    return 0;
}

int clock_gettime(clockid_t clk_id, struct timespec *tp)
{
    struct timeval tv;

    clk_id = clk_id; /* not used */

    if(gettimeofday(&tv, NULL)==-1)
    {
        return -1;
    }

    tp->tv_sec = tv.tv_sec;
	/* convert microsecond to nanosecond */
    tp->tv_nsec = tv.tv_usec * 1000;
    return 0;
}

int is_run_as_administrator(void)
{
	int ret = 0;
	PSID adminGrp = NULL;
	SID_IDENTIFIER_AUTHORITY sidAuth = SECURITY_NT_AUTHORITY;

	if (!AllocateAndInitializeSid(&sidAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGrp))
	{
		/* error */
		return 0;
	}

	if (!CheckTokenMembership(NULL, adminGrp, &ret))
	{
		ret = 0;
	}

	FreeSid(adminGrp);

	return ret;
}
