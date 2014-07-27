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
 * \file utils.h
 * \brief Utils functions.
 * \author Sebastien Vincent
 * \date 2012
 */

#ifndef UTILS_H
#define UTILS_H

#include <WinSock2.h>

/**
 * \enum clockid_t
 * \brief Different type of clock (used with clock_* function).
 */
typedef enum clockid_t
{
    CLOCK_REALTIME, /**< \brief The realtime clock. */
    CLOCK_MONOTONIC /**< \brief The monotonic clock. */
}clockid_t;

/**
 * \struct timespec
 * \brief The timespec structure for Windows.
 */
struct timespec
{
    time_t tv_sec; /**< \brief Seconds. */
    long tv_nsec; /**< \brief Nanoseconds. */
};

/**
 * \brief An implementation of gettimeofday for Windows.
 * \param p the time will be filled in
 * \param tz timezone (it is ignored).
 * \return 0
 */
int gettimeofday(struct timeval* p, void* tz);

/**
 * \brief A clock_gettime function replacement.
 * \param clk_id the type of clock we want
 * \param tp structure that will be filled with the time
 * \return 0 if success, negative integer otherwise
 */
int clock_gettime(clockid_t clk_id, struct timespec *tp);

/**
 * \brief Returns whether or not the code is run as administrator.
 * \return 1 if run as administrator, 0 otherwise.
 */
int is_run_as_administrator(void);

#endif
