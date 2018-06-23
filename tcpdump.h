/*
 * File      : tcpdump.c
 * This is file that captures the IP message based on the RT-Thread
 * and saves in the file system.
 * COPYRIGHT (C) 2006 - 2018, RT-Thread Development Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Change Logs:
 * Date           Author       Notes
 * 2018-06-21     never        the first version
 */
#ifndef __TCPDUMP_H_
#define __TCPDUMP_H_
/* header file content */

#include <rtdef.h>
#include "netif/ethernetif.h"

struct rt_ip_mess
{
    rt_uint8_t *payload;
    rt_uint16_t len;
};
typedef struct rt_ip_mess rt_ip_mess_t;

struct rt_pcap_file_header
{
    rt_uint32_t magic;           // 0xa1b2c3d4
    rt_uint16_t version_major;   // 0x0200
    rt_uint16_t version_minor;   // 0x0400
    rt_int32_t thiszone;         // 0
    rt_uint32_t sigfigs;         //
    rt_uint32_t snaplen;         //
    rt_uint32_t linktype;        // 1
};

struct rt_timeval
{
    rt_uint32_t tv_sec;          //    os_tick
    rt_uint32_t tv_msec;         //    os_tick
};

struct rt_pcap_header
{
    struct rt_timeval ts;
    rt_uint32_t caplen;
    rt_uint32_t len;
};    

struct rt_pcap_file
{
    struct rt_pcap_file_header   p_f_h;
    struct rt_pcap_header        p_h;
    void *ip_mess;
    size_t ip_len;
};
typedef struct rt_pcap_file    rt_pcap_file_t;

#define PCAP_HEADER_LENGTH    (8)

rt_pcap_file_t *rt_creat_pcap_file(rt_ip_mess_t *pkg);
int rt_del_pcap_file(rt_pcap_file_t *file);
int rt_save_pcap_file(rt_pcap_file_t *file, const char *filename);
rt_ip_mess_t *rt_recv_ip_mess(void);
void rt_send_ip_mess(struct pbuf *p);
int rt_del_ip_mess(struct rt_ip_mess *pkg);

#endif /* __FILE_H__ */
