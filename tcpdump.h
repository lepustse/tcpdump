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
#include <ethernetif.h>

#define TCPDUMP_MAX_MSG      (10)

#define PCAP_FILE_ID                (0xA1B2C3D4)
#define PCAP_VERSION_MAJOR          (0x200)
#define PCAP_VERSION_MINOR          (0x400)
#define GREENWICH_MEAN_TIME         (0)  
#define PRECISION_OF_TIME_STAMP     (0)
#define MAX_LENTH_OF_CAPTURE_PKG    (0xFFFF)
#define ETHERNET                    (1)

union rt_u32_data
{
    rt_uint32_t u32byte;
    rt_uint8_t  a[4];
};

union rt_u16_data
{
    rt_uint16_t u16byte;
    rt_uint8_t  a[2];
};

struct rt_pcap_file_header
{
    rt_uint32_t magic;           // 0xa1b2c3d4
    rt_uint16_t version_major;   // 0x0200
    rt_uint16_t version_minor;   // 0x0400
    rt_int32_t  thiszone;        // GMT
    rt_uint32_t sigfigs;         //
    rt_uint32_t snaplen;         //
    rt_uint32_t linktype;        // 1
};
typedef struct rt_pcap_file_header  rt_pcap_file_header_t;

struct rt_timeval
{
    rt_uint32_t tv_sec;          //    os_tick
    rt_uint32_t tv_msec;         //    os_tick
};

struct rt_pcap_pkthdr
{
    struct rt_timeval ts;
    rt_uint32_t caplen;
    rt_uint32_t len;
};    

struct rt_pcap_file
{
    struct rt_pcap_file_header   p_f_h;
    struct rt_pcap_pkthdr        p_pktdr;
    void *ip_mess;
    rt_size_t ip_len;
};

struct tcpdump_msg 
{
    void *pbuf;
    rt_uint32_t sec;
    rt_uint32_t msec;
};

#define PCAP_FILE_FORMAT_SIZE   (sizeof(struct rt_pcap_file_header) + sizeof(struct rt_pcap_pkthdr))

static void rt_struct_to_u8(struct rt_pcap_file *file, rt_uint8_t *buf);

#endif /* __FILE_H__ */
