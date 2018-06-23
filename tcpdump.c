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

#include <rtthread.h>
#include <dfs_posix.h>
#include <rtdef.h>
#include "tcpdump.h"
#include <stdio.h>

extern rt_mailbox_t tcpdump_mb;

#if 1
rt_uint8_t ip[74] =
{
    0x00, 0x04, 0x9f, 0x05, 0x44, 0xe5, 0xe0, 0xd5, 0x5e, 0x71, 0x99, 0x95, 0x08, 0x00, 0x45, 0x00,
    0x00, 0x3c, 0x28, 0x6a, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x6d, 0xc0, 0xa8,
    0x01, 0x1e, 0x08, 0x00, 0x4d, 0x1a, 0x00, 0x01, 0x00, 0x41, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
    0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
    0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69
};
#endif

rt_pcap_file_t *rt_creat_pcap_file(rt_ip_mess_t *pkg)
{
    rt_pcap_file_t *file = RT_NULL;

    file = rt_malloc(sizeof(struct rt_pcap_file) + pkg->len);
    if (file == RT_NULL)
        return RT_NULL;
    file->ip_mess = (rt_uint8_t *)file + sizeof(struct rt_pcap_file);

    file->p_f_h.magic = 0xa1b2c3d4;
    file->p_f_h.version_major = 0x200;
    file->p_f_h.version_minor = 0x400;
    file->p_f_h.thiszone = 0;
    file->p_f_h.sigfigs = 0;
    file->p_f_h.snaplen = 0xff;
    file->p_f_h.linktype = 1;

    file->p_h.ts.tv_sec = 0;   //  os_tick
    file->p_h.ts.tv_msec = 0;  //  os_tick
    file->p_h.caplen = pkg->len;   //  ip len
    file->p_h.len = pkg->len;      //

    rt_memcpy(file->ip_mess, pkg->payload, pkg->len);
    file->ip_len = pkg->len;

    return file;
}

int rt_del_pcap_file(rt_pcap_file_t *file)
{
    if (file == RT_NULL)
        return -1;
    rt_free(file);
    return 0;
}

int rt_save_pcap_file(rt_pcap_file_t *file, const char *filename)
{
    int fd, length;

    fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0);
    if (fd < 0)
    {
        rt_kprintf("open file for write failed\n");
        return -1;
    }

    length = write(fd, ip, sizeof(ip));
    if (length != sizeof(ip))
    {
        rt_kprintf("write data failed\n");
        close(fd);
        return -1;
    }
    close(fd);
//    /* write file */
//    length = write(fd, file, sizeof(rt_pcap_file_t) - PCAP_HEADER_LENGTH);
//    if (length != sizeof(rt_pcap_file_t) - PCAP_HEADER_LENGTH)
//    {
//        rt_kprintf("write data failed\n");
//        close(fd);
//        return -1;
//    }
//    rt_kprintf("fd:%d\n", fd);
//    close(fd);

//    fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, 0);
//    if (fd < 0)
//    {
//        rt_kprintf("open file for append write failed\n");
//        return -1;
//    }
//    length = write(fd, ip, sizeof(ip));
//    if (length != file->ip_len)
//    {
//        rt_kprintf("append write data failed\n");
//        close(fd);
//        return -1;
//    }
//    close(fd);

    rt_kprintf("read/write done.\n");
    return 0;
}

void rt_send_ip_mess(struct pbuf *p)
{
    if (rt_mb_send(tcpdump_mb, (rt_uint32_t)p) == RT_EOK)
    {
        pbuf_ref(p);
    }
}

rt_ip_mess_t *rt_recv_ip_mess(void)
{
    struct pbuf *p;
    rt_ip_mess_t *pkg;
    rt_uint8_t *ptr;
    rt_uint32_t mbval;

    if (rt_mb_recv(tcpdump_mb, &mbval, RT_WAITING_FOREVER) == RT_EOK)
    {
        p = (struct pbuf *)mbval;

        pkg = rt_malloc(sizeof(struct rt_ip_mess) + p->tot_len);
        if (pkg == RT_NULL)
            return RT_NULL;

        pkg->payload = (rt_uint8_t *)pkg + sizeof(struct rt_ip_mess);
        pkg->len = p->tot_len;

        ptr = pkg->payload;

        while (p)
        {
            rt_memcpy(ptr, p->payload, p->len);
            ptr += p->len;
            p = p->next;
        }
        return pkg;
    }
    else
    {
        return RT_NULL;
    }
}

int rt_del_ip_mess(struct rt_ip_mess *pkg)
{
    if (pkg == RT_NULL)
    {
        return -1;
    }
    else
    {
        rt_free(pkg);
        return 0;
    }
}

void rt_tcp_dump_thread(void *param)
{
    struct rt_ip_mess *p;
    int i = 0, j = 0;
    rt_uint32_t mbval;
    rt_uint8_t *ptr;
    rt_pcap_file_t *file;
    int res = -1;
    while (1)
    {
        p = rt_recv_ip_mess();

        if (p != RT_NULL)
        {
            //  rt_kprintf("malloc ok\n");

            file = rt_creat_pcap_file(p);
//            if (res == -1)
//                res = rt_save_pcap_file(file, "s5.pcap");

            rt_kprintf("%x ", file->p_f_h.magic);
            rt_kprintf("%x ", file->p_f_h.version_major);
            rt_kprintf("%x ", file->p_f_h.version_minor);
            rt_kprintf("%x ", file->p_f_h.thiszone);
            rt_kprintf("%x ", file->p_f_h.sigfigs);
            rt_kprintf("%x ", file->p_f_h.snaplen);
            rt_kprintf("%x ", file->p_f_h.linktype);

            rt_kprintf("%x ", file->p_h.ts.tv_msec);
            rt_kprintf("%x ", file->p_h.ts.tv_sec);
            rt_kprintf("%x ", file->p_h.len);
            rt_kprintf("%x ", file->p_h.caplen);
            ptr = p->payload;

            for (j = 0; j < p->len; j++)
            {
                if ((i % 8) == 0)
                {
                    rt_kprintf("  ");
                }
                if ((i % 16) == 0)
                {
                    rt_kprintf("\r\n");
                }
                rt_kprintf("%02x ", *ptr);

                i++;
                ptr++;
            }
            rt_kprintf("\n\n");

            rt_del_ip_mess(p);
            rt_del_pcap_file(file);
        }
        else
        {
            return;
        }
    }
}
