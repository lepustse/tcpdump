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

static struct netif *netif;
static rt_mailbox_t mb;
static netif_linkoutput_fn link_output;

#if 0
rt_uint8_t ip[74] =
{
    0x00, 0x04, 0x9f, 0x05, 0x44, 0xe5, 0xe0, 0xd5, 0x5e, 0x71, 0x99, 0x95, 0x08, 0x00, 0x45, 0x00,
    0x00, 0x3c, 0x28, 0x6a, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x6d, 0xc0, 0xa8,
    0x01, 0x1e, 0x08, 0x00, 0x4d, 0x1a, 0x00, 0x01, 0x00, 0x41, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
    0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
    0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69
};

rt_uint8_t buf[42] = 
{
    0x30, 0x52, 0xcb, 0x7d, 0x75, 0x47, 0x00, 0x04, 0x9f, 0x05, 0x44, 0xe5, 0x08, 0x06, 0x00, 0x01,   
    0x08, 0x00, 0x06, 0x04, 0x00, 0x02, 0x00, 0x04, 0x9f, 0x05, 0x44, 0xe5, 0xc0, 0xa8, 0x01, 0x1e,   
    0x30, 0x52, 0xcb, 0x7d, 0x75, 0x47, 0xc0, 0xa8, 0x01, 0x79
};
#endif

/**
 * This function will create a PCAP-formatted file.
 *
 * @param pkg IP packets that need to be processed.
 *
 * @return PCAP-formatted file.
 */
rt_pcap_file_t *rt_creat_pcap_file(rt_ip_mess_t *pkg)
{
    rt_pcap_file_t *file = RT_NULL;

    file = rt_malloc(sizeof(struct rt_pcap_file) + pkg->len);
    if (file == RT_NULL)
        return RT_NULL;
    file->ip_mess = (rt_uint8_t *)file + sizeof(struct rt_pcap_file);

    file->p_f_h.magic = PCAP_FILE_ID;
    file->p_f_h.version_major = PCAP_VERSION_MAJOR;
    file->p_f_h.version_minor = PCAP_VERSION_MINOR;
    file->p_f_h.thiszone = GREENWICH_MEAN_TIME;
    file->p_f_h.sigfigs = PRECISION_OF_TIME_STAMP;
    file->p_f_h.snaplen = MAX_LENTH_OF_CAPTURE_PKG;
    file->p_f_h.linktype = ETHERNET;

    file->p_h.ts.tv_sec = 0;        //  os_tick
    file->p_h.ts.tv_msec = 0;       //  os_tick
    file->p_h.caplen = pkg->len;    //  ip len
    file->p_h.len = pkg->len;       //

    rt_memcpy(file->ip_mess, pkg->payload, pkg->len);
    file->ip_len = pkg->len;

    return file;
}

/**
 * This function will capture the time that the IP message was received.
 *
 * @param flag second or millisecond.
 *
 * @return the time captured.
 */
rt_uint32_t rt_capture_time(rt_uint8_t flag)
{
    rt_uint32_t tick = rt_tick_get();

    if (flag == SECOND)
    {
        return (tick / 1000);
    }
    else if (flag == MILLISECOND)
    {
        return (tick % 1000);
    }
    else
    {
        return 0;
    }
}

/**
 * This function will delete the PCAP-formatted file.
 *
 * @param file PCAP-formatted file.
 *
 * @return status.
 */
int rt_del_pcap_file(rt_pcap_file_t *file)
{
    if (file == RT_NULL)
        return -1;
    rt_free(file);
    return 0;
}

/**
 * This function will save the PCAP-formatted file in File system.
 *
 * @param file PCAP-formatted file.
 * @param filename save it with name.
 *
 * @return status.
 */
int rt_save_pcap_file(rt_pcap_file_t *file, const char *filename)
{
    int fd, length;
    rt_uint8_t *ptr;
    int i, j;

    fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0);
    if (fd < 0)
    {
        rt_kprintf("open file for write failed\n");
        return -1;
    }

    /* write file */
    length = write(fd, file, sizeof(file->p_f_h) + sizeof(file->p_h));

    if (length != sizeof(file->p_f_h) + sizeof(file->p_h))
    {
        rt_kprintf("write data failed\n");
        close(fd);
        return -1;
    }
    close(fd);

    /* open file */
    fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, 0);
    if (fd < 0)
    {
        rt_kprintf("open file for append write failed\n");
        return -1;
    }
    
    /* append file */
    length = write(fd, (rt_uint8_t *)file->ip_mess, file->ip_len);
    if (length != file->ip_len)
    {
        rt_kprintf("append write data failed\n");
        close(fd);
        return -1;
    }
    close(fd);

    rt_kprintf("read/write done.\n");
    return 0;
}


/**
 * This function will receive IP message from mailbox and save.
 *
 * @param none.
 *
 * @return IP message.
 */
rt_ip_mess_t *rt_recv_ip_mess(void)
{
    struct pbuf *p, *pbuf;
    rt_ip_mess_t *pkg;
    rt_uint8_t *ptr;
    rt_uint32_t mbval;

    if (rt_mb_recv(mb, &mbval, RT_WAITING_FOREVER) == RT_EOK)
    {
        p = (struct pbuf *)mbval;
        pbuf = p;

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
        pbuf_free(pbuf);
        return pkg;
    }
    else
    {
        return RT_NULL;
    }
}

/**
 * This function will delete IP message.
 *
 * @param pkg IP message.
 *
 * @return status.
 */
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

static err_t _netif_linkoutput(struct netif *netif, struct pbuf *p)
{
    pbuf_ref(p);

    if (rt_mb_send(mb, (rt_uint32_t)p) != RT_EOK)
    {
        pbuf_free(p);
    }

    link_output(netif, p);
}

/**
 * This function will print PCAP-formatted file in serial terminal.
 *
 * @param file PCAP-formatted file.
 *
 * @return none.
 */
void rt_printf_pcap_file(rt_pcap_file_t *file)
{
    rt_u32_data_t u32_data;
    rt_u16_data_t u16_data;
    int k, i, j;
    rt_uint8_t *ptr = file->ip_mess;
    rt_pcap_file_header_t *p_p_f_h = (rt_pcap_file_header_t *)file;
    rt_uint32_t *p32_p_f_h = (rt_uint32_t *)p_p_f_h + 2;

    rt_pcap_header_t *p32_p_h = (rt_pcap_header_t *)(p_p_f_h + 1);
    rt_uint32_t *p32 = (rt_uint32_t *)p32_p_h;

    rt_uint16_t *p16 = (rt_uint16_t *)p_p_f_h + 2;

    /* struct rt_pcap_file_header. magic */
    u32_data.u32byte = 0;
    u32_data.u32byte = file->p_f_h.magic;
    for (k = 3; k != -1; k--)
        rt_kprintf("%02x ", u32_data.a[k]);

    /* struct rt_pcap_file_header. version_major & version_minor*/
    for (i = 0, j = 0; i < 2; i++)
    {
        u16_data.u16byte = 0;
        u16_data.u16byte = *(p16 + i);
        for (k = 1; k != -1; k--)
        {
            rt_kprintf("%02x ", u16_data.a[k]);
            j++;
        }
        if (j % 4 == 0)
        {
            rt_kprintf("  ");
        }
    }

    /* struct rt_pcap_header.thiszone ~ linktype */
    for (i = 0, j = 0; i < 4; i++)
    {
        u32_data.u32byte = 0;
        u32_data.u32byte = *(p32_p_f_h + i);
        for (k = 3; k != -1; k--)
        {

            rt_kprintf("%02x ", u32_data.a[k]);
            j++;
        }
        if (j == 8)
        {
            rt_kprintf("\r\n");
        }
        if (j == 16)
        {
            rt_kprintf("  ");
        }
    }
    /* struct rt_pcap_header */
    for (i = 0, j = 0; i < 4; i++)
    {
        u32_data.u32byte = 0;
        u32_data.u32byte = *(p32 + i);
        for (k = 3; k != -1; k--)
        {

            rt_kprintf("%02x ", u32_data.a[k]);
            j++;
        }
        if (j == 8)
        {
            rt_kprintf("\r\n");
        }
        if (j == 16)
        {
            rt_kprintf("  ");
        }
    }

    for (i = 0, j = 0; i < file->ip_len; i++)
    {
        if ((j % 8) == 0)
        {
            rt_kprintf("  ");
        }
        if ((j % 16) == 0)
        {
            rt_kprintf("\r\n");
        }
        rt_kprintf("%02x ", *ptr);

        j++;
        ptr++;
    }
    rt_kprintf("\n\n");
}

/**
 * This function is tcpdump thread entry.
 *
 * @param param.
 *
 * @return none.
 */
void rt_tcp_dump_thread(void *param)
{
    struct rt_ip_mess *p;
    rt_pcap_file_t *file;

    while (1)
    {
        p = rt_recv_ip_mess();

        if (p != RT_NULL)
        {
            file = rt_creat_pcap_file(p);
            
            rt_save_pcap_file(file, SAVE_NAME);

            rt_printf_pcap_file(file);

            rt_del_ip_mess(p);
            rt_del_pcap_file(file);
        }
        else
        {
            rt_kprintf("malloc error\n");
            return;
        }
    }
}

/**
 * This function will initialize thread, mailbox, device etc.
 *
 * @param none.
 *
 * @return status.
 */
rt_err_t rt_tcp_dump_init(void)
{
    static struct eth_device *dev;
    struct rt_thread *tid;

    dev = (struct eth_device *)rt_device_find("e0");
    if (dev == RT_NULL)
        return -RT_ERROR;

    mb = rt_mb_create("tcp_dump", 10, RT_IPC_FLAG_FIFO);
    if (mb == RT_NULL)
        return -RT_ERROR;

    tid = rt_thread_create("tcp_dump", rt_tcp_dump_thread, RT_NULL, 2048, 10, 10);
    if (tid == RT_NULL)
    {
        rt_mb_delete(mb);
        rt_kprintf("tcp dump thread create fail\n");
        return -RT_ERROR;
    }

    netif = dev->netif;
    link_output = netif->linkoutput;    //   save
    netif->linkoutput = _netif_linkoutput;

    rt_thread_startup(tid);
    return RT_EOK;
}
INIT_APP_EXPORT(rt_tcp_dump_init);