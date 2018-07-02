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

static struct netif *netif;
static struct rt_messagequeue *mq;
static netif_linkoutput_fn link_output;
static char *filename;
static rt_uint32_t tcpdump_flag;

#define TCPDUMP_WRITE_FLAG (0x1 << 2)
#define TCPDUMP_DEFAULT_NAME    ("tcpdump_file.pcap")
#define TCPDUMP_FILE_SIZE(_file) \
    (sizeof(struct rt_pcap_file) + _file->ip_len) 

#define TCPDUMP_DEBUG
#ifdef TCPDUMP_DEBUG
#define __is_print(ch) ((unsigned int)((ch) - ' ') < 127u - ' ')
static void print_hex(const rt_uint8_t *ptr, rt_size_t buflen)
{
    unsigned char *buf = (unsigned char*)ptr;
    int i, j;

    for (i=0; i<buflen; i+=16) 
    {
        rt_kprintf("%08X: ", i);

        for (j=0; j<16; j++)
            if (i+j < buflen)
                rt_kprintf("%02X ", buf[i+j]);
            else
                rt_kprintf("   ");
        rt_kprintf(" ");

        for (j=0; j<16; j++)
            if (i+j < buflen)
                rt_kprintf("%c", __is_print(buf[i+j]) ? buf[i+j] : '.');
        rt_kprintf("\n");
    }
}

static void rt_tcpdump_file_print(struct rt_pcap_file *file)
{
    rt_uint8_t buf[PCAP_FILE_FORMAT_SIZE] = {0};
    
    if (file == RT_NULL)
    {
        rt_kprintf("file is null\n");
        return;
    }
    rt_kprintf("\n\n");
    rt_kprintf("-------------------------file header---------------------\n");
    rt_kprintf("magi       major  minor  zone   sigfigs  snaplen linktype\n");
    rt_kprintf("0x%08x ", file->p_f_h.magic);
    rt_kprintf("0x%04x ", file->p_f_h.version_major);
    rt_kprintf("0x%04x ", file->p_f_h.version_minor);
    rt_kprintf("0x%04x ", file->p_f_h.thiszone);
    rt_kprintf("0x%04x   ", file->p_f_h.sigfigs);
    rt_kprintf("0x%04x  ", file->p_f_h.snaplen);
    rt_kprintf("0x%04x\n\n", file->p_f_h.linktype);

    rt_kprintf("       msec         sec         len      caplen \n");
    rt_kprintf("%11d ", file->p_pktdr.ts.tv_msec);
    rt_kprintf("%11d ", file->p_pktdr.ts.tv_sec);
    rt_kprintf("%11d ", file->p_pktdr.len);
    rt_kprintf("%11d \n\n", file->p_pktdr.caplen);

    rt_struct_to_u8(file, buf);
    print_hex(buf, sizeof(buf));
    print_hex(file->ip_mess, file->ip_len);
    rt_kprintf("---------------------------end---------------------------\n");
    rt_kprintf("\n\n");
}
#endif

static struct rt_pcap_file *rt_tcpdump_pcap_file_create(struct pbuf *p)
{
    struct rt_pcap_file *file = RT_NULL;
    struct pbuf *pbuf = p;
    struct tcpdump_msg msg;
    rt_uint8_t *ip_mess = RT_NULL;
    rt_size_t ip_len = p->tot_len;
    
    file = rt_malloc(sizeof(struct rt_pcap_file) + ip_len);
    if (file == RT_NULL)
        return RT_NULL;
    file->ip_mess = (rt_uint8_t *)file + sizeof(struct rt_pcap_file);
    file->ip_len = ip_len;
    
    file->p_f_h.magic = PCAP_FILE_ID;
    file->p_f_h.version_major = PCAP_VERSION_MAJOR;
    file->p_f_h.version_minor = PCAP_VERSION_MINOR;
    file->p_f_h.thiszone = GREENWICH_MEAN_TIME;
    file->p_f_h.sigfigs = PRECISION_OF_TIME_STAMP;
    file->p_f_h.snaplen = MAX_LENTH_OF_CAPTURE_PKG;
    file->p_f_h.linktype = ETHERNET;

    file->p_pktdr.ts.tv_sec = msg.sec;      //  os_tick
    file->p_pktdr.ts.tv_msec = msg.msec;    //  os_tick
    file->p_pktdr.caplen = ip_len;          //  ip len
    file->p_pktdr.len = ip_len;             //

    ip_mess = p->payload;
    while (p) 
    {
        rt_memcpy(file->ip_mess, ip_mess, p->len);
        ip_mess += p->len;
        p = p->next;
    }
    pbuf_free(pbuf);

    return file;
}

static rt_err_t rt_tcpdump_pcap_file_del(struct rt_pcap_file *file)
{
    if (file == RT_NULL)
        return -RT_ERROR;
    rt_free(file);
    return RT_EOK;
}

static rt_err_t rt_tcpdump_pcap_file_write(struct rt_pcap_file *file, rt_size_t len)
{
    int fd, length;

    if (filename == RT_NULL) 
    {
        rt_kprintf("file name failed\n");
        return -RT_ERROR;
    }

    /* write and append */
    fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, 0);
    if (fd < 0) 
    {
        rt_kprintf("open file for write failed\n");
        return -RT_ERROR;
    }

    /* write pcap file */
    length = write(fd, file, len);
    if (length != len)
    {
        rt_kprintf("write data failed\n");
        close(fd);
        return -RT_ERROR;
    }
    close(fd);

    rt_kprintf("tcpdump file write done.\n");
    return RT_EOK;
}

static struct pbuf *rt_tcpdump_ip_mess_recv(void)
{
    struct tcpdump_msg msg;
    struct pbuf *p;

    if (rt_mq_recv(mq, &msg, sizeof(msg), RT_WAITING_FOREVER) == RT_EOK) 
    {
        p = msg.pbuf;
        return p;
    } 
    else 
    {
        return RT_NULL;
    }
}

static err_t _netif_linkoutput(struct netif *netif, struct pbuf *p)
{
    struct tcpdump_msg msg;
    rt_uint32_t tick = rt_tick_get();

    if (p != RT_NULL) 
    {
        pbuf_ref(p);
        msg.pbuf = p;
        msg.sec  = tick / 1000;
        msg.msec = tick % 1000;

        if (rt_mq_send(mq, &msg, sizeof(msg)) != RT_EOK) 
        {
            rt_kprintf("mq send failed\n");
            pbuf_free(p);
            return -RT_ERROR;
        }
    }
    return link_output(netif, p);
}

static void rt_struct_to_u8(struct rt_pcap_file *file, rt_uint8_t *buf)
{
    union rt_u32_data u32_data;
    union rt_u16_data u16_data;
    int k, i, j;
    
    struct rt_pcap_file_header *p_p_f_h = (struct rt_pcap_file_header *)file;
    rt_uint32_t *p32_p_f_h = (rt_uint32_t *)p_p_f_h + 2;

    struct rt_pcap_pkthdr *p32_pktdr = (struct rt_pcap_pkthdr *)(p_p_f_h + 1);
    rt_uint32_t *p32 = (rt_uint32_t *)p32_pktdr;

    rt_uint16_t *p16 = (rt_uint16_t *)p_p_f_h + 2;

    /* struct rt_pcap_file_header. magic */
    u32_data.u32byte = 0;
    u32_data.u32byte = file->p_f_h.magic;
    for (k = 3; k != -1; k--)
        buf[k] = u32_data.a[k];
    
    /* struct rt_pcap_file_header. version_major & version_minor*/
    for (i = 0, j = 4; i < 4; i++)
    {
        u16_data.u16byte = 0;
        u16_data.u16byte = *(p16 + 0);
        for (k = 1; k != -1; k--) 
        {
            buf[k+j] = u16_data.a[k];
        }
        j += 4;
    }

    /* struct rt_pcap_header.thiszone ~ linktype */
    for (i = 0, j = 8; i < 4; i++) 
    {
        u32_data.u32byte = 0;
        u32_data.u32byte = *(p32_p_f_h + i);
        for (k = 3; k != -1; k--) 
        {
            buf[k+j] = u32_data.a[k];
        }
        j += 4;
    }
    /* struct rt_pcap_header */
    for (i = 0, j = 24; i < 4; i++) 
    {
        u32_data.u32byte = 0;
        u32_data.u32byte = *(p32 + i);
        for (k = 3; k != -1; k--) 
        {
            buf[k+j] = u32_data.a[k];
        }
        j += 4;
    }
}

static void rt_tcp_dump_thread(void *param)
{
    struct rt_pcap_file *file = RT_NULL;
    struct pbuf *p = RT_NULL;

    while (1) 
    {
        p = rt_tcpdump_ip_mess_recv();

        file = rt_tcpdump_pcap_file_create(p);

        if ((tcpdump_flag & TCPDUMP_WRITE_FLAG) && (file != RT_NULL))
        {
            if (rt_tcpdump_pcap_file_write(file, TCPDUMP_FILE_SIZE(file)) != RT_EOK)
            {
                rt_kprintf("tcp dump write file fail\nstop write file\n");
                tcpdump_flag &= ~TCPDUMP_WRITE_FLAG;
            }
        }
        
#ifdef TCPDUMP_DEBUG
        rt_tcpdump_file_print(file);
#endif
        rt_tcpdump_pcap_file_del(file);
    }
}

/**
 * This function will enable to write into file system.
 *
 * @param none.
 *
 * @return none.
 */
void rt_tcpdump_write_enable(void)
{
    tcpdump_flag |= TCPDUMP_WRITE_FLAG;
}

/**
 * This function will disable to write into file system.
 *
 * @param none.
 *
 * @return none.
 */
void rt_tcpdump_write_disable(void)
{
    tcpdump_flag &= ~TCPDUMP_WRITE_FLAG;
}

/**
 * This function will set filename.
 *
 * @param name.
 *
 * @return none.
 */
void rt_tcpdump_set_filename(const char *name)
{
    if (filename != RT_NULL) 
    {
        rt_free(filename);
    }

    filename = rt_strdup(name);
}

/**
 * This function will initialize thread, mailbox, device etc.
 *
 * @param none.
 *
 * @return status.
 */
int rt_tcp_dump_init(void)
{
    static struct eth_device *dev = RT_NULL;
    struct rt_thread *tid = RT_NULL;
    rt_base_t level;
    
    dev = (struct eth_device *)rt_device_find("e0");
    if (dev == RT_NULL)
        return -RT_ERROR;

    mq = rt_mq_create("tcp_dump", sizeof(struct tcpdump_msg), TCPDUMP_MAX_MSG, RT_IPC_FLAG_FIFO);
    if (mq == RT_NULL) 
    {
        rt_kprintf("mq error\n");
        return -RT_ERROR;
    }

    tid = rt_thread_create("tcp_dump", rt_tcp_dump_thread, RT_NULL, 2048, 10, 10);
    if (tid == RT_NULL) 
    {
        rt_kprintf("tcp dump thread create fail\n");
        rt_mq_delete(mq);
        return -RT_ERROR;
    }
    rt_tcpdump_set_filename("test1.pcap");
    level = rt_hw_interrupt_disable();
    netif = dev->netif;
    link_output = netif->linkoutput;    //   save
    netif->linkoutput = _netif_linkoutput;
    rt_hw_interrupt_enable(level);
    rt_thread_startup(tid);
    return RT_EOK;
}
INIT_APP_EXPORT(rt_tcp_dump_init);

/**
 * This function will reset thread, mailbox, device etc.
 *
 * @param none.
 *
 * @return none.
 */
void rt_tcpdump_deinit(void)
{
    rt_base_t level;
    
    level = rt_hw_interrupt_disable();
    netif->linkoutput = link_output;
    netif = RT_NULL;
    rt_mq_delete(mq);
    rt_hw_interrupt_enable(level);
    mq = RT_NULL;
}

void tcpdump_init(void)
{
    rt_tcp_dump_init();
}
MSH_CMD_EXPORT(tcpdump_init, init);

void tcpdump_deinit(void)
{
    rt_tcp_dump_init();
}
MSH_CMD_EXPORT(tcpdump_deinit, deinit);

void tcpdump_save(void)
{
    rt_tcpdump_write_enable();
}
MSH_CMD_EXPORT(tcpdump_save, save);

int tcpdump_name(int argc, char *argv[])
{
    if (argc != 2)   
    {
        rt_kprintf("user: tcpdump filename\n");
    }
    rt_tcpdump_set_filename(argv[1]);
    rt_kprintf("set file name: %s\n", argv[1]);
    return 0;
}
MSH_CMD_EXPORT(tcpdump_name, my command with args);