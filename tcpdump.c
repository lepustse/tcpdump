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
 * 2018-07-05     never        the first version
 */

#include <rtthread.h>
#include <dfs_posix.h>
#include <rtdef.h>
#include <stdio.h>
#include "netif/ethernetif.h"

union rt_u32_data
{
    rt_uint32_t u32byte;
    rt_uint8_t a[4];
};

union rt_u16_data
{
    rt_uint16_t u16byte;
    rt_uint8_t a[2];
};

struct rt_pcap_file_header
{
    rt_uint32_t magic;           // 0xa1b2c3d4
    rt_uint16_t version_major;   // 0x0200
    rt_uint16_t version_minor;   // 0x0400
    rt_int32_t thiszone;         // Greenwich Mean Time
    rt_uint32_t sigfigs;         //
    rt_uint32_t snaplen;         //
    rt_uint32_t linktype;        // ethernet
};

struct rt_timeval
{
    rt_uint32_t tv_sec;          // os_tick
    rt_uint32_t tv_msec;         // os_tick
};

struct rt_pkthdr
{
    struct rt_timeval ts;
    rt_uint32_t caplen;
    rt_uint32_t len;
};

#define DBG_ENABLE
//#undef  DBG_ENABLE
#define DBG_SECTION_NAME  "[TCPDUMP]"
#define DBG_LEVEL         DBG_INFO
#define DBG_COLOR
#include <rtdbg.h>

#define TCPDUMP_MAX_MSG             (10)
#define TCPDUMP_DEFAULT_NAME        ("sample.pcap")

#define PCAP_FILE_ID                (0xA1B2C3D4)
#define PCAP_VERSION_MAJOR          (0x200)
#define PCAP_VERSION_MINOR          (0x400)
#define GREENWICH_MEAN_TIME         (0)
#define PRECISION_OF_TIME_STAMP     (0)
#define MAX_LENTH_OF_CAPTURE_PKG    (0xFFFF)
#define ETHERNET                    (1)

#define PCAP_FILE_HEADER_SIZE       (24)
#define PCAP_PKTHDR_SIZE            (16)

#define TICK_1_MS                   (1000)

//#define PACP_FILE_HEADER_CREEATE(_head)             \
//    do {                                            \
//    (_head)->magic = PCAP_FILE_ID;                  \
//    (_head)->version_major = PCAP_VERSION_MAJOR;    \
//    (_head)->version_minor = PCAP_VERSION_MINOR;    \
//    (_head)->thiszone = GREENWICH_MEAN_TIME;        \
//    (_head)->sigfigs = PRECISION_OF_TIME_STAMP;     \
//    (_head)->snaplen = MAX_LENTH_OF_CAPTURE_PKG;    \
//    (_head)->linktype = ETHERNET;                   \
//    } while (0)

//#define PACP_PKTHDR_CREEATE(_head, _p)                   \
//    do {                                                 \
//    (_head)->ts.tv_sec  = (rt_tick_get() / TICK_1_MS);   \
//    (_head)->ts.tv_msec = (rt_tick_get() % TICK_1_MS);   \
//    (_head)->caplen = _p->tot_len;                       \
//    (_head)->len = _p->tot_len;                          \
//    } while (0)

static struct rt_mailbox *tcpdump_mb;
static struct netif *netif;
static netif_linkoutput_fn link_output;
static char *filename;

static netif_input_fn input;

static int fd = -1;
static int close_flag;
static int count;
static int pkt_count;
static int name_change;
static int stop_count = 1;

void rt_tcpdump_deinit(void);

#define TCPDUMP_DEBUG
#ifdef  TCPDUMP_DEBUG
#define __is_print(ch) ((unsigned int)((ch) - ' ') < 127u - ' ')
static void dump_hex(const rt_uint8_t *ptr, rt_size_t buflen)
{
    unsigned char *buf = (unsigned char *)ptr;
    int i, j;

    RT_ASSERT(ptr != RT_NULL);
    
    for (i = 0; i < buflen; i += 16)
    {
        rt_kprintf("%08X: ", i);

        for (j = 0; j < 16; j++)
            if (i + j < buflen)
                rt_kprintf("%02X ", buf[i + j]);
            else
                rt_kprintf("   ");
        rt_kprintf(" ");

        for (j = 0; j < 16; j++)
            if (i + j < buflen)
                rt_kprintf("%c", __is_print(buf[i + j]) ? buf[i + j] : '.');
        rt_kprintf("\n");
    }
}

static void rt_tcpdump_ip_mess_print(struct pbuf *p)
{
    rt_uint8_t *buf = (rt_uint8_t *)rt_malloc(p->tot_len);
    
    RT_ASSERT(buf != RT_NULL);
    
    pbuf_copy_partial(p, buf, p->tot_len, 0);
    
    dump_hex(buf, p->tot_len);
    
    rt_free(buf);
}

#endif

static err_t _netif_linkoutput(struct netif *netif, struct pbuf *p)
{
    RT_ASSERT(netif != RT_NULL);
    
    if (p != RT_NULL)
    {
        pbuf_ref(p);

        if (rt_mb_send(tcpdump_mb, (rt_uint32_t)p) != RT_EOK)
        {
            pbuf_free(p);
        }
    }
    return link_output(netif, p);
}

static err_t _netif_input(struct pbuf *p, struct netif *inp)
{
    RT_ASSERT(inp != RT_NULL);
    
    if (p != RT_NULL)
    {
        pbuf_ref(p);
        if (rt_mb_send(tcpdump_mb, (rt_uint32_t)p) != RT_EOK)
        {
            pbuf_free(p);
        }
    }
    return input(p, inp);
}

static void rt_tcpdump_pcap_file_header_create(struct rt_pcap_file_header *file_header)
{
    file_header->magic = PCAP_FILE_ID;                  
    file_header->version_major = PCAP_VERSION_MAJOR;    
    file_header->version_minor = PCAP_VERSION_MINOR;    
    file_header->thiszone = GREENWICH_MEAN_TIME;        
    file_header->sigfigs = PRECISION_OF_TIME_STAMP;     
    file_header->snaplen = MAX_LENTH_OF_CAPTURE_PKG;    
    file_header->linktype = ETHERNET;                   
}

static void rt_tcpdump_pcap_pkthdr_create(struct rt_pkthdr *pkthdr, struct pbuf *p)
{
    pkthdr->ts.tv_sec  = rt_tick_get() / TICK_1_MS;   
    pkthdr->ts.tv_msec = rt_tick_get() % TICK_1_MS;   
    pkthdr->caplen = p->tot_len;                       
    pkthdr->len = p->tot_len;                                             
}

static rt_err_t rt_tcpdump_pcap_file_write(void *buf, int len)
{
    int length;

    if (filename == RT_NULL)
    {
        dbg_log(DBG_ERROR, "file name is null\n");
        return -RT_ERROR;
    }

    if ((len == 0) && (fd > 0))
    {
        dbg_log(DBG_ERROR, "ip mess error and close file\n");
        close(fd);
        fd = -1;
    }

    rt_kprintf("fd? %d\n", fd);
    rt_kprintf("count: %d\n", count);
    if (fd < 0)
    {
        fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0);
        if (fd < 0)
        {
            dbg_log(DBG_ERROR, "append. open file failed\n");
            return -RT_ERROR;
        }
    }

    length = write(fd, buf, len);
    if (length != len)
    {
        dbg_log(DBG_ERROR, "write data failed, length: %d\n", length);
        close(fd);
        return -RT_ERROR;
    }

    return RT_EOK;
}

static rt_err_t rt_tcpdump_pcap_file_init(void)
{
    struct rt_pcap_file_header file_header;

    rt_tcpdump_pcap_file_header_create(&file_header);
    
#ifdef TCPDUMP_DEBUG
    dump_hex((rt_uint8_t *)&file_header, PCAP_FILE_HEADER_SIZE);
#endif

    if (rt_tcpdump_pcap_file_write(&file_header, sizeof(file_header)) != RT_EOK)
    {
        dbg_log(DBG_ERROR, "tcpdump file init failed!\n");
        return RT_ERROR;
    }

    return RT_EOK;
}

rt_uint8_t init = 1;
static void rt_tcpdump_thread_entry(void *param)
{
    struct pbuf *pbuf, *p;
    struct rt_pkthdr pkthdr;
    rt_uint32_t mbval;
    struct stat file_status;
    file_status.st_size = 0;

    rt_uint8_t buf[PCAP_PKTHDR_SIZE] = {0};
    rt_uint8_t ip_len;

    while (1)
    {
        if (rt_mb_recv(tcpdump_mb, &mbval, RT_WAITING_FOREVER) == RT_EOK)
        {
            if (stop_count == 1)
            {
                pkt_count++;
                rt_kprintf("pkt_count: %d\n", pkt_count);
            }
            pbuf = (struct pbuf *)mbval;
            p = pbuf;
            ip_len = p->tot_len;

            if (init == 1)
            {
                rt_kprintf("file is new, and init!\n");
                rt_tcpdump_pcap_file_init();
                init = 0;
            }

            if (name_change == 1)       //  msh/> change file name
            {
                dbg_log(DBG_INFO, "name is change\n");
                rt_tcpdump_pcap_file_init();
                name_change = 0;
            }

            if (close_flag == 1)        //  Only determine if a file of the same name
            {
                rt_kprintf("filename: %s\n", filename);
                stat(filename, &file_status);
                if (file_status.st_size > 0)   // old file
                {
                    rt_tcpdump_pcap_file_init();
                    close_flag = 0;
                }
            }

            rt_tcpdump_pcap_pkthdr_create(&pkthdr, p);
            rt_tcpdump_pcap_file_write(&pkthdr, sizeof(pkthdr));
        
        #ifdef TCPDUMP_DEBUG
            dump_hex((rt_uint8_t *)&pkthdr, PCAP_PKTHDR_SIZE);
            rt_tcpdump_ip_mess_print(p);
        #endif
            
            while (p)
            {                 
                rt_tcpdump_pcap_file_write(p->payload, p->len);
                p = p->next;
            }
            pbuf_free(pbuf);

            if (pkt_count >= count)
            {
                stop_count = 0;
                rt_kprintf("pkt_count reach: %d\n", pkt_count);
                rt_kprintf("pkt_count reach. fd: %d\n", fd);
                close(fd);
                pkt_count = 0;
            }
        }
        
        else
        {
            rt_kprintf("tcp dump thread exit\n");
            return;
        }
    }
}

void rt_tcpdump_set_filename(const char *name)
{
    if (filename != RT_NULL)
    {
        rt_free(filename);
    }

    filename = rt_strdup(name);
}

int rt_tcpdump_init(void)
{
    struct eth_device *device;
    rt_thread_t tid;
    rt_base_t level;

    if (netif != RT_NULL)
    {
        return RT_EOK;
    }
    device = (struct eth_device *)rt_device_find("e0");
    if (device == RT_NULL)
    {
        rt_kprintf("device not find\n");
        return -RT_ERROR;
    }
    if ((device->netif == RT_NULL) || (device->netif->linkoutput == RT_NULL))
    {
        rt_kprintf("this device not eth\n");
        return -RT_ERROR;
    }
    tcpdump_mb = rt_mb_create("tcpdump", TCPDUMP_MAX_MSG, RT_IPC_FLAG_FIFO);
    if (tcpdump_mb == RT_NULL)
    {
        rt_kprintf("tcp dump mp create fail\n");
        return -RT_ERROR;
    }
    tid = rt_thread_create("tcp_dump", rt_tcpdump_thread_entry, RT_NULL, 2048, 10, 10);
    if (tid == RT_NULL)
    {
        rt_mb_delete(tcpdump_mb);
        tcpdump_mb = RT_NULL;
        rt_kprintf("tcp dump thread create fail\n");
        return -RT_ERROR;
    }

    if (filename == RT_NULL)
    {
        filename = rt_strdup(TCPDUMP_DEFAULT_NAME);
    }
    netif = device->netif;
    level = rt_hw_interrupt_disable();
    link_output = netif->linkoutput;
    netif->linkoutput = _netif_linkoutput;

    input = netif->input;
    netif->input = _netif_input;

    rt_hw_interrupt_enable(level);
    rt_thread_startup(tid);

    return RT_EOK;
}

void rt_tcpdump_deinit(void)
{
    rt_base_t level;

    if (netif == RT_NULL)
    {
        return;
    }
    level = rt_hw_interrupt_disable();

    netif->linkoutput = link_output;
    netif->input = input;
    netif = RT_NULL;

    rt_hw_interrupt_enable(level);
    rt_mb_delete(tcpdump_mb);
    tcpdump_mb = RT_NULL;
}

int tcpdump_f(int argc, char *argv[])
{
    if (argc != 3)
    {
        dbg_log(DBG_INFO, "user: tcpdump filename\n");
    }
    rt_tcpdump_set_filename(argv[1]);

    dbg_log(DBG_INFO, "set file name: %s\n", argv[1]);
    name_change = 1;

    count = atoi(argv[2]);

    dbg_log(DBG_INFO, "numbers of pkt: %d\n", count);
    stop_count = 1;
    rt_tcpdump_init();
    fd = -1;
    return 0;
}
MSH_CMD_EXPORT(tcpdump_f, my command with args);

int tcpdump_c(int argc, char *argv[])
{
    if (argc != 2)
    {
        dbg_log(DBG_INFO, "please enter the number of captured packets\n");
        return -1;
    }

    count = atoi(argv[1]);
    stop_count = 1;

    dbg_log(DBG_INFO, "numbers of pkt: %d\n", count);

    rt_tcpdump_init();
    fd = -1;
    close_flag = 1;
    return 0;
}
MSH_CMD_EXPORT(tcpdump_c, my command with args);

void tcpdump_w(void)
{
    close(fd);
    fd = -1;
    close_flag = 1;
}
MSH_CMD_EXPORT(tcpdump_w, save);
