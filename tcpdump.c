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
 * 2018-07-10     never        the first version
 */

#include <rtthread.h>
#include <dfs_posix.h>
#include <rtdef.h>
#include "netif/ethernetif.h"
#include "optparse.h"

#define DBG_ENABLE
//#undef  DBG_ENABLE
#define DBG_SECTION_NAME  "[TCPDUMP]"
#define DBG_LEVEL         DBG_INFO
#define DBG_COLOR
#include <rtdbg.h>

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

#define TCPDUMP_MAX_MSG             (10)
#define PCAP_FILE_HEADER_SIZE       (24)
#define PCAP_PKTHDR_SIZE            (16)

#define PCAP_FILE_ID                (0xA1B2C3D4)
#define PCAP_VERSION_MAJOR          (0x200)
#define PCAP_VERSION_MINOR          (0x400)
#define GREENWICH_MEAN_TIME         (0)
#define PRECISION_OF_TIME_STAMP     (0)
#define MAX_LENTH_OF_CAPTURE_PKG    (0xFFFF)

#define LINKTYPE_NULL           0
#define LINKTYPE_ETHERNET       1               /* also for 100Mb and up */
#define LINKTYPE_EXP_ETHERNET   2               /* 3Mb experimental Ethernet */
#define LINKTYPE_AX25           3
#define LINKTYPE_PRONET         4
#define LINKTYPE_CHAOS          5
#define LINKTYPE_TOKEN_RING     6               /* DLT_IEEE802 is used for Token Ring */
#define LINKTYPE_ARCNET         7
#define LINKTYPE_SLIP           8
#define LINKTYPE_PPP            9
#define LINKTYPE_FDDI           10
#define LINKTYPE_PPP_HDLC       50              /* PPP in HDLC-like framing */
#define LINKTYPE_PPP_ETHER      51              /* NetBSD PPP-over-Ethernet */
#define LINKTYPE_ATM_RFC1483    100             /* LLC/SNAP-encapsulated ATM */
#define LINKTYPE_RAW            101             /* raw IP */
#define LINKTYPE_SLIP_BSDOS     102             /* BSD/OS SLIP BPF header */
#define LINKTYPE_PPP_BSDOS      103             /* BSD/OS PPP BPF header */
#define LINKTYPE_C_HDLC         104             /* Cisco HDLC */
#define LINKTYPE_IEEE802_11     105             /* IEEE 802.11 (wireless) */
#define LINKTYPE_ATM_CLIP       106             /* Linux Classical IP over ATM */
#define LINKTYPE_LOOP           108             /* OpenBSD loopback */
#define LINKTYPE_LINUX_SLL      113             /* Linux cooked socket capture */
#define LINKTYPE_LTALK          114             /* Apple LocalTalk hardware */
#define LINKTYPE_ECONET         115             /* Acorn Econet */
#define LINKTYPE_CISCO_IOS      118             /* For Cisco-internal use */
#define LINKTYPE_PRISM_HEADER   119             /* 802.11+Prism II monitor mode */
#define LINKTYPE_AIRONET_HEADER 120             /* FreeBSD Aironet driver stuff */

static struct rt_mailbox *tcpdump_mb;
static struct netif *netif;
static netif_linkoutput_fn link_output;
static netif_input_fn input;

static const char *name;
static char *filename;

static const char *eth;
static char *ethname;

static int fd = -1;

static void rt_tcpdump_filename_del(void);
static void rt_tcpdump_ethname_del(void);

#define TCPDUMP_DEBUG
#ifdef  TCPDUMP_DEBUG
#define __is_print(ch) ((unsigned int)((ch) - ' ') < 127u - ' ')
static void hex_dump(const rt_uint8_t *ptr, rt_size_t buflen)
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
    
    hex_dump(buf, p->tot_len);
    
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

static void rt_tcpdump_pcap_pkthdr_create(struct rt_pkthdr *pkthdr, struct pbuf *p)
{
    pkthdr->ts.tv_sec  = rt_tick_get() / RT_TICK_PER_SECOND;   
    pkthdr->ts.tv_msec = rt_tick_get() % RT_TICK_PER_SECOND;   
    pkthdr->caplen = p->tot_len;                       
    pkthdr->len = p->tot_len;                                             
}

static rt_err_t rt_tcpdump_pcap_file_write(const void *buf, int len)
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
        return -RT_ERROR;
    }

    if (fd < 0)
    {
        fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0);
        if (fd < 0)
        {
            dbg_log(DBG_ERROR, "open file failed\n");
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

/* write pcap file header */
static rt_err_t rt_tcpdump_pcap_file_init(void)
{
    static const struct rt_pcap_file_header file_header = 
    {
        .magic = PCAP_FILE_ID,                  
        .version_major = PCAP_VERSION_MAJOR,    
        .version_minor = PCAP_VERSION_MINOR,    
        .thiszone = GREENWICH_MEAN_TIME,        
        .sigfigs = PRECISION_OF_TIME_STAMP,     
        .snaplen = MAX_LENTH_OF_CAPTURE_PKG,    
        .linktype = LINKTYPE_ETHERNET,
    };
    
#ifdef TCPDUMP_DEBUG
    hex_dump((rt_uint8_t *)&file_header, PCAP_FILE_HEADER_SIZE);
#endif

    if (rt_tcpdump_pcap_file_write(&file_header, sizeof(file_header)) != RT_EOK)
    {
        dbg_log(DBG_ERROR, "tcpdump file init failed!\n");
        return RT_ERROR;
    }

    return RT_EOK;
}

static void rt_tcpdump_thread_entry(void *param)
{
    struct pbuf *pbuf, *p;
    struct rt_pkthdr pkthdr;
    rt_uint32_t mbval;
    struct stat file_status;
    file_status.st_size = 0;
    
    while (1)
    {
        if (rt_mb_recv(tcpdump_mb, &mbval, RT_WAITING_FOREVER) == RT_EOK)
        {
            pbuf = (struct pbuf *)mbval;
            p = pbuf;

            /* write pkthdr */
            rt_tcpdump_pcap_pkthdr_create(&pkthdr, p);
            rt_tcpdump_pcap_file_write(&pkthdr, sizeof(pkthdr));

        #ifdef TCPDUMP_DEBUG
            hex_dump((rt_uint8_t *)&pkthdr, PCAP_PKTHDR_SIZE);
            rt_tcpdump_ip_mess_print(p);
        #endif
            
            while (p)
            {                 
                rt_tcpdump_pcap_file_write(p->payload, p->len);
                p = p->next;
            }
            pbuf_free(pbuf);
        }
        
        else
        {
            rt_kprintf("tcp dump thread exit\n");
            close(fd);
            fd = -1;
            rt_tcpdump_filename_del();
            rt_tcpdump_ethname_del();
            return;
        }
    }
}

static void rt_tcpdump_filename_set(const char *name)
{
    filename = rt_strdup(name);
}

static void rt_tcpdump_filename_del(void)
{
    if (filename != RT_NULL)
        rt_free(filename);
}

static void rt_tcpdump_ethname_set(const char *eth)
{
    ethname = rt_strdup(eth);
}

static void rt_tcpdump_ethname_del(void)
{
    if (ethname != RT_NULL)
        rt_free(ethname);
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
    device = (struct eth_device *)rt_device_find(eth);
    if (device == RT_NULL)
    {
        dbg_log(DBG_ERROR, "device not find\n");
        return -RT_ERROR;
    }
    if ((device->netif == RT_NULL) || (device->netif->linkoutput == RT_NULL))
    {
        dbg_log(DBG_ERROR, "this device not eth\n");
        return -RT_ERROR;
    }
    tcpdump_mb = rt_mb_create("tcpdump", TCPDUMP_MAX_MSG, RT_IPC_FLAG_FIFO);
    if (tcpdump_mb == RT_NULL)
    {
        dbg_log(DBG_ERROR, "tcp dump mp create fail\n");
        return -RT_ERROR;
    }
    tid = rt_thread_create("tcp_dump", rt_tcpdump_thread_entry, RT_NULL, 2048, 10, 10);
    if (tid == RT_NULL)
    {
        rt_mb_delete(tcpdump_mb);
        tcpdump_mb = RT_NULL;
        dbg_log(DBG_ERROR, "tcp dump thread create fail\n");
        return -RT_ERROR;
    }

    rt_tcpdump_filename_set(name);
    rt_tcpdump_ethname_set(eth);
    
    netif = device->netif;
   
    level = rt_hw_interrupt_disable();
    link_output = netif->linkoutput;
    netif->linkoutput = _netif_linkoutput;

    input = netif->input;
    netif->input = _netif_input;
    rt_hw_interrupt_enable(level);
    
    rt_thread_startup(tid);
    rt_tcpdump_pcap_file_init();
    dbg_log(DBG_INFO, "tcpdump start!\n");
    
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
    
    dbg_log(DBG_INFO, "tcpdump stop!\n");
}

int rt_tcpdump_cmd_init(int argc, char *argv[])
{
    int ch; 
    struct optparse options;
    char stop = 0;
    
    optparse_init(&options, argv); 
    while((ch = optparse(&options, "i:w:p::h::")) != -1)
    {
        ch = ch; 
        dbg_log(DBG_INFO, "optind = %d\n", options.optind);
        switch(options.optind)
        {
        case 2:
            if (options.optopt == 'p')
            {
                stop = options.optopt;
                rt_tcpdump_deinit();
                dbg_log(DBG_LOG, "optind = %d\n", options.optind);
                dbg_log(DBG_LOG, "optopt = %c\n", options.optopt);
            }
            if (options.optopt == 'h')
            {
                rt_kprintf("\n");
                rt_kprintf("-------------------------- help --------------------------\n");
                rt_kprintf("-h: help\n");
                rt_kprintf("-i: specify the network interface for listening\n");
                rt_kprintf("tcpdump -i [] -w []\n");
                rt_kprintf("-w: write the captured packets into an xxx.pcap file\n");
                rt_kprintf("-p: stop capturing packets\n\n"); 
                rt_kprintf("e.g.:\n");
                rt_kprintf("specify a network adapter device and save to an X file\n");
                rt_kprintf("tcpdump -i e0 -w sample.pcap\n\n");
                rt_kprintf("save to X file only\n");
                rt_kprintf("tcpdump -w sample.pcap\n\n");
                rt_kprintf("stop capturing packets\n");
                rt_kprintf("tcpdump -p\n");
                rt_kprintf("help\n");
                rt_kprintf("tcpdump -h\n");
                rt_kprintf("--------------------------- end --------------------------\n");
                rt_kprintf("\n");
            }
            break;
        case 3:
            if (options.optopt == 'i')
            {
                eth = options.optarg;
                dbg_log(DBG_LOG, "optind = %d\n", options.optind);
                dbg_log(DBG_LOG, "optarg = %s\n", options.optarg);
            }
            else
            {    
                eth = "e0";
            }
            
            if (options.optopt == 'w')
            {
                name = options.optarg;
                dbg_log(DBG_LOG, "optind = %d\n", options.optind);
                dbg_log(DBG_LOG, "optarg = %s\n", options.optarg);
            }
            break;
        case 5:
            if (options.optopt == 'w')
                name = options.optarg;
                dbg_log(DBG_LOG, "optind = %d\n", options.optind);
                dbg_log(DBG_LOG, "optarg = %s\n", options.optarg);
            break;
        default:
            break;
        }
    }

    if (stop == 'p')
        return RT_EOK;
    
    rt_tcpdump_init();
    
    return RT_EOK;    
}
MSH_CMD_EXPORT_ALIAS(rt_tcpdump_cmd_init, tcpdump, test optparse_short cmd.);
