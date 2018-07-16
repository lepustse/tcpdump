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
 * 2018-07-13     never        the first version
 */

#include <rtthread.h>
#include <dfs_posix.h>
#include <rtdef.h>
#include "netif/ethernetif.h"
#include "optparse.h"
#include "rdbd.h"

#ifdef PKG_NETUTILS_TCPDUMP_DBG
#define DBG_ENABLE

#define DBG_SECTION_NAME  "[TCPDUMP]"
#define DBG_LEVEL         DBG_INFO
#define DBG_COLOR
#else
#undef  DBG_ENABLE
#endif
#include <rtdbg.h>

#define TCPDUMP_DEFAULT_NANE        ("sample.pcap")

#define TCPDUMP_MAX_MSG             (10)
#define PCAP_FILE_HEADER_SIZE       (24)
#define PCAP_PKTHDR_SIZE            (16)

#define PCAP_FILE_ID                (0xA1B2C3D4)
#define PCAP_VERSION_MAJOR          (0x200)
#define PCAP_VERSION_MINOR          (0x400)
#define GREENWICH_MEAN_TIME         (0)
#define PRECISION_OF_TIME_STAMP     (0)
#define MAX_LENTH_OF_CAPTURE_PKG    (0xFFFF)

#define LINKTYPE_NULL               (0)
#define LINKTYPE_ETHERNET           (1)               /* also for 100Mb and up */
#define LINKTYPE_EXP_ETHERNET       (2)               /* 3Mb experimental Ethernet */
#define LINKTYPE_AX25               (3)
#define LINKTYPE_PRONET             (4)
#define LINKTYPE_CHAOS              (5)
#define LINKTYPE_TOKEN_RING         (6)               /* DLT_IEEE802 is used for Token Ring */
#define LINKTYPE_ARCNET             (7)
#define LINKTYPE_SLIP               (8)
#define LINKTYPE_PPP                (9)
#define LINKTYPE_FDDI               (10)
#define LINKTYPE_PPP_HDLC           (50)              /* PPP in HDLC-like framing */
#define LINKTYPE_PPP_ETHER          (51)              /* NetBSD PPP-over-Ethernet */
#define LINKTYPE_ATM_RFC1483        (100)             /* LLC/SNAP-encapsulated ATM */
#define LINKTYPE_RAW                (101)             /* raw IP */
#define LINKTYPE_SLIP_BSDOS         (102)             /* BSD/OS SLIP BPF header */
#define LINKTYPE_PPP_BSDOS          (103)             /* BSD/OS PPP BPF header */
#define LINKTYPE_C_HDLC             (104)             /* Cisco HDLC */
#define LINKTYPE_IEEE802_11         (105)             /* IEEE 802.11 (wireless) */
#define LINKTYPE_ATM_CLIP           (106)             /* Linux Classical IP over ATM */
#define LINKTYPE_LOOP               (108)             /* OpenBSD loopback */
#define LINKTYPE_LINUX_SLL          (113)             /* Linux cooked socket capture */
#define LINKTYPE_LTALK              (114)             /* Apple LocalTalk hardware */
#define LINKTYPE_ECONET             (115)             /* Acorn Econet */
#define LINKTYPE_CISCO_IOS          (118)             /* For Cisco-internal use */
#define LINKTYPE_PRISM_HEADER       (119)             /* 802.11+Prism II monitor mode */
#define LINKTYPE_AIRONET_HEADER     (120)             /* FreeBSD Aironet driver stuff */

#define PACP_FILE_HEADER_CREATE(_head)                          \
do {                                                            \
(_head)->magic = 0xa1b2c3d4;                                    \
(_head)->version_major = 0x200;                                 \
(_head)->version_minor = 0x400;                                 \
(_head)->thiszone = 0;                                          \
(_head)->sigfigs = 0;                                           \
(_head)->snaplen = 0xff;                                        \
(_head)->linktype = 1;                                          \
} while (0)

#define PACP_PKTHDR_CREATE(_head, _p)                           \
    do {                                                        \
    (_head)->ts.tv_sec = rt_tick_get() / RT_TICK_PER_SECOND;    \
    (_head)->ts.tv_msec = rt_tick_get() % RT_TICK_PER_SECOND;   \
    (_head)->caplen = _p->tot_len;                              \
    (_head)->len = _p->tot_len;                                 \
    } while (0)

#define STRCMP(a, R, b)   (rt_strcmp((a), (b)) (R) (0))

struct rt_pcap_file_header
{
    rt_uint32_t magic;
    rt_uint16_t version_major;
    rt_uint16_t version_minor;
    rt_int32_t thiszone;
    rt_uint32_t sigfigs;
    rt_uint32_t snaplen;
    rt_uint32_t linktype;
};

struct rt_timeval
{
    rt_uint32_t tv_sec;
    rt_uint32_t tv_msec;
};

struct rt_pkthdr
{
    struct rt_timeval ts;
    rt_uint32_t caplen;
    rt_uint32_t len;
};

enum rt_tcpdump_return_param
{
    STOP = -2,
    HELP = -3,
    INTERNET = -4,
    WRITE = -5,
    SAVEIN = -7,
    INIT = -8,
};

static struct rdbd_device *d_to_h_pipe;

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
static void rt_tcpdump_error_info_deal(void);

static rt_err_t (*tcpdump_write)(const void *buf, int len);

#ifdef  PKG_NETUTILS_TCPDUMP_PRINT
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

static rt_err_t rt_tcpdump_pcap_file_save(const void *buf, int len)
{
    rt_device_write((rt_device_t)d_to_h_pipe, 0, buf, len);
}

/* write pcap file header */
static rt_err_t rt_tcpdump_pcap_file_init(void)
{
    struct rt_pcap_file_header file_header;
    int res = -1;

    if (rt_device_open((rt_device_t)d_to_h_pipe, RT_DEVICE_OFLAG_WRONLY) != RT_EOK)
    {
        dbg_log(DBG_LOG, "not found pipe device\n");
        return -RT_ERROR;
    }

    PACP_FILE_HEADER_CREATE(&file_header);

#ifdef  PKG_NETUTILS_TCPDUMP_PRINT
    hex_dump((rt_uint8_t *)&file_header, PCAP_FILE_HEADER_SIZE);
#endif

    if (tcpdump_write != RT_NULL)
        res = tcpdump_write(&file_header, sizeof(file_header));

    if (res != RT_EOK)
        return -RT_ERROR;

    return RT_EOK;
}

static void rt_tcpdump_thread_entry(void *param)
{
    struct pbuf *pbuf = RT_NULL, *p = RT_NULL;
    struct rt_pkthdr pkthdr;
    rt_uint32_t mbval;

    while (1)
    {
        if (rt_mb_recv(tcpdump_mb, &mbval, RT_WAITING_FOREVER) == RT_EOK)
        {
            pbuf = (struct pbuf *)mbval;
            p = pbuf;

            RT_ASSERT(pbuf != RT_NULL);

            /* write pkthdr */
            PACP_PKTHDR_CREATE(&pkthdr, p);
            if (tcpdump_write != RT_NULL)
                tcpdump_write(&pkthdr, sizeof(pkthdr));

#ifdef  PKG_NETUTILS_TCPDUMP_PRINT
            hex_dump((rt_uint8_t *)&pkthdr, PCAP_PKTHDR_SIZE);
            rt_tcpdump_ip_mess_print(p);
#endif

            while (p)
            {
                if (tcpdump_write != RT_NULL)
                    tcpdump_write(p->payload, p->len);

                p = p->next;
            }
            pbuf_free(pbuf);
            pbuf = RT_NULL;
        }
        else
        {
            dbg_log(DBG_INFO, "tcp dump thread exit\n");
            close(fd);
            fd = -1;
            if (d_to_h_pipe != RT_NULL)
                rt_device_close((rt_device_t)d_to_h_pipe);
            tcpdump_write = RT_NULL;
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
    name = RT_NULL;
    if (filename != RT_NULL)
        rt_free(filename);

    filename = RT_NULL;
}

static void rt_tcpdump_ethname_set(const char *eth)
{
    ethname = rt_strdup(eth);
}

static void rt_tcpdump_ethname_del(void)
{
    eth = RT_NULL;
    if (ethname != RT_NULL)
        rt_free(ethname);
}

static int rt_tcpdump_pipe_init(void)
{
    struct rdbd_device *rdbd;

    rdbd = (struct rdbd_device *)rt_device_find("urdbd");
    if (rdbd == RT_NULL)
    {
        LOG_E("rdbd device [%s] not found", "urdbd");

        return -1;
    }

    d_to_h_pipe = (struct rdbd_device *)rdbd_pipe_create(rdbd, "tdrdb", RDBD_SERVICE_ID_TCP_DUMP, RDBD_PIPE_DEVICE_TO_HOST, 2048);
    if (d_to_h_pipe == RT_NULL)
    {
        LOG_E("pipe device shin create failed");
        return -1;
    }

    rt_kprintf("pipe init ok!\n");

    return RT_EOK;
}
MSH_CMD_EXPORT(rt_tcpdump_pipe_init, rdbd_pipe_test_case);
//INIT_COMPONENT_EXPORT(rt_tcpdump_pipe_init);

static int rt_tcpdump_init(void)
{
    struct eth_device *device;

    rt_thread_t tid;
    rt_base_t level;

    if (netif != RT_NULL)
    {
        dbg_log(DBG_ERROR, "This command is running, please stop before you use the \"tcpdump -p\" command!\n");
        return RT_EOK;
    }

    /* sd card mode does not judge pipe */
    if (tcpdump_write != rt_tcpdump_pcap_file_write)
    {
        if (d_to_h_pipe == RT_NULL)
        {
            dbg_log(DBG_ERROR, "pipe is error\n");
            return -RT_ERROR;
        }
    }

    device = (struct eth_device *)rt_device_find(eth);
    if (device == RT_NULL)
    {
        dbg_log(DBG_ERROR, "network interface card \"%s\" device not find!\n", eth);
        return -RT_ERROR;
    }
    if ((device->netif == RT_NULL) || (device->netif->linkoutput == RT_NULL))
    {
        dbg_log(DBG_ERROR, "this device not e0!\n");
        return -RT_ERROR;
    }

    tcpdump_mb = rt_mb_create("tdrmb", TCPDUMP_MAX_MSG, RT_IPC_FLAG_FIFO);
    if (tcpdump_mb == RT_NULL)
    {
        dbg_log(DBG_ERROR, "tcp dump mp create fail!\n");
        return -RT_ERROR;
    }

    tid = rt_thread_create("tdth", rt_tcpdump_thread_entry, RT_NULL, 2048, 10, 10);
    if (tid == RT_NULL)
    {
        rt_mb_delete(tcpdump_mb);
        tcpdump_mb = RT_NULL;
        dbg_log(DBG_ERROR, "tcp dump thread create fail!\n");
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

static void rt_tcpdump_deinit(void)
{
    rt_base_t level;

    if (netif == RT_NULL)
    {
        dbg_log(DBG_ERROR, "capture packet stopped, no repeat input required!\n");
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

static void rt_tcpdump_help_info_print(void)
{
    rt_kprintf("\n");
    rt_kprintf("|<-------------------------- help ---------------------->|\n");
    rt_kprintf("| tcpdump [-ph] [-i interface] [-m mode] [-w file]       |\n");
    rt_kprintf("|                                                        |\n");
    rt_kprintf("| -h: help                                               |\n");
    rt_kprintf("| -i: specify the network interface for listening        |\n");
    rt_kprintf("| -m: choose what mode to save the file                  |\n");
    rt_kprintf("| -w: write the captured packets into an xxx.pcap file   |\n");
    rt_kprintf("| -p: stop capturing packets                             |\n");
    rt_kprintf("|                                                        |\n");
    rt_kprintf("| e.g.:                                                  |\n");
    rt_kprintf("| specify a network adapter device and save to an x file |\n");
    rt_kprintf("| tcpdump -ie0 -msd -wtext.pcap                          |\n");
    rt_kprintf("| tcpdump -ie0 -mrdb -wtext.pcap                         |\n");
    rt_kprintf("|                                                        |\n");
    rt_kprintf("| -m: sd-card mode                                       |\n");
    rt_kprintf("| tcpdump -msd                                           |\n");
    rt_kprintf("|                                                        |\n");
    rt_kprintf("| -m: rdb mode                                           |\n");
    rt_kprintf("| tcpdump -mrdb                                          |\n");
    rt_kprintf("|                                                        |\n");
    rt_kprintf("| -w: file                                               |\n");
    rt_kprintf("| tcpdump -wtext.pcap                                    |\n");
    rt_kprintf("|                                                        |\n");
    rt_kprintf("| -p: stop                                               |\n");
    rt_kprintf("| tcpdump -p                                             |\n");
    rt_kprintf("|                                                        |\n");
    rt_kprintf("| -h: help                                               |\n");
    rt_kprintf("| tcpdump -h                                             |\n");
    rt_kprintf("|<-------------------------- help ---------------------->|\n");
    rt_kprintf("\n");
}

static void rt_tcpdump_error_info_deal(void)
{
    dbg_log(DBG_ERROR, "tcpdump command is incorrect, please refer to the help information\n");
    rt_tcpdump_help_info_print();
}

static int rt_tcpdump_single_parse(struct optparse *options)
{
    if (options->optopt == 'p')
    {
        rt_tcpdump_deinit();
        return STOP;
    }
    else if (options->optopt == 'h')
    {
        rt_tcpdump_help_info_print();
        return HELP;
    }
    else
    {
        ;
    }
}

static int rt_tcpdump_single_cmd(char *argv[], const char *cmd)
{
    int ch;
    struct optparse options;
    int invalid_argv = 0;   /* prevent illegal parameters. e.g.: tcpdump x */
    int res;
    optparse_init(&options, argv);

    while ((ch = optparse(&options, cmd)) != -1)
    {
        invalid_argv = 1;

        /* So the single command is called repeatedly, so it prevents repeated parsing */
        if (*(argv[1] + 1) != *cmd)
            return -RT_ERROR;

        ch = ch;
        res = rt_tcpdump_single_parse(&options);
    }

    if (invalid_argv == 0)
    {
        return -RT_ERROR;
    }
    return res;
}

static int rt_tcpdump_comp_parse(struct optparse *options)
{
    if (options->optopt == 'i')
    {
        if (options->optarg == RT_NULL)
            return -RT_ERROR;
        eth = options->optarg;
        rt_kprintf("select \"%s\" network card device\n", eth);
        return INTERNET;
    }

    else if (options->optopt == 'm')
    {
        if (options->optarg == RT_NULL)
            return -RT_ERROR;

        if (!CMP(options->optarg, "sd"))
        {
            rt_kprintf("select \"sd-card\" mode\n");
            tcpdump_write = rt_tcpdump_pcap_file_write;
            return SAVEIN;
        }

        if (!CMP(options->optarg, "rdb"))
        {
            rt_kprintf("select \"rdb\" mode\n");
            tcpdump_write = rt_tcpdump_pcap_file_save;
            return SAVEIN;
        }
        name = TCPDUMP_DEFAULT_NANE;
    }

    else if (options->optopt == 'w')
    {
        if (options->optarg == RT_NULL)
            return -RT_ERROR;

        name = options->optarg;
        rt_kprintf("save in \"%s\"\n", name);

        return WRITE;
    }

    else
    {
        return -RT_ERROR;
    }
}

static int rt_tcpdump_comp_cmd(char *argv[], const char *cmd)
{
    int ch;
    struct optparse options;
    int res;
    int invalid_argv = 0;   /* prevent illegal parameters. e.g.: tcpdump x */

    optparse_init(&options, argv);

    while ((ch = optparse(&options, cmd)) != -1)
    {
        invalid_argv = 1;

        /* Prevent parameters that are not yet defined. e.g.: tcpdump -u */
        if ((*(argv[1] + 1) != *cmd) && (*(argv[1] + 1) != *(cmd + 3)) \
                && (*(argv[1] + 1) != *(cmd + 6)))
            return -RT_ERROR;

        ch = ch;
        res = rt_tcpdump_comp_parse(&options);
        if (res == -RT_ERROR)
            return -RT_ERROR;
    }

    if (invalid_argv == 0)
    {
        return -RT_ERROR;
    }

    return res;
}

static int tcpdump_test(int argc, char *argv[])
{
    int res;
    tcpdump_write = RT_NULL;

    if (argc == 1)
    {
        eth = "e0";
        name = TCPDUMP_DEFAULT_NANE;
        tcpdump_write = rt_tcpdump_pcap_file_write;
        rt_kprintf("default selection \"e0\" network card device\n");
        rt_kprintf("default selection \"sd-card\" mode\n");
        rt_kprintf("default selection \"sample.pcap\"\n");
        rt_tcpdump_init();
        return RT_EOK;
    }

    res = rt_tcpdump_single_cmd(argv, "p");
    if (res  == STOP)
        return RT_EOK;

    res = rt_tcpdump_single_cmd(argv, "h");
    if (res == HELP)
        return RT_EOK;

    res = rt_tcpdump_comp_cmd(argv, "i::m::w::");

    if (res == INTERNET)
        res = INIT;

    if (res == SAVEIN)
        res = SAVEIN;

    if (res == WRITE)
        res = INIT;

    if (res == -RT_ERROR)
    {
        rt_tcpdump_error_info_deal();
        return -RT_ERROR;
    }

    if (name == RT_NULL)
    {
        rt_kprintf("default selection \"sample.pcap\"\n");
        name = TCPDUMP_DEFAULT_NANE;
    }

    if (eth == RT_NULL)
    {
        rt_kprintf("default selection \"e0\" network card device\n");
        eth = "e0";
    }

    if (tcpdump_write == RT_NULL)
    {
        rt_kprintf("default selection \"sd-card\" mode\n");
        tcpdump_write = rt_tcpdump_pcap_file_write;
    }

    rt_tcpdump_init();

    return RT_EOK;
}
#ifdef RT_USING_FINSH
#include <finsh.h>
MSH_CMD_EXPORT_ALIAS(tcpdump_test, tcpdump, test optparse_short cmd.);
#endif
