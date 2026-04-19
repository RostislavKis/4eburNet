/*
 * tc_fast.c — TC ingress fast path через cls_u32 + act_skbedit (v1.2-2)
 *
 * Поток: LAN dst pkt → TC sets mark=TC_FAST_MARK → nft accept → минует TPROXY.
 * Всё через rtnetlink без iproute2. Стек ≤512 байт на функцию (MIPS).
 * Все linux/ структуры определены inline — musl не экспортирует linux/ заголовки.
 */

#include "routing/tc_fast.h"
#include "routing/nftables.h"
#include "net_utils.h"
#include "4eburnet.h"

#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>

/* ── Netlink: inline структуры (из linux/netlink.h, linux/rtnetlink.h) ── */

#define NETLINK_ROUTE       0
#define AF_NETLINK_V        16   /* PF_NETLINK из sys/socket.h — здесь псевдоним */
#define NLMSG_ALIGNTO       4U
#define NLMSG_ALIGN(len)    (((len) + NLMSG_ALIGNTO - 1) & ~(NLMSG_ALIGNTO - 1))
#define NLMSG_ERROR         2
#define NLM_F_REQUEST       1
#define NLM_F_MULTI         2
#define NLM_F_ACK           4
#define NLM_F_EXCL          512
#define NLM_F_CREATE        1024
#define RTM_NEWQDISC        36
#define RTM_DELQDISC        37
#define RTM_NEWTFILTER      44

/* TCA_* enum из linux/rtnetlink.h */
#define TCA_UNSPEC          0
#define TCA_KIND            1
#define TCA_OPTIONS         2

struct nl_msghdr {
    uint32_t nlmsg_len;
    uint16_t nlmsg_type;
    uint16_t nlmsg_flags;
    uint32_t nlmsg_seq;
    uint32_t nlmsg_pid;
};

struct nl_sockaddr {
    uint16_t nl_family;
    uint16_t nl_pad;
    uint32_t nl_pid;
    uint32_t nl_groups;
};

struct nl_tc_msg {
    uint8_t  tcm_family;
    uint8_t  tcm__pad1;
    uint16_t tcm__pad2;
    int32_t  tcm_ifindex;
    uint32_t tcm_handle;
    uint32_t tcm_parent;
    uint32_t tcm_info;
};

/* ── TC константы (из linux/pkt_cls.h, linux/tc_act/tc_skbedit.h) ── */
#define TC_H_INGRESS        0xFFFFFFF1U
#define TC_INGRESS_HANDLE   0xFFFF0000U
#define TC_ACT_OK           0
#define TCA_U32_SEL         5
#define TCA_U32_ACT         7
#define TCA_ACT_KIND        1
#define TCA_ACT_OPTIONS     2
#define TCA_SKBEDIT_PARMS   2
#define TCA_SKBEDIT_MARK    5
#define TCA_SKBEDIT_FLAGS   9
#define SKBEDIT_F_MARK      4ULL
#define TC_FAST_MARK        0x20U  /* LAN bypass mark; 0x10 занят FWMARK_DEVICE_PROXY */

/* NLA_F_NESTED: бит 15 в типе атрибута */
#define NLA_F_NESTED        (1u << 15)

/* ── Inline struct-определения (из linux/pkt_cls.h, linux/tc_act/tc_skbedit.h) ── */

struct tc_u32_key {
    uint32_t mask;
    uint32_t val;
    int32_t  off;
    int32_t  offmask;
};

/* Компилятор добавляет 2 байта padding перед hmask (выравнивание uint32_t).
 * Итог: 16 байт заголовок + 16 байт на ключ = 32 байта. */
struct tc_u32_sel {
    uint8_t  flags, offshift, nkeys, offmask_u8;
    uint16_t off_u16;
    int16_t  offoff, hoff;
    uint32_t hmask;
    struct tc_u32_key keys[1];
};

/* tc_gen: index(4)+capab(4)+action(4)+refcnt(4)+bindcnt(4) = 20 байт */
struct tc_skbedit {
    uint32_t index, capab;
    int32_t  action, refcnt, bindcnt;
};

/* ── Глобальное состояние (один интерфейс) ── */
static bool g_active          = false;
static int  g_ifindex         = 0;
static int  g_nft_rule_handle = -1;

/* ── NLA хелперы ── */

static int nla_put(char *buf, int *pos, int cap,
                   uint16_t type, const void *data, uint16_t dlen)
{
    int aligned = (dlen + 3) & ~3;
    if (*pos + 4 + aligned > cap) return -1;
    uint16_t nla_len = (uint16_t)(4 + dlen);
    memcpy(buf + *pos,     &nla_len, 2);
    memcpy(buf + *pos + 2, &type,    2);
    if (dlen > 0) memcpy(buf + *pos + 4, data, dlen);
    if (aligned > dlen) memset(buf + *pos + 4 + dlen, 0, (size_t)(aligned - dlen));
    *pos += 4 + aligned;
    return 0;
}

static int nla_nest_begin(char *buf, int *nest_pos, int *pos, int cap, uint16_t type)
{
    if (*pos + 4 > cap) return -1;
    *nest_pos = *pos;
    uint16_t zero = 0;
    uint16_t t    = type | (uint16_t)NLA_F_NESTED;
    memcpy(buf + *pos,     &zero, 2);
    memcpy(buf + *pos + 2, &t,    2);
    *pos += 4;
    return 0;
}

static void nla_nest_end(char *buf, int nest_pos, int cur_pos)
{
    uint16_t len = (uint16_t)(cur_pos - nest_pos);
    memcpy(buf + nest_pos, &len, 2);
}

/* ── Netlink: открыть сокет ── */

static int nl_open(void)
{
    /* AF_NETLINK = 16 = PF_NETLINK из musl sys/socket.h */
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return -1;
    struct nl_sockaddr sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* ── Netlink: отправить сообщение, прочитать ACK ── */

static int nl_send_recv_ack(int fd, const char *buf, int msglen)
{
    if (send(fd, buf, (size_t)msglen, 0) < 0) return -1;
    char ack[128];
    ssize_t n = recv(fd, ack, sizeof(ack), 0);
    if (n < (ssize_t)sizeof(struct nl_msghdr)) return -1;
    struct nl_msghdr nh;
    memcpy(&nh, ack, sizeof(nh));
    if (nh.nlmsg_type != NLMSG_ERROR) return -1;
    if (n < (ssize_t)(sizeof(struct nl_msghdr) + sizeof(int))) return -1;
    int err;
    memcpy(&err, ack + sizeof(struct nl_msghdr), sizeof(int));
    return err; /* 0 = успех */
}

/* ── Загрузка kmod из /lib/modules/4eburnet/ ── */

static void kmod_load(const char *modname)
{
    char syspath[80];
    snprintf(syspath, sizeof(syspath), "/sys/module/%s", modname);
    if (access(syspath, F_OK) == 0) return;
    char modpath[128];
    snprintf(modpath, sizeof(modpath), "/lib/modules/4eburnet/%s.ko", modname);
    const char *argv[] = { "insmod", modpath, NULL };
    char errbuf[64];
    if (exec_cmd_safe(argv, errbuf, sizeof(errbuf)) != 0)
        log_msg(LOG_WARN, "tc_fast: insmod %s: %s", modname, errbuf);
}

/* ── RTM_NEWQDISC / RTM_DELQDISC для ingress qdisc ── */

static int tc_qdisc_ingress_op(int nl_fd, int ifindex, bool add)
{
    char buf[96];
    memset(buf, 0, sizeof(buf));

    struct nl_msghdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.nlmsg_flags = (uint16_t)(NLM_F_REQUEST | NLM_F_ACK |
                      (add ? (NLM_F_EXCL | NLM_F_CREATE) : 0));
    hdr.nlmsg_type  = (uint16_t)(add ? RTM_NEWQDISC : RTM_DELQDISC);
    hdr.nlmsg_seq   = 1;

    struct nl_tc_msg tc;
    memset(&tc, 0, sizeof(tc));
    tc.tcm_family  = AF_UNSPEC;
    tc.tcm_ifindex = ifindex;
    tc.tcm_handle  = TC_INGRESS_HANDLE;
    tc.tcm_parent  = TC_H_INGRESS;

    int pos = 0;
    memcpy(buf + pos, &hdr, sizeof(hdr)); pos += (int)sizeof(hdr);
    memcpy(buf + pos, &tc,  sizeof(tc));  pos += (int)sizeof(tc);
    if (nla_put(buf, &pos, (int)sizeof(buf), TCA_KIND, "ingress", 8) < 0) return -1;
    hdr.nlmsg_len = (uint32_t)pos;
    memcpy(buf, &hdr, sizeof(hdr));
    return nl_send_recv_ack(nl_fd, buf, pos) == 0 ? 0 : -1;
}

/* ── RTM_NEWTFILTER: cls_u32 + act_skbedit ── */

static int tc_filter_u32_add(int nl_fd, int ifindex,
                              uint32_t lan_prefix, uint32_t lan_mask)
{
    char buf[256];
    memset(buf, 0, sizeof(buf));

    struct nl_msghdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.nlmsg_flags = (uint16_t)(NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE);
    hdr.nlmsg_type  = RTM_NEWTFILTER;
    hdr.nlmsg_seq   = 2;

    struct nl_tc_msg tc;
    memset(&tc, 0, sizeof(tc));
    tc.tcm_family  = AF_UNSPEC;
    tc.tcm_ifindex = ifindex;
    /* priority=1, protocol=htons(ETH_P_IP=0x0800) */
    tc.tcm_info    = (1u << 16) | (uint32_t)htons(0x0800);
    tc.tcm_parent  = TC_INGRESS_HANDLE;

    int pos = 0;
    memcpy(buf + pos, &hdr, sizeof(hdr)); pos += (int)sizeof(hdr);
    memcpy(buf + pos, &tc,  sizeof(tc));  pos += (int)sizeof(tc);
    if (nla_put(buf, &pos, (int)sizeof(buf), TCA_KIND, "u32", 4) < 0) return -1;

    int opts_nest;
    if (nla_nest_begin(buf, &opts_nest, &pos, (int)sizeof(buf), TCA_OPTIONS) < 0) return -1;

    struct tc_u32_sel sel;
    memset(&sel, 0, sizeof(sel));
    sel.nkeys           = 1;
    sel.keys[0].mask    = htonl(lan_mask);
    sel.keys[0].val     = htonl(lan_prefix & lan_mask);
    sel.keys[0].off     = 16; /* dst IP в IP-заголовке */
    sel.keys[0].offmask = 0;
    if (nla_put(buf, &pos, (int)sizeof(buf),
                TCA_U32_SEL, &sel, (uint16_t)sizeof(sel)) < 0) return -1;

    int act_nest;
    if (nla_nest_begin(buf, &act_nest, &pos, (int)sizeof(buf), TCA_U32_ACT) < 0) return -1;

    int act1_nest;
    if (nla_nest_begin(buf, &act1_nest, &pos, (int)sizeof(buf), 1) < 0) return -1;
    if (nla_put(buf, &pos, (int)sizeof(buf), TCA_ACT_KIND, "skbedit", 8) < 0) return -1;

    int aopts_nest;
    if (nla_nest_begin(buf, &aopts_nest, &pos, (int)sizeof(buf), TCA_ACT_OPTIONS) < 0) return -1;

    struct tc_skbedit parms;
    memset(&parms, 0, sizeof(parms));
    parms.action = TC_ACT_OK;
    if (nla_put(buf, &pos, (int)sizeof(buf),
                TCA_SKBEDIT_PARMS, &parms, (uint16_t)sizeof(parms)) < 0) return -1;

    uint32_t mark = TC_FAST_MARK;
    if (nla_put(buf, &pos, (int)sizeof(buf),
                TCA_SKBEDIT_MARK, &mark, sizeof(mark)) < 0) return -1;

    uint64_t flags = SKBEDIT_F_MARK;
    if (nla_put(buf, &pos, (int)sizeof(buf),
                TCA_SKBEDIT_FLAGS, &flags, sizeof(flags)) < 0) return -1;

    nla_nest_end(buf, aopts_nest, pos);
    nla_nest_end(buf, act1_nest,  pos);
    nla_nest_end(buf, act_nest,   pos);
    nla_nest_end(buf, opts_nest,  pos);

    hdr.nlmsg_len = (uint32_t)pos;
    memcpy(buf, &hdr, sizeof(hdr));
    return nl_send_recv_ack(nl_fd, buf, pos) == 0 ? 0 : -1;
}

/* ── nftables: добавить правило accept для mark=TC_FAST_MARK ── */

static int nft_add_accept_rule(void)
{
    const char *argv[] = {
        "nft", "insert", "rule", "inet", NFT_TABLE_NAME, NFT_CHAIN_PRE,
        "position", "0", "meta", "mark", "0x00000010", "accept", NULL
    };
    return exec_cmd_safe(argv, NULL, 0);
}

/* ── Парсинг handle из вывода nft --handle list chain ── */

static void parse_handle_cb(const char *line, void *ctx)
{
    int *handle = (int *)ctx;
    if (!strstr(line, "meta mark 0x00000010 accept")) return;
    const char *p = strstr(line, "# handle ");
    if (!p) return;
    p += 9;
    long v = strtol(p, NULL, 10);
    if (v > 0) *handle = (int)v;
}

static int nft_find_rule_handle(void)
{
    char cmd[128];
    snprintf(cmd, sizeof(cmd),
             "nft --handle list chain inet %s %s",
             NFT_TABLE_NAME, NFT_CHAIN_PRE);
    int handle = -1;
    exec_cmd_lines(cmd, parse_handle_cb, &handle);
    return handle;
}

/* ── nftables: удалить правило по handle ── */

static void nft_del_accept_rule(void)
{
    if (g_nft_rule_handle < 0) return;
    char handle_str[16];
    snprintf(handle_str, sizeof(handle_str), "%d", g_nft_rule_handle);
    const char *argv[] = {
        "nft", "delete", "rule", "inet", NFT_TABLE_NAME, NFT_CHAIN_PRE,
        "handle", handle_str, NULL
    };
    exec_cmd_safe(argv, NULL, 0);
    g_nft_rule_handle = -1;
}

/* ── Публичный API ── */

int tc_fast_enable(const char *ifname, uint32_t lan_prefix, uint32_t lan_mask)
{
    if (g_active) tc_fast_disable(ifname);

    kmod_load("sch_ingress");
    kmod_load("cls_u32");
    kmod_load("act_skbedit");

    int ifindex = (int)if_nametoindex(ifname);
    if (ifindex <= 0) {
        log_msg(LOG_WARN, "tc_fast: интерфейс %s не найден", ifname);
        return -1;
    }

    int nl = nl_open();
    if (nl < 0) {
        log_msg(LOG_WARN, "tc_fast: nl_open: %s", strerror(errno));
        return -1;
    }

    if (tc_qdisc_ingress_op(nl, ifindex, true) < 0) {
        log_msg(LOG_WARN, "tc_fast: не удалось добавить ingress qdisc");
        close(nl);
        return -1;
    }

    if (tc_filter_u32_add(nl, ifindex, lan_prefix, lan_mask) < 0) {
        log_msg(LOG_WARN, "tc_fast: не удалось добавить u32 фильтр");
        tc_qdisc_ingress_op(nl, ifindex, false);
        close(nl);
        return -1;
    }
    close(nl);

    if (nft_add_accept_rule() < 0) {
        log_msg(LOG_WARN, "tc_fast: не удалось добавить nft правило");
        int nl2 = nl_open();
        if (nl2 >= 0) {
            tc_qdisc_ingress_op(nl2, ifindex, false);
            close(nl2);
        }
        return -1;
    }

    g_nft_rule_handle = nft_find_rule_handle();
    g_ifindex = ifindex;
    g_active  = true;

    log_msg(LOG_INFO, "tc_fast: активирован на %s, mark=0x%02x, nft handle=%d",
            ifname, TC_FAST_MARK, g_nft_rule_handle);
    return 0;
}

void tc_fast_disable(const char *ifname)
{
    if (!g_active) return;

    nft_del_accept_rule();

    int nl = nl_open();
    if (nl >= 0) {
        int idx = g_ifindex > 0 ? g_ifindex : (int)if_nametoindex(ifname);
        if (idx > 0) tc_qdisc_ingress_op(nl, idx, false);
        close(nl);
    }

    g_active  = false;
    g_ifindex = 0;
    log_msg(LOG_INFO, "tc_fast: деактивирован (%s)", ifname);
}

bool tc_fast_is_active(void)
{
    return g_active;
}
