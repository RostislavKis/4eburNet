#ifndef TC_FAST_H
#define TC_FAST_H

#include <stdint.h>
#include <stdbool.h>

/*
 * TC ingress fast path: cls_u32 + act_skbedit на br-lan.
 * Пакеты с dst в LAN-подсети получают mark=0x10 до netfilter
 * и принимаются правилом nftables без прохождения TPROXY-цепочки.
 */

int  tc_fast_enable(const char *ifname, uint32_t lan_prefix, uint32_t lan_mask);
void tc_fast_disable(const char *ifname);
bool tc_fast_is_active(void);

#endif /* TC_FAST_H */
