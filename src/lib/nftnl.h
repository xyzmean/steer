#ifndef STEER_NFTNL_H
#define STEER_NFTNL_H
#include <stdint.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include "nlbuf.h"

#define NFTLK_MSG_CAP     512   /* biggest msg we build: hdrs + ~3 nested attrs */

/* SPLIFY_DNSD_DEBUG за окружением — см. dbg() в nftnl.c. Общий для всего резолвера: netlink
 * (эта библиотека) и горячий путь proxy.c спрашивают его же. */
int dbg(void);

extern const char *g_nft_table;      /* "<family> <table>" — наборы (см. nftnl.c) */
extern const char *g_nft_map_table;  /* "<family> <table>" — карта fakeip (может отличаться) */
extern int g_nft_sets_interval;      /* 1 — наборы принимают "начало + конец диапазона" */
extern int g_nlk_fd;                 /* долгоживущий сокет nfnetlink, -1 — не открыт */

int nftlk_open(void);
int nftlk_elem_msg(uint16_t nft_msg_type, const char *table,
                    const char *obj_name, const void *key_net,
                    int interval, const void *data_net,
                    uint64_t timeout_ms);
uint32_t set_ttl_clamp(uint32_t ttl);
int nft_add_element(const char *set_name, uint32_t key_host, uint32_t ttl);
/* Элемент составного набора `ipv4_addr . inet_proto . inet_service` (см. nftnl.c): адрес и
 * ящик «протоколы × порты». add — положить (ttl в секундах, 0 — навсегда) или убрать. 0 —
 * в ядре желаемое состояние (EEXIST при добавлении и ENOENT при удалении — тоже). */
struct nftlk_box { uint8_t plo, phi; uint16_t lo, hi; };
int nft_concat_element(int add, const char *set_name, uint32_t addr_host,
                       const struct nftlk_box *box, uint32_t ttl);
int nft_map_set_element(const char *map_name, uint32_t fake_host,
                         uint32_t real_host, uint32_t known_real);

#endif
