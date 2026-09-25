#include "dnsd_int.h"

/* ---------------------------------------------------------------------- */
/* DNS wire-format parsing (read-only; never mutates the packet)          */
/* ---------------------------------------------------------------------- */

/* Decodes a (possibly compressed) name starting at pos into out (dot-joined,
 * NUL terminated), and returns via *next the stream position right after the
 * name (following RFC1035 compression-pointer semantics: only the FIRST
 * pointer counts toward the caller's next-field offset). */
static int parse_name_adv(const uint8_t *pkt, size_t len, size_t pos, char *out,
                           size_t outlen, size_t *next) {
    size_t start = pos;
    size_t opos = 0;
    int jumps = 0;
    size_t cursor = pos;
    size_t advance_to = 0;
    int pointer_taken = 0;

    for (;;) {
        if (cursor >= len) return -1;
        uint8_t lbl = pkt[cursor];
        if (lbl == 0) {
            if (!pointer_taken) advance_to = cursor + 1;
            break;
        }
        if ((lbl & 0xC0) == 0xC0) {
            if (cursor + 1 >= len) return -1;
            size_t target = ((size_t)(lbl & 0x3F) << 8) | pkt[cursor + 1];
            if (!pointer_taken) {
                advance_to = cursor + 2;
                pointer_taken = 1;
            }
            if (++jumps > 32) return -1;
            cursor = target;
            continue;
        }
        if ((lbl & 0xC0) != 0) return -1;
        size_t label_len = lbl;
        cursor++;
        if (cursor + label_len > len) return -1;
        if (opos + label_len + 1 >= outlen) return -1;
        if (opos > 0) out[opos++] = '.';
        memcpy(out + opos, pkt + cursor, label_len);
        opos += label_len;
        cursor += label_len;
    }
    out[opos] = '\0';
    (void)start;
    *next = advance_to;
    return 0;
}

/* Parses a DNS response: extracts the question name (out_qname), question
 * type (out_qtype), the stream offset right after the question section
 * (out_qend — the header[0,12) + question[12,*out_qend) prefix is byte-
 * identical between the real response and anything we build to replace it,
 * so callers can reuse it verbatim), and every A-record (class IN) answer
 * IP+TTL, up to max_ips entries. Only correct for qdcount==1 (universally
 * true for a resolver's own queries) — anything else is treated as
 * unparseable. Returns the number of A-record IPs found, or -1 on a
 * malformed/short/multi-question packet (caller must still relay the raw
 * bytes to the client regardless). */
int parse_response(const uint8_t *pkt, size_t len, char *out_qname,
                    size_t qname_len, uint16_t *out_qtype,
                    size_t *out_qend, struct answer_ip *ips,
                    int max_ips) {
    if (len < 12) return -1;
    uint16_t qdcount = (pkt[4] << 8) | pkt[5];
    uint16_t ancount = (pkt[6] << 8) | pkt[7];

    size_t pos = 12;
    if (qdcount != 1) return -1;

    size_t next = 0;
    if (parse_name_adv(pkt, len, pos, out_qname, qname_len, &next) != 0)
        return -1;
    pos = next;
    if (pos + 4 > len) return -1;
    *out_qtype = (uint16_t)((pkt[pos] << 8) | pkt[pos + 1]);
    pos += 4; /* qtype + qclass */
    *out_qend = pos;

    int found = 0;
    for (uint16_t a = 0; a < ancount && pos < len; a++) {
        char rrname[MAX_HOSTNAME];
        if (parse_name_adv(pkt, len, pos, rrname, sizeof(rrname), &next) != 0)
            break;
        pos = next;
        if (pos + 10 > len) break;
        uint16_t rtype = (pkt[pos] << 8) | pkt[pos + 1];
        uint16_t rclass = (pkt[pos + 2] << 8) | pkt[pos + 3];
        uint32_t ttl = ((uint32_t)pkt[pos + 4] << 24) | ((uint32_t)pkt[pos + 5] << 16) |
                       ((uint32_t)pkt[pos + 6] << 8) | pkt[pos + 7];
        uint16_t rdlen = (pkt[pos + 8] << 8) | pkt[pos + 9];
        pos += 10;
        if (pos + rdlen > len) break;
        if (rtype == DNS_TYPE_A && rclass == 1 /* IN */ && rdlen == 4 &&
            found < max_ips) {
            uint32_t addr;
            memcpy(&addr, pkt + pos, 4);
            ips[found].addr = addr;
            ips[found].ttl = ttl;
            found++;
        }
        pos += rdlen;
    }
    return found;
}

/* Разбор ВОПРОСА клиентского запроса: имя, тип, конец секции вопроса. Той же
 * механикой, что parse_response, но на пути «клиент → upstream», где ответа ещё
 * нет. Не-запрос (QR=1), не один вопрос или мусор — -1: вызывающий пересылает
 * пакет наверх как раньше, быстрый путь просто не срабатывает. */
int parse_query(const uint8_t *pkt, size_t len, char *out_qname,
                 size_t qname_len, uint16_t *out_qtype, size_t *out_qend) {
    if (len < 12) return -1;
    if (pkt[2] & 0x80) return -1;               /* QR: это уже ответ */
    uint16_t qdcount = (pkt[4] << 8) | pkt[5];
    if (qdcount != 1) return -1;
    size_t next = 0;
    if (parse_name_adv(pkt, len, 12, out_qname, qname_len, &next) != 0) return -1;
    if (next + 4 > len) return -1;
    *out_qtype = (uint16_t)((pkt[next] << 8) | pkt[next + 1]);
    *out_qend = next + 4;
    return 0;
}

/* Ответ, собранный из ЗАПРОСА, обязан сам выставить флаги ответа — в отличие от
 * ответа, собранного из ответа upstream, где они уже стоят. QR — это ответ; opcode
 * и RD переносятся из запроса; RA — рекурсию даёт upstream, и мы отвечаем за него;
 * AA/TC/RCODE — нули. */
void make_response_flags(uint8_t *pkt) {
    pkt[2] = (uint8_t)(0x80 | (pkt[2] & 0x79));
    pkt[3] = 0x80;
}

/* Builds a reply reusing the original response's header+question bytes
 * verbatim ([0, qend) — same transaction ID, same echoed question), with
 * ancount/nscount/arcount patched and (if with_answer) exactly one A record
 * appended pointing at fake_addr_host. nscount/arcount are always zeroed:
 * dropping any authority/additional section (e.g. an upstream EDNS OPT
 * record) is fine, our substitute answer is tiny and needs neither. Returns
 * the built length, or 0 if it wouldn't fit (defensive only — qend is
 * bounded by MAX_HOSTNAME and the answer is a fixed 16 bytes, so this never
 * actually happens with out_cap sized as callers use it below). */
size_t build_rewritten_response(const uint8_t *orig, size_t qend,
                                 uint8_t *out, size_t out_cap,
                                 int with_answer, uint32_t fake_addr_host) {
    if (qend > out_cap) return 0;
    memcpy(out, orig, qend);
    /* Флаги — здесь, в единственном сборщике: путь из ответа upstream копировал их как есть,
     * и клиент видел TC (переспрашивал по TCP:53 мимо заворота — реальный адрес мимо туннеля)
     * и AD на неподписанном синтетическом ответе. */
    make_response_flags(out);
    out[6] = 0; out[7] = with_answer ? 1 : 0;               /* ancount */
    out[8] = 0; out[9] = 0; out[10] = 0; out[11] = 0;       /* nscount, arcount */

    size_t pos = qend;
    if (with_answer) {
        if (pos + 16 > out_cap) return 0;
        out[pos++] = 0xC0; out[pos++] = 0x0C; /* name: pointer to question @ offset 12 */
        out[pos++] = 0x00; out[pos++] = 0x01; /* type A */
        out[pos++] = 0x00; out[pos++] = 0x01; /* class IN */
        out[pos++] = 0x00; out[pos++] = 0x00;
        out[pos++] = 0x00; out[pos++] = FAKEIP_ANSWER_TTL;  /* ttl (fits in one byte) */
        out[pos++] = 0x00; out[pos++] = 0x04;               /* rdlength */
        uint32_t addr_net = htonl(fake_addr_host);
        memcpy(out + pos, &addr_net, 4);
        pos += 4;
    }
    return pos;
}
