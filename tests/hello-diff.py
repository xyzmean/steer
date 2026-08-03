#!/usr/bin/env python3
"""Сравнить ClientHello двух клиентов из двух перехватов.

Зачем это в репозитории. Вся идея Reality в том, что клиент неотличим от браузера, а
аутентификатор подписывает ClientHello ЦЕЛИКОМ. Значит форма Hello — не косметика, а условие
работы, и проверить её можно только сравнением с эталоном на проводе. На глаз и по коду это
не видно: наш Hello собирается вручную, и «похож на браузерный» ничего не значит, пока не
разложено по полям рядом с настоящим.

Так была найдена причина, по которой узел перестал нас признавать при рабочем sing-box на том
же узле и тех же ключах: у нас 3 набора шифров против 16, 10 расширений против 18, ни одного
GREASE, нет encrypted_client_hello и alpn, зато есть encrypt_then_mac, которого Chrome не
посылает. Симптом при этом выглядел как «узел умер» — у Reality нет отрицательного ответа,
непризнанного клиента он молча проксирует на маскировочный сайт.

Снять перехваты (tcpdump пишет в stdout: под ограничениями прав файл он может не создать):

    tcpdump -i eth0 -s 0 -U -w - "tcp port 9443" > эталон.pcap &
    <запустить эталонный клиент>
    tcpdump -i eth0 -s 0 -U -w - "tcp port 9443" > наш.pcap &
    steer vless-probe ВЫХОД --node N --spec СПЕКА

    tests/hello-diff.py эталон.pcap наш.pcap

ВАЖНО: оба перехвата должны быть до ОДНОГО И ТОГО ЖЕ узла. Первый раз я сравнил свой клиент
на одном узле с эталоном на другом (номер узла в подписке значит разное в разных её версиях),
и разница в SNI выглядела как находка, которой не было.
"""
import struct, sys

EXT = {
 0:'server_name',1:'max_fragment_length',5:'status_request',10:'supported_groups',
 11:'ec_point_formats',13:'signature_algorithms',14:'use_srtp',15:'heartbeat',
 16:'alpn',17:'status_request_v2',18:'signed_cert_timestamp',21:'padding',
 22:'encrypt_then_mac',23:'extended_master_secret',27:'compress_certificate',
 28:'record_size_limit',35:'session_ticket',41:'pre_shared_key',42:'early_data',
 43:'supported_versions',44:'cookie',45:'psk_key_exchange_modes',
 47:'certificate_authorities',49:'post_handshake_auth',50:'signature_algorithms_cert',
 51:'key_share',17513:'application_settings',17613:'application_settings_new',
 65037:'encrypted_client_hello',65281:'renegotiation_info',
}
def grease(v): return (v & 0x0f0f) == 0x0a0a and (v >> 8) == (v & 0xff)
def name(t): return ('GREASE' if grease(t) else EXT.get(t, '0x%04x' % t))

def pcap_streams(path):
    d = open(path,'rb').read()
    if len(d) < 24: return []
    magic, = struct.unpack('<I', d[:4])
    le = magic in (0xa1b2c3d4, 0xa1b23c4d)
    endian = '<' if le else '>'
    linktype, = struct.unpack(endian+'I', d[20:24])
    off = 24; out = []
    while off + 16 <= len(d):
        ts_s, ts_us, caplen, origlen = struct.unpack(endian+'IIII', d[off:off+16])
        off += 16
        pkt = d[off:off+caplen]; off += caplen
        if linktype == 1: l2 = 14
        elif linktype == 113: l2 = 16
        else: l2 = 14
        if len(pkt) < l2 + 20: continue
        ip = pkt[l2:]
        if (ip[0] >> 4) != 4: continue
        ihl = (ip[0] & 0xf) * 4
        if ip[9] != 6: continue
        tcp = ip[ihl:]
        if len(tcp) < 20: continue
        doff = (tcp[12] >> 4) * 4
        payload = tcp[doff:]
        dport = struct.unpack('>H', tcp[2:4])[0]
        if payload and dport == 9443:
            out.append(payload)
    return out

def parse_hello(b):
    # запись TLS
    if len(b) < 5 or b[0] != 0x16: return None
    body = b[5:5+struct.unpack('>H', b[3:5])[0]]
    if not body or body[0] != 0x01: return None
    p = 4
    r = {}
    r['legacy_version'] = '0x%04x' % struct.unpack('>H', body[p:p+2])[0]; p += 2
    r['random'] = body[p:p+32].hex(); p += 32
    sid_n = body[p]; p += 1
    r['session_id'] = body[p:p+sid_n].hex(); p += sid_n
    cs_n = struct.unpack('>H', body[p:p+2])[0]; p += 2
    suites = [struct.unpack('>H', body[p+i:p+i+2])[0] for i in range(0, cs_n, 2)]; p += cs_n
    r['suites'] = ['GREASE' if grease(s) else '0x%04x' % s for s in suites]
    comp_n = body[p]; p += 1 + comp_n
    exts_n = struct.unpack('>H', body[p:p+2])[0]; p += 2
    end = p + exts_n
    exts = []
    while p + 4 <= end:
        t, ln = struct.unpack('>HH', body[p:p+4]); p += 4
        exts.append((name(t), ln, body[p:p+ln])); p += ln
    r['exts'] = exts
    r['record_version'] = '0x%04x' % struct.unpack('>H', b[1:3])[0]
    r['total'] = len(b)
    return r

def show(tag, path):
    for pl in pcap_streams(path):
        h = parse_hello(pl)
        if h:
            print("=== %s" % tag)
            print("  запись версия %s, всего %d байт" % (h['record_version'], h['total']))
            print("  legacy_version %s" % h['legacy_version'])
            print("  session_id (%d байт): %s" % (len(h['session_id'])//2, h['session_id']))
            print("  шифров %d: %s" % (len(h['suites']), ' '.join(h['suites'])))
            print("  расширений %d:" % len(h['exts']))
            for n_, ln, raw in h['exts']:
                extra = ''
                if n_ == 'supported_groups':
                    gs = [struct.unpack('>H', raw[2+i:4+i])[0] for i in range(0, struct.unpack('>H', raw[:2])[0], 2)]
                    extra = ' -> ' + ' '.join('GREASE' if grease(g) else '0x%04x' % g for g in gs)
                if n_ == 'supported_versions':
                    vs = [struct.unpack('>H', raw[1+i:3+i])[0] for i in range(0, raw[0], 2)]
                    extra = ' -> ' + ' '.join('GREASE' if grease(v) else '0x%04x' % v for v in vs)
                if n_ == 'key_share':
                    q = 2; ks = []
                    while q + 4 <= len(raw):
                        g, kl = struct.unpack('>HH', raw[q:q+4]); q += 4 + kl
                        ks.append(('GREASE' if grease(g) else '0x%04x' % g) + '/%d' % kl)
                    extra = ' -> ' + ' '.join(ks)
                if n_ == 'server_name':
                    extra = ' -> ' + raw[5:].decode('ascii', 'replace')
                if n_ == 'alpn':
                    extra = ' -> ' + repr(raw[2:])
                print("    %-26s %4d%s" % (n_, ln, extra))
            return h
    print("=== %s: ClientHello не найден" % tag)
    return None

a = show('sing-box (РАБОТАЕТ)', sys.argv[1])
print()
b = show('steer (отказ)', sys.argv[2])
if a and b:
    print("\n=== чего нет у steer, но есть у sing-box:")
    sa = [e[0] for e in a['exts']]; sb_ = [e[0] for e in b['exts']]
    print("   ", [x for x in sa if x not in sb_] or "ничего")
    print("=== чего нет у sing-box, но есть у steer:")
    print("   ", [x for x in sb_ if x not in sa] or "ничего")
