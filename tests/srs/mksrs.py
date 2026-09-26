#!/usr/bin/env python3
# Сборщик наборов sing-box (.srs) для стендов: JSON в синтаксисе headless-правил sing-box на
# входе, двоичный .srs на выходе.
#
# ЗАЧЕМ СВОЙ. Настоящие файлы издателя (discord/telegram/youtube.srs рядом) проверяют читатель
# против чужой записи, но в них нет ни логических правил, ни invert, ни source_ip_cidr, ни
# package_name, ни не-ASCII имён, ни наборов на сотни тысяч элементов. Собрать такие без
# sing-box нечем — поэтому запись здесь, по исходникам sing-box (common/srs/binary.go,
# common/domain/matcher.go и set.go, netipx.IPSet): тот же порядок ключей дерева, те же
# метки, то же сжатие zlib. Что запись совпадает с настоящей, стенд проверяет на
# telegram/youtube: их .lst, собранные здесь, читаются в те же списки, что и файлы издателя.
#
# Запуск: mksrs.py IN.json OUT.srs [--version N] [--legacy-suffix]
#         mksrs.py --big N OUT.srs [--kind domains|cidrs|both]   (набор на N элементов)
import ipaddress
import json
import struct
import sys
import zlib

IT = {
    "network": 1, "domain": 2, "domain_keyword": 3, "domain_regex": 4,
    "source_ip_cidr": 5, "ip_cidr": 6, "source_port": 7, "source_port_range": 8,
    "port": 9, "port_range": 10, "process_name": 11, "process_path": 12,
    "package_name": 13, "wifi_ssid": 14, "wifi_bssid": 15,
}
PREFIX_LABEL = "\r"
ROOT_LABEL = "\n"


def uvarint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def strlist(items):
    out = bytearray(uvarint(len(items)))
    for s in items:
        b = s.encode("utf-8")
        out += uvarint(len(b)) + b
    return bytes(out)


def set_bit(bm, i, v):
    while len(bm) <= i // 64:
        bm.append(0)
    if v:
        bm[i // 64] |= 1 << (i % 64)
    else:
        bm[i // 64] &= ~(1 << (i % 64))


def succinct(keys):
    """newSuccinctSet из sing-box: LOUDS по отсортированным ключам (байтам)."""
    keys = sorted(keys)
    leaves, bitmap, labels = [], [], bytearray()
    lidx = 0
    queue = [(0, len(keys), 0)]
    i = 0
    while i < len(queue):
        s, e, col = queue[i]
        if s < e and col == len(keys[s]):
            s += 1
            set_bit(leaves, i, 1)
        j = s
        while j < e:
            frm = j
            while j < e and keys[j][col] == keys[frm][col]:
                j += 1
            queue.append((frm, j, col + 1))
            labels.append(keys[frm][col])
            set_bit(bitmap, lidx, 0)
            lidx += 1
        set_bit(bitmap, lidx, 1)
        lidx += 1
        i += 1
    out = bytearray(uvarint(len(leaves)))
    for w in leaves:
        out += struct.pack(">Q", w & 0xFFFFFFFFFFFFFFFF)
    out += uvarint(len(bitmap))
    for w in bitmap:
        out += struct.pack(">Q", w & 0xFFFFFFFFFFFFFFFF)
    out += uvarint(len(labels)) + bytes(labels)
    return bytes(out)


def reverse_domain(s):
    return s[::-1]          # по рунам, как в sing-box


def matcher(domains, suffixes, legacy):
    lst, seen = [], set()
    for d in suffixes:
        if d in seen:
            continue
        seen.add(d)
        if d.startswith("."):
            lst.append(reverse_domain(PREFIX_LABEL + d))
        elif legacy:
            lst.append(reverse_domain(d))
            sd = "." + d
            if sd not in seen:
                seen.add(sd)
                lst.append(reverse_domain(PREFIX_LABEL + sd))
        else:
            lst.append(reverse_domain(ROOT_LABEL + d))
    for d in domains:
        if d in seen:
            continue
        seen.add(d)
        lst.append(reverse_domain(d))
    keys = [k.encode("utf-8") for k in lst]
    return b"\x00" + succinct(keys)


def ipset(cidrs):
    """netipx.IPSet: диапазоны слиты, v4 первыми."""
    rng = {4: [], 6: []}
    for c in cidrs:
        n = ipaddress.ip_network(c, strict=False)
        rng[n.version].append([int(n.network_address), int(n.broadcast_address)])
    out_ranges = []
    for v in (4, 6):
        r = sorted(rng[v])
        merged = []
        for lo, hi in r:
            if merged and lo <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], hi)
            else:
                merged.append([lo, hi])
        width = 4 if v == 4 else 16
        for lo, hi in merged:
            out_ranges.append((lo.to_bytes(width, "big"), hi.to_bytes(width, "big")))
    out = bytearray(b"\x01") + struct.pack(">Q", len(out_ranges))
    for a, b in out_ranges:
        out += uvarint(len(a)) + a + uvarint(len(b)) + b
    return bytes(out)


def default_rule(r, legacy):
    out = bytearray(b"\x00")
    dom = r.get("domain", [])
    suf = r.get("domain_suffix", [])
    if isinstance(dom, str):
        dom = [dom]
    if isinstance(suf, str):
        suf = [suf]
    if dom or suf:
        out += bytes([IT["domain"]]) + matcher(dom, suf, legacy)
    for key in ("domain_keyword", "domain_regex", "network", "port_range", "source_port_range",
                "process_name", "process_path", "package_name", "wifi_ssid", "wifi_bssid"):
        v = r.get(key)
        if v is None:
            continue
        if isinstance(v, str):
            v = [v]
        out += bytes([IT[key]]) + strlist(v)
    for key in ("ip_cidr", "source_ip_cidr"):
        v = r.get(key)
        if v:
            if isinstance(v, str):
                v = [v]
            out += bytes([IT[key]]) + ipset(v)
    for key in ("port", "source_port"):
        v = r.get(key)
        if v is None:
            continue
        if isinstance(v, int):
            v = [v]
        out += bytes([IT[key]]) + uvarint(len(v)) + b"".join(struct.pack(">H", p) for p in v)
    out += b"\xff" + (b"\x01" if r.get("invert") else b"\x00")
    return bytes(out)


def rule(r, legacy):
    if r.get("type") == "logical":
        out = bytearray(b"\x01")
        out.append(1 if r.get("mode", "and") == "or" else 0)
        out += uvarint(len(r["rules"]))
        for k in r["rules"]:
            out += rule(k, legacy)
        out.append(1 if r.get("invert") else 0)
        return bytes(out)
    return default_rule(r, legacy)


def write(path, rules, version=3, legacy=False):
    body = bytearray(uvarint(len(rules)))
    for r in rules:
        body += rule(r, legacy)
    with open(path, "wb") as f:
        f.write(b"SRS" + bytes([version]) + zlib.compress(bytes(body), 9))


def big(n, kind):
    rules = []
    if kind in ("domains", "both"):
        rules.append({"domain_suffix": ["h%07d.example-%d.com" % (i, i % 97) for i in range(n)]})
    if kind in ("cidrs", "both"):
        # /32 через одну: соседние не сливаются в диапазон, и префиксов выходит ровно n.
        base = int(ipaddress.ip_address("10.0.0.0"))
        rules.append({"ip_cidr": [str(ipaddress.ip_address(base + 2 * i)) + "/32" for i in range(n)]})
    return rules


def main():
    a = sys.argv[1:]
    version, legacy = 3, False
    if "--version" in a:
        k = a.index("--version")
        version = int(a[k + 1])
        del a[k:k + 2]
    if "--legacy-suffix" in a:
        legacy = True
        a.remove("--legacy-suffix")
    if a and a[0] == "--big":
        kind = "both"
        if "--kind" in a:
            k = a.index("--kind")
            kind = a[k + 1]
            del a[k:k + 2]
        write(a[2], big(int(a[1]), kind), version, legacy)
        return
    with open(a[0], encoding="utf-8") as f:
        doc = json.load(f)
    write(a[1], doc["rules"] if isinstance(doc, dict) else doc, version, legacy)


if __name__ == "__main__":
    main()
