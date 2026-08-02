#!/bin/sh
# Golden tests for the compiler: spec in, ruleset text out. No router, no nft, no
# network — the whole reason the engine is a compiler rather than a daemon.
set -u
BIN="${STEER:-./build/steer}"
[ -x "$BIN" ] || { echo "not built: $BIN (make)"; exit 2; }

pass=0 fail=0
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
S="--state-dir $tmp/state"

check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1))
        printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}

printf '203.0.113.0/24\n198.51.100.5\n' > "$tmp/a.lst"
printf '198.51.100.5\n' > "$tmp/b.lst"

spec() { sed "s|TMP|$tmp|g" > "$tmp/spec.json"; }

spec <<'EOF'
{ "schema": 1,
  "from_default": ["192.168.1.0/24"],
  "outputs": {
    "direct": { "kind": "direct" },
    "vpn":    { "kind": "interface", "device": "wg0" }
  },
  "channels": [
    { "name": "keep",    "match": { "prefixes_file": "TMP/b.lst" }, "out": "direct" },
    { "name": "blocked", "match": { "prefixes_file": "TMP/a.lst" }, "out": "vpn" }
  ] }
EOF

out="$("$BIN" apply --dry-run --spec "$tmp/spec.json" $S)"

# The whole ruleset, once: a diff here is a behaviour change, which is exactly what
# a golden test is for.
want="$(cat <<'EOF'
table inet steer {
    set direct_ip {
        type ipv4_addr
        flags interval
        auto-merge
        elements = { 198.51.100.5 }
    }
    set vpn_ip {
        type ipv4_addr
        flags interval
        auto-merge
        elements = { 203.0.113.0/24, 198.51.100.5 }
    }
    chain prerouting_mark {
        type filter hook prerouting priority mangle + 1; policy accept;
        ip saddr { 192.168.1.0/24 } ip daddr @direct_ip counter return comment "steer:direct_ip"
        ip saddr { 192.168.1.0/24 } ip daddr @vpn_ip meta mark set 0x00100000 counter return comment "steer:vpn_ip"
    }
}
EOF
)"
check "generates the expected ruleset" "$want" "$out"

# Precedence is the spec's central promise: 198.51.100.5 is in BOTH lists, and the
# rule that claims it must be the one written first.
first="$(printf '%s\n' "$out" | grep -n 'comment "steer:' | head -1 | sed 's/.*steer://; s/".*//')"
# The order of GROUPS follows the first channel that created each, so "first match
# wins" still reads off the spec even though several channels may share one rule.
check "first channel in the spec is first in the chain" "direct_ip" "$first"

# A direct output claims the packet and marks nothing — the point of `return`.
check "direct output sets no mark" "0" \
    "$(printf '%s\n' "$out" | grep 'steer:direct_ip' | grep -c 'meta mark set')"

# ---- domain channels ---------------------------------------------------------
# A domain channel's set is filled by the resolver, but the RULE still has to test
# it. Emitting the daddr match only for prefix channels once left a domain channel
# matching everything from the LAN and marking it all into that tunnel.
printf 'example.com\n' > "$tmp/d.lst"
cat > "$tmp/dspec.json" <<EOF
{ "schema": 1, "from_default": ["192.168.1.0/24"], "lan_device": "br-lan",
  "outputs": { "geo": { "kind": "interface", "device": "tun0" } },
  "channels": [ { "name": "dom", "match": { "domains_file": "$tmp/d.lst" }, "out": "geo" } ] }
EOF
dout="$("$BIN" apply --dry-run --spec "$tmp/dspec.json" --state-dir "$tmp/state-dom")"
check "domain channel still tests its set" "1" \
    "$(printf '%s\n' "$dout" | grep 'steer:geo_dom' | grep -c 'ip daddr @geo_dom')"
check "domain set is declared empty, with timeouts" "1" \
    "$(printf '%s\n' "$dout" | grep -A3 'set geo_dom' | grep -c 'flags interval,timeout')"
check "fake-IP DNAT appears with a domain channel" "1" \
    "$(printf '%s\n' "$dout" | grep -c 'dnat ip to ip daddr map @fakeip')"
check "DNS redirect covers IPv6 too" "1" \
    "$(printf '%s\n' "$dout" | grep -c 'nfproto ipv6 iifname "br-lan" udp dport 53')"
# No domain channel means none of that plumbing should exist at all.
check "no fake-IP plumbing without domain channels" "0" \
    "$(printf '%s\n' "$out" | grep -c 'fakeip')"

# explain must consult a domain channel's set as well — those hold the fake IPs,
# which are precisely the addresses someone asks explain about.
check "explain queries domain channels too" "1" \
    "$(STEER_EXPLAIN_TRACE=1 "$BIN" explain 198.18.0.1 --spec "$tmp/dspec.json" \
        --state-dir "$tmp/state-dom" 2>&1 | grep -c 'geo_dom')"

# realip mode exists so traceroute stays legible: no DNAT means the kernel does not
# rewrite ICMP errors, so hops show real routers instead of the fake address.
cat > "$tmp/rspec.json" <<EOF
{ "schema": 1, "from_default": ["192.168.1.0/24"], "lan_device": "br-lan",
  "outputs": { "geo": { "kind": "interface", "device": "tun0" } },
  "channels": [ { "name": "dom", "match": { "domains_file": "$tmp/d.lst", "mode": "realip" }, "out": "geo" } ] }
EOF
rout="$("$BIN" apply --dry-run --spec "$tmp/rspec.json" --state-dir "$tmp/state-r")"
check "realip needs no fake-IP translation" "0" "$(printf '%s\n' "$rout" | grep -c 'fakeip')"
# Two rules, not one: IPv4 by subnet and IPv6 by device — a client that prefers the
# router's IPv6 resolver must not slip past the proxy.
check "realip still redirects DNS on both families" "2" \
    "$(printf '%s\n' "$rout" | grep -c 'udp dport 53 counter redirect')"
check "realip channel still has its set" "1" \
    "$(printf '%s\n' "$rout" | grep -c 'ip daddr @geo_dom')"

sed 's/"mode": "realip"/"mode": "nonsense"/' "$tmp/rspec.json" > "$tmp/rbad.json"
"$BIN" apply --dry-run --spec "$tmp/rbad.json" --state-dir "$tmp/state-r" >/dev/null 2>&1
check "refuses an unknown mode" "2" "$?"

# Intermediate traceroute hops: untracking ICMP time-exceeded stops the kernel from
# rewriting its source to the fake address. Only type 11 — dest-unreachable must stay
# tracked or path-MTU discovery breaks.
sed 's/"schema": 1,/"schema": 1, "traceroute_hops": true,/' "$tmp/dspec.json" > "$tmp/tspec.json"
tout="$("$BIN" apply --dry-run --spec "$tmp/tspec.json" --state-dir "$tmp/state-t")"
check "untracks time-exceeded when asked" "1" \
    "$(printf '%s\n' "$tout" | grep -c 'icmp type time-exceeded counter notrack')"
check "leaves dest-unreachable tracked" "0" \
    "$(printf '%s\n' "$tout" | grep -c 'destination-unreachable')"
check "off by default" "0" "$(printf '%s\n' "$dout" | grep -c notrack)"

# ---- several lists in one channel -------------------------------------------
# Enabling "youtube" and "google" must not force two channels: as far as routing is
# concerned they are one destination. The lists are read as several files rather than
# concatenated by the caller — duplicating list bytes to express "and" costs overlay
# space on the box that has least of it.
printf '10.1.0.0/24\n' > "$tmp/m1.lst"
printf '10.2.0.0/24\n10.1.0.0/24\n' > "$tmp/m2.lst"
cat > "$tmp/mspec.json" <<EOF
{ "schema": 1, "from_default": ["192.168.1.0/24"],
  "outputs": { "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [ { "name": "many",
                  "match": { "prefixes_files": ["$tmp/m1.lst", "$tmp/m2.lst"] },
                  "out": "vpn" } ] }
EOF
mout="$("$BIN" apply --dry-run --spec "$tmp/mspec.json" --state-dir "$tmp/state-m")"
# Two lists, one output: one set and one rule, not two of each. On the weak box that
# is the difference between walking two rules per packet and walking a dozen.
check "one set from several lists" "1" "$(printf '%s\n' "$mout" | grep -c 'set vpn_ip')"
check "and one rule" "1" "$(printf '%s\n' "$mout" | grep -c 'comment "steer:vpn_ip"')"
check "all three entries present" "1" \
    "$(printf '%s\n' "$mout" | grep -c 'elements = { 10.1.0.0/24, 10.2.0.0/24, 10.1.0.0/24 }')"
# The duplicate is not deduplicated in text on purpose: the kernel folds it via
# auto-merge, which is cheaper than us rewriting the list.
check "auto-merge lets the kernel fold the duplicate" "1" \
    "$(printf '%s\n' "$mout" | grep -A3 'set vpn_ip' | grep -c 'auto-merge')"

# A channel cannot hold both kinds: they reach the set by different routes.
cat > "$tmp/xspec.json" <<EOF
{ "schema": 1, "outputs": { "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [ { "name": "mixed",
                  "match": { "prefixes_files": ["$tmp/m1.lst"], "domains_files": ["$tmp/d.lst"] },
                  "out": "vpn" } ] }
EOF
"$BIN" apply --dry-run --spec "$tmp/xspec.json" --state-dir "$tmp/state-m" >/dev/null 2>&1
check "refuses addresses and domains in one channel" "2" "$?"

# ---- does the spec need the resolver ----------------------------------------
# The init script asks the engine this. It used to grep the spec for the literal
# `"domains_file"`, and when the plural `domains_files` arrived the match stopped
# matching: the resolver did not start while apply still installed the DNS redirect,
# so every LAN query went to a closed port. DNS died on a live router.
"$BIN" needs-dnsd --spec "$tmp/dspec.json" --state-dir "$tmp/state-n" >/dev/null 2>&1
check "needs-dnsd: yes for a domain channel" "0" "$?"
"$BIN" needs-dnsd --spec "$tmp/spec.json" --state-dir "$tmp/state-n" >/dev/null 2>&1
check "needs-dnsd: no for address channels only" "1" "$?"

# And the shipped init script must ASK rather than guess, or the same trap returns
# the next time a key is renamed.
init=../files/etc/init.d/steer
if [ -f "$init" ]; then
    check "init script asks the engine" "1" "$(grep -c 'needs-dnsd' "$init")"
    check "init script does not grep the spec for keys" "0" \
        "$(grep -c "grep -q '\"domains" "$init")"
fi

# ---- пустая спека законна ----------------------------------------------------
# Отказ на ней запирал настройку наглухо: чтобы завести канал, нужен выход, а сохранить
# выход без каналов движок не давал. Из такого тупика нельзя выйти изнутри интерфейса.
printf '{"schema":1,"outputs":{},"channels":[]}' > "$tmp/empty.json"
"$BIN" apply --dry-run --spec "$tmp/empty.json" --state-dir "$tmp/state-e" >"$tmp/eo" 2>&1
check "пустая спека компилируется" "0" "$?"
check "и даёт таблицу с пустой цепочкой" "1" "$(grep -c 'chain prerouting_mark' "$tmp/eo")"
check "без наборов" "0" "$(grep -c '    set ' "$tmp/eo")"

printf '{"schema":1,"outputs":{"vpn":{"kind":"interface","device":"wg0"}},"channels":[]}' > "$tmp/only.json"
"$BIN" apply --dry-run --spec "$tmp/only.json" --state-dir "$tmp/state-e" >/dev/null 2>&1
check "выходы без каналов — законное состояние" "0" "$?"

# ---- защита от конфигураций, отрезающих роутер -------------------------------
# Всё это компилируется и применяется без жалоб, а замечается как "роутер пропал".
# Отказать дешевле, чем объяснять, как чинить коробку, до которой не достучаться.
cat > "$tmp/all.json" <<EOF
{ "schema": 1, "outputs": { "o": { "kind": "interface", "device": "wg0" } },
  "channels": [ { "name": "все", "match": { "any": true }, "out": "o" } ] }
EOF
"$BIN" apply --dry-run --spec "$tmp/all.json" --state-dir "$tmp/state-g" >/dev/null 2>&1
check "канал any без списка отвергается" "2" "$?"

# ...но остаётся выразимым, когда это правда то, что нужно.
sed 's/"any": true/"any": true, "allow_all": true/' "$tmp/all.json" > "$tmp/allok.json"
"$BIN" apply --dry-run --spec "$tmp/allok.json" --state-dir "$tmp/state-g" >/dev/null 2>&1
check "с allow_all он проходит" "0" "$?"

sed 's/"device": "wg0"/"device": "br-lan"/' "$tmp/allok.json" > "$tmp/loop.json"
"$BIN" apply --dry-run --spec "$tmp/loop.json" --state-dir "$tmp/state-g" >/dev/null 2>&1
check "выход в локальный мост отвергается" "2" "$?"

sed 's/"device": "wg0"/"devices": ["wg0","wg0"]/' "$tmp/allok.json" > "$tmp/dup.json"
"$BIN" apply --dry-run --spec "$tmp/dup.json" --state-dir "$tmp/state-g" >/dev/null 2>&1
check "дубликат устройства отвергается" "2" "$?"

# Сообщение обязано называть виновника: "steer: " без текста — это отказ, из
# которого нельзя понять, что чинить.
msg="$("$BIN" apply --dry-run --spec "$tmp/loop.json" --state-dir "$tmp/state-g" 2>&1 | tail -1)"
check "и объясняет, что не так" "1" "$(printf '%s' "$msg" | grep -c 'br-lan')"

# ---- failover ----------------------------------------------------------------
# devices — это приоритет, и единственное число остаётся сокращением для одного,
# чтобы прежние спеки не сломались.
cat > "$tmp/fo.json" <<EOF
{ "schema": 1,
  "outputs": { "o": { "kind": "interface", "devices": ["wg0", "wg1"], "on_fail": "drop" } },
  "channels": [ { "name": "c", "match": { "domains_files": ["$tmp/d.lst"] }, "out": "o" } ] }
EOF
"$BIN" apply --dry-run --spec "$tmp/fo.json" --state-dir "$tmp/state-f" >/dev/null 2>&1
check "список устройств принимается" "0" "$?"

sed 's/"on_fail": "drop"/"on_fail": "чепуха"/' "$tmp/fo.json" > "$tmp/fobad.json"
"$BIN" apply --dry-run --spec "$tmp/fobad.json" --state-dir "$tmp/state-f" >/dev/null 2>&1
check "неизвестный on_fail отвергается" "2" "$?"

# ---- refusals ---------------------------------------------------------------
# Guessing at an unknown schema would mean compiling a config we do not understand
# into firewall rules.
sed 's/"schema": 1/"schema": 2/' "$tmp/spec.json" > "$tmp/s2.json"
"$BIN" apply --dry-run --spec "$tmp/s2.json" $S >/dev/null 2>&1
check "refuses an unknown schema" "2" "$?"

sed 's/"out": "vpn"/"out": "nope"/' "$tmp/spec.json" > "$tmp/s3.json"
"$BIN" apply --dry-run --spec "$tmp/s3.json" $S >/dev/null 2>&1
check "refuses a channel pointing at a missing output" "2" "$?"

sed 's/"kind": "interface", "device": "wg0"/"kind": "interface"/' "$tmp/spec.json" > "$tmp/s4.json"
"$BIN" apply --dry-run --spec "$tmp/s4.json" $S >/dev/null 2>&1
check "refuses an interface output with no device" "2" "$?"

# An address from the command line reaches an nft invocation. This used to go
# through system(), which made `explain '$(...)'` a command-injection hole.
"$BIN" explain '$(id)' --spec "$tmp/spec.json" $S >/dev/null 2>&1
check "refuses an address that is not address-shaped" "2" "$?"

# ---- registry ----------------------------------------------------------------
# An output must keep its mark across runs: a reshuffle leaves stale `ip rule`
# entries pointing at the wrong table, and traffic silently takes another path.
before="$(cat "$tmp/state/registry")"
sed 's|"vpn":    { "kind": "interface", "device": "wg0" }|"vpn": { "kind": "interface", "device": "wg0" }, "extra": { "kind": "interface", "device": "wg1" }|' \
    "$tmp/spec.json" > "$tmp/s5.json"
"$BIN" apply --dry-run --spec "$tmp/s5.json" $S >/dev/null 2>&1
check "adding an output keeps the existing marks" "$before" \
    "$(grep -v '^extra ' "$tmp/state/registry")"
check "and gives the new one its own" "1" \
    "$(grep -c '^extra ' "$tmp/state/registry")"

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
