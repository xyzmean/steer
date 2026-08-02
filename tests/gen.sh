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
    set ch_keep {
        type ipv4_addr
        flags interval
        elements = { 198.51.100.5 }
    }
    set ch_blocked {
        type ipv4_addr
        flags interval
        elements = { 203.0.113.0/24, 198.51.100.5 }
    }
    chain prerouting_mark {
        type filter hook prerouting priority mangle + 1; policy accept;
        ip saddr { 192.168.1.0/24 } ip daddr @ch_keep counter return comment "steer:keep"
        ip saddr { 192.168.1.0/24 } ip daddr @ch_blocked meta mark set 0x00100000 counter return comment "steer:blocked"
    }
}
EOF
)"
check "generates the expected ruleset" "$want" "$out"

# Precedence is the spec's central promise: 198.51.100.5 is in BOTH lists, and the
# rule that claims it must be the one written first.
first="$(printf '%s\n' "$out" | grep -n 'comment "steer:' | head -1 | sed 's/.*steer://; s/".*//')"
check "first channel in the spec is first in the chain" "keep" "$first"

# A direct output claims the packet and marks nothing — the point of `return`.
check "direct output sets no mark" "0" \
    "$(printf '%s\n' "$out" | grep 'steer:keep' | grep -c 'meta mark set')"

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
