#!/bin/sh
# Golden tests for the fitter. Runs entirely offline on fixtures — no router, no
# network, no nft. That is the point of making the engine a compiler: the behaviour
# that used to be verifiable only by installing on a 580MHz box and watching what
# happened to a browser is now a text comparison.
set -u
BIN="${STEER_AGGREGATE:-./build/steer-aggregate}"
[ -x "$BIN" ] || { echo "not built: $BIN (make)"; exit 2; }

pass=0 fail=0
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# check NAME EXPECTED ACTUAL
check() {
    if [ "$2" = "$3" ]; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
# field NAME < report
field() { sed -n "s/.*\"$1\":\([0-9]*\).*/\1/p"; }
flag()  { sed -n "s/.*\"$1\":\(true\|false\).*/\1/p"; }

# ---- parsing ---------------------------------------------------------------
# Every form this tool can EMIT must also parse, or the ladder stops being
# composable and the golden files below stop round-tripping.
# Non-adjacent on purpose: touching entries merge losslessly first, which would
# hide whether the parser understood each form.
out="$(printf '10.0.0.1\n10.0.2.0/24\n10.0.9.0-10.0.9.5\n' | "$BIN" 2>/dev/null)"
check "parses host, prefix and range" "10.0.0.1
10.0.2.0/24
10.0.9.0-10.0.9.5" "$out"

out="$(printf 'nonsense\n10.0.0.1\n999.1.1.1\n10.0.0.2/33\n' | "$BIN" 2>"$tmp/r")"
check "skips malformed lines" "10.0.0.1" "$out"
check "counts malformed lines" "3" "$(field malformed < "$tmp/r")"

# ---- lossless merge --------------------------------------------------------
out="$(printf '10.0.0.0/25\n10.0.0.128/25\n' | "$BIN" 2>/dev/null)"
check "merges touching prefixes into one" "10.0.0.0/24" "$out"

out="$(printf '10.0.0.0/24\n10.0.2.0/24\n' | "$BIN" 2>/dev/null)"
check "leaves a real gap alone" "10.0.0.0/24
10.0.2.0/24" "$out"

# ---- density collapse ------------------------------------------------------
out="$(printf '10.0.0.1\n10.0.0.9\n10.0.0.200\n' | "$BIN" --budget 1 2>/dev/null)"
check "collapses a /24 holding three addresses" "10.0.0.0/24" "$out"

# A lone address in a /24 buys nothing by collapsing and costs 255 addresses: in the
# real blocklist 8 428 of 10 716 /24s look like this, which is why the threshold is 2.
printf '10.0.0.1\n10.5.0.1\n' | "$BIN" --budget 1 2>"$tmp/r" >/dev/null
check "does not collapse single-address /24s" "0" "$(field level < "$tmp/r")"
check "reports it did not fit" "false" "$(flag fits < "$tmp/r")"

printf '10.0.0.1\n10.0.0.200\n' | "$BIN" --budget 1 2>"$tmp/r" >/dev/null
check "reports the waste it caused" "254" "$(field waste_addresses < "$tmp/r")"

# A wider level must demand more entries, or a /16 holding two lonely addresses
# swallows 65 534 of them to save one element.
printf '10.0.0.1\n10.0.9.1\n' | "$BIN" --budget 1 --levels '24:2 16:16' 2>"$tmp/r" >/dev/null
check "wide level refuses a sparse network" "0" "$(field level < "$tmp/r")"

# ---- exclusions ------------------------------------------------------------
printf '10.0.0.99\n' > "$tmp/ex"
printf '10.0.0.1\n10.0.0.200\n' | "$BIN" --budget 1 --exclude "$tmp/ex" 2>"$tmp/r" >"$tmp/o"
check "refuse mode keeps the /32s" "10.0.0.1
10.0.0.200" "$(cat "$tmp/o")"

printf '10.0.0.1\n10.0.0.200\n' | "$BIN" --budget 1 --exclude "$tmp/ex" \
    --punch-out "$tmp/p" 2>"$tmp/r" >"$tmp/o"
check "punch mode collapses anyway" "10.0.0.0/24" "$(cat "$tmp/o")"
check "punch mode hands back the excluded address" "10.0.0.99" "$(cat "$tmp/p")"
check "punch mode counts what it punched" "1" "$(field punched < "$tmp/r")"

# The invariant that makes punch mode safe: everything handed back is inside what
# was collapsed. If the caller routes the punch list first, nothing loses its
# direct path — and if this ever breaks, addresses silently ride the tunnel.
printf '10.0.0.1\n10.0.0.200\n10.9.9.9\n' > "$tmp/in"
printf '10.0.0.99\n10.9.9.9\n192.168.1.1\n' > "$tmp/ex2"
"$BIN" --budget 2 --exclude "$tmp/ex2" --punch-out "$tmp/p" "$tmp/in" >"$tmp/o" 2>/dev/null
check "punches only what a collapse swallowed" "10.0.0.99" "$(cat "$tmp/p")"

# ---- truncation is opt-in --------------------------------------------------
# Defaulting to truncation is how a router ends up silently unprotected above one
# address, with nothing in the logs tying the symptom to memory.
printf '10.0.0.1\n10.5.0.1\n10.9.0.1\n' > "$tmp/in"
"$BIN" --budget 1 "$tmp/in" >"$tmp/o" 2>"$tmp/r"; rc=$?
check "without --truncate nothing is dropped" "3" "$(wc -l < "$tmp/o" | tr -d ' ')"
check "and it says so" "false" "$(flag fits < "$tmp/r")"
check "exit code signals the misfit" "1" "$rc"

"$BIN" --budget 1 --truncate "$tmp/in" >"$tmp/o" 2>"$tmp/r"
check "with --truncate it drops the tail" "1" "$(wc -l < "$tmp/o" | tr -d ' ')"
check "and names the boundary" '"covered_through":"10.0.0.1"' \
    "$(sed -n 's/.*\("covered_through":"[^"]*"\).*/\1/p' < "$tmp/r")"

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
