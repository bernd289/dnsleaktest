#!/usr/bin/env bash
set -uo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

QUERIES=100
TIMEOUT=3
PARALLEL=20
INTERFACE=""

usage() {
  cat <<EOF
Usage: $0 [-i source_ip] [-q queries] [-t timeout] [-p parallel]

Options:
  -i  Source IP for dig -b (must be a local IP bound to an interface), e.g. 192.168.1.10
  -q  Number of DNS queries, default: 100
  -t  Timeout per query in seconds, default: 3
  -p  Max concurrent queries, default: 20
  -h  Show help
EOF
}

die() {
  echo -e "${RED}Error:${NC} $*" >&2
  exit 1
}

command -v dig >/dev/null 2>&1 || die "'dig' not found. Install dnsutils/bind-tools."

while getopts ":i:q:t:p:h" opt; do
  case "$opt" in
    i) INTERFACE="$OPTARG" ;;
    q) QUERIES="$OPTARG" ;;
    t) TIMEOUT="$OPTARG" ;;
    p) PARALLEL="$OPTARG" ;;
    h) usage; exit 0 ;;
    :) die "Option -$OPTARG requires an argument." ;;
    \?) die "Unknown option: -$OPTARG" ;;
  esac
done

[[ "$QUERIES" =~ ^[0-9]+$ ]] || die "Queries must be a number."
[[ "$TIMEOUT" =~ ^[0-9]+$ ]] || die "Timeout must be a number."
[[ "$PARALLEL" =~ ^[0-9]+$ ]] || die "Parallel must be a number."
(( QUERIES > 0 )) || die "Queries must be greater than 0."
(( TIMEOUT > 0 )) || die "Timeout must be greater than 0."
(( PARALLEL > 0 )) || die "Parallel must be greater than 0."

if [[ -n "$INTERFACE" ]]; then
  [[ "$INTERFACE" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] \
    || die "-i requires a local IPv4 address (dig -b binds to an IP, not an interface name)."
fi

DIG_BASE_ARGS=(+short "+time=$TIMEOUT" +tries=1 TXT)
if [[ -n "$INTERFACE" ]]; then
  DIG_BASE_ARGS=(-b "$INTERFACE" "${DIG_BASE_ARGS[@]}")
  echo -e "${BOLD}Source IP bind:${NC} ${INTERFACE}\n"
fi

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

# Splits on the first ": " only, so values containing further colons
# (e.g. "resolverGeo: Berlin, DE") are still captured intact.
extract_field() {
  local field="$1"
  local input="$2"

  printf '%s\n' "$input" \
    | grep -o '"[^"]*"' \
    | sed 's/^"//; s/"$//' \
    | awk -F': ' -v key="$field" '$1 == key { print substr($0, length(key) + 3); exit }'
}

run_query() {
  local outfile="$1"
  local nonce qname result resolver geo org proto

  nonce="$(printf '%08x' "$(( (RANDOM << 16) | RANDOM ))")"
  qname="${nonce}.test.dnscheck.tools"

  result="$(dig "${DIG_BASE_ARGS[@]}" "$qname" 2>/dev/null || true)"

  resolver="$(extract_field "resolver" "$result")"
  [[ -z "$resolver" ]] && return 0

  geo="$(extract_field "resolverGeo" "$result")"
  org="$(extract_field "resolverOrg" "$result")"
  proto="$(extract_field "proto" "$result")"

  # One file per query -- avoids relying on PIPE_BUF line-atomicity when
  # many background jobs write to a single shared stream concurrently.
  printf '%s|%s|%s|%s\n' \
    "${org:-Unknown}" \
    "$resolver" \
    "${geo:-Unknown}" \
    "${proto:-Unknown}" \
    > "$outfile"
}

echo -e "${BOLD}=== DNS Leak Test ===${NC}\n"
echo "Running ${QUERIES} queries (max ${PARALLEL} concurrent)..."

running=0
for ((i = 1; i <= QUERIES; i++)); do
  run_query "$TMPDIR/$i" &
  (( running++ ))
  if (( running >= PARALLEL )); then
    wait -n
    (( running-- ))
  fi
done
wait

RESULTS_LIST="$(
  cat "$TMPDIR"/* 2>/dev/null \
    | awk -F'|' '!seen[$2]++' \
    | sort -t'|' -k1,1 -k2,2
)"
RESULT_COUNT="$(grep -c '|' <<< "$RESULTS_LIST" || true)"

if (( RESULT_COUNT == 0 )); then
  die "No resolver information could be parsed."
fi

echo
echo -e "${BOLD}=== Results ===${NC}\n"

while IFS='|' read -r org resolver geo proto; do
  [[ -z "$resolver" ]] && continue
  echo -e " ${GREEN}${org}${NC} | ${resolver} | ${geo} | ${proto}"
done <<< "$RESULTS_LIST"

echo
echo -e "${BOLD}${RESULT_COUNT} resolver(s) found.${NC}"

if (( RESULT_COUNT > 1 )); then
  echo -e "${YELLOW}Potential DNS leak or multiple upstream resolvers detected.${NC}"
else
  echo -e "${GREEN}No obvious DNS leak detected.${NC}"
fi
