#!/usr/bin/env bash
set -uo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

QUERIES=100
TIMEOUT=3
INTERFACE=""

usage() {
  cat <<EOF
Usage: $0 [-i interface_ip] [-q queries] [-t timeout]

Options:
  -i  Source IP/interface for dig -b, e.g. 192.168.1.10
  -q  Number of DNS queries, default: 100
  -t  Timeout per query in seconds, default: 3
  -h  Show help
EOF
}

die() {
  echo -e "${RED}Error:${NC} $*" >&2
  exit 1
}

command -v dig >/dev/null 2>&1 || die "'dig' not found. Install dnsutils/bind-tools."

while getopts ":i:q:t:h" opt; do
  case "$opt" in
    i) INTERFACE="$OPTARG" ;;
    q) QUERIES="$OPTARG" ;;
    t) TIMEOUT="$OPTARG" ;;
    h) usage; exit 0 ;;
    :) die "Option -$OPTARG requires an argument." ;;
    \?) die "Unknown option: -$OPTARG" ;;
  esac
done

[[ "$QUERIES" =~ ^[0-9]+$ ]] || die "Queries must be a number."
[[ "$TIMEOUT" =~ ^[0-9]+$ ]] || die "Timeout must be a number."
(( QUERIES > 0 )) || die "Queries must be greater than 0."
(( TIMEOUT > 0 )) || die "Timeout must be greater than 0."

DIG_BASE_ARGS=(+short "+time=$TIMEOUT" +tries=1 TXT)

if [[ -n "$INTERFACE" ]]; then
  DIG_BASE_ARGS=(-b "$INTERFACE" "${DIG_BASE_ARGS[@]}")
  echo -e "${BOLD}Interface/source bind:${NC} ${INTERFACE}\n"
fi

extract_field() {
  local field="$1"
  local input="$2"

  printf '%s\n' "$input" \
    | grep -o '"[^"]*"' \
    | sed 's/^"//; s/"$//' \
    | awk -F': ' -v key="$field" '$1 == key { print substr($0, length(key) + 3); exit }'
}

echo -e "${BOLD}=== DNS Leak Test ===${NC}\n"
echo "Running ${QUERIES} queries..."

declare -A SEEN
RESULT_COUNT=0
RESULTS_LIST=""
FIRST_RAW_RESULT=""

for ((i = 1; i <= QUERIES; i++)); do
  nonce="$(printf '%08x' "$(( (RANDOM << 16) | RANDOM ))")"
  qname="${nonce}.test.dnscheck.tools"

  result="$(dig "${DIG_BASE_ARGS[@]}" "$qname" 2>/dev/null || true)"

  if [[ -z "$FIRST_RAW_RESULT" && -n "$result" ]]; then
    FIRST_RAW_RESULT="$result"
  fi

  resolver="$(extract_field "resolver" "$result")"
  [[ -z "$resolver" ]] && continue
  [[ -n "${SEEN[$resolver]:-}" ]] && continue

  SEEN["$resolver"]=1
  ((RESULT_COUNT++))

  geo="$(extract_field "resolverGeo" "$result")"
  org="$(extract_field "resolverOrg" "$result")"
  proto="$(extract_field "proto" "$result")"

  RESULTS_LIST+="${org:-Unknown}|${resolver}|${geo:-Unknown}|${proto:-Unknown}"$'\n'
done

if (( RESULT_COUNT == 0 )); then
  echo -e "${RED}Error:${NC} No resolver information could be parsed." >&2

  if [[ -n "$FIRST_RAW_RESULT" ]]; then
    echo >&2
    echo "First raw dig result was:" >&2
    echo "$FIRST_RAW_RESULT" >&2
  else
    echo "No DNS response received from dnscheck.tools." >&2
  fi

  exit 1
fi

echo
echo -e "${BOLD}=== Results ===${NC}\n"

sort <<< "$RESULTS_LIST" | while IFS='|' read -r org resolver geo proto; do
  [[ -z "$resolver" ]] && continue
  echo -e " ${GREEN}${org}${NC} | ${resolver} | ${geo} | ${proto}"
done

echo
echo -e "${BOLD}${RESULT_COUNT} resolver(s) found.${NC}"
echo
