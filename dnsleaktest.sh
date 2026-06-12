#!/usr/bin/env bash
# DNS Leak Test via dnscheck.tools
# Usage: ./dnsleaktest.sh [-i interface_ip|interface_name]

BOLD='\033[1m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

QUERIES=100

getopts "i:" opt
INTERFACE=$OPTARG

DIG_OPTS=""
if [ -n "$INTERFACE" ]; then
    DIG_OPTS="-b $INTERFACE"
    echo -e "${BOLD}Interface: ${INTERFACE}${NC}\n"
fi

echo -e "${BOLD}=== DNS Leak Test ===${NC}\n"
echo "Running ${QUERIES} queries..."

declare -A SEEN
RESULTS_LIST=""

for i in $(seq 1 $QUERIES); do
    result=$(dig $DIG_OPTS +short +time=3 TXT "test.dnscheck.tools" 2>/dev/null)
    resolver=$(echo "$result" | grep 'resolver:' | cut -d' ' -f2 | tr -d '"')
    [ -z "$resolver" ] && continue
    [ -n "${SEEN[$resolver]}" ] && continue
    SEEN[$resolver]=1

    geo=$(echo "$result"   | grep 'resolverGeo:' | cut -d' ' -f2- | tr -d '"')
    org=$(echo "$result"   | grep 'resolverOrg:' | cut -d' ' -f2- | tr -d '"')
    proto=$(echo "$result" | grep 'proto:'       | cut -d' ' -f2  | tr -d '"')

    RESULTS_LIST+="${org}|${resolver}|${geo}|${proto}"$'\n'
done

if [ ${#SEEN[@]} -eq 0 ]; then
    echo -e "${RED}No response from test server.${NC}" >&2
    exit 1
fi

echo ""
echo -e "${BOLD}=== Results ===${NC}\n"

while IFS='|' read -r org resolver geo proto; do
    [ -z "$resolver" ] && continue
    echo -e "  ${GREEN}${org}${NC} | ${resolver} | ${geo} | ${proto}"
done < <(echo "$RESULTS_LIST" | sort)

echo ""
echo -e "${BOLD}${#SEEN[@]} resolver(s) found.${NC}"
