#!/usr/bin/env bash
set -uo pipefail

QUERIES=100
TIMEOUT=3
PARALLEL=20
SOURCE_IP=""
HAVE_WAIT_N=0

if ((BASH_VERSINFO[0] > 4 ||
     (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 3))); then
  HAVE_WAIT_N=1
fi

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  BOLD=$'\033[1m'
  GREEN=$'\033[0;32m'
  RED=$'\033[0;31m'
  YELLOW=$'\033[0;33m'
  NC=$'\033[0m'
else
  BOLD=""
  GREEN=""
  RED=""
  YELLOW=""
  NC=""
fi

usage() {
  cat <<EOF
Usage: ${0##*/} [-i source_ip] [-q queries] [-t timeout] [-p parallel]

Options:
  -i  Source IPv4/IPv6 address for dig -b, e.g. 192.168.1.10
      (must be assigned locally; this is an IP address, not an interface name)
  -q  Number of DNS queries, default: 100, maximum: 100000
  -t  Timeout per query in seconds, default: 3, maximum: 300
  -p  Maximum concurrent queries, default: 20, maximum: 1000
  -h  Show this help

Interpretation:
  Multiple resolver IPs can be normal with anycast, load balancing, or multiple
  configured upstreams. A DNS leak is indicated only when an unexpected resolver
  or resolver organization appears. A non-/0 EDNS Client Subnet (ECS) means the
  resolver disclosed part of the client network to the authoritative server.
EOF
}

die() {
  printf '%bError:%b %s\n' "$RED" "$NC" "$*" >&2
  exit 1
}

warn() {
  printf '%bWarning:%b %s\n' "$YELLOW" "$NC" "$*" >&2
}

NORMALIZED_INT=0
normalize_positive_int() {
  local label="$1"
  local value="$2"
  local maximum="$3"

  [[ "$value" =~ ^[0-9]+$ ]] || die "$label must be a positive integer."
  ((${#value} <= 18)) || die "$label is too large."

  NORMALIZED_INT=$((10#$value))
  ((NORMALIZED_INT > 0)) || die "$label must be greater than 0."
  ((NORMALIZED_INT <= maximum)) || die "$label must not exceed $maximum."
}

valid_ipv4() {
  local ip="$1"
  local octet
  local -a octets

  [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1

  IFS='.' read -r -a octets <<< "$ip"
  ((${#octets[@]} == 4)) || return 1

  for octet in "${octets[@]}"; do
    [[ "$octet" =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
    ((10#$octet <= 255)) || return 1
  done
}

IPV6_GROUP_COUNT=0
count_ipv6_groups() {
  local section="$1"
  local group
  local -a groups

  IPV6_GROUP_COUNT=0
  [[ -n "$section" ]] || return 0

  IFS=':' read -r -a groups <<< "$section"
  for group in "${groups[@]}"; do
    [[ "$group" =~ ^[0-9A-Fa-f]{1,4}$ ]] || return 1
  done
  IPV6_GROUP_COUNT=${#groups[@]}
}

valid_ipv6() {
  local address="$1"
  local ipv4_tail
  local left
  local right
  local remainder
  local left_count
  local right_count

  [[ "$address" == *:* ]] || return 1
  [[ "$address" =~ ^[0-9A-Fa-f:.]+$ ]] || return 1
  [[ "$address" != *:::* ]] || return 1
  [[ "$address" != :* || "$address" == ::* ]] || return 1
  [[ "$address" != *: || "$address" == *:: ]] || return 1

  # An embedded IPv4 address occupies two IPv6 groups.
  if [[ "$address" == *.* ]]; then
    ipv4_tail="${address##*:}"
    valid_ipv4 "$ipv4_tail" || return 1
    address="${address%:*}:0:0"
  fi

  if [[ "$address" == *::* ]]; then
    remainder="${address#*::}"
    [[ "$remainder" != *::* ]] || return 1

    left="${address%%::*}"
    right="${address#*::}"

    count_ipv6_groups "$left" || return 1
    left_count=$IPV6_GROUP_COUNT
    count_ipv6_groups "$right" || return 1
    right_count=$IPV6_GROUP_COUNT

    # "::" must replace at least one of the eight groups.
    ((left_count + right_count < 8))
  else
    [[ "$address" != :* && "$address" != *: ]] || return 1
    count_ipv6_groups "$address" || return 1
    ((IPV6_GROUP_COUNT == 8))
  fi
}

NORMALIZED_IPV6=""
normalize_ipv6() {
  local address="$1"
  local ipv4_tail
  local ipv4_high
  local ipv4_low
  local left
  local right
  local missing
  local group
  local normalized_group
  local normalized=""
  local -a octets
  local -a left_groups
  local -a right_groups
  local -a all_groups

  valid_ipv6 "$address" || return 1

  if [[ "$address" == *.* ]]; then
    ipv4_tail="${address##*:}"
    IFS='.' read -r -a octets <<< "$ipv4_tail"
    printf -v ipv4_high '%x' \
      "$((10#${octets[0]} * 256 + 10#${octets[1]}))"
    printf -v ipv4_low '%x' \
      "$((10#${octets[2]} * 256 + 10#${octets[3]}))"
    address="${address%:*}:$ipv4_high:$ipv4_low"
  fi

  left_groups=()
  right_groups=()
  all_groups=()

  if [[ "$address" == *::* ]]; then
    left="${address%%::*}"
    right="${address#*::}"
    [[ -z "$left" ]] || IFS=':' read -r -a left_groups <<< "$left"
    [[ -z "$right" ]] || IFS=':' read -r -a right_groups <<< "$right"

    all_groups=("${left_groups[@]}")
    missing=$((8 - ${#left_groups[@]} - ${#right_groups[@]}))
    while ((missing > 0)); do
      all_groups+=("0")
      missing=$((missing - 1))
    done
    all_groups+=("${right_groups[@]}")
  else
    IFS=':' read -r -a all_groups <<< "$address"
  fi

  for group in "${all_groups[@]}"; do
    printf -v normalized_group '%x' "$((16#$group))"
    if [[ -n "$normalized" ]]; then
      normalized="$normalized:$normalized_group"
    else
      normalized="$normalized_group"
    fi
  done

  NORMALIZED_IPV6="$normalized"
}

source_ip_is_local() {
  local wanted="$1"
  local wanted_normalized=""
  local candidate_normalized
  local index
  local interface
  local family
  local address
  local remainder
  local address_list

  if valid_ipv6 "$wanted"; then
    normalize_ipv6 "$wanted" || return 1
    wanted_normalized="$NORMALIZED_IPV6"
  fi

  if ! address_list="$(ip -o address show 2>/dev/null)"; then
    return 2
  fi

  while read -r index interface family address remainder; do
    address="${address%%/*}"
    if [[ "$family" == "inet" && "$address" == "$wanted" ]]; then
      return 0
    fi
    if [[ "$family" == "inet6" && -n "$wanted_normalized" ]] &&
       normalize_ipv6 "$address"; then
      candidate_normalized="$NORMALIZED_IPV6"
      [[ "$candidate_normalized" == "$wanted_normalized" ]] && return 0
    fi
  done <<< "$address_list"

  return 1
}

while getopts ":i:q:t:p:h" opt; do
  case "$opt" in
    i) SOURCE_IP="$OPTARG" ;;
    q) QUERIES="$OPTARG" ;;
    t) TIMEOUT="$OPTARG" ;;
    p) PARALLEL="$OPTARG" ;;
    h)
      usage
      exit 0
      ;;
    :) die "Option -$OPTARG requires an argument." ;;
    \?) die "Unknown option: -$OPTARG" ;;
  esac
done

shift "$((OPTIND - 1))"
(($# == 0)) || die "Unexpected argument: $1"

normalize_positive_int "Queries" "$QUERIES" 100000
QUERIES=$NORMALIZED_INT
normalize_positive_int "Timeout" "$TIMEOUT" 300
TIMEOUT=$NORMALIZED_INT
normalize_positive_int "Parallelism" "$PARALLEL" 1000
PARALLEL=$NORMALIZED_INT

((PARALLEL <= QUERIES)) || PARALLEL=$QUERIES

if [[ -n "$SOURCE_IP" ]]; then
  if ! valid_ipv4 "$SOURCE_IP" && ! valid_ipv6 "$SOURCE_IP"; then
    die "-i requires a valid local IPv4/IPv6 address (not an interface name)."
  fi

  if command -v ip >/dev/null 2>&1; then
    source_ip_is_local "$SOURCE_IP"
    SOURCE_IP_STATUS=$?
    if ((SOURCE_IP_STATUS == 1)); then
      die "Source IP $SOURCE_IP is not assigned to a local interface."
    elif ((SOURCE_IP_STATUS == 2)); then
      warn "Could not inspect local addresses; dig will validate the source binding."
    fi
  fi
fi

command -v dig >/dev/null 2>&1 \
  || die "'dig' not found. Install dnsutils/bind-tools."

for dependency in awk find sort mktemp; do
  command -v "$dependency" >/dev/null 2>&1 \
    || die "'$dependency' not found."
done

DIG_BASE_ARGS=(+short "+time=$TIMEOUT" +tries=1)
if [[ -n "$SOURCE_IP" ]]; then
  DIG_BASE_ARGS=(-b "$SOURCE_IP" "${DIG_BASE_ARGS[@]}")
fi

WORK_DIR="$(mktemp -d)" || die "Could not create a temporary directory."
RAW_DIR="$WORK_DIR/raw"
if ! mkdir "$RAW_DIR"; then
  rmdir "$WORK_DIR" 2>/dev/null || true
  die "Could not create the diagnostic directory."
fi
PIDS=()

refresh_worker_pids() {
  local pid

  jobs -pr > "$WORK_DIR/active-pids" 2>/dev/null || true
  PIDS=()
  while IFS= read -r pid; do
    [[ "$pid" =~ ^[0-9]+$ ]] && PIDS+=("$pid")
  done < "$WORK_DIR/active-pids"
}

cleanup() {
  local exit_code=$?

  trap - EXIT
  # A repeated Ctrl+C must not interrupt cleanup halfway through.
  trap '' INT TERM

  refresh_worker_pids
  if ((${#PIDS[@]} > 0)); then
    kill "${PIDS[@]}" 2>/dev/null || true
    wait "${PIDS[@]}" 2>/dev/null || true
  fi

  if [[ -n "${WORK_DIR:-}" && -d "$WORK_DIR" ]]; then
    rm -rf -- "$WORK_DIR"
  fi

  exit "$exit_code"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

parse_response() {
  awk '
    BEGIN { OFS = "\t" }

    /^".*"$/ {
      line = $0
      sub(/^"/, "", line)
      sub(/"$/, "", line)
      gsub(/" "/, "", line)

      separator = index(line, ": ")
      if (separator == 0) {
        next
      }

      key = substr(line, 1, separator - 1)
      value = substr(line, separator + 2)

      if (key == "resolver") {
        resolver = value
      } else if (key == "resolverGeo") {
        geo = value
      } else if (key == "resolverOrg") {
        organization = value
      } else if (key == "proto") {
        protocol = value
      } else if (key == "clientSubnet") {
        client_subnet = value
      }
    }

    END {
      if (resolver == "") {
        exit 1
      }

      if (organization == "") {
        organization = "Unknown"
      }
      if (geo == "") {
        geo = "Unknown"
      }
      if (protocol == "") {
        protocol = "Unknown"
      }
      if (client_subnet == "") {
        client_subnet = "None"
      }

      print resolver, organization, geo, protocol, client_subnet
    }
  '
}

run_query() {
  local outfile="$1"
  local rawfile="$2"
  local nonce="$3"
  local qname="${nonce}.test.dnscheck.tools"
  local result
  local parsed

  # Ensure every started job leaves a status record, even after an internal
  # failure. Successful and expected failure paths overwrite this marker.
  printf 'INTERNAL_ERROR\n' > "$outfile"

  if ! result="$(dig "${DIG_BASE_ARGS[@]}" "$qname" TXT 2>&1)"; then
    result="${result//$'\n'/ }"
    result="${result//$'\t'/ }"
    printf 'DIG_ERROR\t%.240s\n' "${result:-dig returned an error}" > "$outfile"
    return 0
  fi

  if ! parsed="$(printf '%s\n' "$result" | parse_response)"; then
    printf '%s\n' "$result" > "$rawfile"
    printf 'PARSE_ERROR\t%s\n' \
      'The response did not contain a resolver field.' \
      > "$outfile"
    return 0
  fi

  printf 'OK\t%s\n' "$parsed" > "$outfile"
}

printf '%b=== DNS Resolver Test ===%b\n\n' "$BOLD" "$NC"
if [[ -n "$SOURCE_IP" ]]; then
  printf '%bSource IP bind:%b %s\n\n' "$BOLD" "$NC" "$SOURCE_IP"
fi
printf 'Running %d queries (maximum %d concurrent)...\n' "$QUERIES" "$PARALLEL"

# Generate cache-busting names in the parent process. Adding the query number
# guarantees uniqueness within this run while keeping the documented random
# label at no more than eight hexadecimal digits.
NONCE_SEED=$(((RANDOM << 16) | RANDOM))

for ((i = 1; i <= QUERIES; i++)); do
  printf -v nonce '%08x' "$(((NONCE_SEED + i) & 0xffffffff))"
  run_query "$WORK_DIR/query.$i" "$RAW_DIR/response.$i" "$nonce" &
  PIDS+=("$!")

  if ((${#PIDS[@]} >= PARALLEL)); then
    if ((HAVE_WAIT_N)); then
      wait -n || true
    else
      # Bash 3.2 fallback: waiting for the oldest worker is compatible but can
      # briefly under-use the configured parallelism when that worker is slow.
      wait "${PIDS[0]}" || true
    fi
    refresh_worker_pids
  fi
done

wait || true
PIDS=()

RESULT_DATA="$WORK_DIR/all-results.tsv"
find "$WORK_DIR" -type f -name 'query.*' -exec awk '1' {} + > "$RESULT_DATA"

STATS="$(
  awk -F '\t' '
    $1 == "OK"             { ok++ }
    $1 == "DIG_ERROR"      { dig_error++ }
    $1 == "PARSE_ERROR"    { parse_error++ }
    $1 == "INTERNAL_ERROR" { internal_error++ }
    END {
      printf "%d\t%d\t%d\t%d\n",
        ok + 0, dig_error + 0, parse_error + 0, internal_error + 0
    }
  ' "$RESULT_DATA"
)"

IFS=$'\t' read -r \
  SUCCESS_COUNT DIG_ERROR_COUNT PARSE_ERROR_COUNT INTERNAL_ERROR_COUNT \
  <<< "$STATS"

RESULTS_LIST="$(
  awk -F '\t' '
    $1 == "OK" && !seen[$2]++ {
      print $3 "\t" $2 "\t" $4 "\t" $5
    }
  ' "$RESULT_DATA" \
    | LC_ALL=C sort -t $'\t' -k1,1 -k2,2
)"

RESULT_COUNT="$(
  printf '%s\n' "$RESULTS_LIST" \
    | awk -F '\t' 'NF >= 2 { count++ } END { print count + 0 }'
)"

ORG_COUNT="$(
  printf '%s\n' "$RESULTS_LIST" \
    | awk -F '\t' 'NF >= 2 && !seen[$1]++ { count++ } END { print count + 0 }'
)"

ECS_DETAILS="$(
  awk -F '\t' '
    $1 == "OK" &&
    $6 != "" &&
    $6 != "None" &&
    $6 !~ /\/0$/ {
      key = $2 SUBSEP $6
      if (!seen[key]++) {
        print $3 "\t" $2 "\t" $6
      }
    }
  ' "$RESULT_DATA" \
    | LC_ALL=C sort -t $'\t' -k1,1 -k2,2 -k3,3
)"

ECS_COUNT="$(
  printf '%s\n' "$ECS_DETAILS" \
    | awk -F '\t' 'NF >= 3 { count++ } END { print count + 0 }'
)"

if ((RESULT_COUNT == 0)); then
  FIRST_ERROR="$(
    awk -F '\t' '
      $1 != "OK" && NF > 1 {
        sub(/^[^\t]*\t/, "")
        print
        exit
      }
    ' "$RESULT_DATA"
  )"

  if [[ -n "$FIRST_ERROR" ]]; then
    FIRST_RAW_FILE="$(
      find "$RAW_DIR" -type f -name 'response.*' -print 2>/dev/null \
        | awk 'NR == 1 { print }'
    )"
    if [[ -n "$FIRST_RAW_FILE" ]]; then
      printf 'First unparsable response:\n' >&2
      while IFS= read -r raw_line || [[ -n "$raw_line" ]]; do
        printf '  %s\n' "$raw_line" >&2
      done < "$FIRST_RAW_FILE"
    fi
    die "No resolver information could be parsed. First error: $FIRST_ERROR"
  fi
  die "No resolver information could be parsed."
fi

printf '\n%b=== Results ===%b\n\n' "$BOLD" "$NC"

while IFS=$'\t' read -r organization resolver geo protocol; do
  [[ -n "$resolver" ]] || continue
  printf ' %b%s%b | %s | %s | %s\n' \
    "$GREEN" "$organization" "$NC" "$resolver" "$geo" "$protocol"
done <<< "$RESULTS_LIST"

printf '\n%b%d resolver egress IP(s) across %d organization(s).%b\n' \
  "$BOLD" "$RESULT_COUNT" "$ORG_COUNT" "$NC"
printf '%d/%d queries returned parseable resolver information.\n' \
  "$SUCCESS_COUNT" "$QUERIES"

if ((SUCCESS_COUNT < QUERIES)); then
  printf '%bUnusable queries: %d dig error(s), %d parse error(s), %d internal error(s).%b\n' \
    "$YELLOW" \
    "$DIG_ERROR_COUNT" \
    "$PARSE_ERROR_COUNT" \
    "$INTERNAL_ERROR_COUNT" \
    "$NC"
fi

if ((ORG_COUNT > 1)); then
  printf '%bMultiple resolver organizations detected. Check that every one is expected.%b\n' \
    "$YELLOW" "$NC"
elif ((RESULT_COUNT > 1)); then
  printf '%bMultiple egress IPs from one organization detected; this is commonly normal.%b\n' \
    "$GREEN" "$NC"
else
  printf '%bOne resolver egress IP was observed.%b\n' "$GREEN" "$NC"
fi

if ((ECS_COUNT > 0)); then
  printf '%bEDNS Client Subnet disclosure detected:%b\n' "$YELLOW" "$NC"
  while IFS=$'\t' read -r organization resolver client_subnet; do
    [[ -n "$resolver" ]] || continue
    printf ' %s | %s | %s\n' "$organization" "$resolver" "$client_subnet"
  done <<< "$ECS_DETAILS"
else
  printf '%bNo non-/0 EDNS Client Subnet was observed.%b\n' "$GREEN" "$NC"
fi

printf 'A resolver-path leak exists only if a listed resolver/provider is not one you expect.\n'
