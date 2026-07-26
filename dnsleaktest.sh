#!/usr/bin/env bash
set -uo pipefail

QUERIES=100
TIMEOUT=3
PARALLEL=20
SOURCE_IP=""
ENRICH_UNKNOWN=0
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
Usage: ${0##*/} [-e] [-i source_ip] [-q queries] [-t timeout] [-p parallel]

Options:
  -e  Enrich missing resolver organizations using dnscheck.tools known ranges
      and public RDAP data (best effort; requires curl and Python 3)
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

while getopts ":ei:q:t:p:h" opt; do
  case "$opt" in
    e) ENRICH_UNKNOWN=1 ;;
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

if ((ENRICH_UNKNOWN)); then
  command -v curl >/dev/null 2>&1 \
    || die "'curl' is required for provider enrichment."
  command -v python3 >/dev/null 2>&1 \
    || die "'python3' is required for provider enrichment."
fi

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
        client_subnet = "Unknown"
      }

      print resolver, organization, geo, protocol, client_subnet
    }
  '
}

enrich_unknown_organizations() {
  local results_file="$1"

  # dnscheck.tools enriches its browser results with known provider ranges and
  # RDAP. Keep that optional here so the DNS-only test remains dependency-light.
  python3 - "$results_file" <<'PY'
import ipaddress
import json
import re
import subprocess
import sys
import urllib.parse

results_file = sys.argv[1]
unknown = []
seen = set()

with open(results_file, encoding="utf-8", errors="replace") as results:
    for line in results:
        fields = line.rstrip("\n").split("\t")
        if len(fields) < 2 or fields[0] != "Unknown" or fields[1] in seen:
            continue
        try:
            address = ipaddress.ip_address(fields[1])
        except ValueError:
            continue
        seen.add(fields[1])
        unknown.append(address)

# Always emit a header so the mapping file is non-empty even when every lookup
# fails. This also keeps the following POSIX awk join correct.
print("#resolver\torganization")
if not unknown:
    raise SystemExit


def get_json(url):
    completed = subprocess.run(
        [
            "curl",
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--max-redirs",
            "5",
            "--connect-timeout",
            "6",
            "--max-time",
            "20",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--header",
            "Accept: application/rdap+json, application/json",
            "--user-agent",
            "dnsleaktest/rdap-enrichment",
            url,
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=25,
    )
    return json.loads(completed.stdout)


known_ranges = []
try:
    for obj in get_json("https://dnscheck.tools/known-ipranges.json"):
        description = obj.get("desc")
        if not isinstance(description, str) or not description:
            continue
        for cidr in obj.get("ranges", []):
            try:
                known_ranges.append(
                    (ipaddress.ip_network(cidr, strict=False), description)
                )
            except ValueError:
                pass
except Exception:
    # RDAP still provides useful fallback data if the friendly-name list is
    # temporarily unavailable.
    pass


def known_description(address):
    for network, description in known_ranges:
        if address in network:
            return description
    return None


rdap_cache = []


def rdap_lookup(address):
    for start, end, data in rdap_cache:
        if start <= address <= end:
            return data

    encoded = urllib.parse.quote(str(address), safe=":")
    data = get_json("https://rdap.arin.net/registry/ip/" + encoded)
    try:
        start = ipaddress.ip_address(data["startAddress"])
        end = ipaddress.ip_address(data["endAddress"])
        if start.version == address.version and end.version == address.version:
            rdap_cache.append((start, end, data))
    except (KeyError, ValueError):
        pass
    return data


def vcard_name(entity):
    card = entity.get("vcardArray")
    if not isinstance(card, list) or len(card) < 2:
        return None, None
    if not isinstance(card[1], list):
        return None, None

    name = None
    kind = None
    for prop in card[1]:
        if not isinstance(prop, list) or len(prop) < 4:
            continue
        if prop[0] == "fn" and name is None and isinstance(prop[3], str):
            name = prop[3]
        elif prop[0] == "kind" and kind is None and isinstance(prop[3], str):
            kind = prop[3]
    return name, kind


def provider_from_rdap(data):
    cards = []
    for entity in data.get("entities", []):
        if "registrant" not in entity.get("roles", []):
            continue
        name, kind = vcard_name(entity)
        if name:
            cards.append((name, kind))

    provider = next((name for name, kind in cards if kind == "org"), None)
    if provider is None and cards:
        provider = cards[0][0]
    if provider is None:
        provider = data.get("name") or data.get("handle")
    if not isinstance(provider, str):
        return None

    return re.sub(
        r",?\s+(?:l\.?l\.?c\.?|ltd\.?|inc\.?)$",
        "",
        provider,
        flags=re.IGNORECASE,
    )


def sanitize(value):
    return value.replace("\t", " ").replace("\r", " ").replace("\n", " ").strip()


for address in unknown:
    description = known_description(address)
    if description and "{}" not in description:
        provider = description
    else:
        try:
            provider = provider_from_rdap(rdap_lookup(address))
        except Exception:
            provider = None
        if provider and description:
            provider = description.replace("{}", provider)

    if provider:
        print(f"{address}\t{sanitize(provider)}")
PY
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

BASE_RESULTS_FILE="$WORK_DIR/resolvers.tsv"
awk -F '\t' '
  $1 == "OK" && !seen[$2]++ {
    print $3 "\t" $2 "\t" $4 "\t" $5
  }
' "$RESULT_DATA" \
  | LC_ALL=C sort -t $'\t' -k1,1 -k2,2 \
  > "$BASE_RESULTS_FILE"

RESULT_COUNT="$(
  awk -F '\t' 'NF >= 2 { count++ } END { print count + 0 }' \
    "$BASE_RESULTS_FILE"
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

RESULTS_FILE="$BASE_RESULTS_FILE"
ENRICHMENT_TARGET_COUNT="$(
  awk -F '\t' '$1 == "Unknown" { count++ } END { print count + 0 }' \
    "$BASE_RESULTS_FILE"
)"
ENRICHED_COUNT=0

if ((ENRICH_UNKNOWN && ENRICHMENT_TARGET_COUNT > 0)); then
  PROVIDER_MAP="$WORK_DIR/provider-map.tsv"
  if enrich_unknown_organizations "$BASE_RESULTS_FILE" > "$PROVIDER_MAP"; then
    ENRICHED_COUNT="$(
      awk -F '\t' '$1 != "#resolver" && NF >= 2 { count++ } END { print count + 0 }' \
        "$PROVIDER_MAP"
    )"
    ENRICHED_RESULTS_FILE="$WORK_DIR/enriched-resolvers.tsv"
    awk -F '\t' '
      BEGIN { OFS = "\t" }
      NR == FNR {
        if ($1 != "#resolver" && NF >= 2) {
          provider[$1] = $2
        }
        next
      }
      {
        if ($1 == "Unknown" && $2 in provider) {
          $1 = provider[$2]
        }
        print
      }
    ' "$PROVIDER_MAP" "$BASE_RESULTS_FILE" \
      | LC_ALL=C sort -t $'\t' -k1,1 -k2,2 \
      > "$ENRICHED_RESULTS_FILE"
    RESULTS_FILE="$ENRICHED_RESULTS_FILE"
  else
    warn "Provider enrichment failed; DNS results remain usable."
  fi
fi

RESULTS_LIST="$(
  awk '1' "$RESULTS_FILE"
)"

KNOWN_ORG_COUNT="$(
  awk -F '\t' '
    NF >= 2 && $1 != "Unknown" && !seen[$1]++ { count++ }
    END { print count + 0 }
  ' "$RESULTS_FILE"
)"

UNKNOWN_RESOLVER_COUNT="$(
  awk -F '\t' '$1 == "Unknown" { count++ } END { print count + 0 }' \
    "$RESULTS_FILE"
)"

ECS_DETAILS="$(
  awk -F '\t' '
    BEGIN { OFS = "\t" }
    NR == FNR {
      if (NF >= 2) {
        organization[$2] = $1
      }
      next
    }
    $1 == "OK" &&
    $6 != "" &&
    $6 != "None" &&
    $6 != "Unknown" &&
    $6 !~ /\/0$/ {
      key = $2 SUBSEP $6
      if (!seen[key]++) {
        provider = ($2 in organization) ? organization[$2] : $3
        print provider, $2, $6
      }
    }
  ' "$RESULTS_FILE" "$RESULT_DATA" \
    | LC_ALL=C sort -t $'\t' -k1,1 -k2,2 -k3,3
)"

ECS_COUNT="$(
  printf '%s\n' "$ECS_DETAILS" \
    | awk -F '\t' 'NF >= 3 { count++ } END { print count + 0 }'
)"

ECS_FIELD_COUNT="$(
  awk -F '\t' '
    $1 == "OK" && $6 != "" && $6 != "Unknown" { count++ }
    END { print count + 0 }
  ' "$RESULT_DATA"
)"
ECS_MISSING_COUNT=$((SUCCESS_COUNT - ECS_FIELD_COUNT))

printf '\n%b=== Results ===%b\n\n' "$BOLD" "$NC"

while IFS=$'\t' read -r organization resolver geo protocol; do
  [[ -n "$resolver" ]] || continue
  printf ' %b%s%b | %s | %s | %s\n' \
    "$GREEN" "$organization" "$NC" "$resolver" "$geo" "$protocol"
done <<< "$RESULTS_LIST"

if ((UNKNOWN_RESOLVER_COUNT > 0)); then
  printf '\n%b%d resolver egress IP(s): %d identified organization(s), %d resolver(s) with unknown organization.%b\n' \
    "$BOLD" \
    "$RESULT_COUNT" \
    "$KNOWN_ORG_COUNT" \
    "$UNKNOWN_RESOLVER_COUNT" \
    "$NC"
else
  printf '\n%b%d resolver egress IP(s) across %d organization(s).%b\n' \
    "$BOLD" "$RESULT_COUNT" "$KNOWN_ORG_COUNT" "$NC"
fi
printf '%d/%d queries returned parseable resolver information.\n' \
  "$SUCCESS_COUNT" "$QUERIES"

if ((ENRICHED_COUNT > 0)); then
  printf '%d/%d previously unidentified resolver(s) enriched via known ranges/RDAP.\n' \
    "$ENRICHED_COUNT" "$ENRICHMENT_TARGET_COUNT"
fi
if ((ENRICH_UNKNOWN && ENRICHMENT_TARGET_COUNT > ENRICHED_COUNT)); then
  printf '%bProvider enrichment left %d resolver(s) unidentified; DNS results remain valid.%b\n' \
    "$YELLOW" \
    "$((ENRICHMENT_TARGET_COUNT - ENRICHED_COUNT))" \
    "$NC"
fi

if ((SUCCESS_COUNT < QUERIES)); then
  printf '%bUnusable queries: %d dig error(s), %d parse error(s), %d internal error(s).%b\n' \
    "$YELLOW" \
    "$DIG_ERROR_COUNT" \
    "$PARSE_ERROR_COUNT" \
    "$INTERNAL_ERROR_COUNT" \
    "$NC"
fi

if ((UNKNOWN_RESOLVER_COUNT > 0)); then
  printf '%bAt least one resolver organization could not be identified. Check every resolver manually.%b\n' \
    "$YELLOW" "$NC"
elif ((KNOWN_ORG_COUNT > 1)); then
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
  if ((ECS_MISSING_COUNT > 0)); then
    printf '%bThe clientSubnet field was absent from %d additional response(s).%b\n' \
      "$YELLOW" "$ECS_MISSING_COUNT" "$NC"
  fi
elif ((ECS_FIELD_COUNT == SUCCESS_COUNT)); then
  printf '%bNo non-/0 EDNS Client Subnet was observed.%b\n' "$GREEN" "$NC"
elif ((ECS_FIELD_COUNT > 0)); then
  printf '%bNo non-/0 EDNS Client Subnet was observed in %d response(s); the clientSubnet field was absent from %d response(s).%b\n' \
    "$YELLOW" "$ECS_FIELD_COUNT" "$ECS_MISSING_COUNT" "$NC"
else
  printf '%bThe TXT responses did not include clientSubnet information; ECS disclosure could not be assessed.%b\n' \
    "$YELLOW" "$NC"
fi

printf 'A resolver-path leak exists only if a listed resolver/provider is not one you expect.\n'

