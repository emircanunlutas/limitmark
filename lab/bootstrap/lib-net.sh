# Sourced by sut-bootstrap.sh and sut-teardown.sh (and by tests). Pure bash: no side effects, no network, no privileged command.
# Provides strict CIDR validation and parsing of `ufw status numbered` output.

# ipv4_to_int a.b.c.d  -> prints the address as an integer; fails on anything that is not a canonical dotted quad.
ipv4_to_int() {
  local ip="$1"
  [[ "$ip" =~ ^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$ ]] || return 1
  local a="${BASH_REMATCH[1]}" b="${BASH_REMATCH[2]}" c="${BASH_REMATCH[3]}" d="${BASH_REMATCH[4]}"
  (( a <= 255 && b <= 255 && c <= 255 && d <= 255 )) || return 1
  printf '%s\n' $(( (a << 24) | (b << 16) | (c << 8) | d ))
}

# Reserved ranges (hex base / prefix) an allow rule must never overlap: "this network", loopback, link-local (cloud
# metadata lives there), multicast and everything above. Hex, so the script embeds no dotted-quad literal.
LAB_RESERVED_RANGES=("0x00000000/8" "0x7F000000/8" "0xA9FE0000/16" "0xE0000000/3")
# Allowed prefix lengths. Anything broader than /16 is refused: two complementary /1 networks together are the whole
# IPv4 internet, so "never /0" alone is not a safe rule.
LAB_MIN_PREFIX=16
LAB_MAX_ENTRIES=8

# cidr_check CIDR -> returns 0 when acceptable; otherwise prints the reason on stderr and returns 1.
cidr_check() {
  local cidr="$1" ip prefix base mask entry range_base range_prefix range_mask
  if ! [[ "$cidr" =~ ^([0-9.]+)/([0-9]{1,2})$ ]]; then echo "not a.b.c.d/n: $cidr" >&2; return 1; fi
  ip="${BASH_REMATCH[1]}"; prefix="${BASH_REMATCH[2]}"
  if ! base="$(ipv4_to_int "$ip")"; then echo "invalid IPv4 address in CIDR: $cidr" >&2; return 1; fi
  if [ "${prefix#0}" != "$prefix" ] && [ "$prefix" != 0 ]; then echo "prefix has a leading zero: $cidr" >&2; return 1; fi
  if (( prefix < LAB_MIN_PREFIX || prefix > 32 )); then echo "prefix must be /${LAB_MIN_PREFIX}../32 (broader networks are refused): $cidr" >&2; return 1; fi
  mask=$(( (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))
  if (( (base & mask) != base )); then echo "host bits are set; use the network address of the range: $cidr" >&2; return 1; fi
  for entry in "${LAB_RESERVED_RANGES[@]}"; do
    range_base=$(( ${entry%/*} )); range_prefix="${entry#*/}"
    range_mask=$(( (0xFFFFFFFF << (32 - range_prefix)) & 0xFFFFFFFF ))
    # The candidate prefix is >= 16 and every reserved prefix is <= 16, so overlap means the candidate lies inside the range.
    if (( (base & range_mask) == range_base )); then echo "overlaps a reserved range (this-network, loopback, link-local, multicast): $cidr" >&2; return 1; fi
  done
}

# cidr_list_check COMMA_LIST LABEL -> every entry valid, 1..LAB_MAX_ENTRIES entries, no empty entry, no whitespace.
cidr_list_check() {
  local list="$1" label="$2" cidr
  local -a items
  [[ "$list" =~ [[:space:]] ]] && { echo "$label: whitespace is not allowed" >&2; return 1; }
  [[ "$list" == ,* || "$list" == *, || "$list" == *,,* ]] && { echo "$label: empty list entry" >&2; return 1; }
  IFS=',' read -r -a items <<< "$list"
  if (( ${#items[@]} < 1 || ${#items[@]} > LAB_MAX_ENTRIES )); then echo "$label: 1..${LAB_MAX_ENTRIES} entries required" >&2; return 1; fi
  for cidr in "${items[@]}"; do cidr_check "$cidr" 2>&1 | sed "s/^/$label: /" >&2; [ "${PIPESTATUS[0]}" = 0 ] || return 1; done
}

# ufw prints a /32 as the bare address; compare in that form.
ufw_normalize_cidr() { printf '%s\n' "${1%/32}"; }

# ufw_lab_rules < `ufw status numbered` -> "number|port|from" for every rule carrying the lab comment tag.
# Handles single-digit numbering ("[ 1]") as well as two digits ("[10]").
ufw_lab_rules() {
  sed -nE 's/^\[ *([0-9]+)\][[:space:]]+([0-9]+)\/tcp[[:space:]]+ALLOW IN[[:space:]]+([0-9./]+)[[:space:]]+#[[:space:]]*limitmark-lab (ssh|app)[[:space:]]*$/\1|\2|\3/p'
}

# ufw_lab_rule_numbers < `ufw status numbered` -> rule numbers of every lab rule, highest first (so deleting one does not renumber the next).
ufw_lab_rule_numbers() { ufw_lab_rules | cut -d'|' -f1 | sort -rn; }

# ufw_stale_lab_rule_numbers DESIRED... < `ufw status numbered` -> numbers of lab rules NOT in DESIRED ("port|from"), highest first.
ufw_stale_lab_rule_numbers() {
  local -a desired=("$@")
  local number port from key entry keep
  while IFS='|' read -r number port from; do
    key="${port}|${from}"; keep=0
    for entry in "${desired[@]}"; do [ "$entry" = "$key" ] && keep=1; done
    [ "$keep" = 1 ] || printf '%s\n' "$number"
  done < <(ufw_lab_rules) | sort -rn
}

# ---------------------------------------------------------------- Docker state for teardown (UNKNOWN is never ABSENT)
# These need the caller's `run`, `log` and a FAILURES array (sut-teardown.sh defines them; tests define their own).

# docker_cli_state -> no-cli | up | down. "down" means a docker CLI exists but its daemon does not answer.
docker_cli_state() {
  if ! command -v docker >/dev/null 2>&1; then echo no-cli
  elif docker info >/dev/null 2>&1; then echo up
  else echo down; fi
}

# docker_object_state container|network NAME -> present | absent | unknown. Only a SUCCESSFUL listing that does not contain the name is "absent";
# a failing command (daemon gone mid-way) is "unknown".
docker_object_state() {
  local out
  case "$1" in
    container) out="$(docker ps -a --filter "name=^${2}\$" --format '{{.Names}}' 2>/dev/null)" || { echo unknown; return 0; } ;;
    network) out="$(docker network ls --filter "name=^${2}\$" --format '{{.Name}}' 2>/dev/null)" || { echo unknown; return 0; } ;;
    *) echo unknown; return 0 ;;
  esac
  if [ -n "$out" ]; then echo present; else echo absent; fi
}

# Read-only label lookups: no label means "not ours".
label_of() { local out; if out="$(docker inspect --format '{{index .Config.Labels "limitmark.lab"}}' "$1" 2>/dev/null)"; then printf '%s' "$out"; fi; }
network_label_of() { local out; if out="$(docker network inspect --format '{{index .Labels "limitmark.lab"}}' "$1" 2>/dev/null)"; then printf '%s' "$out"; fi; }

record_failure() { FAILURES+=("$*"); printf '[teardown] FAILED: %s\n' "$*" >&2; }

# teardown_lab_containers: removes the lab-labelled containers and network. Anything that cannot be established is a FAILURE
# (recovery state is then preserved by the caller); it is never read as "nothing to remove".
teardown_lab_containers() {
  local state name obj
  state="$(docker_cli_state)"
  case "$state" in
    no-cli) log "docker is not installed; there are no lab containers to remove"; return 0 ;;
    down) record_failure "docker is installed but its daemon is unreachable: lab containers could not be inspected (unknown is not absent)"; return 0 ;;
  esac
  for name in limitmark-lab-pg16 limitmark-lab-pg17 limitmark-lab-app; do
    obj="$(docker_object_state container "$name")"
    case "$obj" in
      absent) ;;
      unknown) record_failure "could not determine whether container $name exists" ;;
      present)
        if [ "$(label_of "$name")" = disposable ]; then run docker rm -f -v "$name"
        else record_failure "container $name exists but its lab label could not be confirmed; left in place"; fi ;;
    esac
  done
  obj="$(docker_object_state network limitmark-lab_lab)"
  case "$obj" in
    absent) ;;
    unknown) record_failure "could not determine whether network limitmark-lab_lab exists" ;;
    present)
      if [ "$(network_label_of limitmark-lab_lab)" = disposable ]; then run docker network rm limitmark-lab_lab
      else record_failure "network limitmark-lab_lab exists but its lab label could not be confirmed; left in place"; fi ;;
  esac
}
