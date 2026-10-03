#!/usr/bin/env bash
# Bounded host-metrics sampler for the system under test. Reads only /proc and `ss -s` counters,
# writes JSON lines of aggregates (no addresses, no process arguments, no payloads).
#
#   host-metrics.sh --duration <seconds 1..3600> --interval <seconds 1..60> --out <file>
set -euo pipefail
duration=""; interval=""; out=""
while [ $# -gt 0 ]; do
  case "$1" in
    --duration) duration="${2:-}"; shift 2 ;;
    --interval) interval="${2:-}"; shift 2 ;;
    --out) out="${2:-}"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done
[[ "$duration" =~ ^[1-9][0-9]{0,3}$ ]] && [ "$duration" -le 3600 ] || { echo "--duration must be an integer 1..3600" >&2; exit 64; }
[[ "$interval" =~ ^[1-9][0-9]?$ ]] && [ "$interval" -le 60 ] || { echo "--interval must be an integer 1..60" >&2; exit 64; }
[[ "$out" =~ ^[A-Za-z0-9._/-]+$ ]] || { echo "--out must be a plain path" >&2; exit 64; }

cpu_totals() { awk '/^cpu /{idle=$5+$6; total=0; for(i=2;i<=NF;i++) total+=$i; print total, idle}' /proc/stat; }
net_totals() { awk 'NR>2 && $1 !~ /^lo:/ {rx+=$2; tx+=$10} END{print rx+0, tx+0}' /proc/net/dev; }

read -r prev_total prev_idle < <(cpu_totals)
end=$(( $(date +%s) + duration ))
while [ "$(date +%s)" -lt "$end" ]; do
  sleep "$interval"
  read -r total idle < <(cpu_totals)
  dt=$(( total - prev_total )); di=$(( idle - prev_idle )); prev_total=$total; prev_idle=$idle
  cpu_busy=$(awk -v dt="$dt" -v di="$di" 'BEGIN{ if (dt>0) printf "%.1f", 100*(dt-di)/dt; else print "0.0" }')
  read -r load1 load5 _ < /proc/loadavg
  mem_avail_kb=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)
  mem_total_kb=$(awk '/^MemTotal:/{print $2}' /proc/meminfo)
  read -r rx tx < <(net_totals)
  tcp_estab=$(ss -s | awk '/^TCP:/{gsub(/[(),]/," "); for(i=1;i<=NF;i++) if($i=="estab") print $(i+1)}')
  tcp_timewait=$(ss -s | awk '/^TCP:/{gsub(/[(),]/," "); for(i=1;i<=NF;i++) if($i=="timewait") print $(i+1)}')
  printf '{"t":%s,"cpuBusyPct":%s,"load1":%s,"load5":%s,"memAvailableKb":%s,"memTotalKb":%s,"netRxBytes":%s,"netTxBytes":%s,"tcpEstablished":%s,"tcpTimeWait":%s}\n' \
    "$(date +%s)" "$cpu_busy" "$load1" "$load5" "$mem_avail_kb" "$mem_total_kb" "$rx" "$tx" "${tcp_estab:-0}" "${tcp_timewait:-0}" >> "$out"
done
