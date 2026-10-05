#!/usr/bin/env bash
# scripts/perf/report.sh — agrega micro-benchmarks + carga + RSS en un informe.
#
# Uso:
#   scripts/perf/report.sh <bench_file> <load_json> <salida_base>
#
# Ejemplo:
#   scripts/perf/report.sh perf/bench.txt perf/load-20261003-120000.txt perf/report-20261003-120000
#
# Genera <salida_base>.txt (legible en terminal) y <salida_base>.md (tabla para
# el repositorio). El informe lleva SIEMPRE la cabecera de entorno: un ns/op sin
# saber qué CPU lo produjo no es comparable con nada.

set -euo pipefail

BENCH_FILE="${1:?falta el fichero de benchmarks}"
LOAD_JSON="${2:?falta el JSON de carga}"
OUT_BASE="${3:?falta la base de salida}"

for f in "$BENCH_FILE" "$LOAD_JSON"; do
	[ -r "$f" ] || { echo "report.sh: no se puede leer $f" >&2; exit 1; }
done

mkdir -p "$(dirname "$OUT_BASE")"

# --- Entorno -----------------------------------------------------------------
CPU_MODEL=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//')
CPU_COUNT=$(nproc)
MEM_TOTAL=$(awk '/MemTotal/ {printf "%.1f GiB", $2/1024/1024}' /proc/meminfo)
MEM_AVAIL=$(awk '/MemAvailable/ {printf "%.1f GiB", $2/1024/1024}' /proc/meminfo)
KERNEL=$(uname -r)

# --- Entorno de la corrida de carga (viene del propio JSON) ------------------
read -r GO_VERSION GOOS NUMCPU GOMAXPROCS DBBYTES DBEND RSSIDLE RSSHWM UPSTREAM < <(
	jq -r '[.go_version, .goos, (.num_cpu|tostring), (.gomaxprocs|tostring),
	        (.db_bytes|tostring), (.db_bytes_after_load|tostring),
	        (.idle_rss_bytes|tostring), (.idle_hwm_bytes|tostring), .upstream]
	        | join(" ")' "$LOAD_JSON"
)
TS=$(jq -r '.timestamp' "$LOAD_JSON")

mib() { awk -v b="$1" 'BEGIN{printf "%.1f", b/1048576}'; }

# --- Tabla de micro-benchmarks ----------------------------------------------
# Se parsea la salida de `go test -bench`: nombre, ns/op, B/op, allocs/op.
bench_table() {
	awk '
		/^Benchmark/ {
			name = $1
			for (i = 1; i <= NF; i++) {
				if ($i ~ /ns\/op$/)   { ns   = $(i-1) }
				if ($i ~ /B\/op$/)    { b    = $(i-1) }
				if ($i ~ /allocs\/op$/) { a = $(i-1) }
			}
			if (!(name in seen) && ns != "") {
				seen[name] = 1
				printf "| %s | %s | %s | %s |\n", name, ns, (b==""?"-":b), (a==""?"-":a)
			}
		}
	' "$BENCH_FILE"
}

# --- Tabla de carga ----------------------------------------------------------
load_table() {
	jq -r '
		. as $root
		| "| perfil | conc. | req/s | p50 ms | p95 ms | p99 ms | req | errores (429/5xx/4xx) | RSS pico MiB | ΔRSS MiB |",
		  "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: |",
		  (.phases[]
		   | "| \(.profile) | \(.concurrency) | \(.rps|round) | \(.lat_p50_ms) | \(.lat_p95_ms) | \(.lat_p99_ms) | \(.requests) | \(.status_429_rate_limit)/\(.status_5xx)/\(.status_4xx) | \((.rss_peak_bytes/1048576*10|round)/10) | \(((.rss_delta_bytes)/1048576*10|round)/10) |")
	' "$LOAD_JSON"
}

# --- Escritura ---------------------------------------------------------------
{
	echo "==============================================================================="
	echo " reGIO — INFORME DE RENDIMIENTO"
	echo "==============================================================================="
	echo "Fecha            : $TS"
	echo "Host             : $(uname -n)"
	echo "CPU              : $CPU_MODEL"
	echo "Núcleos lógicos  : $CPU_COUNT"
	echo "RAM total/disp.  : $MEM_TOTAL / $MEM_AVAIL"
	echo "Kernel           : $KERNEL"
	echo "Go               : $GO_VERSION ($GOOS)"
	echo "GOMAXPROCS       : $GOMAXPROCS"
	echo "Dataset          : $LOAD_JSON → db $(mib "$DBBYTES") → $(mib "$DBEND") tras la carga"
	echo "RSS en reposo    : $(mib "$RSSIDLE") MiB (VmHWM $(mib "$RSSHWM") MiB)"
	echo "Upstream dummy   : $UPSTREAM"
	echo
	echo "-------------------------------------------------------------------------------"
	echo " 1. MICRO-BENCHMARKS (go test -bench, camino caliente en proceso)"
	echo "-------------------------------------------------------------------------------"
	echo
	echo "| benchmark | ns/op | B/op | allocs/op |"
	echo "| --- | ---: | ---: | ---: |"
	bench_table
	echo
	if [ -r bench/baseline.txt ] && command -v benchstat >/dev/null 2>&1; then
		base_os=$(awk '/^goos:/ {print $2; exit}' bench/baseline.txt)
		base_arch=$(awk '/^goarch:/ {print $2; exit}' bench/baseline.txt)
		cur_os=$(awk '/^goos:/ {print $2; exit}' "$BENCH_FILE")
		cur_arch=$(awk '/^goarch:/ {print $2; exit}' "$BENCH_FILE")
		if [ "$base_os/$base_arch" = "$cur_os/$cur_arch" ]; then
			echo "Comparativa contra bench/baseline.txt ($cur_os/$cur_arch):"
			echo
			benchstat bench/baseline.txt "$BENCH_FILE" 2>/dev/null || echo "(benchstat no pudo comparar)"
			echo
		else
			echo "Comparativa contra bench/baseline.txt OMITIDA: el baseline es"
			echo "$base_os/$base_arch y esta corrida es $cur_os/$cur_arch. benchstat no"
			echo "puede comparar plataformas distintas; regenera el baseline con"
			echo "'make bench-baseline' en la máquina destino."
			echo
		fi
	fi
	echo "-------------------------------------------------------------------------------"
	echo " 2. PRUEBA DE CARGA (proceso real, upstream dummy)"
	echo "-------------------------------------------------------------------------------"
	echo
	load_table
	echo
	echo "RSS en reposo = antes de la carga. RSS pico = VmHWM. ΔRSS = fin − inicio de la"
	echo "fase; un Δ positivo sostenido entre fases indica memoria retenida, no fuga"
	echo "confirmada (comprueba con make test-race antes de acusar)."
	echo
	echo "OJO — las fases se ejecutan en un solo proceso y en este orden: health, proxy,"
	echo "auth. Go no devuelve la memoria al SO de inmediato, así que el RSS de arranque"
	echo "de auth arrastra lo que dejaron proxy y las fases anteriores. Para un RSS de"
	echo "auth limpio, ejecuta 'make test-load PERF_PROFILES=auth' por separado."
	echo
	echo "-------------------------------------------------------------------------------"
	echo " 3. PERFILES"
	echo "-------------------------------------------------------------------------------"
	echo
	jq -r '.profiles_measured | to_entries[] | "\(.key)\n    \(.value)"' "$LOAD_JSON"
	echo
	echo "-------------------------------------------------------------------------------"
	echo " 4. NOTA SOBRE EL DATASET"
	echo "-------------------------------------------------------------------------------"
	echo
	jq -r '.seed_note' "$LOAD_JSON"
	echo
	echo "==============================================================================="
	echo " Reproducir:  make perf    (seed + bench + test-load + perf-report)"
	echo "==============================================================================="
} > "$OUT_BASE.txt"

# El .md es el mismo informe sin los caracteres de caja (se ve bien en el repo).
sed 's/===*//g; s/---*//g' "$OUT_BASE.txt" > "$OUT_BASE.md"

echo "informe: $OUT_BASE.txt"
echo "informe: $OUT_BASE.md"