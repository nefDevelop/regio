#!/bin/sh
# scripts/bench_gate.sh — gate de rendimiento con benchstat (aprobación B3a).
#
# Uso:  bench_gate.sh baseline   ->  (re)genera bench/baseline.txt
#       bench_gate.sh gate       ->  compara contra el baseline y falla si
#                                    hay REGRESIÓN significativa de recursos:
#                                      allocs/op  > +10%
#                                      B/op       > +20%
#                                    ns/op es SOLO informativo (el baseline
#                                    local y los runners de CI tienen CPU
#                                    distintos; las asignaciones no).
#
# Requiere: benchstat (go install golang.org/x/perf/cmd/benchstat@latest)
set -eu
cd "$(dirname "$0")/.."

BASELINE=bench/baseline.txt
CURRENT=bench/current.txt
STAT=bench/current.stat
COUNT="${BENCH_COUNT:-6}"

run_bench() {
	MASTER_KEY=test-master-key-32-bytes-length-!!! \
	go test -run='^$' -bench=. -benchmem -benchtime=200ms -count="$COUNT" \
		./internal/security/ ./internal/handlers/ ./internal/auth/ ./internal/db/
}

if ! command -v benchstat >/dev/null 2>&1; then
	echo "bench_gate: benchstat no instalado -> go install golang.org/x/perf/cmd/benchstat@latest" >&2
	exit 1
fi

case "${1:-gate}" in
baseline)
	mkdir -p bench
	run_bench > "$BASELINE"
	echo "bench_gate: baseline generado en $BASELINE (revisa el diff antes de commitearlo)"
	;;
gate)
	if [ ! -f "$BASELINE" ]; then
		echo "bench_gate: SIN BASELINE — generando en modo bootstrap."
		echo "bench_gate: commitea bench/baseline.txt para activar el gate en próximas corridas."
		mkdir -p bench
		run_bench > "$BASELINE"
		exit 0
	fi
	mkdir -p bench
	run_bench > "$CURRENT"
	benchstat "$BASELINE" "$CURRENT" > "$STAT" || true
	echo "===== benchstat (baseline vs actual) ====="
	cat "$STAT"
	echo "==========================================="
	# Parseo: por sección (sec/op, B/op, allocs/op) se buscan deltas "+N%"
	# (ASCII; el ruido sale como "~" y las mejoras como "-N%").
	fail=$(awk '
		/allocs\/op/ { sec = "allocs"; next }
		/B\/op/      { sec = "bytes";  next }
		/sec\/op/    { sec = "sec";    next }
		{
			if (sec == "" || sec == "sec") next
			for (i = 1; i <= NF; i++) {
				if ($i ~ /^[-+][0-9]+(\.[0-9]+)?%$/) {
					v = $i
					gsub(/%/, "", v)
					if (v+0 > 0) {
						lim = (sec == "allocs") ? 10 : 20
						if (v+0 > lim) {
							printf "REGRESIÓN %s: %s > +%d%% (%s)\n", sec, $i, lim, $1
							bad++
						}
					}
				}
			}
		}
		END { print bad + 0 }
	' "$STAT")
	if [ "$fail" != "0" ]; then
		echo "bench_gate: GATE DE RENDIMIENTO FALLADO ($fail regresiones)"
		exit 1
	fi
	echo "bench_gate: OK (sin regresiones significativas de allocs/bytes)"
	;;
*)
	echo "uso: bench_gate.sh [baseline|gate]" >&2
	exit 2
	;;
esac
