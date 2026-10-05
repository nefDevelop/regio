#!/usr/bin/env sh
# scripts/perf_gate.sh — gate local de la prueba de carga.
#
# Uso:
#   scripts/perf_gate.sh <load_json> [rss_max_mib] [p95_max_ms]
#
# Compara la última corrida contra perf/load-baseline.json y falla si hay
# regresión. Las tolerancias por defecto son deliberadamente amplias, porque
# una máquina de escritorio introduce ruido entre corridas:
#
#   RSS pico   +15 %   memoria retenida por el proceso
#   p95        +25 %   latencia de cola
#   RPS        -10 %   menos peticiones por segundo
#
# Los argumentos opcionales son techos ABSOLUTOS y tienen prioridad sobre las
# tolerancias. Con ambos vacíos solo aplican las tolerancias.
#
# Por qué NO va en CI: RPS, p95 y RSS dependen de la CPU y de la carga de la
# máquina; en un runner compartido un gate de tiempo produce falsos positivos.
# En CI sí tiene sentido `make bench-gate`, que compara allocs/op y B/op, que
# son independientes de la máquina.

set -eu

CURRENT="${1:?falta el JSON de carga}"
RSS_ABS="${2:-}"
P95_ABS="${3:-}"

BASELINE=perf/load-baseline.json

command -v jq >/dev/null 2>&1 || {
	echo "perf_gate: jq no instalado (apt install jq)" >&2
	exit 1
}

[ -r "$CURRENT" ] || { echo "perf_gate: no se puede leer $CURRENT" >&2; exit 1; }

if [ ! -r "$BASELINE" ]; then
	echo "perf_gate: SIN BASELINE — tomando $CURRENT como referencia."
	echo "perf_gate: revisa el informe y commitea perf/load-baseline.json para activar el gate."
	mkdir -p "$(dirname "$BASELINE")"
	cp "$CURRENT" "$BASELINE"
	exit 0
fi

echo "===== perf_gate ====="
echo "  referencia : $BASELINE"
echo "  actual     : $CURRENT"
[ -n "$RSS_ABS" ] && echo "  techo RSS  : ${RSS_ABS} MiB (absoluto)"
[ -n "$P95_ABS" ] && echo "  techo p95  : ${P95_ABS} ms (absoluto)"
echo

# Una sola pasada de jq sobre ambos ficheros: comparar "a mano" con joinuf8 es
# frágil y el while por pipe perdería el código de salida (subshell).
table=$(jq -s -r '
	def mib: (. / 1048576 * 10 | round) / 10;
	def key: (.profile + "/" + (.concurrency | tostring));

	(.[0].phases | map({key: key, value: .}) | from_entries) as $b
	| (.[1].phases | map({key: key, value: .}) | from_entries) as $c

	# OJO con la precedencia de jq: "A | . as $x | B" se parsea como
	# "(A | .) as $x | B", no como "A | (. as $x | B)". Por eso se usan keys[] con
	# el lado izquierdo ya parenthesizado, y no to_entries con . as $e.
	| (["perfil/conc", "RPS", "p95 ms", "RSS pico MiB", "veredicto"] | @tsv),
	  (["---", "---:", "---:", "---:", "---"] | @tsv),
	  ($c | keys_unsorted[]) as $k
	  | $b[$k] as $base
	  | $c[$k] as $cur
	  | (if $base == null then
	       ([$k, "-", "-", ($cur.rss_peak_bytes | mib), "SIN REFERENCIA"] | @tsv)
	     else
	       ([ (if $cur.rss_peak_bytes > $base.rss_peak_bytes * 1.15 then "REGRESION rss" else empty end),
	          (if $cur.lat_p95_ms     > $base.lat_p95_ms     * 1.25 then "REGRESION p95" else empty end),
	          (if $cur.rps            < $base.rps            * 0.90 then "REGRESION rps" else empty end)
	        ]) as $bad
	       | [$k, ($cur.rps | round), (($cur.lat_p95_ms * 10 | round) / 10),
	          ($cur.rss_peak_bytes | mib),
	          (if ($bad | length) > 0 then ($bad | join(", ")) else "ok" end)]
	       | @tsv
	     end)
' "$BASELINE" "$CURRENT")

printf '%s\n' "$table" | awk -F'\t' '
	NR == 1 { printf "  %-18s %10s %12s %12s  %s\n", $1, $2, $3, $4, $5; next }
	NR == 2 { next }
	{
		printf "  %-18s %10s %12s %12s  %s\n", $1, $2, $3, $4, $5
		if ($5 != "ok" && $5 != "SIN REFERENCIA") exit_code = 1
	}
	END { exit exit_code }
'
rc=$?

# Techos absolutos.
if [ -n "$RSS_ABS" ]; then
	peak=$(jq -r '([.phases[].rss_peak_bytes] | max) as $m | (($m / 1048576 * 10 | round) / 10)' "$CURRENT")
	if awk -v a="$peak" -v b="$RSS_ABS" 'BEGIN{exit !(a > b)}'; then
		echo "  FALLO: RSS pico ${peak} MiB > techo ${RSS_ABS} MiB"
		rc=1
	fi
fi
if [ -n "$P95_ABS" ]; then
	p95=$(jq -r '([.phases[].lat_p95_ms] | max) as $m | (($m * 10 | round) / 10)' "$CURRENT")
	if awk -v a="$p95" -v b="$P95_ABS" 'BEGIN{exit !(a > b)}'; then
		echo "  FALLO: p95 ${p95} ms > techo ${P95_ABS} ms"
		rc=1
	fi
fi

echo
if [ "$rc" -ne 0 ]; then
	echo "perf_gate: REGRESIÓN de rendimiento (gate local, no CI)."
	echo "            Si el cambio es intencionado, regenera la referencia:"
	echo "            make perf-baseline"
	exit 1
fi
echo "perf_gate: sin regresión."
exit 0