#!/bin/sh
# scripts/cover_gate.sh <cover.out>
#
# Gate de cobertura de la suite (ver plan de testing Fase 3).
# - Lee un profile generado con: go test -covermode=atomic -coverpkg=./...
# - Fusiona los bloques duplicados (cada binario de test instrumenta todo el
#   módulo, por lo que -coverpkg repite posiciones con distinto count).
# - Comprueba cobertura global y por paquete contra los umbrales de ratchet
#   y sale con código != 0 si alguno no se cumple.
#
# Los paquetes cmd/ quedan fuera del gate: su cobertura es 0% de forma
# esperada (se validan con los tests e2e del binario real).
#
# Umbrales (baseline 42,9% global + trabajo de Fase 3-5, con margen -2):
#   global 70 | auth 85 | db 84 | handlers 85 | security 83

PROFILE="${1:-cover.out}"

if [ ! -f "$PROFILE" ]; then
	echo "cover_gate: no existe el profile '$PROFILE'" >&2
	exit 1
fi

awk '
function gate(name, val, min) {
	if (val + 0 < min + 0) {
		printf "  FAIL  %-32s %5.1f%% < %d%%\n", name, val, min
		fails++
	} else {
		printf "  OK    %-32s %5.1f%% >= %d%%\n", name, val, min
	}
}
NR == 1 { next }  # cabecera "mode: ..."
{
	pos = $1; num = $2 + 0; cnt = $3 + 0
	if (!(pos in seen)) {
		seen[pos] = 1
		n = split(pos, a, "/")
		pkg = a[1]
		for (i = 2; i < n; i++) pkg = pkg "/" a[i]
		pospkg[pos] = pkg
		total[pkg] += num
		gtotal += num
		if (cnt > 0) { cov[pos] = 1; covpkg[pkg] += num; gcov += num }
	} else if (cnt > 0 && !(pos in cov)) {
		cov[pos] = 1
		covpkg[pospkg[pos]] += num
		gcov += num
	}
}
END {
	g = (gtotal > 0) ? 100 * gcov / gtotal : 0
	printf "Cobertura global: %.1f%% (%d/%d statements)\n", g, gcov, gtotal
	printf "Umbrales:\n"
	gate("regio (global)", g, 70)
	for (p in total) {
		if (p == "regio/cmd/seed") {
			# El seed tiene sus propios tests (B1): umbral propio
			c = (total[p] > 0) ? 100 * covpkg[p] / total[p] : 0
			gate(p, c, 60)
			continue
		}
		if (p ~ /^regio\/cmd\//) {
			c = (total[p] > 0) ? 100 * covpkg[p] / total[p] : 0
			printf "  (excluido) %-27s %5.1f%%  -> cubierto vía e2e\n", p, c
			continue
		}
		c = (total[p] > 0) ? 100 * covpkg[p] / total[p] : 0
		min = 0
		if (p == "regio/internal/auth") min = 85
		else if (p == "regio/internal/db") min = 84
		else if (p == "regio/internal/handlers") min = 85
		else if (p == "regio/internal/security") min = 83
		else { printf "  (sin umbral) %-27s %5.1f%%\n", p, c; continue }
		gate(p, c, min)
	}
	if (fails > 0) {
		printf "GATE DE COBERTURA: FALLADO (%d umbrales)\n", fails
		exit 1
	}
	print "GATE DE COBERTURA: OK"
}
' "$PROFILE"
