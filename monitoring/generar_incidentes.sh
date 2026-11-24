#!/usr/bin/env bash
# Simula incidentes de seguridad contra la app en produccion para que
# aparezcan en Grafana. Uso: bash generar_incidentes.sh [URL]
URL="${1:-http://localhost:5000}"
JAR="$(mktemp)"

echo "[1/4] Logins fallidos (fuerza bruta)..."
for i in $(seq 1 8); do
  curl -s -o /dev/null -d "username=admin&password=incorrecta$i" "$URL/login"
done

echo "[2/4] Intentos de SQL Injection..."
for p in "' OR '1'='1" "admin' --" "' UNION SELECT 1,2,3 --"; do
  curl -s -o /dev/null --data-urlencode "username=$p" --data-urlencode "password=x" "$URL/login"
done

echo "[3/4] Login valido + intento de XSS..."
curl -s -o /dev/null -c "$JAR" -d "username=admin&password=admin123" "$URL/login"
TOKEN=$(curl -s -b "$JAR" "$URL/dashboard" | grep -o 'name="csrf_token" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//')
curl -s -o /dev/null -b "$JAR" --data-urlencode "csrf_token=$TOKEN" \
  --data-urlencode "nueva_bio=<script>alert('XSS')</script>" "$URL/update_bio"

echo "[4/4] Peticiones sin token CSRF (ataque CSRF)..."
for i in $(seq 1 4); do
  curl -s -o /dev/null -b "$JAR" -d "nueva_bio=HACKEADA" "$URL/update_bio"
done

rm -f "$JAR"
echo "Listo. Revisa Grafana en unos segundos."
