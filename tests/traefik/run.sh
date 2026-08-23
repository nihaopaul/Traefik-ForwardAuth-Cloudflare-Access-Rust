#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_name=forward-auth-traefik-test-$$
test_port=${TRAEFIK_TEST_PORT:-18080}

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    engine=docker
elif command -v podman >/dev/null 2>&1 && podman compose version >/dev/null 2>&1; then
    engine=podman
else
    echo "docker compose or podman compose is required" >&2
    exit 1
fi

compose() {
    "$engine" compose --project-name "$project_name" --file "$script_dir/compose.yml" "$@"
}

cleanup() {
    compose down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

compose up --detach

request_status() {
    curl --silent --show-error --output /dev/null --write-out '%{http_code}' "$@"
}

assert_status() {
    expected=$1
    description=$2
    shift 2
    actual=$(request_status "$@")
    if [ "$actual" != "$expected" ]; then
        echo "$description: expected HTTP $expected, got $actual" >&2
        compose logs >&2
        exit 1
    fi
}

attempt=0
while [ "$attempt" -lt 30 ]; do
    if [ "$(request_status "http://127.0.0.1:$test_port/bound" 2>/dev/null || true)" = "200" ]; then
        break
    fi
    attempt=$((attempt + 1))
    sleep 1
done

assert_status 200 \
    "configured binding must overwrite client input and ignore its query string" \
    --header "X-Auth-Audience: client-supplied-aud" \
    "http://127.0.0.1:$test_port/bound?aud=client-supplied-aud"

assert_status 200 \
    "configured binding must replace duplicate client headers with one trusted value" \
    --header "X-Auth-Audience: client-a" \
    --header "X-Auth-Audience: client-b" \
    "http://127.0.0.1:$test_port/bound"

assert_status 403 \
    "entrypoint middleware must strip client input from an unbound route" \
    --header "X-Auth-Audience: dashboard-aud" \
    "http://127.0.0.1:$test_port/unbound"

assert_status 403 \
    "a route bound to another application must be denied by the probe" \
    "http://127.0.0.1:$test_port/wrong"

echo "Traefik audience-binding integration test passed"
