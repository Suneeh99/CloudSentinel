#!/usr/bin/env bash
set -euo pipefail
name="cloudsentinel-ci-$$"
test_image="${TEST_IMAGE:-cloudsentinel:test}"
cleanup() {
  docker rm -f "$name-db" >/dev/null 2>&1 || true
  docker network rm "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT
# This test image contains Chromium; the shipped runtime image does not.
docker build --target test -t "$test_image" .
docker network create "$name" >/dev/null
docker run -d --name "$name-db" --network "$name" --network-alias dynamodb \
  amazon/dynamodb-local:3.1.0 -jar DynamoDBLocal.jar -sharedDb -inMemory >/dev/null
for attempt in $(seq 1 60); do
  if docker exec "$name-db" curl -s http://localhost:8000 >/dev/null; then break; fi
  if [ "$attempt" -eq 60 ]; then docker logs "$name-db"; exit 1; fi
  sleep 1
done
docker run --rm --network "$name" --shm-size=1g \
  -e DYNAMODB_LOCAL_ENDPOINT=http://dynamodb:8000 \
  "$test_image" sh -ec 'npm run format:check && npm run check && npm run test:e2e && npm audit --audit-level=moderate'
