#!/usr/bin/env bash
set -euo pipefail
name="cloudsentinel-smoke-$$"
image="${CLOUDSENTINEL_IMAGE:-cloudsentinel:local}"
cleanup() {
  docker rm -f "$name-app" "$name-db" "$name-prod" >/dev/null 2>&1 || true
  docker volume rm "$name-mfa" "$name-data" >/dev/null 2>&1 || true
  docker network rm "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker network create "$name" >/dev/null
docker volume create "$name-mfa" >/dev/null
docker volume create "$name-data" >/dev/null
docker run -d --name "$name-db" --network "$name" --network-alias dynamodb \
  --user root -v "$name-data:/home/dynamodblocal/data" amazon/dynamodb-local:3.1.0 \
  -jar DynamoDBLocal.jar -sharedDb -dbPath /home/dynamodblocal/data >/dev/null
for attempt in $(seq 1 60); do
  if docker exec "$name-db" curl -s http://localhost:8000 >/dev/null; then break; fi
  if [ "$attempt" -eq 60 ]; then docker logs "$name-db"; exit 1; fi
  sleep 1
done
docker run --rm --network "$name" -e DYNAMODB_LOCAL_ENDPOINT=http://dynamodb:8000 \
  "$image" node dist/server/init-db.js
docker run -d --name "$name-app" --network "$name" --network-alias app \
  --read-only --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp \
  -v "$name-mfa:/app/.local" -e APP_ENV=local -e APP_ORIGIN=http://localhost:3000 \
  -e DYNAMODB_LOCAL_ENDPOINT=http://dynamodb:8000 "$image" >/dev/null
wait_ready() {
  docker exec "$name-app" node --input-type=module -e '
    for(let i=0;i<60;i++){try{if((await fetch("http://localhost:3000/api/ready")).ok)process.exit(0)}catch{} await new Promise(r=>setTimeout(r,1000))}process.exit(1)'
}
wait_ready
# Another container accesses the app over its network interface, not its loopback address.
docker run --rm -i --network "$name" -v "$name-mfa:/app/.local" "$image" node --input-type=module - <<'NODE'
import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { TOTP, Secret } from 'otpauth';
const root='http://app:3000', origin='http://localhost:3000';
assert.equal((await fetch(root)).status,200);
const password='Synthetic container passphrase!',email=`container-${Date.now()}@example.test`;
const post=(path,body,cookie,csrf)=>fetch(`${root}/api${path}`,{method:'POST',headers:{origin,'content-type':'application/json',...(cookie?{cookie}:{}),...(csrf?{'x-csrf-token':csrf}:{})},body:JSON.stringify(body)});
assert.equal((await post('/auth/register',{email,password,name:'Container Owner',organization:'Container Lab'})).status,202);
const login=await post('/auth/login',{email,password});assert.equal(login.status,200);
const cookie=login.headers.get('set-cookie').split(';')[0],csrf=(await login.json()).csrfToken;
assert.equal((await post('/auth/logout',{},cookie)).status,403);
const enrollment=await post('/auth/mfa/enroll',{password},cookie,csrf);assert.equal(enrollment.status,200);
const {secret}=await enrollment.json();
const totp=new TOTP({issuer:'CloudSentinel',label:email,algorithm:'SHA1',digits:6,period:30,secret:Secret.fromBase32(secret)});
assert.equal((await post('/auth/mfa/confirm',{code:totp.generate()},cookie,csrf)).status,200);
await writeFile('/app/.local/smoke-state.json',JSON.stringify({cookie}),{mode:0o600});
console.log('Container registration, login, CSRF and MFA passed.');
NODE
docker restart "$name-app" >/dev/null
wait_ready
docker run --rm -i --network "$name" -v "$name-mfa:/app/.local:ro" "$image" node --input-type=module - <<'NODE'
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
const {cookie}=JSON.parse(await readFile('/app/.local/smoke-state.json','utf8'));
const result=await fetch('http://app:3000/api/auth/me',{headers:{cookie}});
assert.equal(result.status,200);assert.equal((await result.json()).security.mfa,'enabled');
console.log('Session and MFA state survive application restart.');
NODE
docker stop "$name-db" >/dev/null
docker exec "$name-app" node --input-type=module -e '
  import assert from "node:assert/strict";
  assert.equal((await fetch("http://localhost:3000/api/health")).status,200);
  assert.equal((await fetch("http://localhost:3000/api/ready")).status,503);
  console.log("Liveness stays healthy and readiness fails when the database is down.");'
docker start "$name-db" >/dev/null
wait_ready
# Ensure deployed mode rejects absent secrets instead of silently generating a local key.
if docker run --rm -e APP_ENV=aws -e APP_ORIGIN=https://cloudsentinel.example.com \
  -e IDENTITY_TABLE=cloudsentinel-identity "$image" >/dev/null 2>&1; then
  echo 'ERROR: AWS mode accepted a missing MFA key' >&2; exit 1
fi
# AWS mode runs with a read-only root and no local key file or network credentials.
docker run -d --name "$name-prod" --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --tmpfs /tmp -e APP_ENV=aws \
  -e APP_ORIGIN=https://cloudsentinel.example.com -e IDENTITY_TABLE=cloudsentinel-identity \
  -e AWS_REGION=us-east-1 -e AWS_EC2_METADATA_DISABLED=true \
  -e MFA_ENCRYPTION_KEY=abababababababababababababababababababababababababababababababab \
  "$image" >/dev/null
docker exec "$name-prod" node --input-type=module -e '
  import assert from "node:assert/strict";
  let healthy=false;
  for(let i=0;i<30;i++){try{if((await fetch("http://localhost:3000/api/health")).ok){healthy=true;break}}catch{} await new Promise(r=>setTimeout(r,1000))}
  assert.equal(healthy,true);
  assert.equal((await fetch("http://localhost:3000/api/ready")).status,503);
  console.log("AWS mode starts without a writable key file and reports unavailable database credentials safely.");'
docker stop --time 35 "$name-app" >/dev/null
test "$(docker inspect --format '{{.State.ExitCode}}' "$name-app")" = 0
echo 'Container smoke checks passed, including graceful SIGTERM shutdown.'
