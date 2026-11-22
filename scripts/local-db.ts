import { spawnSync } from 'node:child_process';
const name = 'cloudsentinel-dynamodb-local';
function docker(args: string[], quiet = false) {
  const result = spawnSync('docker', args, { encoding: 'utf8', stdio: quiet ? 'pipe' : 'inherit' });
  return result;
}
if (process.argv[2] === 'stop') {
  const r = docker(['stop', name]);
  process.exit(r.status ?? 1);
}
const existing = docker(['inspect', '--format', '{{.Config.Image}}', name], true);
if (existing.status === 0) {
  if (existing.stdout.trim() !== 'amazon/dynamodb-local:3.1.0')
    throw new Error('Existing container image mismatch. Inspect manually.');
  if (docker(['start', name]).status !== 0) process.exit(1);
} else {
  const r = docker([
    'run',
    '-d',
    '--name',
    name,
    '--publish',
    '127.0.0.1:8000:8000',
    '--volume',
    'cloudsentinel-dynamodb-data:/home/dynamodblocal/data',
    '--user',
    'root',
    'amazon/dynamodb-local:3.1.0',
    '-jar',
    'DynamoDBLocal.jar',
    '-sharedDb',
    '-dbPath',
    '/home/dynamodblocal/data',
  ]);
  if (r.status !== 0) process.exit(r.status ?? 1);
}
let ready = false;
for (let attempt = 0; attempt < 30; attempt++) {
  try {
    await fetch('http://127.0.0.1:8000', { signal: AbortSignal.timeout(1000) });
    ready = true;
    break;
  } catch {
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
}
if (!ready)
  throw new Error(
    'DynamoDB Local failed to start. Inspect docker logs cloudsentinel-dynamodb-local.',
  );
console.log('DynamoDB Local is ready. Persistent Docker volume: cloudsentinel-dynamodb-data.');
