import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { CreateTableCommand, DeleteTableCommand } from '@aws-sdk/client-dynamodb';
import { database } from '../packages/shared-utils/src/store.js';
const client = database(true),
  TableName = `cloudsentinel-local-e2e-${randomUUID()}`;
await client.send(
  new CreateTableCommand({
    TableName,
    BillingMode: 'PAY_PER_REQUEST',
    KeySchema: [
      { AttributeName: 'pk', KeyType: 'HASH' },
      { AttributeName: 'sk', KeyType: 'RANGE' },
    ],
    AttributeDefinitions: [
      { AttributeName: 'pk', AttributeType: 'S' },
      { AttributeName: 'sk', AttributeType: 'S' },
    ],
  }),
);
try {
  const result = await new Promise<number>((resolve, reject) => {
    const child = spawn(
      'node',
      ['node_modules/@playwright/test/cli.js', 'test', ...process.argv.slice(2)],
      { stdio: 'inherit', env: { ...process.env, LOCAL_IDENTITY_TABLE: TableName } },
    );
    child.on('error', reject);
    child.on('exit', (code) => resolve(code ?? 1));
  });
  process.exitCode = result;
} finally {
  await client.send(new DeleteTableCommand({ TableName }));
  client.destroy();
}
