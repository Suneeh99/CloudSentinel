import {
  CreateTableCommand,
  DescribeTableCommand,
  UpdateTimeToLiveCommand,
} from '@aws-sdk/client-dynamodb';
import { database } from '../packages/shared-utils/src/store.js';
const client = database(true);
const TableName = process.env.LOCAL_IDENTITY_TABLE ?? 'cloudsentinel-local-identity';
if (!/^cloudsentinel-local-(identity|e2e-[a-f0-9-]+)$/.test(TableName))
  throw new Error('Invalid local table name');
try {
  await client.send(new DescribeTableCommand({ TableName }));
} catch (error) {
  if (!(error instanceof Error) || error.name !== 'ResourceNotFoundException') throw error;
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
  await client.send(
    new UpdateTimeToLiveCommand({
      TableName,
      TimeToLiveSpecification: { AttributeName: 'expiresAt', Enabled: true },
    }),
  );
}
console.log('Local identity table is ready. No AWS resources were accessed.');
client.destroy();
