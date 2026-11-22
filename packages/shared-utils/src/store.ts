import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  GetCommand,
  QueryCommand,
  TransactWriteCommand,
  UpdateCommand,
  type TransactWriteCommandInput,
} from '@aws-sdk/lib-dynamodb';

export function database(local = false) {
  return DynamoDBDocumentClient.from(
    new DynamoDBClient(
      local
        ? {
            region: 'us-east-1',
            endpoint: process.env.DYNAMODB_LOCAL_ENDPOINT ?? 'http://127.0.0.1:8000',
            credentials: { accessKeyId: 'localdevelopment', secretAccessKey: 'localdevelopment' },
          }
        : {},
    ),
    { marshallOptions: { removeUndefinedValues: true } },
  );
}
export class Store {
  constructor(
    readonly client: DynamoDBDocumentClient,
    readonly table: string,
  ) {}
  async get<T>(pk: string, sk: string, abortSignal?: AbortSignal): Promise<T | undefined> {
    const r = await this.client.send(
      new GetCommand({ TableName: this.table, Key: { pk, sk }, ConsistentRead: true }),
      { abortSignal },
    );
    return r.Item as T | undefined;
  }
  async query<T>(pk: string, prefix: string, limit = 50): Promise<T[]> {
    const r = await this.client.send(
      new QueryCommand({
        TableName: this.table,
        KeyConditionExpression: 'pk = :p AND begins_with(sk, :s)',
        ExpressionAttributeValues: { ':p': pk, ':s': prefix },
        ConsistentRead: true,
        ScanIndexForward: false,
        Limit: limit,
      }),
    );
    return (r.Items ?? []) as T[];
  }
  async transact(items: NonNullable<TransactWriteCommandInput['TransactItems']>) {
    await this.client.send(new TransactWriteCommand({ TransactItems: items }));
  }
  put(item: Record<string, unknown>, unique = true) {
    return {
      Put: {
        TableName: this.table,
        Item: item,
        ...(unique ? { ConditionExpression: 'attribute_not_exists(pk)' } : {}),
      },
    };
  }
  delete(pk: string, sk: string) {
    return { Delete: { TableName: this.table, Key: { pk, sk } } };
  }
  async limit(key: string, now: number, maximum: number, seconds = 900) {
    const bucket = Math.floor(now / seconds);
    try {
      await this.client.send(
        new UpdateCommand({
          TableName: this.table,
          Key: { pk: `RATE#${key}#${bucket}`, sk: 'LIMIT' },
          UpdateExpression: 'SET expiresAt = :ttl ADD attempts :one',
          ConditionExpression: 'attribute_not_exists(attempts) OR attempts < :max',
          ExpressionAttributeValues: { ':ttl': (bucket + 2) * seconds, ':one': 1, ':max': maximum },
        }),
      );
      return true;
    } catch (e) {
      if (isConditional(e)) return false;
      throw e;
    }
  }
}
export function isConditional(e: unknown) {
  if (!(e instanceof Error)) return false;
  if (e.name === 'ConditionalCheckFailedException') return true;
  if (e.name !== 'TransactionCanceledException') return false;
  const reasons = (e as Error & { CancellationReasons?: { Code?: string }[] }).CancellationReasons;
  return reasons?.some((r) => r.Code === 'ConditionalCheckFailed') ?? false;
}
