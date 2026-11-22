import { randomUUID } from 'node:crypto';
import {
  connectionSchema,
  regions,
  type Connection,
  type Scan,
} from '../../../packages/schemas/src/cloud.js';
import { Store, isConditional } from '../../../packages/shared-utils/src/store.js';
import {
  readPolicy,
  trustPolicy,
  rules,
  awsMessage,
  type CloudGateway,
} from '../../connector-worker/src/aws.js';

export type CloudConfig = { principalArn: string; gateway: CloudGateway };
export class CloudError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}
export function cloudService(store: Store, config?: CloudConfig) {
  if (config && !/^arn:aws:iam::\d{12}:role\/[A-Za-z0-9_+=,.@/-]+$/.test(config.principalArn))
    throw new Error('CLOUDSENTINEL_AWS_PRINCIPAL_ARN must be an IAM role ARN');
  const clean = (row: Scan) => {
    const value = { ...row } as Scan & { pk?: string; sk?: string };
    delete value.pk;
    delete value.sk;
    return value;
  };
  return {
    async list(tenantId: string, owner: boolean) {
      const connections = await store.query<Connection>(`TENANT#${tenantId}`, 'CONNECTION#', 10);
      return {
        configured: !!config,
        regions,
        rules,
        connections: connections.map((c) => ({
          id: c.id,
          name: c.name,
          accountId: c.accountId,
          region: c.region,
          status: c.status,
          createdAt: c.createdAt,
          verifiedAt: c.verifiedAt,
          ...(owner
            ? {
                roleArn: c.roleArn,
                externalId: c.externalId,
                trustPolicy: config ? trustPolicy(config.principalArn, c.externalId) : null,
                readPolicy,
              }
            : {}),
        })),
      };
    },
    async history(tenantId: string) {
      const scans = await store.query<Scan>(`TENANT#${tenantId}`, 'SCAN#', 20);
      return { scans: scans.map(clean), limit: 20 };
    },
    async summary(tenantId: string) {
      const connections = await store.query<Connection>(`TENANT#${tenantId}`, 'CONNECTION#', 10);
      const connected = connections.filter((c) => c.status === 'connected');
      const latest = await Promise.all(
        connected.map((c) =>
          c.latestScanKey ? store.get<Scan>(`TENANT#${tenantId}`, c.latestScanKey) : undefined,
        ),
      );
      const assessed = connected.length > 0 && latest.every((s) => s?.status === 'completed');
      const results = latest.filter((s): s is Scan => !!s);
      const measured = results.filter(
        (s) =>
          s.status === 'completed' ||
          (s.status === 'partial' && s.checks.some((c) => c.status !== 'error')),
      );
      return {
        assessment:
          connected.length === 0
            ? 'not_connected'
            : assessed
              ? 'assessed'
              : results.length
                ? 'partial'
                : 'not_assessed',
        assets: measured.length ? measured.reduce((n, s) => n + s.resources, 0) : null,
        findings: measured.length
          ? measured.reduce((n, s) => n + s.checks.filter((c) => c.status === 'fail').length, 0)
          : null,
        criticalFindings: measured.length
          ? measured.reduce(
              (n, s) =>
                n + s.checks.filter((c) => c.status === 'fail' && c.severity === 'critical').length,
              0,
            )
          : null,
        incidents: null,
        recentAssessments: results.map((s) => ({
          id: s.id,
          status: s.status,
          startedAt: s.startedAt,
        })),
        capabilities: { cloudConnections: !!config, assessments: !!config, incidents: false },
      };
    },
    async mutate(
      tenantId: string,
      actorId: string,
      request: Request,
      action: string[],
      input: unknown,
      now: number,
    ) {
      const started = Date.now();
      if (!config)
        throw new CloudError(
          503,
          'AWS scanning is not configured. Ask the operator to configure the AWS role identity and credentials.',
        );
      const pk = `TENANT#${tenantId}`;
      const event = (name: string, id: string) =>
        store.put({
          pk,
          sk: `AUDIT#${now.toString().padStart(12, '0')}#${randomUUID()}`,
          id: randomUUID(),
          actorId,
          action: name,
          connectionId: id,
          createdAt: now,
        });
      if (action.length === 0 && request.method === 'POST') {
        const data = connectionSchema.omit({ roleArn: true }).parse(input);
        const c: Connection = {
          ...data,
          id: randomUUID(),
          tenantId,
          accountId: '',
          roleArn: '',
          externalId: randomUUID(),
          status: 'pending',
          createdAt: now,
        };
        try {
          await store.transact([
            {
              Update: {
                TableName: store.table,
                Key: { pk, sk: 'CONNECTION_LIMIT' },
                UpdateExpression: 'ADD #count :one',
                ConditionExpression: 'attribute_not_exists(#count) OR #count < :max',
                ExpressionAttributeNames: { '#count': 'count' },
                ExpressionAttributeValues: { ':one': 1, ':max': 10 },
              },
            },
            store.put({ pk, sk: `CONNECTION#${c.id}`, ...c }),
            event('cloud.connection_created', c.id),
          ]);
        } catch (error) {
          if (isConditional(error))
            throw new CloudError(
              409,
              'This organization has reached the limit of 10 connection records.',
            );
          throw error;
        }
        return {
          connection: {
            ...c,
            trustPolicy: trustPolicy(config.principalArn, c.externalId),
            readPolicy,
          },
        };
      }
      const [id, operation] = action;
      if (!id || action.length > 2) throw new CloudError(404, 'Cloud endpoint not found.');
      const c = await store.get<Connection>(pk, `CONNECTION#${id}`);
      if (!c || c.tenantId !== tenantId) throw new CloudError(404, 'Connection not found.');
      if (operation === 'verify' && request.method === 'POST') {
        const data = connectionSchema.pick({ roleArn: true }).parse(input);
        const candidate = { ...c, roleArn: data.roleArn, accountId: data.roleArn.split(':')[4] };
        if (c.status === 'connected' && c.roleArn !== data.roleArn)
          throw new CloudError(409, 'Prepare a new connection to use a different IAM role.');
        if (c.status === 'disconnected')
          throw new CloudError(409, 'This connection was disconnected. Prepare a new connection.');
        try {
          await config.gateway.verify(candidate);
        } catch (error) {
          throw new CloudError(
            400,
            `${awsMessage(error)} The trust policy must require the exact external ID shown here.`,
          );
        }
        try {
          await store.transact([
            {
              Update: {
                TableName: store.table,
                Key: { pk, sk: `CONNECTION#${id}` },
                UpdateExpression:
                  'SET #status = :connected, roleArn = :role, accountId = :account, verifiedAt = :now',
                ConditionExpression:
                  '#status <> :disabled AND (attribute_not_exists(leaseUntil) OR leaseUntil <= :now)',
                ExpressionAttributeNames: { '#status': 'status' },
                ExpressionAttributeValues: {
                  ':connected': 'connected',
                  ':disabled': 'disconnected',
                  ':role': candidate.roleArn,
                  ':account': candidate.accountId,
                  ':now': now,
                },
              },
            },
            {
              Put: {
                TableName: store.table,
                Item: {
                  pk,
                  sk: `CLOUD_ACCOUNT#${candidate.accountId}#${c.region}`,
                  connectionId: id,
                },
                ConditionExpression: 'attribute_not_exists(pk) OR connectionId = :id',
                ExpressionAttributeValues: { ':id': id },
              },
            },
            event('cloud.connection_verified', id),
          ]);
        } catch (error) {
          if (isConditional(error))
            throw new CloudError(
              409,
              'This account and region are already connected, a scan is running, or the connection changed. Refresh and retry.',
            );
          throw error;
        }
        return { message: 'AWS account connected. Run a scan to assess its configuration.' };
      }
      if (!operation && request.method === 'DELETE') {
        try {
          await store.transact([
            {
              Update: {
                TableName: store.table,
                Key: { pk, sk: `CONNECTION#${id}` },
                UpdateExpression: 'SET #status = :disabled',
                ConditionExpression:
                  '#status = :previous AND (attribute_not_exists(leaseUntil) OR leaseUntil <= :now)',
                ExpressionAttributeNames: { '#status': 'status' },
                ExpressionAttributeValues: {
                  ':disabled': 'disconnected',
                  ':previous': c.status,
                  ':now': now,
                },
              },
            },
            ...(c.status === 'connected'
              ? [
                  {
                    Delete: {
                      TableName: store.table,
                      Key: { pk, sk: `CLOUD_ACCOUNT#${c.accountId}#${c.region}` },
                      ConditionExpression: 'connectionId = :id',
                      ExpressionAttributeValues: { ':id': id },
                    },
                  },
                ]
              : []),
            event('cloud.connection_disconnected', id),
          ]);
        } catch (error) {
          if (isConditional(error))
            throw new CloudError(
              409,
              'A scan is running. Wait for it to finish before disconnecting.',
            );
          throw error;
        }
        return {
          message:
            'Disconnected in CloudSentinel. Remove the IAM role or trust policy in AWS to revoke AWS access.',
        };
      }
      if (operation === 'scans' && request.method === 'POST') {
        if (c.status !== 'connected')
          throw new CloudError(409, 'Verify this AWS connection before scanning.');
        if (!(await store.limit(`cloud-scan:${tenantId}`, now, 5, 3600)))
          throw new CloudError(
            429,
            'The organization scan limit is 5 scans per hour. Try again later.',
          );
        const scan: Scan = {
          id: randomUUID(),
          connectionId: id,
          connectionName: c.name,
          accountId: c.accountId,
          region: c.region,
          startedAt: now,
          status: 'running',
          checks: [],
          resources: 0,
          errors: [],
        };
        const sk = `SCAN#${now.toString().padStart(12, '0')}#${scan.id}`;
        try {
          await store.transact([
            {
              Update: {
                TableName: store.table,
                Key: { pk, sk: `CONNECTION#${id}` },
                UpdateExpression:
                  'SET leaseUntil = :lease, leaseId = :id, latestScanKey = :scanKey',
                ConditionExpression:
                  '#status = :connected AND roleArn = :role AND (attribute_not_exists(leaseUntil) OR leaseUntil <= :now)',
                ExpressionAttributeNames: { '#status': 'status' },
                ExpressionAttributeValues: {
                  ':lease': now + 120,
                  ':id': scan.id,
                  ':scanKey': sk,
                  ':connected': 'connected',
                  ':now': now,
                  ':role': c.roleArn,
                },
              },
            },
            store.put({ pk, sk, ...scan }),
            event('cloud.scan_started', id),
          ]);
        } catch (error) {
          if (isConditional(error))
            throw new CloudError(
              409,
              'Another scan is running or this connection changed. Refresh and retry.',
            );
          throw error;
        }
        try {
          Object.assign(scan, await config.gateway.scan(c));
        } catch (error) {
          scan.status = 'failed';
          scan.errors = [awsMessage(error)];
        }
        scan.finishedAt = now + Math.round((Date.now() - started) / 1000);
        await store.transact([
          store.put({ pk, sk, ...scan }, false),
          {
            Update: {
              TableName: store.table,
              Key: { pk, sk: `CONNECTION#${id}` },
              UpdateExpression: 'REMOVE leaseUntil, leaseId',
              ConditionExpression: 'leaseId = :id',
              ExpressionAttributeValues: { ':id': scan.id },
            },
          },
          event(`cloud.scan_${scan.status}`, id),
        ]);
        return { scan };
      }
      throw new CloudError(404, 'Cloud endpoint not found.');
    },
  };
}
