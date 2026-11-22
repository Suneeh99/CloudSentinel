import { afterEach, describe, expect, it, vi } from 'vitest';
import { STSClient, AssumeRoleCommand, GetCallerIdentityCommand } from '@aws-sdk/client-sts';
import { EC2Client } from '@aws-sdk/client-ec2';
import { S3Client, ListBucketsCommand, GetPublicAccessBlockCommand } from '@aws-sdk/client-s3';
import {
  AwsGateway,
  groupChecks,
  readPolicy,
  trustPolicy,
} from '../../services/connector-worker/src/aws.js';
import {
  encryptSecret,
  decryptSecret,
  authenticator,
  counter,
} from '../../services/identity-service/src/mfa.js';
import type { Connection } from '../../packages/schemas/src/cloud.js';
const connection: Connection = {
  id: 'one',
  name: 'AWS',
  tenantId: 'tenant',
  accountId: '123456789012',
  roleArn: 'arn:aws:iam::123456789012:role/Scan',
  region: 'us-east-1',
  externalId: 'unique-id',
  status: 'connected',
  createdAt: 1,
};
const credentials = {
  AccessKeyId: 'synthetic',
  SecretAccessKey: 'synthetic',
  SessionToken: 'synthetic',
};
afterEach(() => vi.restoreAllMocks());
describe('predefined configuration rules', () => {
  it('detects IPv4, IPv6, numeric TCP, port ranges and all protocols without flagging private sources or UDP', () => {
    expect(
      groupChecks(
        'sg-1',
        [{ IpProtocol: '6', FromPort: 20, ToPort: 25, Ipv6Ranges: [{ CidrIpv6: '::/0' }] }],
        'us-east-1',
      ).map((c) => c.status),
    ).toEqual(['fail', 'pass', 'pass']);
    expect(
      groupChecks(
        'sg-1',
        [{ IpProtocol: '-1', IpRanges: [{ CidrIp: '0.0.0.0/0' }] }],
        'us-east-1',
      ).map((c) => c.status),
    ).toEqual(['fail', 'fail', 'fail']);
    expect(
      groupChecks(
        'sg-1',
        [
          { IpProtocol: 'tcp', FromPort: 3389, ToPort: 3389, IpRanges: [{ CidrIp: '10.0.0.0/8' }] },
          { IpProtocol: 'udp', FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: '0.0.0.0/0' }] },
        ],
        'us-east-1',
      ).every((c) => c.status === 'pass'),
    ).toBe(true);
  });
  it('scopes trust to an explicit principal and unique external ID; requests no resource writes or object contents', () => {
    expect(
      trustPolicy('arn:aws:iam::111111111111:role/Runtime', 'unique').Statement[0].Condition
        .StringEquals['sts:ExternalId'],
    ).toBe('unique');
    const actions = readPolicy.Statement.flatMap((s) => s.Action);
    expect(actions).toEqual([
      'ec2:DescribeSecurityGroups',
      's3:ListAllMyBuckets',
      's3:GetBucketPublicAccessBlock',
      's3:GetBucketPolicyStatus',
    ]);
  });
  it('rejects a role that can be assumed with a wrong external ID and detects account mismatches', async () => {
    const send = vi.spyOn(STSClient.prototype, 'send');
    send.mockImplementation(async (command) =>
      command instanceof GetCallerIdentityCommand
        ? { Account: connection.accountId }
        : { Credentials: credentials },
    );
    await expect(new AwsGateway().verify(connection)).rejects.toThrow('must require');
    send.mockImplementation(async (command) =>
      command instanceof GetCallerIdentityCommand
        ? { Account: '999999999999' }
        : { Credentials: credentials },
    );
    await expect(new AwsGateway().verify(connection)).rejects.toThrow('mismatch');
  });
  it('verifies account identity and rejects wrong external IDs using temporary credentials', async () => {
    const send = vi.spyOn(STSClient.prototype, 'send').mockImplementation(async (command) => {
      if (command instanceof GetCallerIdentityCommand) return { Account: connection.accountId };
      if (
        command instanceof AssumeRoleCommand &&
        command.input.ExternalId !== connection.externalId
      )
        throw Object.assign(new Error('private AWS error'), { name: 'AccessDenied' });
      return { Credentials: credentials };
    });
    await expect(new AwsGateway().verify(connection)).resolves.toBeUndefined();
    expect(send).toHaveBeenCalledTimes(3);
  });
  it('records S3 missing protections as findings and denied checks as errors; pagination produces partial coverage', async () => {
    vi.spyOn(STSClient.prototype, 'send').mockResolvedValue({ Credentials: credentials } as never);
    vi.spyOn(EC2Client.prototype, 'send').mockResolvedValue({
      SecurityGroups: [
        {
          GroupId: 'sg-public',
          IpPermissions: [{ IpProtocol: '-1', IpRanges: [{ CidrIp: '0.0.0.0/0' }] }],
        },
      ],
      NextToken: 'more',
    } as never);
    vi.spyOn(S3Client.prototype, 'send').mockImplementation(async (command) => {
      if (command instanceof ListBucketsCommand) {
        expect(command.input).toMatchObject({ BucketRegion: 'us-east-1', MaxBuckets: 25 });
        return { Buckets: [{ Name: 'test-bucket' }], ContinuationToken: 'more' };
      }
      if (command instanceof GetPublicAccessBlockCommand)
        throw Object.assign(new Error('missing'), { name: 'NoSuchPublicAccessBlockConfiguration' });
      throw Object.assign(new Error('private account error and secret'), { name: 'AccessDenied' });
    });
    const result = await new AwsGateway().scan(connection);
    expect(result.status).toBe('partial');
    expect(result.resources).toBe(2);
    expect(result.checks.filter((c) => c.status === 'fail')).toHaveLength(4);
    expect(result.checks.filter((c) => c.status === 'error')).toHaveLength(1);
    expect(result.errors).toHaveLength(2);
    expect(JSON.stringify(result)).not.toContain('private account');
  });
  it('never reports successful coverage when inventory access fails', async () => {
    vi.spyOn(STSClient.prototype, 'send').mockResolvedValue({ Credentials: credentials } as never);
    vi.spyOn(EC2Client.prototype, 'send').mockRejectedValue(
      Object.assign(new Error('secret'), { name: 'AccessDenied' }),
    );
    vi.spyOn(S3Client.prototype, 'send').mockRejectedValue(
      Object.assign(new Error('secret'), { name: 'TimeoutError' }),
    );
    const result = await new AwsGateway().scan(connection);
    expect(result.status).toBe('failed');
    expect(result.errors).toHaveLength(2);
    expect(result.checks).toEqual([]);
  });
});
describe('authenticator security', () => {
  it('encrypts seeds with authenticated user binding and rejects TOTP replay and expiry', () => {
    const key = 'ab'.repeat(32),
      secret = 'JBSWY3DPEHPK3PXP';
    const encrypted = encryptSecret(secret, key, 'alice');
    expect(encrypted).not.toContain(secret);
    expect(decryptSecret(encrypted, key, 'alice')).toBe(secret);
    expect(() => decryptSecret(encrypted, key, 'bob')).toThrow();
    expect(() => decryptSecret(encrypted, 'cd'.repeat(32), 'alice')).toThrow();
    const now = 1800000000,
      token = authenticator(secret, 'alice').generate({ timestamp: now * 1000 });
    const value = counter(secret, token, now)!;
    expect(value).toBe(Math.floor(now / 30));
    expect(counter(secret, token, now, value)).toBeNull();
    expect(counter(secret, token, now + 90)).toBeNull();
  });
});
