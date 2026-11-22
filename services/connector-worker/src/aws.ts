import { randomUUID } from 'node:crypto';
import { STSClient, AssumeRoleCommand, GetCallerIdentityCommand } from '@aws-sdk/client-sts';
import { EC2Client, DescribeSecurityGroupsCommand, type IpPermission } from '@aws-sdk/client-ec2';
import {
  S3Client,
  ListBucketsCommand,
  GetPublicAccessBlockCommand,
  GetBucketPolicyStatusCommand,
} from '@aws-sdk/client-s3';
import type { Check, Connection, ScanResult } from '../../../packages/schemas/src/cloud.js';

export const rules = [
  {
    id: 'EC2_SSH_PUBLIC',
    title: 'SSH open to the internet',
    severity: 'high',
    remediation:
      'Restrict inbound TCP port 22 to trusted IP ranges or use AWS Systems Manager Session Manager.',
  },
  {
    id: 'EC2_RDP_PUBLIC',
    title: 'RDP open to the internet',
    severity: 'high',
    remediation:
      'Restrict inbound TCP port 3389 to trusted IP ranges or use a private access path.',
  },
  {
    id: 'EC2_ALL_PUBLIC',
    title: 'All traffic open to the internet',
    severity: 'critical',
    remediation:
      'Remove unrestricted all-protocol ingress and allow only the protocols and sources required.',
  },
  {
    id: 'S3_PUBLIC_BLOCK',
    title: 'Bucket public access protections incomplete',
    severity: 'medium',
    remediation:
      'Enable all four bucket Block Public Access settings. Check account and organization controls before changing intended public workloads.',
  },
  {
    id: 'S3_PUBLIC_POLICY',
    title: 'Bucket policy classified as public',
    severity: 'high',
    remediation:
      'Remove public principals from the bucket policy unless public access is intentional. Verify effective account and bucket access controls.',
  },
] as const;
export const readPolicy = {
  Version: '2012-10-17',
  Statement: [
    {
      Effect: 'Allow',
      Action: ['ec2:DescribeSecurityGroups', 's3:ListAllMyBuckets'],
      Resource: '*',
    },
    {
      Effect: 'Allow',
      Action: ['s3:GetBucketPublicAccessBlock', 's3:GetBucketPolicyStatus'],
      Resource: 'arn:aws:s3:::*',
    },
  ],
};
export function trustPolicy(principalArn: string, externalId: string) {
  return {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Principal: { AWS: principalArn },
        Action: 'sts:AssumeRole',
        Condition: { StringEquals: { 'sts:ExternalId': externalId } },
      },
    ],
  };
}
export interface CloudGateway {
  verify(connection: Connection): Promise<void>;
  scan(connection: Connection): Promise<ScanResult>;
}
export function awsMessage(error: unknown) {
  const name = error instanceof Error ? error.name : '';
  if (
    ['AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation', 'Forbidden'].includes(name)
  )
    return 'AWS denied access. Review the trust policy, external ID, role permissions, and any organization restrictions.';
  if (['AbortError', 'TimeoutError', 'RequestTimeout'].includes(name))
    return 'AWS request timed out. Retry the scan.';
  if (
    [
      'ExpiredToken',
      'InvalidClientTokenId',
      'CredentialsProviderError',
      'UnrecognizedClientException',
    ].includes(name)
  )
    return 'AWS credentials are unavailable or expired. Ask the CloudSentinel operator to check its AWS identity.';
  return 'AWS could not complete this check. Review the role configuration and retry.';
}
export function internet(permission: IpPermission) {
  return (
    permission.IpRanges?.some((r) => r.CidrIp === '0.0.0.0/0') ||
    permission.Ipv6Ranges?.some((r) => r.CidrIpv6 === '::/0')
  );
}
export function exposed(permission: IpPermission, port: number) {
  return (
    !!internet(permission) &&
    (permission.IpProtocol === '-1' ||
      (['tcp', '6'].includes(permission.IpProtocol ?? '') &&
        (permission.FromPort ?? 65536) <= port &&
        (permission.ToPort ?? -1) >= port))
  );
}
export function groupChecks(id: string, permissions: IpPermission[], region: string): Check[] {
  return rules.slice(0, 3).map((rule, i) => {
    const fail = permissions.some((p) =>
      i === 2 ? internet(p) && p.IpProtocol === '-1' : exposed(p, i === 0 ? 22 : 3389),
    );
    return {
      ruleId: rule.id,
      title: rule.title,
      severity: rule.severity,
      resource: id,
      region,
      status: fail ? 'fail' : 'pass',
      evidence: fail
        ? 'Ingress allows 0.0.0.0/0 or ::/0 for this protocol/port. Reachability also depends on routing and other network controls.'
        : 'No matching unrestricted internet ingress rule was found.',
      remediation: rule.remediation,
    };
  });
}
export class AwsGateway implements CloudGateway {
  private async assume(
    connection: Connection,
    signal: AbortSignal,
    externalId = connection.externalId,
  ) {
    const sts = new STSClient({ region: connection.region, maxAttempts: 1 });
    try {
      const response = await sts.send(
        new AssumeRoleCommand({
          RoleArn: connection.roleArn,
          ExternalId: externalId,
          RoleSessionName: `cloudsentinel-${randomUUID()}`,
          DurationSeconds: 900,
          Policy: JSON.stringify(readPolicy),
        }),
        { abortSignal: signal },
      );
      const c = response.Credentials;
      if (!c?.AccessKeyId || !c.SecretAccessKey || !c.SessionToken)
        throw new Error('Missing temporary credentials');
      return {
        accessKeyId: c.AccessKeyId,
        secretAccessKey: c.SecretAccessKey,
        sessionToken: c.SessionToken,
      };
    } finally {
      sts.destroy();
    }
  }
  async verify(connection: Connection) {
    const signal = AbortSignal.timeout(15000);
    const credentials = await this.assume(connection, signal);
    const sts = new STSClient({ region: connection.region, credentials, maxAttempts: 1 });
    try {
      const identity = await sts.send(new GetCallerIdentityCommand({}), { abortSignal: signal });
      if (identity.Account !== connection.accountId) throw new Error('AWS account mismatch');
      // Reject roles that ignore the unique external ID, rather than merely sending it.
      try {
        await this.assume(connection, signal, randomUUID());
      } catch (error) {
        if (
          error instanceof Error &&
          ['AccessDenied', 'AccessDeniedException'].includes(error.name)
        )
          return;
        throw error;
      }
      throw new Error('Trust policy must require this connection external ID');
    } finally {
      sts.destroy();
    }
  }
  async scan(connection: Connection): Promise<ScanResult> {
    const signal = AbortSignal.timeout(20000);
    const checks: Check[] = [],
      errors: string[] = [];
    let resources = 0;
    const credentials = await this.assume(connection, signal);
    const config = { region: connection.region, credentials, maxAttempts: 1 };
    const ec2 = new EC2Client(config),
      s3 = new S3Client(config);
    const options = { abortSignal: signal };
    try {
      await Promise.all([
        (async () => {
          try {
            const response = await ec2.send(
              new DescribeSecurityGroupsCommand({ MaxResults: 50 }),
              options,
            );
            if (response.NextToken)
              errors.push('Security group coverage is limited to the first 50 groups.');
            for (const group of (response.SecurityGroups ?? []).slice(0, 50)) {
              if (!group.GroupId) continue;
              resources++;
              checks.push(
                ...groupChecks(group.GroupId, group.IpPermissions ?? [], connection.region),
              );
            }
          } catch (error) {
            errors.push(`Security group inventory: ${awsMessage(error)}`);
          }
        })(),
        (async () => {
          try {
            const response = await s3.send(
              new ListBucketsCommand({ BucketRegion: connection.region, MaxBuckets: 25 }),
              options,
            );
            if (response.ContinuationToken)
              errors.push('S3 coverage is limited to the first 25 buckets in this region.');
            const buckets = (response.Buckets ?? []).slice(0, 25);
            // Five requests at a time bounds outbound concurrency and the 20-second scan budget.
            for (let offset = 0; offset < buckets.length; offset += 5) {
              await Promise.all(
                buckets.slice(offset, offset + 5).map(async (bucket) => {
                  if (!bucket.Name) return;
                  resources++;
                  const input = { Bucket: bucket.Name, ExpectedBucketOwner: connection.accountId };
                  for (const rule of rules.slice(3)) {
                    const check: Check = {
                      ruleId: rule.id,
                      title: rule.title,
                      severity: rule.severity,
                      resource: bucket.Name,
                      region: connection.region,
                      status: 'error',
                      evidence: '',
                      remediation: rule.remediation,
                    };
                    try {
                      if (rule.id === 'S3_PUBLIC_BLOCK') {
                        const result = await s3.send(
                          new GetPublicAccessBlockCommand(input),
                          options,
                        );
                        const p = result.PublicAccessBlockConfiguration;
                        const safe =
                          p?.BlockPublicAcls &&
                          p.IgnorePublicAcls &&
                          p.BlockPublicPolicy &&
                          p.RestrictPublicBuckets;
                        check.status = safe ? 'pass' : 'fail';
                        check.evidence = safe
                          ? 'All four bucket Block Public Access settings are enabled.'
                          : 'At least one bucket Block Public Access setting is disabled. This alone does not establish public exposure; account and organization controls may still block access.';
                      } else {
                        const result = await s3.send(
                          new GetBucketPolicyStatusCommand(input),
                          options,
                        );
                        if (typeof result.PolicyStatus?.IsPublic !== 'boolean')
                          throw new Error('Missing policy status');
                        check.status = result.PolicyStatus.IsPublic ? 'fail' : 'pass';
                        check.evidence = result.PolicyStatus.IsPublic
                          ? 'AWS classifies this bucket policy as public. Effective public access may still be blocked by account or bucket settings.'
                          : 'AWS does not classify this bucket policy as public.';
                      }
                    } catch (error) {
                      const name = error instanceof Error ? error.name : '';
                      if (
                        rule.id === 'S3_PUBLIC_BLOCK' &&
                        name === 'NoSuchPublicAccessBlockConfiguration'
                      ) {
                        check.status = 'fail';
                        check.evidence =
                          'No bucket-level Block Public Access configuration exists. Account or organization controls may still block access.';
                      } else if (rule.id === 'S3_PUBLIC_POLICY' && name === 'NoSuchBucketPolicy') {
                        check.status = 'pass';
                        check.evidence =
                          'No bucket policy exists. ACL-based access is outside this rule.';
                      } else {
                        check.evidence = awsMessage(error);
                      }
                    }
                    checks.push(check);
                  }
                }),
              );
            }
          } catch (error) {
            errors.push(`S3 inventory: ${awsMessage(error)}`);
          }
        })(),
      ]);
    } finally {
      ec2.destroy();
      s3.destroy();
    }
    const incomplete = errors.length > 0 || checks.some((c) => c.status === 'error');
    return {
      status: incomplete
        ? checks.some((c) => c.status !== 'error')
          ? 'partial'
          : 'failed'
        : 'completed',
      checks: checks.sort((a, b) =>
        `${a.resource}:${a.ruleId}`.localeCompare(`${b.resource}:${b.ruleId}`),
      ),
      resources,
      errors,
    };
  }
}
