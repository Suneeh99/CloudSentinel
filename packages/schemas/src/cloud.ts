import { z } from 'zod';
export const regions = [
  'us-east-1',
  'us-east-2',
  'us-west-1',
  'us-west-2',
  'eu-west-1',
  'eu-west-2',
  'eu-west-3',
  'eu-central-1',
  'eu-north-1',
  'ap-south-1',
  'ap-northeast-1',
  'ap-northeast-2',
  'ap-southeast-1',
  'ap-southeast-2',
  'ca-central-1',
  'sa-east-1',
] as const;
export const connectionSchema = z
  .object({
    name: z.string().trim().min(2).max(80),
    roleArn: z.string().regex(/^arn:aws:iam::\d{12}:role\/[A-Za-z0-9_+=,.@/-]{1,512}$/),
    region: z.enum(regions),
  })
  .strict();
export type Connection = {
  id: string;
  name: string;
  tenantId: string;
  roleArn: string;
  accountId: string;
  region: string;
  externalId: string;
  status: 'pending' | 'connected' | 'disconnected';
  createdAt: number;
  verifiedAt?: number;
  leaseUntil?: number;
  latestScanKey?: string;
  leaseId?: string;
};
export type Check = {
  ruleId: string;
  title: string;
  severity: 'critical' | 'high' | 'medium';
  resource: string;
  region: string;
  status: 'pass' | 'fail' | 'error';
  evidence: string;
  remediation: string;
};
export type ScanResult = {
  status: 'completed' | 'partial' | 'failed';
  checks: Check[];
  resources: number;
  errors: string[];
};
export type Scan = Omit<ScanResult, 'status'> & {
  id: string;
  connectionId: string;
  connectionName: string;
  accountId: string;
  region: string;
  startedAt: number;
  finishedAt?: number;
  status: ScanResult['status'] | 'running';
};
