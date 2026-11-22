'use client';
import { Button } from './button';
import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react';
import { Cloud, Play, RefreshCw, ShieldCheck } from 'lucide-react';
import { api, ApiError } from './api';
import type { Connection, Scan } from '../../../packages/schemas/src/cloud';

type Account = Connection & { trustPolicy?: unknown; readPolicy?: unknown };
type Catalog = {
  configured: boolean;
  regions: string[];
  rules: { id: string; title: string; severity: string }[];
  connections: Account[];
};
type Security = { configured: boolean; mfaEnabled: boolean; elevatedUntil: number };
type Me = { csrfToken: string; role: string; organization: { id: string } };
const date = (time: number) =>
  new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(
    new Date(time * 1000),
  );
export function CloudPanel({
  me,
  onChanged,
  onSignedOut,
}: {
  me: Me;
  onChanged: () => Promise<void>;
  onSignedOut: () => void;
}) {
  const [catalog, setCatalog] = useState<Catalog | null>(null);
  const [security, setSecurity] = useState<Security | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [selected, setSelected] = useState('');
  const [scanId, setScanId] = useState('');
  const [filter, setFilter] = useState('fail');
  const [page, setPage] = useState(0);
  const [enrollment, setEnrollment] = useState<{ secret: string; qrCode: string } | null>(null);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [now, setNow] = useState(() => Date.now() / 1000);
  const errorRef = useRef<HTMLParagraphElement>(null);
  const base = `/organizations/${me.organization.id}`;
  const owner = me.role === 'owner';
  const approved = !!security?.mfaEnabled && security.elevatedUntil > now;
  const connection = catalog?.connections.find((c) => c.id === selected);
  const scan = scans.find((s) => s.id === scanId) ?? scans[0];
  const checks = scan?.checks.filter((c) => filter === 'all' || c.status === filter) ?? [];
  const load = useCallback(async () => {
    const [accounts, status, history] = await Promise.all([
      api<Catalog>(`${base}/connections`),
      api<Security>('/auth/security'),
      api<{ scans: Scan[] }>(`${base}/scans`),
    ]);
    setCatalog(accounts);
    setSecurity(status);
    setScans(history.scans);
    setSelected((value) => value || accounts.connections[0]?.id || '');
    setNow(Date.now() / 1000);
  }, [base]);
  useEffect(() => {
    void load().catch((e) =>
      setError(e instanceof Error ? e.message : 'Unable to load AWS accounts. Refresh and retry.'),
    );
    const timer = setInterval(() => setNow(Date.now() / 1000), 10000);
    return () => clearInterval(timer);
  }, [load]);
  useEffect(() => {
    if (error) errorRef.current?.focus();
  }, [error]);
  async function action(label: string, work: () => Promise<void>) {
    setBusy(label);
    setError('');
    setNotice('');
    try {
      await work();
      await load();
      await onChanged();
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) onSignedOut();
      else setError(e instanceof Error ? e.message : 'Request failed. Refresh and retry.');
    } finally {
      setBusy('');
    }
  }
  function post<T>(path: string, body?: unknown, method = 'POST') {
    return api<T>(path, {
      method,
      headers: { 'x-csrf-token': me.csrfToken },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  }
  function form(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    return new FormData(event.currentTarget);
  }
  async function copy(value: unknown) {
    try {
      await navigator.clipboard.writeText(JSON.stringify(value, null, 2));
      setNotice('Policy copied.');
    } catch {
      setError('Copy was unavailable. Select and copy the policy text below.');
    }
  }
  return (
    <div className="cloud-workspace" aria-busy={!!busy}>
      {error && (
        <p className="error" role="alert" ref={errorRef} tabIndex={-1}>
          {error}
        </p>
      )}
      <p className="cloud-status" role="status">
        {busy ? `${busy}…` : notice}
      </p>
      {!catalog && !error && <p>Loading cloud accounts…</p>}
      {catalog && (
        <>
          {!catalog.configured && (
            <div className="development-banner">
              <Cloud size={20} aria-hidden="true" />
              <p>
                <strong>AWS scanning needs operator setup.</strong> The server needs its AWS role
                identity and credentials before you can connect an account. You can set up your
                authenticator now.
              </p>
            </div>
          )}
          {owner && (
            <section className="cloud-section" aria-labelledby="cloud-security-heading">
              <div className="cloud-section-heading">
                <div>
                  <h2 id="cloud-security-heading">Approve cloud actions</h2>
                  <p className="muted">
                    Only organization owners can connect accounts, run scans, or disconnect access.
                  </p>
                </div>
                <ShieldCheck size={23} aria-hidden="true" />
              </div>
              {!security?.configured ? (
                <p>MFA encryption is unavailable. Ask the operator to configure it.</p>
              ) : !security.mfaEnabled ? (
                <>
                  <p>
                    Add a time-based authenticator before connecting AWS. Save the setup key
                    securely; account recovery is not available yet.
                  </p>
                  {!enrollment ? (
                    <form
                      className="cloud-form"
                      onSubmit={(event) => {
                        const data = form(event);
                        void action('Preparing authenticator', async () => {
                          setEnrollment(
                            await post('/auth/mfa/enroll', {
                              password: String(data.get('password')),
                            }),
                          );
                        });
                      }}
                    >
                      <label htmlFor="enroll-password">Confirm your password</label>
                      <input
                        id="enroll-password"
                        name="password"
                        type="password"
                        autoComplete="current-password"
                        required
                        maxLength={128}
                      />
                      <Button disabled={!!busy}>Set up authenticator</Button>
                    </form>
                  ) : (
                    <div className="mfa-enrollment">
                      <img
                        src={enrollment.qrCode}
                        width={220}
                        height={220}
                        alt="Scan this QR code with your authenticator app"
                      />
                      <div>
                        <p>Scan the QR code or enter this setup key in your authenticator app.</p>
                        <code className="setup-key" translate="no">
                          {enrollment.secret}
                        </code>
                        <form
                          className="cloud-form"
                          onSubmit={(event) => {
                            const data = form(event);
                            void action('Confirming authenticator', async () => {
                              await post('/auth/mfa/confirm', { code: String(data.get('code')) });
                              setEnrollment(null);
                              setNotice(
                                'Authenticator enabled. Cloud actions approved for 10 minutes.',
                              );
                            });
                          }}
                        >
                          <label htmlFor="confirm-code">Authenticator code</label>
                          <input
                            id="confirm-code"
                            name="code"
                            inputMode="numeric"
                            autoComplete="one-time-code"
                            pattern="[0-9]{6}"
                            minLength={6}
                            maxLength={6}
                            spellCheck={false}
                            required
                          />
                          <Button variant="primary" disabled={!!busy}>
                            Enable authenticator
                          </Button>
                        </form>
                      </div>
                    </div>
                  )}
                </>
              ) : approved ? (
                <p className="good">
                  Cloud actions approved until {date(security.elevatedUntil)}. Your authenticator is
                  required at sign-in.
                </p>
              ) : (
                <form
                  className="cloud-form"
                  onSubmit={(event) => {
                    const data = form(event);
                    void action('Approving cloud actions', async () => {
                      await post('/auth/reauthenticate', {
                        password: String(data.get('password')),
                        code: String(data.get('code')),
                      });
                      setNotice('Cloud actions approved for 10 minutes.');
                    });
                  }}
                >
                  <label htmlFor="reauth-password">Password</label>
                  <input
                    id="reauth-password"
                    name="password"
                    type="password"
                    autoComplete="current-password"
                    required
                    maxLength={128}
                  />
                  <label htmlFor="reauth-code">Fresh authenticator code</label>
                  <input
                    id="reauth-code"
                    name="code"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    pattern="[0-9]{6}"
                    minLength={6}
                    maxLength={6}
                    spellCheck={false}
                    required
                  />
                  <Button variant="primary" disabled={!!busy}>
                    Approve cloud actions
                  </Button>
                </form>
              )}
            </section>
          )}
          <section className="cloud-section" aria-labelledby="aws-accounts-heading">
            <div className="cloud-section-heading">
              <div>
                <h2 id="aws-accounts-heading">AWS accounts</h2>
                <p className="muted">
                  Temporary, read-only access through an IAM role. CloudSentinel does not ask for
                  your AWS secret keys.
                </p>
              </div>
              <Button disabled={!!busy} onClick={() => void action('Refreshing accounts', load)}>
                <RefreshCw size={16} aria-hidden="true" />
                Refresh accounts
              </Button>
            </div>
            {catalog.connections.length === 0 && (
              <p>
                No AWS accounts connected. Prepare a connection to generate its trust policy and
                read permissions.
              </p>
            )}
            {catalog.connections.length > 0 && (
              <>
                <label htmlFor="aws-account">AWS connection</label>
                <select
                  id="aws-account"
                  value={selected}
                  onChange={(e) => setSelected(e.target.value)}
                >
                  {catalog.connections.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.name} · {c.region} · {c.status}
                    </option>
                  ))}
                </select>
              </>
            )}
            {connection && (
              <div className="connection-detail">
                <div className="cloud-section-heading">
                  <div>
                    <h3>{connection.name}</h3>
                    <p className="muted">
                      {connection.accountId || 'AWS account not verified'} · {connection.region} ·{' '}
                      {connection.status}
                    </p>
                  </div>
                  {owner && connection.status === 'connected' && (
                    <Button
                      variant="primary"
                      disabled={!!busy || !approved || !catalog.configured}
                      onClick={() =>
                        void action('Scanning AWS configuration', async () => {
                          const result = await post<{ scan: Scan }>(
                            `${base}/connections/${connection.id}/scans`,
                          );
                          setScanId(result.scan.id);
                          setFilter('fail');
                          setPage(0);
                          setNotice(
                            `Scan ${result.scan.status}. ${result.scan.checks.filter((c) => c.status === 'fail').length} findings recorded.`,
                          );
                        })
                      }
                    >
                      <Play size={16} aria-hidden="true" />
                      Run predefined scan
                    </Button>
                  )}
                </div>
                {owner && connection.status !== 'disconnected' && (
                  <>
                    <details open={connection.status === 'pending'}>
                      <summary>IAM role setup and policies</summary>
                      <p>
                        Create an IAM role in your AWS account using this custom trust policy.
                        Attach the read policy below, then paste the role ARN to verify access. The
                        unique external ID must remain in the trust policy.
                      </p>
                      {(['trustPolicy', 'readPolicy'] as const).map((key) => (
                        <div className="policy-block" key={key}>
                          <div className="cloud-section-heading">
                            <h3>
                              {key === 'trustPolicy'
                                ? 'Role trust policy'
                                : 'Read permissions policy'}
                            </h3>
                            <Button disabled={!!busy} onClick={() => void copy(connection[key])}>
                              Copy {key === 'trustPolicy' ? 'trust policy' : 'read policy'}
                            </Button>
                          </div>
                          <pre
                            tabIndex={0}
                            aria-label={
                              key === 'trustPolicy'
                                ? 'Role trust policy JSON'
                                : 'Read permissions policy JSON'
                            }
                          >
                            <code translate="no">{JSON.stringify(connection[key], null, 2)}</code>
                          </pre>
                        </div>
                      ))}
                      <p className="field-help">
                        Verification also checks that a different external ID is denied. No AWS
                        resources are changed by verification or scans.
                      </p>
                      {connection.status === 'pending' && (
                        <form
                          className="cloud-form"
                          onSubmit={(event) => {
                            const data = form(event);
                            void action('Verifying AWS role', async () => {
                              await post(`${base}/connections/${connection.id}/verify`, {
                                roleArn: String(data.get('roleArn')),
                              });
                              setNotice('AWS role verified. You can now run a scan.');
                            });
                          }}
                        >
                          <label htmlFor="aws-role">AWS IAM role ARN</label>
                          <input
                            id="aws-role"
                            name="roleArn"
                            autoComplete="off"
                            spellCheck={false}
                            required
                            maxLength={560}
                            placeholder="arn:aws:iam::123456789012:role/CloudSentinelReadOnly…"
                          />
                          <Button variant="primary" disabled={!!busy || !approved}>
                            Verify and connect AWS account
                          </Button>
                        </form>
                      )}
                    </details>
                    <details className="disconnect">
                      <summary>Disconnect this account</summary>
                      <p>
                        This stops future CloudSentinel scans and keeps scan history. Remove the
                        role or its trust policy in AWS to revoke AWS access.
                      </p>
                      <Button
                        disabled={!!busy || !approved}
                        onClick={() =>
                          void action('Disconnecting AWS account', async () => {
                            await post(`${base}/connections/${connection.id}`, undefined, 'DELETE');
                            setNotice(
                              'Disconnected. Remove the IAM role or trust policy in AWS to revoke access.',
                            );
                          })
                        }
                      >
                        Confirm disconnect
                      </Button>
                    </details>
                  </>
                )}
              </div>
            )}
            {owner && (
              <details className="add-account" open={catalog.connections.length === 0}>
                <summary>Add an AWS account</summary>
                <p>
                  Choose the region to assess. Scans cover up to 50 security groups and 25 general
                  purpose S3 buckets in that region. Larger inventories are marked partial.
                </p>
                <form
                  className="cloud-form"
                  onSubmit={(event) => {
                    const data = form(event);
                    void action('Preparing AWS connection', async () => {
                      const result = await post<{ connection: Account }>(`${base}/connections`, {
                        name: String(data.get('name')),
                        region: String(data.get('region')),
                      });
                      setSelected(result.connection.id);
                      setNotice(
                        'Connection prepared. Create the AWS role using the generated policies.',
                      );
                    });
                  }}
                >
                  <label htmlFor="connection-name">Connection name</label>
                  <input
                    id="connection-name"
                    name="name"
                    autoComplete="off"
                    minLength={2}
                    maxLength={80}
                    placeholder="Production AWS…"
                    required
                  />
                  <label htmlFor="aws-region">AWS region</label>
                  <select id="aws-region" name="region" defaultValue="us-east-1">
                    {catalog.regions.map((region) => (
                      <option key={region}>{region}</option>
                    ))}
                  </select>
                  <Button
                    variant="primary"
                    disabled={
                      !!busy || !approved || !catalog.configured || catalog.connections.length >= 10
                    }
                  >
                    Generate IAM policies
                  </Button>
                </form>
                <p className="field-help">
                  Up to 10 connection records per organization, including disconnected records.
                  Owners must approve cloud actions first.
                </p>
              </details>
            )}
          </section>
          <section className="cloud-section" aria-labelledby="scan-results-heading">
            <h2 id="scan-results-heading">Scan history & findings</h2>
            <p className="muted">
              Latest 20 scan records, subject to the database response size. Failed checks need
              review; errors mean the check could not be completed. Up to 5 scans per organization
              per hour.
            </p>
            {scans.length === 0 ? (
              <p className="cloud-empty">
                No scans yet. Connect an AWS account and run its predefined scan.
              </p>
            ) : (
              <>
                <label htmlFor="scan-history">Scan run</label>
                <select
                  id="scan-history"
                  value={scan?.id ?? ''}
                  onChange={(e) => {
                    setScanId(e.target.value);
                    setPage(0);
                  }}
                >
                  {scans.map((s) => (
                    <option key={s.id} value={s.id}>
                      {date(s.startedAt)} · {s.connectionName} · {s.status}
                    </option>
                  ))}
                </select>
                {scan && (
                  <>
                    <p className="scan-summary">
                      {scan.accountId} · {scan.region} · <strong>{scan.status}</strong> ·{' '}
                      {scan.resources} resources inspected ·{' '}
                      {scan.checks.filter((c) => c.status === 'fail').length} findings
                    </p>
                    {scan.status === 'running' && (
                      <p role="status">
                        This scan is running or was interrupted. Refresh to check its status. You
                        can retry after the two-minute scan lock expires.
                      </p>
                    )}
                    {scan.status !== 'completed' && (
                      <p className="coverage-warning">
                        Coverage is incomplete. These results do not establish that the account is
                        secure.
                      </p>
                    )}
                    {scan.errors.length > 0 && (
                      <ul className="scan-errors">
                        {scan.errors.map((message, i) => (
                          <li key={i}>{message}</li>
                        ))}
                      </ul>
                    )}
                    <label htmlFor="finding-filter">Show check results</label>
                    <select
                      id="finding-filter"
                      value={filter}
                      onChange={(e) => {
                        setFilter(e.target.value);
                        setPage(0);
                      }}
                    >
                      <option value="fail">Findings</option>
                      <option value="error">Check errors</option>
                      <option value="pass">Passed checks</option>
                      <option value="all">All check results</option>
                    </select>
                    {checks.length === 0 && (
                      <p className="cloud-empty">
                        No {filter === 'fail' ? 'findings' : 'matching check results'} in this run.
                        {scan.status !== 'completed'
                          ? ' Review the coverage gaps before drawing conclusions.'
                          : ' Only the listed predefined checks were assessed.'}
                      </p>
                    )}
                    <div className="finding-list">
                      {checks.slice(page * 20, (page + 1) * 20).map((c) => (
                        <article className="finding-row" key={`${c.resource}:${c.ruleId}`}>
                          <div className="finding-heading">
                            <h3>{c.title}</h3>
                            <span className={`check-state check-${c.status}`}>
                              {c.status === 'fail'
                                ? `${c.severity} finding`
                                : c.status === 'error'
                                  ? 'Check error'
                                  : 'Passed'}
                            </span>
                          </div>
                          <p className="finding-resource" translate="no">
                            {c.resource} · {c.region}
                          </p>
                          <p>{c.evidence}</p>
                          <details>
                            <summary>Remediation & rule details</summary>
                            <p>{c.remediation}</p>
                            <p className="field-help" translate="no">
                              {c.ruleId}
                            </p>
                          </details>
                        </article>
                      ))}
                    </div>
                    {checks.length > 20 && (
                      <div className="cloud-pagination">
                        <Button disabled={page === 0} onClick={() => setPage((value) => value - 1)}>
                          Previous results
                        </Button>
                        <span>
                          Page {page + 1} of {Math.ceil(checks.length / 20)}
                        </span>
                        <Button
                          disabled={(page + 1) * 20 >= checks.length}
                          onClick={() => setPage((value) => value + 1)}
                        >
                          Next results
                        </Button>
                      </div>
                    )}
                  </>
                )}
              </>
            )}
            <details className="rule-catalog">
              <summary>Included predefined checks</summary>
              <ul>
                {catalog.rules.map((rule) => (
                  <li key={rule.id}>
                    <strong>{rule.title}</strong> · {rule.severity}
                    <br />
                    <code translate="no">{rule.id}</code>
                  </li>
                ))}
              </ul>
              <p>
                These configuration checks do not assess every AWS service, effective internet
                reachability, S3 ACLs, or overall compliance. CloudSentinel does not automatically
                remediate resources.
              </p>
            </details>
          </section>
        </>
      )}
    </div>
  );
}
