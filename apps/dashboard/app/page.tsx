'use client';
import { Button } from './button';
import { api, ApiError } from './api';
import { CloudPanel } from './cloud-panel';
import { useCallback, useEffect, useState, useRef, type FormEvent } from 'react';
import * as Tabs from '@radix-ui/react-tabs';
import {
  ShieldCheck,
  LayoutDashboard,
  KeyRound,
  LogOut,
  ArrowRight,
  Cloud,
  Activity,
  Check,
  RefreshCw,
  Monitor,
  Info,
  LockKeyhole,
} from 'lucide-react';

type Me = {
  user: { id: string; name: string; email: string };
  organization: { id: string; name: string };
  role: string;
  csrfToken: string;
  environment: string;
};
type Session = {
  id: string;
  createdAt: number;
  lastSeen: number;
  expiresAt: number;
  current: boolean;
};
type Audit = { id: string; action: string; createdAt: number; actorId: string };
type Overview = {
  assessment: string;
  assets: number | null;
  findings: number | null;
  criticalFindings: number | null;
  incidents: number | null;
};
function Brand() {
  return (
    <span className="brand" translate="no">
      <ShieldCheck aria-hidden="true" size={27} strokeWidth={1.8} />
      CloudSentinel
    </span>
  );
}
const number = new Intl.NumberFormat();
const date = (timestamp: number) =>
  new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(
    new Date(timestamp * 1000),
  );
const actionNames: Record<string, string> = {
  'identity.mfa_enabled': 'Authenticator enabled',
  'identity.reauthenticated': 'Cloud actions approved',
  'cloud.connection_created': 'AWS connection prepared',
  'cloud.connection_verified': 'AWS connection verified',
  'cloud.connection_disconnected': 'AWS connection disconnected',
  'cloud.scan_started': 'AWS scan started',
  'cloud.scan_completed': 'AWS scan completed',
  'cloud.scan_partial': 'AWS scan completed with gaps',
  'cloud.scan_failed': 'AWS scan failed',
  'identity.registered': 'Workspace created',
  'identity.login': 'Signed in',
  'identity.login_failed': 'Sign-in attempt failed',
  'identity.logout': 'Signed out',
  'identity.session_revoked': 'Session revoked',
};

export default function Home() {
  const [me, setMe] = useState<Me | null>(null),
    [ready, setReady] = useState(false),
    [error, setError] = useState('');
  const refreshIdentity = useCallback(async () => {
    try {
      setMe(await api<Me>('/auth/me'));
      setError('');
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) setMe(null);
      else setError(e instanceof Error ? e.message : 'Unable to connect.');
    } finally {
      setReady(true);
    }
  }, []);
  useEffect(() => {
    void refreshIdentity();
  }, [refreshIdentity]);
  if (!ready)
    return (
      <main className="loading" aria-live="polite">
        <Brand />
        <p>Opening your workspace…</p>
      </main>
    );
  if (!me) return <Auth onLogin={refreshIdentity} connectionError={error} />;
  return <Workspace me={me} onSignedOut={() => setMe(null)} />;
}
function Auth({
  onLogin,
  connectionError,
}: {
  onLogin: () => Promise<void>;
  connectionError: string;
}) {
  const [mode, setMode] = useState('login'),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(''),
    [message, setMessage] = useState('');
  const errorRef = useRef<HTMLParagraphElement>(null);
  useEffect(() => {
    if (error) errorRef.current?.focus();
  }, [error]);
  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    setError('');
    setMessage('');
    const data = new FormData(e.currentTarget);
    const input = {
      email: String(data.get('email')),
      password: String(data.get('password')),
      ...(mode === 'login' && data.get('code') ? { code: String(data.get('code')) } : {}),
    };
    try {
      if (mode === 'register') {
        const result = await api<{ message: string }>('/auth/register', {
          method: 'POST',
          body: JSON.stringify({
            ...input,
            name: data.get('name'),
            organization: data.get('organization'),
          }),
        });
        setMessage(result.message);
        setMode('login');
      } else {
        await api('/auth/login', { method: 'POST', body: JSON.stringify(input) });
        await onLogin();
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to continue. Try again.');
    } finally {
      setBusy(false);
    }
  }
  return (
    <main className="auth-shell">
      <section className="auth-intro">
        <Brand />
        <div className="intro-copy">
          <p className="intro-title">Cloud security workspace</p>
          <p>Assess AWS configurations and review access to your organization’s workspace.</p>
          <div className="trust-list">
            <p>
              <ShieldCheck aria-hidden="true" /> Access verified on every request
            </p>
            <p>
              <LockKeyhole aria-hidden="true" /> Access scoped to your organization
            </p>
            <p>
              <Activity aria-hidden="true" /> Audit history for identity and access
            </p>
          </div>
        </div>
      </section>
      <section className="auth-main">
        <div className="local-note">
          <span className="status-dot" /> Local development · Identity preview
        </div>
        <div className="auth-form-wrap">
          <h1>{mode === 'login' ? 'Sign in' : 'Create your workspace'}</h1>
          <p className="muted">
            {mode === 'login'
              ? 'Sign in to your organization’s security workspace.'
              : 'Start with an account and an organization.'}
          </p>
          <Tabs.Root
            value={mode}
            onValueChange={(value) => {
              setMode(value);
              setError('');
              setMessage('');
            }}
          >
            <Tabs.List className="auth-tabs" aria-label="Account access">
              <Tabs.Trigger value="login">Sign in</Tabs.Trigger>
              <Tabs.Trigger value="register">Register</Tabs.Trigger>
            </Tabs.List>
            <Tabs.Content value={mode}>
              <form onSubmit={submit}>
                {mode === 'register' && (
                  <>
                    <label htmlFor="name">Full name</label>
                    <input id="name" name="name" autoComplete="name" required maxLength={80} />
                    <label htmlFor="organization">Organization name</label>
                    <input
                      id="organization"
                      name="organization"
                      autoComplete="organization"
                      required
                      minLength={2}
                      maxLength={80}
                    />
                  </>
                )}
                <label htmlFor="email">Email address</label>
                <input
                  id="email"
                  name="email"
                  type="email"
                  autoComplete="username"
                  spellCheck={false}
                  autoCapitalize="none"
                  required
                  maxLength={254}
                  placeholder="you@company.com…"
                />
                <label htmlFor="password">Password</label>
                <input
                  id="password"
                  name="password"
                  type="password"
                  autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                  required
                  minLength={mode === 'register' ? 15 : 1}
                  maxLength={128}
                  aria-describedby={mode === 'register' ? 'password-hint' : undefined}
                />
                {mode === 'login' && (
                  <>
                    <label htmlFor="login-code">Authenticator code (if enabled)</label>
                    <input
                      id="login-code"
                      name="code"
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      pattern="[0-9]{6}"
                      maxLength={6}
                      spellCheck={false}
                    />
                  </>
                )}
                {mode === 'register' && (
                  <p id="password-hint" className="field-help">
                    Use 15–128 characters. A long, unique passphrase works well.
                  </p>
                )}
                {(error || connectionError) && (
                  <p ref={errorRef} tabIndex={-1} className="error" role="alert">
                    {error || connectionError}
                  </p>
                )}
                {message && (
                  <p className="success" role="status">
                    {message}
                  </p>
                )}
                <Button variant="primary" className="submit" disabled={busy} type="submit">
                  {busy
                    ? 'Please wait…'
                    : mode === 'login'
                      ? 'Sign in to workspace'
                      : 'Create workspace'}
                  <ArrowRight size={18} aria-hidden="true" />
                </Button>
              </form>
            </Tabs.Content>
          </Tabs.Root>
          <p className="auth-disclosure">
            <Info size={17} aria-hidden="true" />
            Development build: email verification and account recovery are not available yet. Use
            test credentials only.
          </p>
        </div>
      </section>
    </main>
  );
}
function Workspace({ me, onSignedOut }: { me: Me; onSignedOut: () => void }) {
  const [tab, setTab] = useState('overview'),
    [overview, setOverview] = useState<Overview | null>(null),
    [sessions, setSessions] = useState<Session[]>([]),
    [events, setEvents] = useState<Audit[]>([]),
    [error, setError] = useState(''),
    [busy, setBusy] = useState(false),
    [loading, setLoading] = useState(true),
    [notice, setNotice] = useState(''),
    [limited, setLimited] = useState(false);
  useEffect(() => {
    const sync = () => {
      const value = window.location.hash.slice(1);
      if (
        ['overview', 'cloud', 'sessions', 'activity'].includes(value) &&
        (value !== 'activity' || me.role === 'owner')
      )
        setTab(value);
    };
    sync();
    window.addEventListener('hashchange', sync);
    return () => window.removeEventListener('hashchange', sync);
  }, [me.role]);
  function changeTab(value: string) {
    setTab(value);
    window.history.replaceState(null, '', `#${value}`);
  }
  const handleError = useCallback(
    (e: unknown) => {
      if (e instanceof ApiError && e.status === 401) onSignedOut();
      else setError(e instanceof Error ? e.message : 'Unable to load your workspace.');
    },
    [onSignedOut],
  );
  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [summary, active, activity] = await Promise.all([
        api<Overview>(`/organizations/${me.organization.id}/overview`),
        api<{ sessions: Session[]; limited: boolean }>('/auth/sessions'),
        me.role === 'owner'
          ? api<{ events: Audit[] }>(`/organizations/${me.organization.id}/audit`)
          : Promise.resolve({ events: [] }),
      ]);
      setOverview(summary);
      setSessions(active.sessions);
      setLimited(active.limited);
      setEvents(activity.events);
    } catch (e) {
      handleError(e);
    } finally {
      setLoading(false);
    }
  }, [me.organization.id, me.role, handleError]);
  useEffect(() => {
    void load();
  }, [load]);
  async function mutate(path: string, method: string, logout = false) {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      await api(path, { method, headers: { 'x-csrf-token': me.csrfToken } });
      if (logout) onSignedOut();
      else {
        setNotice('Session revoked.');
        await load();
      }
    } catch (e) {
      handleError(e);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Tabs.Root value={tab} onValueChange={changeTab} className="workspace">
      <a className="skip-link" href="#workspace-content">
        Skip to content
      </a>
      <aside className="sidebar">
        <Brand />
        <div className="org-label">
          <span className="org-avatar">{me.organization.name.slice(0, 1).toUpperCase()}</span>
          <div>
            <strong>{me.organization.name}</strong>
            <span>Organization workspace</span>
          </div>
        </div>
        <Tabs.List className="nav" aria-label="Workspace sections">
          <Tabs.Trigger value="overview">
            <LayoutDashboard size={19} aria-hidden="true" />
            Overview
          </Tabs.Trigger>
          <Tabs.Trigger value="cloud">
            <Cloud size={19} aria-hidden="true" />
            Cloud accounts
          </Tabs.Trigger>
          <Tabs.Trigger value="sessions">
            <KeyRound size={19} aria-hidden="true" />
            Active sessions<span className="nav-count">{sessions.length}</span>
          </Tabs.Trigger>
          {me.role === 'owner' && (
            <Tabs.Trigger value="activity">
              <Activity size={19} aria-hidden="true" />
              Audit activity
            </Tabs.Trigger>
          )}
        </Tabs.List>
        <div className="sidebar-bottom">
          <div className="identity">
            <span className="user-avatar">{me.user.name.slice(0, 1).toUpperCase()}</span>
            <div>
              <strong>{me.user.name}</strong>
              <span>{me.role}</span>
            </div>
          </div>
          <button
            className="signout"
            disabled={busy}
            onClick={() => void mutate('/auth/logout', 'POST', true)}
          >
            <LogOut size={18} aria-hidden="true" />
            Sign out
          </button>
        </div>
      </aside>
      <div className="workspace-body">
        <header className="topbar">
          <span>
            Security workspace <span className="separator">/</span>{' '}
            {tab === 'overview'
              ? 'Overview'
              : tab === 'cloud'
                ? 'Cloud accounts & scans'
                : tab === 'sessions'
                  ? 'Active sessions'
                  : 'Audit activity'}
          </span>
          <span className="environment">
            <span className="status-dot" />
            {me.environment === 'local' ? 'Local development' : 'AWS environment'}
          </span>
        </header>
        <main id="workspace-content" className="main-content" tabIndex={-1}>
          <div className="page-heading">
            <div>
              <h1>
                {tab === 'overview'
                  ? 'Security overview'
                  : tab === 'cloud'
                    ? 'Cloud accounts & scans'
                    : tab === 'sessions'
                      ? 'Active sessions'
                      : 'Audit activity'}
              </h1>
              <p>
                {tab === 'overview'
                  ? 'Your organization’s security posture, at a glance.'
                  : tab === 'cloud'
                    ? 'Connect AWS accounts and assess their configuration.'
                    : tab === 'sessions'
                      ? 'Review and revoke access to your account.'
                      : 'Recent identity and access events for your organization.'}
              </p>
            </div>
            <Button
              aria-label={loading ? 'Refreshing workspace' : 'Refresh workspace'}
              onClick={() => void load()}
              disabled={loading || busy}
            >
              <RefreshCw size={16} aria-hidden="true" />
              {loading ? 'Refreshing…' : 'Refresh'}
            </Button>
          </div>
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
          {notice && (
            <p className="success" role="status">
              {notice}
            </p>
          )}
          <Tabs.Content value="overview">
            <div className="development-banner">
              <Info size={19} aria-hidden="true" />
              <p>
                <strong>Read-only AWS assessments</strong> · Scan connected accounts for five S3 and
                security group configuration checks. Coverage is limited to each connection’s
                selected region.
              </p>
            </div>
            <section className="posture-panel">
              <div className="posture-title">
                <h2>Cloud posture</h2>
                <span className="badge">
                  {overview?.assessment === 'assessed'
                    ? 'Assessed'
                    : overview?.assessment === 'partial'
                      ? 'Partial coverage'
                      : overview
                        ? 'Not assessed'
                        : loading
                          ? 'Loading…'
                          : 'Unavailable'}
                </span>
              </div>
              <dl className="metrics">
                {[
                  ['Cloud assets', overview?.assets],
                  ['Active findings', overview?.findings],
                  ['Critical findings', overview?.criticalFindings],
                  ['Open incidents', overview?.incidents],
                ].map(([label, value]) => (
                  <div key={String(label)}>
                    <dt>{label}</dt>
                    <dd>
                      {typeof value === 'number' ? (
                        number.format(value)
                      ) : (
                        <span aria-hidden="true">—</span>
                      )}
                      <p>{value == null ? 'Not available' : 'Latest regional scans'}</p>
                    </dd>
                  </div>
                ))}
              </dl>
              <div className="empty-cloud">
                <div className="cloud-icon">
                  <Cloud size={24} strokeWidth={1.8} aria-hidden="true" />
                </div>
                <div>
                  <h3>Assess your AWS configuration</h3>
                  <p>
                    Connect an AWS account to discover assets and assess your security posture.
                    Review evidence and remediation steps for each finding in Cloud accounts.
                  </p>
                </div>
                <Button onClick={() => changeTab('cloud')}>
                  Open cloud accounts
                  <ArrowRight size={16} aria-hidden="true" />
                </Button>
              </div>
            </section>
            <div className="overview-bottom">
              <section className="access-summary">
                <h2>Workspace access</h2>
                <p className="muted">Your current identity and security controls.</p>
                <dl>
                  <div>
                    <dt>Organization</dt>
                    <dd>{me.organization.name}</dd>
                  </div>
                  <div>
                    <dt>Your role</dt>
                    <dd className="capitalize">{me.role}</dd>
                  </div>
                  <div>
                    <dt>Session protection</dt>
                    <dd className="good">
                      <Check size={15} aria-hidden="true" />
                      Active
                    </dd>
                  </div>
                  <div>
                    <dt>Multi-factor authentication</dt>
                    <dd>Manage in Cloud accounts</dd>
                  </div>
                </dl>
                <button className="text-button" onClick={() => changeTab('sessions')}>
                  Manage your sessions
                  <ArrowRight size={16} aria-hidden="true" />
                </button>
              </section>
              <section className="recent-activity">
                <h2>Recent activity</h2>
                <p className="muted">
                  {me.role === 'owner'
                    ? 'Latest events in your organization.'
                    : 'Audit history is available to organization owners.'}
                </p>
                {me.role === 'owner' && (
                  <>
                    <EventList events={events.slice(0, 3)} loading={loading} />
                    <button className="text-button" onClick={() => changeTab('activity')}>
                      View audit activity
                      <ArrowRight size={16} aria-hidden="true" />
                    </button>
                  </>
                )}
              </section>
            </div>
          </Tabs.Content>
          <Tabs.Content value="cloud">
            <CloudPanel me={me} onChanged={load} onSignedOut={onSignedOut} />
          </Tabs.Content>
          <Tabs.Content value="sessions">
            <section className="session-panel">
              <div className="section-intro">
                <h2>Signed-in devices</h2>
                <p>
                  Sessions expire after 30 minutes of inactivity or 12 hours in total. Revoking a
                  session immediately blocks its next request.
                </p>
              </div>
              {limited && (
                <p role="status">
                  Showing up to 100 recent session records. Older sessions still expire
                  automatically.
                </p>
              )}
              {sessions.length === 0 && (
                <p>{loading ? 'Loading sessions…' : 'No active sessions found.'}</p>
              )}
              {sessions.map((s) => (
                <article key={s.id} className="session-row">
                  <Monitor size={24} aria-hidden="true" />
                  <div>
                    <h3>
                      {s.current ? 'This browser session' : 'Other browser session'}
                      {s.current && <span className="badge">Current</span>}
                    </h3>
                    <p>Signed in {date(s.createdAt)}</p>
                    <p>Last active {date(s.lastSeen)}</p>
                  </div>
                  <Button
                    className="revoke"
                    disabled={busy}
                    onClick={() => {
                      if (
                        s.current ||
                        window.confirm(
                          'Revoke this session? That browser will need to sign in again.',
                        )
                      )
                        void mutate(`/auth/sessions/${s.id}`, 'DELETE', s.current);
                    }}
                  >
                    {s.current ? 'Sign out' : 'Revoke session'}
                  </Button>
                </article>
              ))}
            </section>
          </Tabs.Content>
          {me.role === 'owner' && (
            <Tabs.Content value="activity">
              <section className="audit-panel">
                <h2>Identity event history</h2>
                <p className="muted">The latest 25 events. Times use your browser’s time zone.</p>
                <EventList events={events} loading={loading} />
              </section>
            </Tabs.Content>
          )}
          <footer className="workspace-footer">
            <span>
              <ShieldCheck size={14} aria-hidden="true" />
              Tenant-scoped access
            </span>
            <span>CloudSentinel · Development v0.1</span>
          </footer>
        </main>
      </div>
    </Tabs.Root>
  );
}
function EventList({ events, loading }: { events: Audit[]; loading: boolean }) {
  if (!events.length)
    return (
      <p className="muted" role="status">
        {loading ? 'Loading activity…' : 'No recent activity.'}
      </p>
    );
  return (
    <ol className="event-list">
      {events.map((e) => (
        <li key={e.id}>
          <span className="event-icon">
            <Activity size={15} aria-hidden="true" />
          </span>
          <div>
            <strong>{actionNames[e.action] ?? e.action}</strong>
            <time dateTime={new Date(e.createdAt * 1000).toISOString()}>{date(e.createdAt)}</time>
          </div>
        </li>
      ))}
    </ol>
  );
}
