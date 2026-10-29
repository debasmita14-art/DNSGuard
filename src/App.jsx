import React, { useEffect, useMemo, useState } from 'react';
import {
  Activity, AlertTriangle, ArrowUpRight, Bell, Check, CheckCircle2,
  ChevronDown, Clock3, Cpu, Download, ExternalLink, FileText,
  Fingerprint, Globe2, LayoutDashboard, LockKeyhole, Menu, Network,
  Radio, RefreshCw, Search, Server, Shield, ShieldAlert, ShieldCheck,
  Terminal, Wifi, X, Zap
} from 'lucide-react';
import {
  Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip,
  XAxis, YAxis
} from 'recharts';



const API = 'https://industries-hindu-barely-frequency.trycloudflare.com/api';


const TESTS = [
  {
    domain: 'secure.lab.test',
    label: 'Valid DNSSEC signatures',
    expected: 'NOERROR + AD',
    result: 'SECURE',
    detail: 'Expected: validated answer with the Authenticated Data (AD) flag.'
  },
  {
    domain: 'insecure.lab.test',
    label: 'Unsigned zone',
    expected: 'NOERROR, AD absent',
    result: 'INSECURE',
    detail: 'Expected: answer returned without AD; unsigned is not the same as bogus.'
  },
  {
    domain: 'www.bogus.lab.test',
    label: 'Broken DNSSEC chain',
    expected: 'SERVFAIL',
    result: 'BOGUS',
    detail: 'Expected: validating resolver rejects the invalid DNSSEC response.'
  }
];

const INITIAL = [
  {
    id: 1, domain: 'secure.lab.test', type: 'A',
    rcode: 'NOERROR', ad: true, result: 'SECURE',
    latency: null, time: 'Waiting for backend'
  },
  {
    id: 2, domain: 'insecure.lab.test', type: 'A',
    rcode: 'NOERROR', ad: false, result: 'INSECURE',
    latency: null, time: 'Waiting for backend'
  },
  {
    id: 3, domain: 'www.bogus.lab.test', type: 'A',
    rcode: 'SERVFAIL', ad: false, result: 'BOGUS',
    latency: null, time: 'Waiting for backend'
  }
];

const TRAFFIC = [
  ['09:00', 12], ['09:05', 18], ['09:10', 14],
  ['09:15', 27], ['09:20', 22], ['09:25', 34],
  ['09:30', 28], ['09:35', 41], ['09:40', 32],
  ['09:45', 46], ['09:50', 38], ['09:55', 51]
].map(([time, queries]) => ({ time, queries }));

function Pill({ children, kind = 'neutral' }) {
  return (
    <span className={`pill ${kind}`}>
      <i />
      {children}
    </span>
  );
}

function Metric({ icon: Icon, label, value, note, kind = 'teal' }) {
  return (
    <article className="metric">
      <div className="metric-top">
        <span className={`metric-icon ${kind}`}>
          <Icon size={18} />
        </span>
        <small>{note}</small>
      </div>
      <strong>{value}</strong>
      <span>{label}</span>
    </article>
  );
}

function Head({ eyebrow, title, subtitle, action }) {
  return (
    <div className="page-head">
      <div>
        <label>{eyebrow}</label>
        <h1>{title}</h1>
        <p>{subtitle}</p>
      </div>
      {action && <div className="head-actions">{action}</div>}
    </div>
  );
}

function mapQuery(item, index = 0) {
  return {
    id: `${item.domain}-${item.checkedAt || index}`,
    domain: item.domain,
    type: item.type || 'A',
    rcode: item.result || 'UNKNOWN',
    ad: Boolean(item.authenticated),
    result: item.status || 'UNKNOWN',
    latency: Number.isFinite(item.queryTimeMs)
      ? item.queryTimeMs
      : null,
    answer: item.answer || null,
    source: item.source || 'Unknown',
    checkedAt: item.checkedAt || null,
    time: item.checkedAt
      ? new Date(item.checkedAt).toLocaleTimeString()
      : 'Just checked'
  };
}

export default function App() {
  const [page, setPage] = useState('Overview');
  const [mobile, setMobile] = useState(false);
  const [notice, setNotice] = useState(true);
  const [queries, setQueries] = useState(INITIAL);
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState('ALL');
  const [domain, setDomain] = useState(TESTS[0].domain);
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState(null);
  const [refresh, setRefresh] = useState(0);
  const [apiStatus, setApiStatus] = useState('checking');
  const [resolverConnected, setResolverConnected] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [systemMetrics, setSystemMetrics] = useState(null);
  const [metricsError, setMetricsError] = useState('');
  const [auditLogs, setAuditLogs] = useState([]);
  const [logsLoading, setLogsLoading] = useState(false);
  const [logsError, setLogsError] = useState('');
  const selectedTest = TESTS.find(t => t.domain === domain);

  // Load live DNSSEC query results from the Express backend.
  useEffect(() => {
    let active = true;

    const loadBackend = async () => {
      try {
        const [healthResponse, queriesResponse] = await Promise.all([
          fetch(`${API}/health`),
          fetch(`${API}/queries`)
        ]);

        if (!healthResponse.ok || !queriesResponse.ok) {
          throw new Error('Backend API returned an error');
        }

        const health = await healthResponse.json();
        const payload = await queriesResponse.json();

        if (!active) return;

        if (!health.success || !payload.success) {
          throw new Error('Backend or resolver check failed');
        }

        setApiStatus('connected');
        setResolverConnected(Boolean(health.resolverConnected));

        if (Array.isArray(payload.data)) {
          const mapped = payload.data.map((item, index) =>
            mapQuery(item, index)
          );

          setQueries(mapped);
          setLastUpdated(new Date());
        }
      } catch (error) {
        if (active) {
          setApiStatus('offline');
          setResolverConnected(false);
        }
      }
    };

       loadBackend();

    const timer = setInterval(loadBackend, 5000);

    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [refresh]);
 
  
  // Refresh gateway and benchmark metrics from WSL.
  useEffect(() => {
    let active = true;

    const loadMetrics = async () => {
      try {
        const response = await fetch(`${API}/metrics`);

        if (!response.ok) {
          throw new Error('Metrics API unavailable');
        }

        const payload = await response.json();

        if (!payload.success) {
          throw new Error('Metrics request failed');
        }

        if (active) {
          setSystemMetrics(payload.data);
          setMetricsError('');
        }
      } catch (error) {
        if (active) {
          setMetricsError(error.message);
        }
      }
    };

    loadMetrics();
    const timer = setInterval(loadMetrics, 5000);

    return () => {
      active = false;
      clearInterval(timer);
    };
  }, []);

  const nav = [
    ['Overview', LayoutDashboard],
    ['DNSSEC Test Console', ShieldCheck],
    ['Query Explorer', Search],
    ['System Architecture', Network],
    ['Event Logs', Terminal]
  ];

  const filtered = useMemo(
    () =>
      queries.filter(
        q =>
          (filter === 'ALL' || q.result === filter) &&
          `${q.domain} ${q.rcode} ${q.result} ${q.answer || ''}`
            .toLowerCase()
            .includes(search.toLowerCase())
      ),
    [queries, filter, search]
  );
   
const fetchAuditLogs = async () => {
  setLogsLoading(true);
  setLogsError('');

  try {
    const response = await fetch(`${API}/logs`);
    const payload = await response.json();

    if (!response.ok || !payload.success) {
      throw new Error(payload.error || 'Failed to fetch audit logs.');
    }

    setAuditLogs(payload.data || []);
  } catch (error) {
    setLogsError(error.message || 'Could not load audit logs.');
  } finally {
    setLogsLoading(false);
  }
};
useEffect(() => {
  if (page === 'Event Logs') {
    fetchAuditLogs();
  }
}, [page]);
  const runTest = async () => {
    setTesting(true);
    setResult(null);

    const selectedTest = TESTS.find(t => t.domain === domain);

    try {
      console.log("DNSGuard test request:", `${API}/dnssec/test`, domain);
      const response = await fetch(`${API}/dnssec/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      });

      const payload = await response.json();

      if (!response.ok || !payload.success) {
        throw new Error(payload.error || 'Backend test failed');
      }

      const data = payload.data;
      const q = mapQuery(data, Date.now());

      setResult({
  ...selectedTest,
  ...q,
  result: data.status || 'UNKNOWN',
  ranAt: new Date().toLocaleTimeString(),
  apiMessage: payload.message || 'Backend response received.',
  mode: payload.mode || 'unknown',
  explanation: data.explanation || null,
  log: payload.log || null
});

      setQueries(previous =>
        [q, ...previous.filter(item => item.domain !== q.domain)].slice(0, 12)
      );

      setApiStatus('connected');
      setResolverConnected(true);
      setLastUpdated(new Date());
    } catch (error) {
      setResult({
        ...selectedTest,
        result: 'ERROR',
        ranAt: new Date().toLocaleTimeString(),
        apiMessage: error.message ||
          'Could not reach the backend. Check that node server.js is running on port 3001.',
        mode: 'offline'
      });

      setApiStatus('offline');
    } finally {
      setTesting(false);
    }
  };

  const exportCsv = () => {
    const rows = [
      [
        'Domain', 'Type', 'Response Code', 'AD Flag',
        'Classification', 'Latency ms', 'Answer', 'Source', 'Checked At'
      ],
      ...filtered.map(q => [
        q.domain,
        q.type,
        q.rcode,
        q.ad,
        q.result,
        q.latency ?? '',
        q.answer || '',
        q.source || '',
        q.checkedAt || ''
      ])
    ];

    const escapeCsv = value => {
      const text = String(value ?? '');
      return `"${text.replace(/"/g, '""')}"`;
    };

    const csv = rows.map(row => row.map(escapeCsv).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');

    a.href = url;
    a.download = 'dnsguard-query-log.csv';
    a.click();

    URL.revokeObjectURL(url);
  };

  const secureCount = queries.filter(q => q.result === 'SECURE').length;
  const insecureCount = queries.filter(q => q.result === 'INSECURE').length;
  const bogusCount = queries.filter(q => q.result === 'BOGUS').length;

  const latencies = queries
    .filter(q => q.latency != null)
    .map(q => q.latency);

  const averageLatency = latencies.length
    ? `${Math.round(
        latencies.reduce((sum, latency) => sum + latency, 0) /
        latencies.length
      )} ms`
    : '—';

  return (
    <div className="shell">
      <aside className={`sidebar ${mobile ? 'open' : ''}`}>
        <div className="brand">
          <div className="logo"><Shield size={23} /></div>
          <div>
            <b>DNS<span>GUARD</span></b>
            <small>IOT SECURITY CONSOLE</small>
          </div>
          <button
            className="mobile-close"
            onClick={() => setMobile(false)}
          >
            <X />
          </button>
        </div>

        <label className="side-label">WORKSPACE</label>
        <div className="workspace">
          <div>TC</div>
          <span>
            <b>Team TC200</b>
            <small>AIORI-3 · PS-004</small>
          </span>
          <ChevronDown size={15} />
        </div>

        <label className="side-label">MONITORING</label>
        <nav>
          {nav.map(([name, Icon]) => (
            <button
              key={name}
              className={page === name ? 'active' : ''}
              onClick={() => {
                setPage(name);
                setMobile(false);
              }}
            >
              <Icon size={18} />
              {name}
              {name === 'Event Logs' && <small>5</small>}
            </button>
          ))}
        </nav>

        <div className="side-bottom">
          <div className="gateway">
            <label>
              <i /> API STATUS
              <b>
                {apiStatus === 'connected'
                  ? 'CONNECTED'
                  : apiStatus === 'checking'
                    ? 'CHECKING'
                    : 'OFFLINE'}
              </b>
            </label>
            <strong>DNSGuard backend</strong>
            <p>
              <Server size={13} />
              {apiStatus === 'connected'
                ? resolverConnected
                  ? 'Backend and resolver reachable'
                  : 'Backend reachable; resolver pending'
                : apiStatus === 'checking'
                  ? 'Checking local backend API'
                  : 'Backend API unavailable'}
            </p>
            <div>
              <span>DoT · TCP/853</span>
            </div>
          </div>

          <div className="user">
            <div>TC</div>
            <span>
              <b>Team TC200</b>
              <small>Project workspace</small>
            </span>
          </div>
        </div>
      </aside>

      {mobile && (
        <button
          className="scrim"
          onClick={() => setMobile(false)}
          aria-label="Close navigation"
        />
      )}

      <main>
        <header className="topbar">
          <div className="crumb">
            <button className="menu" onClick={() => setMobile(true)}>
              <Menu />
            </button>
            Workspace <span>/</span> <b>{page}</b>
          </div>

          <div className="top-right">
            <span className="demo-tag">
              <i /> {apiStatus === 'connected' ? 'LIVE API DATA' : 'API OFFLINE'}
            </span>
            <button className="bell" onClick={() => setNotice(v => !v)}>
              <Bell size={18} />
            </button>
            <div className="avatar">TC</div>
 
        </div>
      </header>

      <div className="content">
        {page === 'Overview' && (
          <>
            <Head
              eyebrow="SECURITY OVERVIEW"
              title={<>DNS Security <em>Overview</em></>}
              subtitle="Gateway-assisted DNSSEC validation for resource-constrained IoT devices."
              action={

                  <>
                    <button
                      className="btn secondary"
                      onClick={() => setRefresh(x => x + 1)}
                    >
                      <RefreshCw size={15} /> Refresh live data
                    </button>
                    <button
                      className="btn primary"
                      onClick={() => setPage('DNSSEC Test Console')}
                    >
                      <Zap size={15} /> Run DNSSEC test
                    </button>
                  </>
                }
              />

              <div className="status">
                <div className="status-icon"><Radio size={18} /></div>
                <div>
                  <b>
                    {apiStatus === 'connected'
                      ? 'Backend API connected'
                      : apiStatus === 'checking'
                        ? 'Checking backend API'
                        : 'Backend API offline'}
                  </b>
                  <span>
                    {apiStatus === 'connected'
                      ? resolverConnected
                        ? 'Live resolver results received through Express and Unbound.'
                        : 'Express is reachable, but resolver connectivity has not been confirmed.'
                      : 'The dashboard could not retrieve live results from the backend.'}
                  </span>
                </div>
                <Pill kind={apiStatus === 'connected' ? 'teal' : 'warning'}>
                  {apiStatus === 'connected' ? 'API CONNECTED' : 'API UNAVAILABLE'}
                </Pill>
                <small>
                  {resolverConnected ? 'Resolver connected' : 'Resolver pending'}
                </small>
              </div>

              <div className="metrics">
                <Metric
                  icon={Activity}
                  label="Loaded DNS queries"
                  value={queries.length}
                  note="API records"
                  kind="teal"
                />
                <Metric
                  icon={ShieldCheck}
                  label="Secure responses"
                  value={secureCount}
                  note="AD authenticated"
                  kind="green"
                />
                <Metric
                  icon={ShieldAlert}
                  label="Bogus responses"
                  value={bogusCount}
                  note="SERVFAIL expected"
                  kind="red"
                />
                <Metric
                  icon={Clock3}
                  label="Average query time"
                  value={averageLatency}
                  note="Measured latency"
                  kind="purple"
                />
              </div>

              <section className="panel" style={{ marginBottom: 20 }}>
                <div className="panel-head">
                  <div>
                    <h3>Gateway &amp; Benchmark Metrics</h3>
                    <p>Metrics received from the WSL monitoring API</p>
                  </div>
                  <Pill kind={systemMetrics?.gateway?.running ? 'teal' : 'warning'}>
                    {metricsError
                      ? 'METRICS UNAVAILABLE'
                      : systemMetrics
                        ? systemMetrics.gateway?.running
                          ? 'GATEWAY RUNNING'
                          : 'GATEWAY STOPPED'
                        : 'LOADING METRICS'}
                  </Pill>
                </div>

                {systemMetrics ? (
                  <>
                    <div className="metrics">
                      <Metric
                        icon={Cpu}
                        label="Gateway CPU"
                        value={systemMetrics.process?.available
                          ? `${Number(systemMetrics.process.cpu_percent).toFixed(1)}%`
                          : 'N/A'}
                        note="Unbound process"
                        kind="purple"
                      />
                      <Metric
                        icon={Activity}
                        label="Gateway memory"
                        value={systemMetrics.process?.available
                          ? `${Number(systemMetrics.process.memory_mb).toFixed(1)} MB`
                          : 'N/A'}
                        note="Process memory"
                        kind="teal"
                      />
                      <Metric
                        icon={Network}
                        label="Gateway port"
                        value={systemMetrics.gateway?.port ?? 'N/A'}
                        note={`PID ${systemMetrics.gateway?.pid ?? 'N/A'}`}
                        kind="green"
                      />
                      <Metric
                        icon={Clock3}
                        label="Metrics updated"
                        value={systemMetrics.updated_at
                          ? new Date(systemMetrics.updated_at).toLocaleTimeString()
                          : 'N/A'}
                        note="Latest API snapshot"
                        kind="purple"
                      />
                    </div>

                    <div className="table-scroll">
                      <table>
                        <thead>
                          <tr>
                            <th>DNS test</th>
                            <th>Runs</th>
                            <th>Successful</th>
                            <th>SERVFAIL</th>
                            <th>Average latency</th>
                          </tr>
                        </thead>
                        <tbody>
                          {Object.entries(systemMetrics.benchmarks || {}).map(
                            ([name, benchmark]) => (
                              <tr key={name}>
                                <td>{name}</td>
                                <td>{benchmark.runs ?? '—'}</td>
                                <td>{benchmark.success ?? '—'}</td>
                                <td>{benchmark.servfail ?? '—'}</td>
                                <td>
                                  {benchmark.average_latency_ms != null
                                    ? `${benchmark.average_latency_ms} ms`
                                    : '—'}
                                </td>
                              </tr>
                            )
                          )}
                        </tbody>
                      </table>
                    </div>
                  </>
                ) : (
                  <p>
                    {metricsError || 'Waiting for the WSL metrics API…'}
                  </p>
                )}
              </section>

      
              <div className="grid chart-grid">
                <section className="panel">
                  <div className="panel-head">
                    <div>
                      <h3>DNS query activity</h3>
                      <p>Illustrative query volume · not live telemetry</p>
                    </div>
                    <span className="legend"><i /> Sample queries</span>
                  </div>
                  <div className="chart-summary">
                    <strong>{TRAFFIC.reduce((max, item) => Math.max(max, item.queries), 0)}</strong>
                    <span>peak sample queries</span>
                    <small>ILLUSTRATIVE SERIES</small>
                  </div>
                  <div className="chart">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart
                        data={TRAFFIC}
                        margin={{ top: 8, right: 5, left: -18, bottom: 0 }}
                      >
                        <defs>
                          <linearGradient id="fill" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor="#2bdfba" stopOpacity={0.24} />
                            <stop offset="100%" stopColor="#2bdfba" stopOpacity={0} />
                          </linearGradient>
                        </defs>
                        <CartesianGrid stroke="#20332d" strokeDasharray="3 5" vertical={false} />
                        <XAxis
                          dataKey="time"
                          tick={{ fill: '#738a80', fontSize: 10 }}
                          axisLine={false}
                          tickLine={false}
                          interval={2}
                        />
                        <YAxis
                          tick={{ fill: '#738a80', fontSize: 10 }}
                          axisLine={false}
                          tickLine={false}
                        />
                        <Tooltip
                          contentStyle={{
                            background: '#10201b',
                            border: '1px solid #29433a',
                            borderRadius: 8,
                            color: '#e4f3ed',
                            fontSize: 12
                          }}
                        />
                        <Area
                          type="monotone"
                          dataKey="queries"
                          stroke="#2bdfba"
                          strokeWidth={2.5}
                          fill="url(#fill)"
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="chart-foot">
                    <span><i /> Sample query volume</span>
                    <span>Not live telemetry</span>
                  </div>
                </section>

                <section className="panel validation">
                  <div className="panel-head">
                    <div>
                      <h3>DNSSEC validation</h3>
                      <p>Current API query distribution</p>
                    </div>
                    <Pill>API DATA</Pill>
                  </div>
                  <div className="donut-wrap">
                    <div className="donut">
                      <div>
                        <strong>{queries.length}</strong>
                        <span>loaded queries</span>
                      </div>
                    </div>
                  </div>
                  <div className="legend-list">
                    <div>
                      <i className="g" />SECURE
                      <b>{secureCount}</b>
                      <small>
                        {queries.length
                          ? `${(secureCount / queries.length * 100).toFixed(1)}%`
                          : '—'}
                      </small>
                    </div>
                    <div>
                      <i className="a" />INSECURE
                      <b>{insecureCount}</b>
                      <small>
                        {queries.length
                          ? `${(insecureCount / queries.length * 100).toFixed(1)}%`
                          : '—'}
                      </small>
                    </div>
                    <div>
                      <i className="r" />BOGUS
                      <b>{bogusCount}</b>
                      <small>
                        {queries.length
                          ? `${(bogusCount / queries.length * 100).toFixed(1)}%`
                          : '—'}
                      </small>
                    </div>
                  </div>
                  <div className="validation-foot">
                    <ShieldCheck size={15} />
                    Classification from resolver API responses.
                  </div>
                </section>
              </div>

              <section className="panel recent">
                <div className="panel-head">
                  <div>
                    <h3>Recent DNS queries</h3>
                    <p>Records returned by the DNSGuard backend</p>
                  </div>
                  <button className="text-btn" onClick={() => setPage('Query Explorer')}>
                    View all <ExternalLink size={13} />
                  </button>
                </div>
                <QueryTable rows={queries.slice(0, 4)} />
                <div className="table-foot">
                  <span>Showing {Math.min(4, queries.length)} of {queries.length} API records</span>
                  <button className="text-btn" onClick={() => setPage('Query Explorer')}>
                    Open query explorer <ArrowUpRight size={14} />
                  </button>
                </div>
              </section>

              <div className="grid lower">
                <section className="panel">
                  <div className="panel-head">
                    <div>
                      <h3>Request path</h3>
                      <p>Intended gateway-assisted architecture</p>
                    </div>
                    <Pill kind="warning">Not verified</Pill>
                  </div>
                  <div className="flow">
                    <div>
                      <span className="node blue"><Cpu /></span>
                      <b>ESP8266</b>
                      <small>DNS client</small>
                    </div>
                    <i><small>DoT · 853</small><span /></i>
                    <div>
                      <span className="node teal"><LockKeyhole /></span>
                      <b>Gateway</b>
                      <small>Unbound</small>
                    </div>
                    <i><small>Recursive</small><span /></i>
                    <div>
                      <span className="node purple"><Server /></span>
                      <b>NSD zones</b>
                      <small>Test authority</small>
                    </div>
                  </div>
                  <div className="flow-foot">
                    <LockKeyhole size={14} />
                    TLS protects transport; Unbound performs DNSSEC validation.
                  </div>
                </section>

                <section className="panel">
                  <div className="panel-head">
                    <div>
                      <h3>Test zone status</h3>
                      <p>Controlled DNSSEC test scenarios</p>
                    </div>
                  </div>
                  {TESTS.map(t => (
                    <button
                      className="zone-row"
                      key={t.domain}
                      onClick={() => {
                        setDomain(t.domain);
                        setPage('DNSSEC Test Console');
                      }}
                    >
                      <span className={`zone-icon ${t.result.toLowerCase()}`}>
                        {t.result === 'SECURE'
                          ? <ShieldCheck />
                          : t.result === 'BOGUS'
                            ? <ShieldAlert />
                            : <Shield />}
                      </span>
                      <span>
                        <b>{t.domain}</b>
                        <small>{t.expected}</small>
                      </span>
                      <Pill kind={t.result.toLowerCase()}>{t.result}</Pill>
                      <ArrowUpRight size={14} />
                    </button>
                  ))}
                </section>
              </div>
            </>
          )}

          {page === 'DNSSEC Test Console' && (
            <>
              <Head
                eyebrow="VALIDATION WORKBENCH"
                title={<>DNSSEC <em>Test Console</em></>}
                subtitle="Run real resolver checks against controlled DNSSEC test zones."
              />

              <div className="notice">
                <AlertTriangle />
                <div>
                  <b>Live resolver test through Express</b>
                  <p>
                    This console sends the selected domain to your local Express
                    API, which runs a DNS query through Unbound. This verifies the
                    backend-to-resolver path, not the ESP8266 DNS-over-TLS path.
                  </p>
                </div>
              </div>

              <div className="grid test-grid">
                <section className="panel test-form">
                  <div className="panel-head">
                    <div>
                      <h3>Configure test</h3>
                      <p>Select a DNSSEC scenario</p>
                    </div>
                    <small>STEP 01</small>
                  </div>

                  

<label className="field-label" htmlFor="domain">
  TEST DOMAIN
</label>

<div className="select">
  <Globe2 size={16} />

  <input
    id="domain"
    type="text"
    value={domain}
    onChange={e => setDomain(e.target.value)}
    onKeyDown={e => {
      if (e.key === 'Enter' && !testing) runTest();
    }}
    placeholder="Enter a domain, e.g. iem.edu.in"
    autoComplete="off"
    spellCheck={false}
    aria-label="Domain name to test"
  />
</div>

<div className="preset-domains">
  <small>QUICK TESTS</small>
  {TESTS.map(t => (
    <button
      type="button"
      key={t.domain}
      className={domain === t.domain ? 'selected' : ''}
      onClick={() => {
        setDomain(t.domain);
        setResult(null);
      }}
    >
      {t.domain}
    </button>
  ))}

</div>

<div className="scenario">
  <div
    className={`scenario-icon ${
      selectedTest
        ? selectedTest.result.toLowerCase()
        : 'neutral'
    }`}
  >

  >
    {selectedTest?.result === 'BOGUS'
      ? <ShieldAlert />
      : selectedTest?.result === 'SECURE'
        ? <ShieldCheck />
        : <Shield />}
  </div>

  <div>
    <small>TEST TYPE</small>
    <h4>
      {selectedTest
        ? selectedTest.label
        : 'Custom domain validation'}
    </h4>
    <p>
      {selectedTest
        ? selectedTest.detail
        : 'Query the live resolver and inspect its response code, AD flag, answer, and classification.'}
    </p>
  </div>
</div>                 
<div className="expected">
  <small>
    {selectedTest ? 'EXPECTED RESPONSE' : 'LIVE RESULT'}
  </small>
  <b>
    {selectedTest
      ? selectedTest.expected
      : 'Determined by the resolver'}
  </b>

  <span>
    {selectedTest
      ? 'Expected classification:'
      : 'Classification:'}{' '}
    <strong>
      {selectedTest
        ? selectedTest.result
        : result?.domain === domain
          ? result.result
          : 'Pending test'}
    </strong>
  </span>
</div>

                  <button
                    className="btn primary run"
                    disabled={testing}
                    onClick={runTest}
                  >
                    {testing
                      ? <RefreshCw className="spin" />
                      : <Zap size={16} />}
                    {testing ? 'Querying Unbound...' : 'Run live DNSSEC test'}
                  </button>

                  <p className="muted center">
                    <LockKeyhole size={13} />
                    Sends a request to the local Express backend.
                  </p>
                </section>

                <section className="panel result-panel">
                  <div className="panel-head">
                    <div>
                      <h3>Test result</h3>
                      <p>Resolver response</p>
                    </div>
                    <small>STEP 02</small>
                  </div>

                  {!result ? (
                    <div className="empty">
                      <div><Terminal size={28} /></div>
                      <h3>Ready to test</h3>
                      <p>
                        Choose a scenario and run a live resolver query to inspect
                        the returned DNSSEC classification.
                      </p>
                      <small>● Waiting for user action</small>
                    </div>
                  ) : (
                    <div className="result">
                      <div className={`result-hero ${result.result.toLowerCase()}`}>
                        <div>
                          {result.result === 'SECURE'
                            ? <ShieldCheck />
                            : result.result === 'BOGUS'
                              ? <ShieldAlert />
                              : result.result === 'ERROR'
                                ? <AlertTriangle />
                                : <Shield />}
                        </div>
                        <span>
                          <small>
                            {result.mode === 'offline'
                              ? 'BACKEND ERROR'
                              : 'LIVE API RESULT'}
                          </small>
                          <strong>{result.result}</strong>
                         <p>
  {result.result === 'SECURE'
    ? 'Resolver returned a validated answer.'
    : result.result === 'BOGUS'
      ? 'Resolver rejected the invalid DNSSEC response.'
      : result.result === 'INSECURE'
        ? 'The resolver did not mark this response as DNSSEC-authenticated (AD absent).'
        : 'The request did not complete successfully.'}
</p>
                        </span>
                        <Pill kind={result.mode === 'offline' ? 'warning' : 'teal'}>
                          {result.mode === 'offline' ? 'Offline' : 'API response'}
                        </Pill>
                      </div>

                      
{result.explanation && (
  <div className="notice">
    <ShieldCheck />
    <div>
      <b>{result.explanation.title}</b>
      <p>{result.explanation.explanation}</p>

      {Array.isArray(result.explanation.evidence) &&
        result.explanation.evidence.length > 0 && (
          <ul>
            {result.explanation.evidence.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        )}

      {result.log && (
        <small>
          Saved to audit log: {result.log.eventType} ·{" "}
          {new Date(result.log.timestamp).toLocaleString()}
        </small>
      )}
    </div>
  </div>
)}

                      <div className="warning-line">
                        {result.mode === 'offline'
                          ? <AlertTriangle size={15} />
                          : <CheckCircle2 size={15} />}
                        {result.apiMessage}
                      </div>
                    </div>
                  )}
                </section>
              </div>

              <section className="panel matrix">
                <div className="panel-head">
                  <div>
                    <h3>Test matrix</h3>
                    <p>Project scenarios and expected resolver behavior</p>
                  </div>
                </div>
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>SCENARIO</th>
                        <th>TEST DOMAIN</th>
                        <th>EXPECTED RCODE</th>
                        <th>AD FLAG</th>
                        <th>CLASSIFICATION</th>
                      </tr>
                    </thead>
                    <tbody>
                      {TESTS.map(t => (
                        <tr key={t.domain}>
                          <td>{t.label}</td>
                          <td><code>{t.domain}</code></td>
                          <td>{t.result === 'BOGUS' ? 'SERVFAIL' : 'NOERROR'}</td>
                          <td>{t.result === 'SECURE' ? 'Present' : 'Absent'}</td>
                          <td><Pill kind={t.result.toLowerCase()}>{t.result}</Pill></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            </>
          )}

          {page === 'Query Explorer' && (
            <>
              <Head
                eyebrow="QUERY INSPECTION"
                title={<>Query <em>Explorer</em></>}
                subtitle="Inspect DNS answers and DNSSEC classification details returned by the API."
                action={
                  <button className="btn secondary" onClick={exportCsv}>
                    <Download size={15} /> Export CSV
                  </button>
                }
              />

              <div className="metrics compact">
                <Metric
                  icon={Search}
                  label="Displayed records"
                  value={filtered.length}
                  note="Filtered API records"
                />
                <Metric
                  icon={ShieldCheck}
                  label="Secure records"
                  value={filtered.filter(q => q.result === 'SECURE').length}
                  note="AD present"
                  kind="green"
                />
                <Metric
                  icon={AlertTriangle}
                  label="Bogus records"
                  value={filtered.filter(q => q.result === 'BOGUS').length}
                  note="SERVFAIL"
                  kind="red"
                />
                <Metric
                  icon={Clock3}
                  label="Mean query latency"
                  value={
                    filtered.some(q => q.latency != null)
                      ? `${Math.round(
                          filtered
                            .filter(q => q.latency != null)
                            .reduce((sum, q) => sum + q.latency, 0) /
                          filtered.filter(q => q.latency != null).length
                        )} ms`
                      : '—'
                  }
                  note="Measured API latency"
                  kind="purple"
                />
              </div>

              <section className="panel explorer">
                <div className="toolbar">
                  <div className="search">
                    <Search size={16} />
                    <input
                      value={search}
                      onChange={e => setSearch(e.target.value)}
                      placeholder="Search domain, response code..."
                    />
                    <button onClick={() => setSearch('')}>
                      <X size={14} />
                    </button>
                  </div>
                  <div className="filters">
                    {['ALL', 'SECURE', 'INSECURE', 'BOGUS'].map(f => (
                      <button
                        className={filter === f ? 'selected' : ''}
                        onClick={() => setFilter(f)}
                        key={f}
                      >
                        {f}
                      </button>
                    ))}
                  </div>
                </div>

                <QueryTable rows={filtered} full />

                <div className="table-foot">
                  <span>Showing {filtered.length} matching API records</span>
                  <span>Results loaded from the backend</span>
                </div>
              </section>

              <div className="notice">
                <ShieldCheck />
                <div>
                  <b>About the AD flag</b>
                  <p>
                    The Authenticated Data (AD) flag indicates that the validating
                    resolver considers the answer authenticated. In this dashboard,
                    the displayed values come from the resolver API responses.
                  </p>
                </div>
              </div>
            </>
          )}

          {page === 'System Architecture' && (
            <>
              <Head
                eyebrow="SYSTEM DESIGN"
                title={<>System <em>Architecture</em></>}
                subtitle="Reference flow for the gateway-assisted DNSSEC project."
                action={<Pill kind="warning">Integration pending</Pill>}
              />

              <div className="notice">
                <Network />
                <div>
                  <b>Architecture view, not live network discovery</b>
                  <p>
                    This diagram represents the intended design. Backend-to-Unbound
                    testing is separate from verification of the ESP8266 DoT connection.
                  </p>
                </div>
              </div>

              <section className="panel architecture">
                <div className="panel-head">
                  <div>
                    <h3>Resolution and validation path</h3>
                    <p>Conceptual system flow · PS-004</p>
                  </div>
                  <Pill>REFERENCE</Pill>
                </div>

                <div className="architecture-flow">
                  {[
                    {
                      n: '01',
                      name: 'ESP8266 client',
                      icon: Cpu,
                      desc: 'Builds DNS queries and requests resolution over DNS-over-TLS.'
                    },
                    {
                      n: '02',
                      name: 'TLS transport',
                      icon: LockKeyhole,
                      desc: 'DoT uses TLS over TCP port 853 to protect client-to-gateway DNS transport.'
                    },
                    {
                      n: '03',
                      name: 'Unbound resolver',
                      icon: Server,
                      desc: 'Performs recursive DNS resolution and DNSSEC validation.'
                    },
                    {
                      n: '04',
                      name: 'NSD test zones',
                      icon: Globe2,
                      desc: 'Hosts controlled SECURE, INSECURE, and BOGUS zones; NSD is authoritative, not the gateway.'
                    }
                  ].map((s, i) => (
                    <React.Fragment key={s.n}>
                      <article>
                        <div className={`arch-icon c${i}`}><s.icon size={25} /></div>
                        <small>COMPONENT {s.n}</small>
                        <h3>{s.name}</h3>
                        <p>{s.desc}</p>
                      </article>
                      {i < 3 && (
                        <div className="arrow">
                          <small>
                            {['DNS over TLS · 853', 'Recursive query', 'DNSSEC validation'][i]}
                          </small>
                          <b>→</b>
                        </div>
                      )}
                    </React.Fragment>
                  ))}
                </div>

             <div>
                <span>DoT · TCP/853</span>
             </div>
              </section>

              <div className="grid lower">
                <section className="panel text-panel">
                  <div className="panel-head">
                    <div>
                      <h3>Security boundaries</h3>
                      <p>Layer responsibilities</p>
                    </div>
                    <Fingerprint />
                  </div>
                  <div className="bullet">
                    <LockKeyhole />
                    <span>
                      <b>Transport confidentiality</b>
                      <small>
                        TLS protects DNS traffic in transit between the client and gateway.
                      </small>
                    </span>
                  </div>
                  <div className="bullet">
                    <Fingerprint />
                    <span>
                      <b>Gateway authentication</b>
                      <small>
                        Public-key pinning and HMAC challenge-response are design
                        elements; runtime success is not asserted.
                      </small>
                    </span>
                  </div>
                  <div className="bullet">
                    <ShieldCheck />
                    <span>
                      <b>DNSSEC validation</b>
                      <small>
                        Unbound distinguishes secure, insecure, and bogus responses.
                      </small>
                    </span>
                  </div>
                </section>

                <section className="panel text-panel">
                  <div className="panel-head">
                    <div>
                      <h3>Integration checklist</h3>
                      <p>Remaining verification steps</p>
                    </div>
                  </div>
                  {[
                    'Backend health and query endpoints are reachable.',
                    'Actual resolver results are returned through the backend.',
                    'Dashboard query rows display API response fields.',
                    'Verify ESP8266-to-gateway DNS-over-TLS on TCP port 853.'
                  ].map(t => (
                    <div className="check-row" key={t}><i />{t}</div>
                  ))}
                </section>
              </div>
            </>
          )}

          {page === 'Event Logs' && (
            <>
              <Head
                eyebrow="AUDIT TRAIL"
                title={<>Event <em>Logs</em></>}
                subtitle="Local UI events and recent resolver query outcomes."
                action={<Pill kind="warning">Partial logging</Pill>}
              />

              <div className="notice">
                <AlertTriangle />
                <div>
                  <b>These are not device logs</b>
                  <p>
                    The events below are generated by the dashboard and recent API
                    responses. They are not retrieved from the ESP8266 or system journal.
                  </p>
                </div>
              </div>

              <section className="panel logs">
                <div className="panel-head">
                  <div>
                    <h3>Event timeline</h3>
                    <p>Dashboard session and API query records</p>
                  </div>
                  <Pill>LOCAL VIEW</Pill>
                </div>

                
{logsLoading ? (
  <p>Loading audit logs...</p>
) : logsError ? (
  <p className="warning-line">{logsError}</p>
) : auditLogs.length === 0 ? (
  <p>No saved audit logs yet. Run a DNSSEC test to create one.</p>
) : (
  auditLogs.map((e, i) => (
    <div
      className="event"
      key={`${e.timestamp}-${e.domain}-${i}`}
    >
      <div className={e.status === 'BOGUS' ? 'warn' : ''}>
        {e.status === 'BOGUS' ? <AlertTriangle /> : <FileText />}
      </div>

      <span>
        <b>{e.eventType || 'DNSSEC test'} · {e.domain}</b>
        <p>
          Status: {e.status || 'UNKNOWN'}; response: {e.responseCode || 'N/A'};
          {' '}AD flag: {e.authenticated ? 'present' : 'absent'};
          {' '}answer: {e.answer || 'none'}.
        </p>
        {e.explanation && <p>{e.explanation}</p>}
        <small>
          <Clock3 size={12} />{' '}
          {e.timestamp
            ? new Date(e.timestamp).toLocaleString()
            : 'Time unavailable'}
        </small>
      </span>

      <Pill kind={e.status === 'BOGUS' ? 'warning' : 'teal'}>
        {e.status || 'UNKNOWN'}
      </Pill>
    </div>
  ))
)}
</section>
</>

          )}

          <footer>
            <span>DNSGuard <b>v0.1.0</b> · AIORI-3 / PS-004</span>
            <span>
              <i /> {apiStatus === 'connected'
                ? 'Backend connected · ESP8266 DoT pending'
                : 'Backend offline · check local API'}
            </span>
          </footer>
        </div>
      </main>
    </div>
  );
}

function QueryTable({ rows, full = false }) {
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>DOMAIN</th>
            {full && <th>TYPE</th>}
            <th>RESPONSE</th>
            <th>AD FLAG</th>
            <th>CLASSIFICATION</th>
            <th>LATENCY</th>
            <th>TIME</th>
          </tr>
        </thead>

        <tbody>
          {rows.map(q => (
            <tr key={q.id}>
              <td>
                <span className="domain">
                  <Globe2 size={14} />
                  <b>{q.domain}</b>
                </span>
              </td>

              {full && <td><code>{q.type}</code></td>}

              <td>
                <code className={q.rcode === 'SERVFAIL' ? 'fail' : ''}>
                  {q.rcode}
                </code>
              </td>

              <td>
                <span className={`ad ${q.ad ? 'yes' : 'no'}`}>
                  {q.ad ? <Check size={12} /> : <X size={12} />}
                  {q.ad ? 'Present' : 'Absent'}
                </span>
              </td>

              <td>
                <Pill kind={String(q.result).toLowerCase()}>
                  {q.result}
                </Pill>
              </td>

              <td>{q.latency == null ? '—' : `${q.latency} ms`}</td>
              <td className="time">{q.time}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {!rows.length && (
        <div className="no-results">No records match these filters.</div>
      )}
    </div>
  );
}