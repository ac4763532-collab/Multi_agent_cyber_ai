import React from 'react';
import {
  Activity,
  Database,
  Cpu,
  HardDrive,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Clock,
  Server,
  RefreshCw,
} from 'lucide-react';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { useHealth } from '../hooks/useHealth';
import { formatTimestamp, formatUptime } from '../utils/formatters';

export const HealthPage: React.FC = () => {
  const { health, loading, error, lastUpdated, refetch } = useHealth(5000);

  const getStatusIcon = (status?: string) => {
    switch (status) {
      case 'healthy':
        return <CheckCircle2 size={18} style={{ color: 'var(--accent-emerald)' }} />;
      case 'degraded':
        return <AlertTriangle size={18} style={{ color: 'var(--accent-amber)' }} />;
      default:
        return <XCircle size={18} style={{ color: 'var(--accent-rose)' }} />;
    }
  };

  const getSubsystemIcon = (name: string) => {
    switch (name) {
      case 'database':
        return <Database size={20} />;
      case 'event_broker':
        return <HardDrive size={20} />;
      case 'gemini_ai':
        return <Cpu size={20} />;
      default:
        return <Server size={20} />;
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Banner */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          borderBottom: '1px solid var(--border-color)',
          paddingBottom: '16px',
        }}
      >
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, letterSpacing: '-0.02em' }}>
            System Health & Core Subsystems
          </h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', marginTop: '4px' }}>
            Live status verified against <code className="font-mono" style={{ color: 'var(--accent-cyan)' }}>GET /api/health</code>
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <Badge
            variant={
              health?.status === 'healthy'
                ? 'healthy'
                : health?.status === 'degraded'
                ? 'degraded'
                : 'unhealthy'
            }
          >
            {health?.status || (loading ? 'CHECKING...' : 'ERROR')}
          </Badge>
          <Button
            size="sm"
            variant="outline"
            icon={<RefreshCw size={14} className={loading ? 'animate-spin' : ''} />}
            onClick={() => refetch()}
          >
            Refresh Status
          </Button>
        </div>
      </div>

      {error && (
        <div
          style={{
            padding: '16px',
            borderRadius: '8px',
            background: 'rgba(244, 63, 94, 0.1)',
            border: '1px solid rgba(244, 63, 94, 0.3)',
            color: '#fb7185',
            fontSize: '0.875rem',
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
          }}
        >
          <XCircle size={20} />
          <div>
            <strong>Backend Unreachable:</strong> {error}. Ensure the FastAPI server is running on port 8000.
          </div>
        </div>
      )}

      {/* Metrics Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px' }}>
        <Card>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{ padding: '10px', borderRadius: '8px', background: 'rgba(56, 189, 248, 0.1)', color: 'var(--accent-cyan)' }}>
              <Activity size={22} />
            </div>
            <div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                Overall Status
              </div>
              <div style={{ fontSize: '1.25rem', fontWeight: 700, textTransform: 'capitalize' }}>
                {health?.status || 'Unknown'}
              </div>
            </div>
          </div>
        </Card>

        <Card>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{ padding: '10px', borderRadius: '8px', background: 'rgba(16, 185, 129, 0.1)', color: 'var(--accent-emerald)' }}>
              <Clock size={22} />
            </div>
            <div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                Process Uptime
              </div>
              <div style={{ fontSize: '1.25rem', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
                {health ? formatUptime(health.uptime_seconds) : '--'}
              </div>
            </div>
          </div>
        </Card>

        <Card>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{ padding: '10px', borderRadius: '8px', background: 'rgba(168, 85, 247, 0.1)', color: 'var(--accent-purple)' }}>
              <Server size={22} />
            </div>
            <div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                Environment / Version
              </div>
              <div style={{ fontSize: '1.1rem', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>
                {health?.environment || 'dev'} • v{health?.version || '0.1.0'}
              </div>
            </div>
          </div>
        </Card>
      </div>

      {/* Subsystem Health Cards Grid */}
      <div>
        <h2 style={{ fontSize: '1.1rem', fontWeight: 600, marginBottom: '14px' }}>
          Interconnected Subsystems
        </h2>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px' }}>
          {health?.services &&
            Object.entries(health.services).map(([name, sub]) => (
              <Card
                key={name}
                title={name.replace('_', ' ').toUpperCase()}
                icon={getSubsystemIcon(name)}
                headerAction={
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    {getStatusIcon(sub.status)}
                    <span
                      style={{
                        fontSize: '0.75rem',
                        fontFamily: 'var(--font-mono)',
                        fontWeight: 600,
                        textTransform: 'uppercase',
                        color:
                          sub.status === 'healthy'
                            ? 'var(--accent-emerald)'
                            : sub.status === 'degraded'
                            ? 'var(--accent-amber)'
                            : 'var(--accent-rose)',
                      }}
                    >
                      {sub.status}
                    </span>
                  </div>
                }
              >
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '0.8rem' }}>
                  {sub.latency_ms !== undefined && sub.latency_ms !== null && (
                    <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(51, 65, 85, 0.3)', paddingBottom: '4px' }}>
                      <span style={{ color: 'var(--text-muted)' }}>Latency:</span>
                      <span className="font-mono">{sub.latency_ms} ms</span>
                    </div>
                  )}
                  {sub.details &&
                    Object.entries(sub.details).map(([key, val]) => (
                      <div key={key} style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(51, 65, 85, 0.3)', paddingBottom: '4px' }}>
                        <span style={{ color: 'var(--text-muted)' }}>{key}:</span>
                        <span className="font-mono" style={{ maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {String(val ?? 'N/A')}
                        </span>
                      </div>
                    ))}
                </div>
              </Card>
            ))}
        </div>
      </div>

      {/* Raw Payload Inspection */}
      <Card title="Raw Health Payload (/api/health)" subtitle={`Last updated: ${lastUpdated ? formatTimestamp(lastUpdated.toISOString()) : 'Never'}`}>
        <pre
          style={{
            background: 'rgba(9, 13, 22, 0.8)',
            padding: '16px',
            borderRadius: '8px',
            border: '1px solid var(--border-color)',
            fontSize: '0.8rem',
            color: '#38bdf8',
            overflowX: 'auto',
          }}
        >
          {health ? JSON.stringify(health, null, 2) : '// No telemetry received yet'}
        </pre>
      </Card>
    </div>
  );
};
