import React from 'react';
import { Shield, Activity, Radio, Cpu, Lock, Terminal, RefreshCw } from 'lucide-react';
import { Badge } from '../components/ui/Badge';
import { useHealth } from '../hooks/useHealth';

interface DashboardLayoutProps {
  children: React.ReactNode;
  activeTab: string;
  onTabChange: (tab: string) => void;
}

export const DashboardLayout: React.FC<DashboardLayoutProps> = ({
  children,
  activeTab,
  onTabChange,
}) => {
  const { health, loading, refetch } = useHealth(15000);

  const navItems = [
    { id: 'dashboard', label: 'SOC Operations', icon: <Radio size={18} /> },
    { id: 'health', label: 'System Health & Metrics', icon: <Activity size={18} /> },
    { id: 'agents', label: 'Multi-Agent Mesh', icon: <Cpu size={18} />, badge: '12' },
    { id: 'incidents', label: 'Incident Dossiers', icon: <Lock size={18} /> },
  ];

  return (
    <div style={{ display: 'flex', minHeight: '100vh', flexDirection: 'column' }}>
      {/* Top Navbar */}
      <header
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '12px 24px',
          background: 'rgba(15, 23, 42, 0.9)',
          backdropFilter: 'blur(16px)',
          borderBottom: '1px solid var(--border-color)',
          position: 'sticky',
          top: 0,
          zIndex: 50,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: '36px',
              height: '36px',
              borderRadius: '8px',
              background: 'linear-gradient(135deg, #0284c7 0%, #38bdf8 100%)',
              color: '#090d16',
              boxShadow: '0 0 15px rgba(56, 189, 248, 0.4)',
            }}
          >
            <Shield size={22} strokeWidth={2.4} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '1.05rem', fontWeight: 700, letterSpacing: '-0.02em' }}>
                Multi-Agent Cyber AI
              </span>
              <span
                style={{
                  fontSize: '0.65rem',
                  padding: '2px 6px',
                  borderRadius: '4px',
                  background: 'rgba(56, 189, 248, 0.15)',
                  color: 'var(--accent-cyan)',
                  border: '1px solid rgba(56, 189, 248, 0.3)',
                  fontFamily: 'var(--font-mono)',
                  fontWeight: 600,
                }}
              >
                v0.1.0
              </span>
            </div>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Next-Gen Autonomous SOC Threat Detection & Correlation
            </p>
          </div>
        </div>

        {/* Real-Time Status & Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              padding: '6px 12px',
              background: 'rgba(30, 41, 59, 0.5)',
              borderRadius: '8px',
              border: '1px solid var(--border-color)',
            }}
          >
            <span
              className={`pulse-dot pulse-${
                health?.status === 'healthy'
                  ? 'healthy'
                  : health?.status === 'degraded'
                  ? 'degraded'
                  : 'unhealthy'
              }`}
            />
            <span
              style={{
                fontSize: '0.75rem',
                fontFamily: 'var(--font-mono)',
                textTransform: 'uppercase',
                color:
                  health?.status === 'healthy'
                    ? 'var(--accent-emerald)'
                    : health?.status === 'degraded'
                    ? 'var(--accent-amber)'
                    : 'var(--accent-rose)',
              }}
            >
              {health?.status || (loading ? 'CONNECTING...' : 'OFFLINE')}
            </span>
          </div>

          <button
            onClick={() => refetch()}
            style={{
              background: 'transparent',
              border: '1px solid var(--border-color)',
              color: 'var(--text-secondary)',
              borderRadius: '8px',
              padding: '6px 10px',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '0.75rem',
            }}
            title="Refresh System Health"
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            <span>Poll /api/health</span>
          </button>
        </div>
      </header>

      {/* Main Body with Sidebar */}
      <div style={{ display: 'flex', flex: 1 }}>
        {/* Sidebar */}
        <aside
          style={{
            width: '240px',
            background: 'rgba(15, 23, 42, 0.6)',
            borderRight: '1px solid var(--border-color)',
            padding: '20px 12px',
            display: 'flex',
            flexDirection: 'column',
            gap: '6px',
          }}
        >
          <div
            style={{
              fontSize: '0.7rem',
              textTransform: 'uppercase',
              letterSpacing: '0.08em',
              color: 'var(--text-muted)',
              padding: '0 12px 8px 12px',
              fontWeight: 600,
            }}
          >
            Navigation
          </div>
          {navItems.map((item) => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onTabChange(item.id)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '10px 12px',
                  borderRadius: '8px',
                  border: isActive
                    ? '1px solid rgba(56, 189, 248, 0.4)'
                    : '1px solid transparent',
                  background: isActive ? 'rgba(56, 189, 248, 0.1)' : 'transparent',
                  color: isActive ? '#f8fafc' : 'var(--text-secondary)',
                  fontWeight: isActive ? 600 : 400,
                  fontSize: '0.875rem',
                  cursor: 'pointer',
                  textAlign: 'left',
                  transition: 'all 0.15s ease',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span style={{ color: isActive ? 'var(--accent-cyan)' : 'var(--text-muted)' }}>
                    {item.icon}
                  </span>
                  <span>{item.label}</span>
                </div>
                {item.badge && (
                  <Badge variant="purple" className="scale-90">
                    {item.badge}
                  </Badge>
                )}
              </button>
            );
          })}

          <div style={{ marginTop: 'auto', padding: '12px' }}>
            <div
              style={{
                padding: '12px',
                borderRadius: '8px',
                background: 'rgba(30, 41, 59, 0.4)',
                border: '1px solid var(--border-color)',
                fontSize: '0.75rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--accent-cyan)' }}>
                <Terminal size={14} />
                <span style={{ fontWeight: 600 }}>Architecture</span>
              </div>
              <p style={{ color: 'var(--text-muted)', marginTop: '4px', fontSize: '0.7rem' }}>
                7-Layer Detection Engine • 12 Specialized Agents
              </p>
            </div>
          </div>
        </aside>

        {/* Content Area */}
        <main style={{ flex: 1, padding: '24px 32px', overflowY: 'auto' }}>
          {children}
        </main>
      </div>
    </div>
  );
};
