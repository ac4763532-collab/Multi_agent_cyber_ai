import React from 'react';
import {
  ShieldAlert,
  Layers,
  Cpu,
  Radio,
  FileCheck,
  Network,
  Globe,
  Bug,
  Database,
  GitMerge,
  Search,
  ArrowUpRight,
  Send,
  FileText,
} from 'lucide-react';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';

interface DashboardPageProps {
  onNavigateToHealth: () => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({ onNavigateToHealth }) => {
  const agents = [
    { id: 1, name: 'Task Dispatcher Agent', icon: <Radio size={16} />, domain: 'Ingestion / Dispatch' },
    { id: 2, name: 'Email Verification Agent', icon: <FileCheck size={16} />, domain: 'Email & Phishing' },
    { id: 3, name: 'Log Analyzer Agent', icon: <Database size={16} />, domain: 'Auth & Syslog' },
    { id: 4, name: 'Network Threat Analysis Agent', icon: <Network size={16} />, domain: 'Flows & Suricata' },
    { id: 5, name: 'IP Range Analyzer Agent', icon: <Globe size={16} />, domain: 'Subnet & CIDR' },
    { id: 6, name: 'Vulnerability Analysis Agent', icon: <Bug size={16} />, domain: 'CVE & Exposures' },
    { id: 7, name: 'Threat Intelligence Agent', icon: <Database size={16} />, domain: 'MISP / FAISS / MITRE' },
    { id: 8, name: 'Correlation Agent', icon: <GitMerge size={16} />, domain: 'Cross-Domain Graph' },
    { id: 9, name: 'Investigation Agent', icon: <Search size={16} />, domain: 'Autonomous Deep Dive' },
    { id: 10, name: 'Incident Prioritization Agent', icon: <ArrowUpRight size={16} />, domain: 'Severity & Urgency' },
    { id: 11, name: 'Response Recommendation Agent', icon: <Send size={16} />, domain: 'Defensive Playbooks' },
    { id: 12, name: 'Report Generation Agent', icon: <FileText size={16} />, domain: 'Auditable Dossiers' },
  ];

  const detectionLayers = [
    { layer: 1, name: 'Deterministic Rules', latency: '< 5ms', tech: 'Sigma, Suricata, Regex' },
    { layer: 2, name: 'Statistical & Baselines', latency: '< 20ms', tech: 'Z-Scores, Rate Windows' },
    { layer: 3, name: 'Machine Learning', latency: '< 50ms', tech: 'Isolation Forest, Outliers' },
    { layer: 4, name: 'Gemini LLM Semantic Analysis', latency: 'Grounded', tech: 'Intent & Reasoning' },
    { layer: 5, name: 'Threat Intel & Vector RAG', latency: 'Fast Index', tech: 'FAISS + MITRE ATT&CK' },
    { layer: 6, name: 'Cross-Domain Correlation', latency: 'Sliding Win', tech: 'Graph Kill-Chain' },
    { layer: 7, name: 'Human Analyst Verification', latency: 'HITL', tech: 'Analyst Dashboard' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Welcome Banner */}
      <div
        className="glass-panel"
        style={{
          padding: '24px',
          background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.9) 0%, rgba(30, 41, 59, 0.7) 100%)',
          border: '1px solid rgba(56, 189, 248, 0.3)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
            <Badge variant="primary">Phase 02 Baseline</Badge>
            <Badge variant="healthy">Architecture Initialized</Badge>
          </div>
          <h1 style={{ fontSize: '1.6rem', fontWeight: 700, letterSpacing: '-0.02em' }}>
            Next-Gen Autonomous SOC Operations Console
          </h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginTop: '6px', maxWidth: '720px' }}>
            Monorepo foundation successfully established. Ready for autonomous multi-agent threat detection,
            deterministic & ML pipelines, and FAISS-backed MITRE ATT&CK correlation.
          </p>
        </div>
        <Button variant="primary" icon={<Cpu size={16} />} onClick={onNavigateToHealth}>
          Inspect Live Health
        </Button>
      </div>

      {/* Overview Metric Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '16px' }}>
        <Card title="Multi-Agent Mesh" icon={<Cpu size={18} />}>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--accent-cyan)' }}>
            12 Agents
          </div>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            Discrete domain & synthesis agents configured
          </p>
        </Card>

        <Card title="Defense-in-Depth" icon={<Layers size={18} />}>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--accent-emerald)' }}>
            7 Layers
          </div>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            Deterministic to LLM semantic reasoning
          </p>
        </Card>

        <Card title="Threat Domains" icon={<ShieldAlert size={18} />}>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--accent-purple)' }}>
            7 Domains
          </div>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            Auth, Email, Network, Web, Endpoint, CVE, Multi-stage
          </p>
        </Card>
      </div>

      {/* 12 Agents Mesh Grid */}
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
          <div>
            <h2 style={{ fontSize: '1.15rem', fontWeight: 600 }}>12 Autonomous SOC Intelligence Agents</h2>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Contractually bounded autonomous workers defined in Project Constitution
            </p>
          </div>
          <Badge variant="purple">Multi-Agent Swarm</Badge>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '14px' }}>
          {agents.map((ag) => (
            <div
              key={ag.id}
              className="glass-panel"
              style={{
                padding: '14px',
                display: 'flex',
                alignItems: 'flex-start',
                gap: '12px',
              }}
            >
              <div
                style={{
                  padding: '8px',
                  borderRadius: '6px',
                  background: 'rgba(56, 189, 248, 0.1)',
                  color: 'var(--accent-cyan)',
                  marginTop: '2px',
                }}
              >
                {ag.icon}
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    #{ag.id}
                  </span>
                  <span style={{ fontSize: '0.875rem', fontWeight: 600 }}>{ag.name}</span>
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
                  {ag.domain}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* 7-Layer Detection Pipeline */}
      <div>
        <h2 style={{ fontSize: '1.15rem', fontWeight: 600, marginBottom: '14px' }}>
          7-Layer Multi-Layer Threat Detection Architecture
        </h2>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {detectionLayers.map((dl) => (
            <div
              key={dl.layer}
              className="glass-panel"
              style={{
                padding: '12px 16px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                <span
                  style={{
                    width: '28px',
                    height: '28px',
                    borderRadius: '6px',
                    background: 'rgba(59, 130, 246, 0.15)',
                    color: 'var(--accent-blue)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '0.8rem',
                    fontWeight: 700,
                    fontFamily: 'var(--font-mono)',
                  }}
                >
                  L{dl.layer}
                </span>
                <div>
                  <div style={{ fontSize: '0.9rem', fontWeight: 600 }}>{dl.name}</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{dl.tech}</div>
                </div>
              </div>
              <Badge variant="info">{dl.latency}</Badge>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
