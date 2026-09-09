-- =============================================================================
-- Multi-Agent Cyber AI - PostgreSQL Database Initialization Script
-- =============================================================================

-- 1. Essential Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 2. System Metadata & Migration Versioning Table
CREATE TABLE IF NOT EXISTS system_metadata (
    key VARCHAR(64) PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO system_metadata (key, value)
VALUES (
    'schema_version',
    '{"version": "1.0.0", "phase": "03", "description": "Local Infrastructure Baseline"}'::jsonb
)
ON CONFLICT (key) DO UPDATE 
SET value = EXCLUDED.value, updated_at = CURRENT_TIMESTAMP;

-- 3. Raw & Normalized Telemetry Events Table
CREATE TABLE IF NOT EXISTS telemetry_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    trace_id VARCHAR(64) NOT NULL,
    domain VARCHAR(32) NOT NULL,
    source_type VARCHAR(32) NOT NULL,
    raw_payload JSONB NOT NULL,
    normalized_payload JSONB,
    severity VARCHAR(16) DEFAULT 'INFO',
    sha256_hash VARCHAR(64),
    received_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_telemetry_trace_id ON telemetry_events(trace_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_domain ON telemetry_events(domain);
CREATE INDEX IF NOT EXISTS idx_telemetry_created_at ON telemetry_events(created_at DESC);

-- 4. Agent Execution Tracing & Audit Log Table
CREATE TABLE IF NOT EXISTS agent_execution_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    trace_id VARCHAR(64) NOT NULL,
    agent_name VARCHAR(64) NOT NULL,
    event_id UUID REFERENCES telemetry_events(id) ON DELETE SET NULL,
    execution_status VARCHAR(16) NOT NULL,
    input_summary JSONB,
    output_findings JSONB,
    execution_time_ms FLOAT,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_agent_exec_trace ON agent_execution_logs(trace_id);
CREATE INDEX IF NOT EXISTS idx_agent_exec_name ON agent_execution_logs(agent_name);

-- 5. Correlated Incidents Table
CREATE TABLE IF NOT EXISTS incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_number VARCHAR(32) UNIQUE NOT NULL,
    title VARCHAR(255) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    confidence_score FLOAT NOT NULL,
    status VARCHAR(32) DEFAULT 'OPEN',
    summary TEXT,
    mitre_attack_tactics JSONB DEFAULT '[]'::jsonb,
    mitre_attack_techniques JSONB DEFAULT '[]'::jsonb,
    evidence_items JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at DESC);

-- 6. Alerts Table
CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID REFERENCES incidents(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    source_domain VARCHAR(32) NOT NULL,
    source_ip VARCHAR(64),
    destination_ip VARCHAR(64),
    description TEXT,
    dispatched_to_ws BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at DESC);

-- 7. Analyst Actions & Forensics Audit Trail Table
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id VARCHAR(64) NOT NULL,
    action_type VARCHAR(64) NOT NULL,
    resource_type VARCHAR(64) NOT NULL,
    resource_id VARCHAR(64) NOT NULL,
    rationale TEXT,
    details JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_logs(created_at DESC);
