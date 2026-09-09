# SYSTEM ARCHITECTURE SPECIFICATION
**Project:** An AI-Driven Multi-Agent System for Real-Time Cybersecurity Threat Detection and Correlation  
**Document Version:** 1.0.0  
**Phase:** Phase 01 — Complete System Architecture  
**Status:** Approved Architectural Baseline  

---

## 1. High-Level System Architecture

The platform is designed as an asynchronous, event-driven, multi-tier distributed system tailored for real-time security telemetry ingestion, multi-layered threat detection, autonomous multi-agent analysis, graph-based cross-domain correlation, and analyst copilot capabilities.

### 1.1 System Architecture Diagram

```mermaid
graph TB
    subgraph IngestionLayer["1. Telemetry Ingestion Layer"]
        T1[Syslog / Auth Logs]
        T2[Suricata EVE-JSON]
        T3[Email MIME / Headers]
        T4[Network Flows / PCAP]
        T5[Web / App Logs]
        T6[Vulnerability Scans]
        
        C1[Telemetry Collectors / Ingestion Endpoints]
        T1 & T2 & T3 & T4 & T5 & T6 --> C1
    end

    subgraph EventStreaming["2. Event Streaming & Normalization"]
        C1 -->|Fast Async Push| MB[(Message Broker / Redis Streams / Kafka)]
        MB --> NE[Normalization Engine: ECS/OCSF Schema]
        NE --> TDA[Task Dispatcher Agent]
    end

    subgraph DomainAgents["3. Specialized Domain Analysis Agents"]
        TDA -->|Auth & System| LA[Log Analyzer Agent]
        TDA -->|Email Streams| EA[Email Verification Agent]
        TDA -->|Suricata & NetFlow| NA[Network Threat Agent]
        TDA -->|Subnet & Scans| IA[IP Range Analyzer Agent]
        TDA -->|CPE & Exposure| VA[Vulnerability Agent]
    end

    subgraph IntelAndRAG["4. Threat Intelligence & RAG Engine"]
        TI[Threat Intelligence Agent]
        VS[(FAISS Vector Store: MITRE ATT&CK / CVEs)]
        TC[(Local IoC & Cache DB)]
        
        LA & EA & NA & IA & VA <--> TI
        TI <--> VS
        TI <--> TC
    end

    subgraph DetectionAndAI["5. Multi-Layer Detection & AI Engine"]
        DL1[Layer 1: Deterministic Rules & Sigma]
        DL2[Layer 2: Statistical & Baseline Anomalies]
        DL3[Layer 3: Scikit-learn ML Outliers]
        DL4[Layer 4: Gemini LLM Grounded Analysis]
        
        LA & EA & NA & IA & VA --> DL1 & DL2 & DL3
        DL1 & DL2 & DL3 --> DL4
    end

    subgraph CorrelationIncidents["6. Correlation, Prioritization & Response"]
        Findings[Unified Agent Findings]
        DL1 & DL2 & DL3 & DL4 --> Findings
        Findings --> CA[Correlation Agent: Graph & Temporal Engine]
        CA --> INV[Investigation Agent: Deep Forensics]
        CA --> IPA[Incident Prioritization Agent]
        IPA --> RRA[Response Recommendation Agent]
        IPA --> RGA[Report Generation Agent]
    end

    subgraph StorageAndDelivery["7. Persistence & Real-Time Delivery"]
        PG[(PostgreSQL 16: Events, Findings, Incidents, Audits)]
        WS[WebSocket / SSE Server]
        
        CA & INV & IPA & RRA & RGA --> PG
        IPA --> WS
    end

    subgraph PresentationLayer["8. Real-Time SOC Analyst Console"]
        UI[React 18 + TypeScript + Tailwind CSS UI]
        WS --> UI
        UI <-->|REST API / Copilot Queries| FastAPI[FastAPI Backend Gateway]
        FastAPI <--> PG
        FastAPI <--> INV
    end
```

---

## 2. Real-Time Event Architecture

The event subsystem guarantees sub-second ingestion-to-dispatch latency while providing backpressure protection, message persistence, and fault tolerance.

### 2.1 Event Flow Pipeline

```mermaid
sequenceDiagram
    autonumber
    participant Source as Telemetry Source
    participant Ingest as FastAPI Ingestion API
    participant Broker as Redis Stream / Kafka
    participant Normalizer as Normalization Worker
    participant Dispatcher as Task Dispatcher Agent
    participant AgentQueue as Domain Worker Queue

    Source->>Ingest: POST /api/v1/telemetry/events (Raw Batch)
    Ingest->>Ingest: Validate Auth & Payload Size
    Ingest->>Broker: XADD telemetry.raw (Payload, Trace ID)
    Ingest-->>Source: 202 Accepted {trace_id, count, status: "queued"}
    
    Broker->>Normalizer: XREADGROUP telemetry.raw
    Normalizer->>Normalizer: Parse & Transform to ECS/OCSF Schema
    Normalizer->>Broker: XADD telemetry.normalized
    
    Broker->>Dispatcher: XREADGROUP telemetry.normalized
    Dispatcher->>Dispatcher: Classify Domain & Compute Priority
    Dispatcher->>AgentQueue: Push to target queue (e.g., queue.agent.network)
```

### 2.2 Streaming Topics and Queues

| Stream / Queue Name | Payload Type | Partitioning / Routing Key | Max Retention | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| `telemetry.raw` | `RawEventBatch` | `source_type` | 24 Hours / Ring Buffer | Unmodified raw telemetry ingestion buffer |
| `telemetry.normalized` | `NormalizedEvent` | `event_domain` | 24 Hours | ECS/OCSF compliant structured events |
| `queue.agent.email` | `EmailAnalysisTask` | `recipient_domain` | Ephemeral / In-Memory | Mail analysis tasks |
| `queue.agent.logs` | `LogAnalysisTask` | `host_id` | Ephemeral / In-Memory | Syslog, auth, and web log tasks |
| `queue.agent.network` | `NetworkAnalysisTask` | `src_ip` | Ephemeral / In-Memory | NetFlow, PCAP, and Suricata tasks |
| `queue.agent.ip` | `IPScanTask` | `subnet_cidr` | Ephemeral / In-Memory | IP range risk and scan tasks |
| `queue.agent.vuln` | `VulnAssessmentTask` | `asset_id` | Ephemeral / In-Memory | Vulnerability and CPE match tasks |
| `telemetry.findings` | `AgentFinding` | `correlation_key` | 48 Hours | Detection findings emitted by domain agents |
| `incidents.live` | `IncidentEvent` | `incident_id` | 7 Days | Correlated incident stream for real-time UI |
| `telemetry.dlq` | `FailedMessage` | `origin_queue` | 14 Days | Dead-letter queue for unparseable/failed events |

### 2.3 Normalized Event Schema (ECS / OCSF Hybrid)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "trace_id": "c6a2b8e4-8841-4d32-901d-5b3cf5429112",
  "event_id": "evt-20260831-9821034",
  "timestamp": "2026-08-31T14:02:11.452100Z",
  "event_domain": "authentication",
  "event_type": "user_login_failed",
  "severity_hint": 3,
  "source": {
    "ip": "192.168.1.105",
    "port": 54210,
    "geo": {"country": "Internal", "asn": "Private"},
    "mac": "00:1A:2B:3C:4D:5E"
  },
  "destination": {
    "ip": "10.0.0.15",
    "port": 22,
    "hostname": "srv-db-prod01",
    "asset_criticality": "TIER_1"
  },
  "user": {
    "name": "root",
    "domain": "CORP",
    "id": "u-0042"
  },
  "network": {
    "protocol": "tcp",
    "transport": "ssh",
    "bytes_in": 1420,
    "bytes_out": 890
  },
  "raw_data_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "raw_payload_preview": "Aug 31 14:02:11 srv-db-prod01 sshd[4102]: Failed password for root from 192.168.1.105 port 54210 ssh2"
}
```

---

## 3. Multi-Agent Architecture & Inter-Agent Coordination

Each agent is an autonomous state machine conforming to the `BaseAgent` abstract class. Agents do not communicate via uncontrolled peer-to-peer sprawl; instead, coordination occurs via well-defined queues and the centralized **Correlation Engine**.

### 3.1 Agent Interaction Workflow

```mermaid
graph TD
    subgraph Ingestion
        TDA[1. Task Dispatcher Agent]
    end

    subgraph Tier1_Analysis["Tier 1: Domain Analysis Agents (Parallel)"]
        EVA[2. Email Verification Agent]
        LAA[3. Log Analyzer Agent]
        NTA[4. Network Threat Agent]
        IRA[5. IP Range Analyzer Agent]
        VAA[6. Vulnerability Analysis Agent]
    end

    subgraph Tier2_Enrichment["Tier 2: Knowledge & Threat Intel"]
        TIA[7. Threat Intelligence Agent]
    end

    subgraph Tier3_Correlation["Tier 3: Multi-Domain Synthesis"]
        COR[8. Correlation Agent]
    end

    subgraph Tier4_Investigation["Tier 4: Deep Forensics & Triage"]
        INV[9. Investigation Agent]
        IPA[10. Incident Prioritization Agent]
    end

    subgraph Tier5_Response["Tier 5: Remediation & Reporting"]
        RRA[11. Response Recommendation Agent]
        RGA[12. Report Generation Agent]
    end

    TDA -->|Dispatch Email| EVA
    TDA -->|Dispatch Logs| LAA
    TDA -->|Dispatch Traffic| NTA
    TDA -->|Dispatch Ranges| IRA
    TDA -->|Dispatch Assets| VAA

    EVA & LAA & NTA & IRA & VAA <-->|Enrich IoCs / RAG| TIA
    EVA & LAA & NTA & IRA & VAA -->|Emit Domain Findings| COR

    COR -->|Generate Correlated Incident| IPA
    COR -->|Trigger Autonomous Dossier Build| INV
    
    IPA -->|Prioritized Incident| RRA
    IPA -->|Prioritized Incident| RGA
```

### 3.2 Agent Detailed Specifications

```
+---------------------------------------------------------------------------------------------------+
| AGENT SPECIFICATION MATRIX                                                                        |
+-----+-----------------------+-----------------------+-----------------------+---------------------+
| #   | Agent Name            | Ingestion Inputs      | Core Processing Engine| Emitted Output      |
+-----+-----------------------+-----------------------+-----------------------+---------------------+
| 1   | Task Dispatcher       | Normalized Events     | Priority Router & LB  | Target Agent Tasks  |
| 2   | Email Verification    | MIME, Headers, EML    | SPF/DKIM, NLP, URLs   | Phishing Findings   |
| 3   | Log Analyzer          | Syslog, Auth, App Logs| Sigma Engine, Regex   | Log Anomaly Findings|
| 4   | Network Threat        | NetFlow, PCAP, EVE    | Flow Baselines, Beacon| Network Findings    |
| 5   | IP Range Analyzer     | CIDR, Scan Requests   | Nmap (Safe), ASN Geo  | Subnet Exposure Info|
| 6   | Vulnerability Analysis| Asset CPEs, Ports     | NVD / CVE / CVSS DB   | Vulnerability Risks |
| 7   | Threat Intelligence   | IoCs, MITRE Queries   | FAISS RAG, Feeds Cache| Enriched Context    |
| 8   | Correlation Agent     | Stream of Findings    | Graph & Temporal Link | Correlated Incidents|
| 9   | Investigation Agent   | Incident IDs, Entities| Deep Trace & Timelines| Investigation Dossier|
| 10  | Incident Prioritizer  | Draft Incidents       | Severity Formula (ISS)| Triaged Severity Rank|
| 11  | Response Recommender  | Prioritized Incidents | Playbook Matcher + AI | Actionable Playbooks|
| 12  | Report Generator      | Incidents + Evidence  | Markdown/PDF Synthesis| Auditable Reports   |
+-----+-----------------------+-----------------------+-----------------------+---------------------+
```

---

## 4. Backend Architecture

The backend is built with Python 3.11+ and FastAPI, adhering to **Clean Architecture** (Hexagonal/Ports & Adapters) principles to isolate domain entities from external libraries, databases, and network transports.

### 4.1 Layered Architecture

```
backend/
├── app/
│   ├── api/                    # Presentation Layer (FastAPI Routers, WebSockets)
│   │   ├── v1/
│   │   │   ├── endpoints/      # Auth, Events, Agents, Incidents, Alerts, Metrics
│   │   │   └── websockets/     # Live Alert & Metric Streams
│   │   └── deps.py             # Dependency Injection Providers
│   ├── core/                   # Core Infrastructure Layer
│   │   ├── config.py           # Typed Settings (Pydantic BaseSettings)
│   │   ├── logging.py          # Structured JSON Logger
│   │   ├── security.py         # JWT, Argon2 Password Hashing, Input Sanitizers
│   │   └── broker.py           # Redis / Kafka Client Manager
│   ├── domain/                 # Pure Business Logic (No frameworks)
│   │   ├── models/             # Domain Entities (Event, Finding, Incident, Alert)
│   │   └── interfaces/         # Repository & Broker Interface Contracts
│   ├── schemas/                # Pydantic v2 DTOs (Request / Response validation)
│   ├── db/                     # Data Access Layer
│   │   ├── session.py          # Async SQLAlchemy Engine & SessionMaker
│   │   ├── base.py             # Declarative Base
│   │   └── repositories/       # Async Repositories (Events, Incidents, Audits)
│   ├── agents/                 # Multi-Agent Implementations
│   │   ├── base.py             # BaseAgent Abstract Class & Lifecycle
│   │   ├── dispatcher.py       # Task Dispatcher Agent
│   │   ├── email_agent.py      # Email Verification Agent
│   │   ├── log_agent.py        # Log Analyzer Agent
│   │   ├── network_agent.py    # Network Threat Agent
│   │   ├── ip_agent.py         # IP Range Analyzer Agent
│   │   ├── vuln_agent.py       # Vulnerability Agent
│   │   ├── intel_agent.py      # Threat Intelligence Agent
│   │   ├── correlation_agent.py# Correlation Engine Agent
│   │   ├── investigation.py    # Investigation Agent
│   │   ├── prioritizer.py      # Incident Prioritization Agent
│   │   ├── recommender.py      # Response Recommendation Agent
│   │   └── reporter.py         # Report Generation Agent
│   ├── detection/              # Detection Engines (L1, L2, L3)
│   │   ├── rules/              # Sigma / Regex Rule Engine (L1)
│   │   ├── anomaly/            # Statistical Baselines & Z-Scores (L2)
│   │   └── ml/                 # Scikit-learn Isolation Forest Models (L3)
│   ├── rag/                    # Retrieval-Augmented Generation Layer
│   │   ├── vector_store.py     # FAISS Index Manager
│   │   ├── embedder.py         # Sentence-Transformers / Gemini Embeddings
│   │   └── knowledge_base.py   # MITRE ATT&CK & CVE Knowledge Graph
│   └── ai/                     # LLM Integration Layer (L4)
│       ├── gemini_client.py    # Google Gemini Async Client
│       ├── prompts/            # Grounded & Schema-Enforced Prompt Templates
│       └── guards.py           # Anti-Hallucination & Output Schema Validators
```

---

## 5. Frontend Architecture

The frontend is a single-page application (SPA) built with React 18, TypeScript, and Tailwind CSS. It is optimized for high-density, low-latency SOC analyst operations.

### 5.1 Frontend Component Hierarchy

```
frontend/
├── src/
│   ├── assets/                 # Icons, Logos, Static Assets
│   ├── components/             # Reusable UI Atoms and Molecules
│   │   ├── common/             # Button, Badge, Modal, Card, Table, Tooltip
│   │   ├── layout/             # TopNavbar, Sidebar, PageContainer, StatusPill
│   │   ├── graphs/             # AttackGraph (ReactFlow/Vis.js), MetricChart
│   │   └── terminal/           # SecurityLogViewer, LiveStreamTerminal
│   ├── features/               # Domain-Driven Feature Modules
│   │   ├── dashboard/          # Real-time Metrics, EPS, Threat Meter, Recent Alerts
│   │   ├── events/             # Ingested Events Table, Search & Filter Bar
│   │   ├── incidents/          # Incident Dossier, Evidence Viewer, Playbook Actions
│   │   ├── investigation/      # Copilot Query Box, Timeline View, Graph Traversal
│   │   ├── intelligence/       # MITRE ATT&CK Matrix Navigator, IoC Lookup
│   │   └── reports/            # Markdown Report Previewer & PDF Export
│   ├── hooks/                  # Custom React Hooks
│   │   ├── useWebSocket.ts     # Resilient Auto-Reconnecting WebSocket Hook
│   │   ├── useIncidents.ts     # TanStack Query Hook for Incident State
│   │   └── useMetrics.ts       # Live Streamed Performance Telemetry
│   ├── services/               # Axios API Clients & WebSocket Connectors
│   │   ├── api.ts              # Central Axios Client with Auth Interceptors
│   │   └── ws.ts               # WebSocket Event Dispatcher
│   ├── state/                  # Global State (Zustand / Context)
│   │   ├── authStore.ts        # Analyst Session & Token Management
│   │   └── alertStore.ts       # Real-Time Incoming Alert Buffer
│   └── types/                  # TypeScript Interface Definitions
│       ├── event.d.ts          # Normalized Event & Raw Event Types
│       ├── incident.d.ts       # Incident, Finding, and Evidence Types
│       └── metrics.d.ts        # Performance & Health Metric Types
```

---

## 6. Database Architecture & Relational ER Model

The data layer uses PostgreSQL 16+ with async connections (`asyncpg` via SQLAlchemy 2.0). Raw event payloads are indexed using JSONB with GIN indexes, while transactional entities enforce strict referential integrity.

### 6.1 Database Entity Relationship (ER) Diagram

```mermaid
erDiagram
    RAW_EVENTS ||--o{ NORMALIZED_EVENTS : "normalized into"
    NORMALIZED_EVENTS ||--o{ AGENT_FINDINGS : "triggers"
    AGENT_FINDINGS }o--o{ INCIDENTS : "correlated into"
    INCIDENTS ||--o{ ALERTS : "generates"
    INCIDENTS ||--o{ INVESTIGATION_DOSSIERS : "investigated into"
    INCIDENTS ||--o{ RESPONSE_PLAYBOOKS : "recommends"
    INCIDENTS ||--o{ INCIDENT_REPORTS : "synthesizes"
    USERS ||--o{ AUDIT_LOGS : "performs"
    INCIDENTS ||--o{ AUDIT_LOGS : "records actions on"

    RAW_EVENTS {
        uuid id PK
        string trace_id
        string source_type
        text raw_payload
        string sha256_hash
        timestamp received_at
    }

    NORMALIZED_EVENTS {
        uuid id PK
        uuid raw_event_id FK
        string trace_id
        string event_domain
        string event_type
        jsonb source_data
        jsonb destination_data
        jsonb network_data
        jsonb user_data
        timestamp event_timestamp
        timestamp created_at
    }

    AGENT_FINDINGS {
        uuid id PK
        uuid event_id FK
        string agent_name
        string detection_layer
        string finding_type
        float confidence_score
        jsonb evidence_data
        string mitre_technique_id
        timestamp created_at
    }

    INCIDENTS {
        uuid id PK
        string title
        string status
        string severity
        float incident_severity_score
        float threat_urgency_score
        string primary_attack_domain
        jsonb affected_entities
        timestamp opened_at
        timestamp resolved_at
    }

    ALERTS {
        uuid id PK
        uuid incident_id FK
        string alert_title
        string alert_level
        boolean is_acknowledged
        timestamp dispatched_at
    }

    INVESTIGATION_DOSSIERS {
        uuid id PK
        uuid incident_id FK
        jsonb timeline_nodes
        jsonb evidence_citations
        text ai_inference_summary
        timestamp compiled_at
    }

    RESPONSE_PLAYBOOKS {
        uuid id PK
        uuid incident_id FK
        string playbook_name
        jsonb recommended_actions
        jsonb rollback_instructions
        string execution_status
    }

    INCIDENT_REPORTS {
        uuid id PK
        uuid incident_id FK
        string report_format
        text markdown_content
        string generated_by_agent
        timestamp created_at
    }

    USERS {
        uuid id PK
        string username
        string email
        string role
        string hashed_password
        boolean is_active
    }

    AUDIT_LOGS {
        uuid id PK
        uuid user_id FK
        uuid incident_id FK
        string action_type
        jsonb before_state
        jsonb after_state
        timestamp performed_at
    }
```

---

## 7. AI Architecture & Google Gemini Integration

The AI subsystem leverages Google Gemini models via official SDKs for semantic reasoning, contextual threat intent recognition, and structured report synthesis.

### 7.1 AI Processing Pipeline & Anti-Hallucination Sandbox

```mermaid
sequenceDiagram
    autonumber
    participant Agent as Specialized / Investigation Agent
    participant Guard as AI Grounding & Prompt Guard
    participant Gemini as Google Gemini 1.5/2.0 API
    participant Validator as Schema & Hallucination Validator
    participant Output as Structured Evidence Dossier

    Agent->>Guard: Submit Task (Evidence IDs, Normalized Events, RAG Chunks)
    Guard->>Guard: Strip System Secrets & Sanitize Payloads
    Guard->>Guard: Compile Strict Grounded Prompt with Few-Shot Examples
    Guard->>Gemini: Request Structured Inference (Pydantic Response Schema)
    
    Gemini-->>Validator: Raw LLM Output (JSON)
    Validator->>Validator: Validate Schema Conformance
    Validator->>Validator: Verify Entity Grounding (All IPs/Hashes/CVEs match Evidence IDs)
    
    alt Unanchored Entity Detected (Hallucination)
        Validator->>Agent: REJECT & Flag Unanchored Claim
    else All Claims Grounded
        Validator->>Output: Emit Formatted 4-Tier Output Schema
    end
```

### 7.2 Grounded Prompt Template Design
```
You are the AI Reasoning Core for an enterprise SOC.
Analyze ONLY the provided OBSERVED EVIDENCE and RETRIEVED KNOWLEDGE below.

CRITICAL CONSTRAINTS:
1. Do NOT assume, extrapolate, or invent any IP addresses, CVEs, timestamps, or hostnames.
2. Every claim must explicitly cite an Evidence ID [EVID-xxx].
3. You must format your response strictly into the four specified sections.

--- OBSERVED EVIDENCE ---
{evidence_block}

--- RETRIEVED KNOWLEDGE ---
{rag_knowledge_block}

OUTPUT FORMAT:
### 1. OBSERVED EVIDENCE
### 2. RETRIEVED KNOWLEDGE
### 3. AI INFERENCE
### 4. DEFENSIVE RECOMMENDATION
```

---

## 8. RAG (Retrieval-Augmented Generation) Architecture

The RAG subsystem indexes authoritative cybersecurity knowledge bases to supply domain agents and the LLM with grounded tactical context.

### 8.1 RAG Indexing & Retrieval Flow

```mermaid
flowchart TD
    subgraph KnowledgeIngestion["Knowledge Base Ingestion (Offline/Periodic)"]
        K1[MITRE ATT&CK Enterprise v15 JSON]
        K2[NIST NVD / CVE Feeds]
        K3[Verified Defensive Playbooks]
        
        Chunker[Semantic Cyber Chunker]
        Embedder[Embedding Model: text-embedding-004]
        FAISS_DB[(FAISS Vector Index: FlatIP / HNSW)]
        
        K1 & K2 & K3 --> Chunker
        Chunker --> Embedder
        Embedder --> FAISS_DB
    end

    subgraph QueryPipeline["Real-Time RAG Retrieval Pipeline"]
        Query[Agent Query: IoC / Pattern / Technique]
        QueryEmbed[Query Embedder]
        Search[Cosine Similarity Top-K Search]
        Rerank[Cross-Encoder Reranker]
        Context[Context Injection Block]
        
        Query --> QueryEmbed
        QueryEmbed --> Search
        FAISS_DB --> Search
        Search --> Rerank
        Rerank --> Context
    end
```

---

## 9. Threat Intelligence Architecture

The Threat Intelligence Engine unifies local caches, external intelligence feeds, and vector-indexed knowledge.

```
+-------------------------------------------------------------------------------+
|                      THREAT INTELLIGENCE AGENT PIPELINE                       |
+-------------------------------------------------------------------------------+
                                      │
                 Query: Hash / IP / Domain / URL / CVE
                                      │
                                      ▼
                        +----------------------------+
                        |  Local Fast Cache (Redis)   |
                        +----------------------------+
                                      │
                         [Miss]       │       [Hit]
              ┌───────────────────────┴───────────────────────┐
              ▼                                               ▼
+----------------------------+                  +----------------------------+
|  Local Threat Intel Store  |                  | Return Cached Score & TTL  |
|  (STIX/TAXII / MISP Cache) |                  +----------------------------+
+----------------------------+
              │
              ▼
+----------------------------+
|   FAISS MITRE Vector DB    |
| (Technique ID & Tactics)   |
+----------------------------+
              │
              ▼
+-------------------------------------------------------------------------------+
| Consolidated Intel Record: {threat_score, actor, reputation, mitre_tactics}   |
+-------------------------------------------------------------------------------+
```

---

## 10. Correlation Architecture

The Correlation Engine aggregates isolated findings from domain agents over a configurable sliding temporal window (e.g., 10 minutes) and evaluates attack graph topology.

### 10.1 Correlation Pipeline Diagram

```mermaid
flowchart LR
    F1[Email Finding: Phishing URL] --> Win[Sliding Time Window Buffer]
    F2[Log Finding: Auth Failure x50] --> Win
    F3[Net Finding: Port Scan on 22/80] --> Win
    F4[Log Finding: Successful Root Login] --> Win

    Win --> GraphBuilder[Entity Graph Builder]
    GraphBuilder --> Nodes[Nodes: IPs, Users, Hosts]
    GraphBuilder --> Edges[Edges: Communication, Auth, Exploitation]

    Nodes & Edges --> Matcher{Correlation Rules & Graph Traversal}
    Matcher -->|Pattern: Recon -> Initial Access -> Privilege Escalation| KillChain[MITRE Kill Chain Assembly]
    KillChain --> Incident[New Unified Incident: Multi-Stage Attack]
```

### 10.2 Correlation Rules Engine Specifications
1. **Identity & Entity Anchoring:** Link events sharing `source.ip`, `destination.ip`, `user.name`, or `file.sha256`.
2. **Temporal Proximity:** Aggregate events occurring within $\Delta t \le \text{window\_size}$ (default 600s).
3. **Kill Chain Phase Sequencing:** Match sequential progression:
   $$\text{Reconnaissance} \longrightarrow \text{Initial Access} \longrightarrow \text{Execution} \longrightarrow \text{Privilege Escalation} \longrightarrow \text{Exfiltration}$$

---

## 11. Incident Architecture & Prioritization Engine

### 11.1 Incident State Machine Lifecycle

```mermaid
stateDiagram-v2
    [*] --> OPEN_UNASSIGNED: Correlated from Findings
    OPEN_UNASSIGNED --> IN_TRIAGE: Prioritization Agent Evaluates
    IN_TRIAGE --> UNDER_INVESTIGATION: Investigation Agent Builds Dossier
    UNDER_INVESTIGATION --> PENDING_ACTION: Response Playbook Generated
    PENDING_ACTION --> REMEDIATING: Analyst Approves Remediation
    REMEDIATING --> RESOLVED: Actions Executed & Verified
    RESOLVED --> CLOSED: Post-Incident Report Generated
    
    OPEN_UNASSIGNED --> FALSE_POSITIVE: Dismissed by Analyst
    IN_TRIAGE --> FALSE_POSITIVE: Dismissed by Analyst
    UNDER_INVESTIGATION --> FALSE_POSITIVE: Dismissed by Analyst
    
    FALSE_POSITIVE --> [*]
    CLOSED --> [*]
```

### 11.2 Incident Severity & Urgency Formulas

$$\text{ISS} = \min\left(10.0, \; \left(w_{\text{cvss}} \cdot S_{\text{CVSS}}\right) + \left(w_{\text{asset}} \cdot C_{\text{Asset}}\right) + \left(w_{\text{intel}} \cdot I_{\text{Intel}}\right) + \left(w_{\text{killchain}} \cdot K_{\text{Stage}}\right)\right)$$

Where:
- $S_{\text{CVSS}} \in [0, 10]$: Base vulnerability or threat severity
- $C_{\text{Asset}} \in [1, 10]$: Asset Criticality (Tier 1 = 10, Tier 2 = 7, Tier 3 = 4, Dev = 1)
- $I_{\text{Intel}} \in [0, 10]$: Threat Intelligence Confidence
- $K_{\text{Stage}} \in [1, 10]$: Stage in Kill Chain (Exfiltration = 10, Recon = 2)
- Default Weights: $w_{\text{cvss}} = 0.25, \; w_{\text{asset}} = 0.35, \; w_{\text{intel}} = 0.20, \; w_{\text{killchain}} = 0.20$

---

## 12. Alert Architecture & Real-Time Delivery

### 12.1 Real-Time Broadcast Architecture
1. **Deduplication & Rate Limiting:** High-frequency repetitive findings are collapsed using a sliding 60-second hash bucket to prevent alert fatigue.
2. **WebSocket Channels:**
   - `/ws/v1/alerts/live`: Real-time streaming of prioritized alert notifications.
   - `/ws/v1/metrics/stream`: 1-second interval telemetry throughput and latency metrics.
   - `/ws/v1/incidents/{incident_id}`: Real-time collaborative updates for open incident investigations.

---

## 13. Observability Architecture

### 13.1 Metrics Collection & Telemetry Instrumentation

```mermaid
flowchart TD
    subgraph Instrumentation
        FastAPI_App[FastAPI Endpoints] --> PromMiddleware[Prometheus / OpenTelemetry Exporter]
        WorkerPool[Agent Worker Pool] --> PromMiddleware
        Broker[Redis Streams] --> BrokerExporter[Redis Exporter]
    end

    subgraph ObservabilityCore
        PromMiddleware --> MetricsRoute["/api/v1/metrics/live"]
        BrokerExporter --> MetricsRoute
        MetricsRoute --> Aggregator[Real-Time Metrics Aggregator Service]
    end

    subgraph MonitoringOutput
        Aggregator --> WS_Broadcast[WebSocket Broadcast]
        WS_Broadcast --> SOC_Dashboard[SOC Ops Dashboard]
    end
```

### 13.2 Tracked Performance KPIs
- **Throughput:** $EPS_{\text{ingest}}$, $EPS_{\text{normalized}}$, $EPS_{\text{dispatched}}$
- **Processing Latency:** $P_{50}$, $P_{95}$, $P_{99}$ latency across all 12 agents
- **LLM Metrics:** Token count per query, response duration, cache hit ratio
- **Conversion Ratios:** Ingested Events $\rightarrow$ Agent Findings $\rightarrow$ Correlated Incidents $\rightarrow$ Actioned Remediations

---

## 14. Security & Isolation Architecture

### 14.1 Zero-Trust Boundaries & Defenses

```
+-------------------------------------------------------------------------------+
|                             SECURITY PERIMETER                                |
+-------------------------------------------------------------------------------+
| 1. API GATEWAY: Rate-limiting (Token Bucket), JWT verification, CORS whitelist|
+-------------------------------------------------------------------------------+
                                      │
                                      ▼
+-------------------------------------------------------------------------------+
| 2. INPUT VALIDATOR: Pydantic v2 strict schemas, payload size caps (< 10MB)    |
+-------------------------------------------------------------------------------+
                                      │
                                      ▼
+-------------------------------------------------------------------------------+
| 3. NON-EXECUTION SANDBOX: Attachments/URLs statically analyzed (No execution) |
+-------------------------------------------------------------------------------+
                                      │
                                      ▼
+-------------------------------------------------------------------------------+
| 4. SCAN BOUNDARY ENFORCER: Nmap restricted to RFC1918 / Loopback whitelists   |
+-------------------------------------------------------------------------------+
                                      │
                                      ▼
+-------------------------------------------------------------------------------+
| 5. AI PROMPT GUARD: Redact secrets, sanitize injection, enforce 4-tier schema |
+-------------------------------------------------------------------------------+
                                      │
                                      ▼
+-------------------------------------------------------------------------------+
| 6. DATABASE ISOLATION: SQLAlchemy 2.0 async parameterized queries (No raw SQL)|
+-------------------------------------------------------------------------------+
```

---

## 15. Deployment & Container Architecture

The system is fully containerized using Docker and orchestrated via Docker Compose for reproducible local development and production-grade staging.

### 15.1 Container Topology

```mermaid
graph TD
    subgraph FrontendContainer["Container: frontend"]
        Nginx[Nginx Reverse Proxy & Static Host (Port 80/443)]
    end

    subgraph BackendContainers["Containers: backend & workers"]
        API[FastAPI Gateway (Port 8000)]
        Worker1[Worker Pool: Dispatcher & Normalization]
        Worker2[Worker Pool: Domain Agents L1-L5]
        Worker3[Worker Pool: Correlation & Investigation Agents]
    end

    subgraph DataContainers["Containers: data & streaming"]
        RedisDB[(Redis 7: Streams & Cache - Port 6379)]
        PostgresDB[(PostgreSQL 16: Database - Port 5432)]
    end

    Nginx -->|Reverse Proxy /api & /ws| API
    API --> RedisDB
    API --> PostgresDB
    Worker1 & Worker2 & Worker3 --> RedisDB
    Worker1 & Worker2 & Worker3 --> PostgresDB
```

---

## 16. Architectural Evaluation & Non-Functional Assessment

### 16.1 Scalability Assessment
- **Horizontal Agent Scaling:** Agent workers consume from partitioned Redis Streams consumer groups, allowing horizontal worker scaling without state contention.
- **Decoupled Ingestion:** Ingestion APIs do not perform computation; they offload raw payloads to Redis Streams in under 5ms, supporting $> 5,000$ EPS per node.

### 16.2 Security Assessment
- **Zero-Execution Guarantee:** Static analysis only; attachments and scripts are never executed.
- **Zero Raw SQL:** 100% ORM parameterization prevents SQL injection.
- **AI Output Enclosure:** Mandatory validation ensures LLM responses cannot inject unanchored data into incident dossiers.

### 16.3 Fault Tolerance Assessment
- **Dead-Letter Queue (DLQ):** Unparseable or crashed event processing attempts are routed to `telemetry.dlq` after 3 retries.
- **Broker Persistence:** Redis Streams AOF (Append-Only File) persistence prevents message loss during unexpected broker restarts.

### 16.4 Testability Assessment
- **Hexagonal Isolation:** Domain logic and agents operate against abstract repository interfaces, allowing full mock-injected unit testing without live databases or brokers.
- **Deterministic Golden Datasets:** Standardized test PCAP, EVE-JSON, and Syslog fixtures allow automated regression verification.

### 16.5 Maintainability Assessment
- **Modular Directory Structure:** Strictly scoped files with single responsibilities.
- **100% Typing:** Comprehensive Python type hints and TypeScript interfaces eliminate dynamic type ambiguities.

---

**END OF ARCHITECTURE SPECIFICATION**
