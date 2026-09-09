# Multi-Agent Cyber AI: Real-Time Cybersecurity Threat Detection & Correlation

[![CI Backend](https://github.com/organization/Multi_agent_cyber_ai/actions/workflows/ci-backend.yml/badge.svg)](https://github.com/organization/Multi_agent_cyber_ai/actions/workflows/ci-backend.yml)
[![CI Frontend](https://github.com/organization/Multi_agent_cyber_ai/actions/workflows/ci-frontend.yml/badge.svg)](https://github.com/organization/Multi_agent_cyber_ai/actions/workflows/ci-frontend.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111+-green.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18+-61DAFB.svg)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-3178C6.svg)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An enterprise-grade, distributed, event-driven multi-agent platform designed for Next-Generation Security Operations Centers (Next-Gen SOC). The system coordinates 12 specialized autonomous agents to ingest heterogeneous telemetry, execute 7-layer defense-in-depth threat detection, build persistent attack graphs, and provide evidence-grounded incident dossiers powered by Google Gemini and FAISS-backed MITRE ATT&CK retrieval.

---

## 🏛️ System Architecture Overview

```
Heterogeneous Telemetry (Logs, PCAP, Auth, Mail, Suricata)
                         │
                         ▼
        FastAPI Async Ingestion Gateway (< 5ms)
                         │
                         ▼
     Event Broker (Redis Streams / Partitioned Queues)
                         │
                         ▼
          ECS / OCSF Normalization Engine
                         │
                         ▼
             Task Dispatcher Agent
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
   Log Analyzer   Email Verification   Network Threat
   IP Analyzer    Vulnerability Agent  Threat Intel RAG
        └───────────────┬───────────────┘
                         ▼
        Cross-Domain Graph Correlation Engine
                         │
                         ▼
       Incident Prioritization & Triage Agent
        ┌───────────────┴───────────────┐
        ▼                               ▼
Response Playbooks              Incident Reporting
        └───────────────┬───────────────┘
                         ▼
     Real-Time WebSocket Feed to SOC Analyst UI
```

For complete architectural details, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [PROJECT_CONSTITUTION.md](PROJECT_CONSTITUTION.md).

---

## 📂 Monorepo Structure

```
/
├── backend/                   # FastAPI backend service
│   ├── app/
│   │   ├── core/              # Base classes, exceptions, logging
│   │   ├── config/            # Typed Pydantic BaseSettings
│   │   ├── database/          # Async SQLAlchemy 2.0 sessions & engine
│   │   ├── api/               # API routes & versioned endpoints
│   │   ├── models/            # SQLAlchemy database models
│   │   ├── schemas/           # Pydantic v2 schemas & validation
│   │   ├── services/          # Core business services
│   │   ├── agents/            # 12 Autonomous domain agents
│   │   ├── detection/         # Deterministic & anomaly detection layers
│   │   ├── ml/                # Machine learning models & feature extraction
│   │   ├── llm/               # Google Gemini integration & prompt guards
│   │   ├── rag/               # FAISS vector store & MITRE embeddings
│   │   ├── threat_intel/      # Threat intelligence feeds (MISP, AlienVault)
│   │   ├── correlation/       # Temporal graph cross-domain correlation
│   │   ├── incidents/         # Incident management & state transitions
│   │   ├── alerts/            # Real-time alert dispatching
│   │   ├── reports/           # Post-incident report synthesis
│   │   ├── security/          # Sanitizers, boundary guards & zero-trust checks
│   │   ├── observability/     # Prometheus metrics & distributed tracing
│   │   ├── workers/           # Redis Stream asynchronous workers
│   │   └── utils/             # Datetime, hashing & crypto utilities
│   ├── pyproject.toml         # Ruff, Mypy & Pytest configurations
│   ├── requirements.txt       # Production dependencies
│   └── requirements-dev.txt   # Development & testing dependencies
├── frontend/                  # React + TypeScript + Vite SOC Dashboard
│   ├── src/
│   │   ├── components/        # Reusable UI component library
│   │   ├── layouts/           # Dashboard shell, navigation & status bar
│   │   ├── pages/             # Route views (Dashboard, Health, Incidents)
│   │   ├── features/          # Domain-specific feature modules
│   │   ├── hooks/             # Custom React hooks (useHealth, useWebSocket)
│   │   ├── services/          # Typed API client services
│   │   ├── types/             # TypeScript type definitions
│   │   ├── store/             # Global state management
│   │   └── utils/             # Frontend formatting & helpers
│   ├── package.json
│   └── vite.config.ts
├── infrastructure/            # Docker, database, and Nginx configurations
├── configs/                   # Prometheus & system configuration templates
├── data/                      # Local vector indexes, raw/processed artifacts
├── datasets/                  # Golden test datasets (PCAP, EVE-JSON, logs)
├── scripts/                   # Development, linting & test runner scripts
├── tests/                     # Unit and integration test suites
├── docs/                      # Technical specifications & phase baselines
├── reports/                   # Generated incident reports output directory
├── .github/                   # GitHub Actions CI/CD workflows
├── .env.example               # Environment variables template
├── docker-compose.yml         # Local container orchestration
└── README.md
```

---

## 🚀 Quickstart Guide

### Prerequisites
- Python 3.11+
- Node.js 20+ & npm 10+
- Docker & Docker Compose (optional for containerized setup)

### 1. Environment Configuration
```bash
cp .env.example .env
```

### 2. Backend Setup
```bash
# Create and activate virtual environment
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r backend/requirements.txt -r backend/requirements-dev.txt

# Start backend development server
uvicorn backend.app.main:app --reload --port 8000
```

Verify backend health at: [http://127.0.0.1:8000/api/health](http://127.0.0.1:8000/api/health)

### 3. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

The SOC console will be accessible at: [http://localhost:5173](http://localhost:5173)

### 4. Running with Docker Compose
```bash
docker compose up --build
```

---

## 🧪 Testing and Quality Control

### Running Backend Tests & Checks
```bash
# Run unit & integration tests
pytest tests -v

# Run Ruff linter & formatter checks
ruff check backend tests
ruff format --check backend tests

# Run Mypy static type checking
mypy backend/app
```

### Running Frontend Checks
```bash
cd frontend
npm run type-check
npm run lint
npm run build
```

---

## 🛡️ Security & Engineering Standards

- **Zero-Trust Input**: All payloads and attachments are statically analyzed; never executed in runtime.
- **SQL Injection Prevention**: Strict parameterized queries via SQLAlchemy 2.0 Async ORM.
- **Calibrated AI Inferences**: Google Gemini outputs strictly conform to the 4-Section Output Schema (Observed Evidence, Retrieved Knowledge, AI Inference, Defensive Recommendation) with zero hallucination tolerance.
- **100% Type Coverage**: Strictly enforced with `mypy --strict` and `tsc --strict`.
