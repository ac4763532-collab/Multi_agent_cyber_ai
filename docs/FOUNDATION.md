# Infrastructure & Local Development Baseline

**Project:** An AI-Driven Multi-Agent System for Real-Time Cybersecurity Threat Detection and Correlation  
**Phase:** Phase 03 — Local Infrastructure  
**Status:** Completed & Validated  

---

## 1. Local Infrastructure Overview

The local development environment uses Docker Compose to orchestrate 6 tightly integrated services with strict startup ordering, health checking, and zero-secret hardcoding:

```
+-------------------------------------------------------------------------------+
|                            DOCKER COMPOSE TOPOLOGY                            |
+-------------------------------------------------------------------------------+
|                                                                               |
|   +-----------------------+     +-----------------------+                     |
|   | 1. PostgreSQL 16      |     | 2. Redis 7            |                     |
|   | Port: 5432            |     | Port: 6379            |                     |
|   | Volume: postgres_data |     | Volume: redis_data    |                     |
|   | Health: pg_isready    |     | Health: redis-cli ping|                     |
|   +-----------▲-----------+     +-----------▲-----------+                     |
|               │                             │                                 |
|               │   +-------------------------▲-------+                         |
|               │   | 3. Redpanda (Kafka 9092)        |                         |
|               │   | Volume: redpanda_data           |                         |
|               │   | Health: rpk cluster health      |                         |
|               │   +-------------▲-------------------+                         |
|               │                 │                                             |
|               │   +-------------┴-------------------+                         |
|               │   | 4. Topic Provisioner (Ephemeral)|                         |
|               │   | Creates 7 Kafka Topics          |                         |
|               │   +-------------▲-------------------+                         |
|               │                 │                                             |
|               +─────────┬───────┴───────────────────+                         |
|                         │                                                     |
|           +─────────────┴─────────────+                                       |
|           | 5. FastAPI Backend (8000) |                                       |
|           | Health: GET /api/health   |                                       |
|           +─────────────▲─────────────+                                       |
|                         │                                                     |
|           +─────────────┴─────────────+                                       |
|           | 6. React SOC Console (5173|                                       |
|           | Health: HTTP 200 Index    |                                       |
|           +---------------------------+                                       |
+-------------------------------------------------------------------------------+
```

---

## 2. Kafka / Redpanda Topic Registry

The 7 standardized topics provisioned by `redpanda-init-topics` / `scripts/init_topics.py`:

| Topic Name | Purpose | Partitions | Replicas |
| :--- | :--- | :--- | :--- |
| `security-events` | Raw & normalized security event streaming ingestion | 3 | 1 |
| `agent-tasks` | Task Dispatcher work queue for the 12 domain agents | 3 | 1 |
| `agent-results` | Findings and IoC extractions produced by agents | 3 | 1 |
| `correlations` | Temporal graph correlation candidate links & kill chains | 3 | 1 |
| `incidents` | Correlated security incidents requiring triage | 3 | 1 |
| `alerts` | Actionable real-time alert notifications for SOC WebSockets | 3 | 1 |
| `dead-letter` | Unparseable or crashed messages routed after 3 retries | 3 | 1 |

---

## 3. Resilience, Retries, and Timeouts Architecture

1. **PostgreSQL Connection Pool**:
   - `pool_size`: 20 connections
   - `max_overflow`: 10 connections
   - `pool_recycle`: 1800s
   - `pool_pre_ping`: True
   - `connect_timeout`: 5.0s
   - `max_retries`: 3 attempts with exponential backoff
2. **Redis Manager**:
   - `max_connections`: 50
   - `socket_timeout`: 2.0s
   - `retry_on_timeout`: True
   - Token-bucket / sliding window rate limiting
   - Distributed mutex lock (`acquire_lock`, `release_lock`)
3. **Kafka / Redpanda Broker Manager**:
   - `retries`: 5 attempts
   - `retry_backoff_ms`: 300ms
   - `request_timeout_ms`: 5000ms
   - `max_block_ms`: 4000ms
   - Non-blocking TCP health probes

---

## 4. Verification & QA Matrix

| Verification Step | Command | Result |
| :--- | :--- | :--- |
| **Python Linting** | `ruff check backend tests` | **PASSED (0 errors)** |
| **Python Formatting** | `ruff format --check backend tests` | **PASSED (49 files formatted)** |
| **Python Type Checking** | `mypy backend tests` | **PASSED (0 issues in 49 files)** |
| **Unit & Integration Tests** | `pytest tests -v` | **PASSED (11/11 tests)** |
| **Frontend TypeScript** | `cd frontend && npm run type-check` | **PASSED (0 errors)** |
| **Frontend Linting** | `cd frontend && npm run lint` | **PASSED (0 errors)** |
| **Topic Provisioning Check** | `python scripts/init_topics.py` | **PASSED (All 7 topics registered)** |
| **Live API Health Check** | `GET /api/health` | **PASSED (200 OK, 5 Subsystems)** |
