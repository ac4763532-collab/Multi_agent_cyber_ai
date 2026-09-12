# Multi-Agent Cybersecurity AI Platform

A real-time AI-assisted Security Operations Center (SOC) platform featuring 12 specialized autonomous agents for threat detection, investigation, and response.

## Overview

This platform provides comprehensive security monitoring and incident response capabilities through a multi-agent architecture. Each agent specializes in a specific security domain, enabling parallel processing and expert-level analysis across multiple threat vectors.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Frontend (React/Next.js)                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ SOC Dashboard│  │Investigation │  │   Reports    │          │
│  │              │  │  Workspace   │  │              │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FastAPI Backend                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   REST API   │  │  WebSocket   │  │    Auth      │          │
│  │   Endpoints  │  │   Alerting   │  │   (JWT)      │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│ Task Dispatcher │  │Detection Engine │  │  Correlation    │
│                 │  │ Sigma/Regex/IoC │  │     Engine      │
└─────────────────┘  └─────────────────┘  └─────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│                   12 Specialized Agents                         │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐  │
│  │ Email   │ │  Log    │ │ Network │ │  IP     │ │ Vuln    │  │
│  │Verificat│ │Analyzer │ │ Threat  │ │ Range   │ │ Scanner │  │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘  │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐  │
│  │ Threat  │ │Correlat │ │Investig │ │Incident │ │Response │  │
│  │  Intel  │ │  ion    │ │  ation  │ │Priority │ │ Recomm  │  │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘  │
│  ┌─────────┐ ┌─────────┐                                       │
│  │ Report  │ │ System  │                                       │
│  │  Gen    │ │  Log    │                                       │
│  └─────────┘ └─────────┘                                       │
└─────────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│   PostgreSQL    │  │     Redis       │  │  Kafka/Redpanda │
│   (Events DB)   │  │    (Cache)      │  │  (Event Stream) │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

## Features

### Core Capabilities

- **Real-Time Event Ingestion**: Process security events from multiple sources
- **Multi-Format Parsing**: Support for JSON, CSV, Syslog, CEF, ECS, OCSF
- **Detection Engine**: Sigma rules, regex patterns, and IoC matching
- **Cross-Domain Correlation**: Link related events across security domains
- **AI-Powered Investigation**: Automated hypothesis generation and evidence analysis
- **Incident Management**: Full incident lifecycle with MITRE ATT&CK mapping
- **Real-Time Alerting**: WebSocket-based alert delivery
- **Comprehensive Reporting**: PDF, HTML, Markdown report generation

### Specialized Agents

| Agent | Responsibility |
|-------|---------------|
| Email Verification | Phishing detection, header analysis, URL extraction |
| Log Analyzer | Brute force detection, anomaly scoring |
| Network Threat | C2 detection, beaconing analysis, DGA detection |
| IP Range Analyzer | Network scanning, unauthorized access detection |
| Vulnerability | CVE analysis, risk scoring, remediation |
| Threat Intelligence | IoC enrichment, MITRE mapping |
| Correlation | Cross-domain event correlation |
| Investigation | AI-powered incident investigation |
| Incident Prioritization | Risk-based alert prioritization |
| Response Recommendation | Automated response suggestions |
| Report Generation | Multi-format security reports |
| System Log | Infrastructure monitoring |

## Quick Start

### Prerequisites

- Python 3.11+
- PostgreSQL 15+
- Redis 7+
- Kafka/Redpanda (optional for event streaming)

### Installation

```bash
# Clone repository
git clone https://github.com/your-org/multi-agent-cyber-ai.git
cd multi-agent-cyber-ai

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
.\venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Set up environment
cp .env.example .env
# Edit .env with your configuration

# Run database migrations
alembic upgrade head

# Start the server
uvicorn backend.app.main:app --reload
```

### Docker Deployment

```bash
# Development
docker-compose -f docker-compose.yml up -d

# Production
docker-compose -f docker-compose.yml --profile production up -d
```

## API Documentation

Once running, access the API documentation:

- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc
- OpenAPI JSON: http://localhost:8000/openapi.json

### Key Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/events` | POST | Submit security events |
| `/api/v1/events/{id}` | GET | Get event details |
| `/api/v1/alerts` | GET | List security alerts |
| `/api/v1/incidents` | GET/POST | Manage incidents |
| `/api/v1/investigations` | GET/POST | Manage investigations |
| `/api/v1/agents/status` | GET | Agent status |
| `/api/v1/health` | GET | System health check |

## Configuration

### Environment Variables

```bash
# Application
ENVIRONMENT=development
DEBUG=false
SECRET_KEY=your-secret-key
JWT_SECRET_KEY=your-jwt-secret

# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/socdb

# Redis
REDIS_URL=redis://localhost:6379/0

# Kafka (optional)
KAFKA_BOOTSTRAP_SERVERS=localhost:9092

# Detection Engine
SIGMA_RULES_PATH=./rules/sigma
IOC_DATABASE_PATH=./data/iocs

# Agent Configuration
AGENT_TASK_TIMEOUT_SEC=300
AGENT_MAX_RETRIES=3
```

### Detection Rules

Place Sigma rules in `./rules/sigma/` directory:

```yaml
# rules/sigma/phishing_detection.yml
title: Phishing Email Detection
status: experimental
logsource:
  category: email
detection:
  selection:
    subject|contains:
      - 'verify your account'
      - 'urgent action required'
  condition: selection
level: medium
```

## Development

### Project Structure

```
multi-agent-cyber-ai/
├── backend/
│   └── app/
│       ├── agents/           # Multi-agent framework
│       │   ├── base.py       # BaseAgent ABC
│       │   ├── dispatcher/   # Task routing
│       │   ├── specialized/  # 12 agent implementations
│       │   └── registry.py   # Agent registry
│       ├── alerting/         # Real-time alerts
│       ├── api/              # FastAPI routes
│       ├── audit/            # Security auditing
│       ├── config/           # Configuration
│       ├── correlation/      # Cross-domain correlation
│       ├── core/             # Core utilities
│       ├── detection/        # Detection engine
│       ├── evaluation/       # Scientific evaluation
│       ├── incidents/        # Incident management
│       ├── ingestion/        # Event ingestion
│       ├── investigation/    # AI investigation
│       ├── models/           # Database models
│       ├── performance/      # Performance optimization
│       ├── qa/               # Quality assurance
│       ├── rag/              # RAG knowledge base
│       ├── reports/          # Report generation
│       ├── schemas/          # Pydantic schemas
│       ├── threat_intel/     # Threat intelligence
│       └── main.py           # Application entry
├── frontend/                 # React/Next.js UI
├── tests/                    # Test suites
├── rules/                    # Detection rules
├── data/                     # Data files
├── docs/                     # Documentation
└── docker-compose.yml        # Docker deployment
```

### Running Tests

```bash
# All tests
pytest tests/ -v

# Unit tests only
pytest tests/unit/ -v

# With coverage
pytest tests/ --cov=backend --cov-report=html

# Specific test file
pytest tests/unit/test_email_verification_agent.py -v
```

### Code Quality

```bash
# Linting
ruff check backend/ tests/

# Type checking
mypy backend/app --ignore-missing-imports

# Formatting
ruff format backend/ tests/
```

## Monitoring

### Health Checks

```bash
curl http://localhost:8000/api/v1/health
```

Response:
```json
{
  "status": "healthy",
  "components": {
    "api": "healthy",
    "database": "healthy",
    "redis": "healthy",
    "kafka": "healthy",
    "agents": "healthy"
  }
}
```

### Metrics

Prometheus metrics available at `/metrics`:

- `soc_events_processed_total`
- `soc_alerts_generated_total`
- `soc_agent_processing_seconds`
- `soc_detection_matches_total`

### Grafana Dashboards

Pre-configured dashboards for:
- SOC Overview
- Agent Performance
- Detection Metrics
- Incident Response Times

## Security

### Authentication

- JWT-based authentication
- Role-based access control (RBAC)
- MFA support (optional)

### Data Protection

- Encryption at rest (database)
- TLS 1.3 for all communications
- Secrets management via environment variables

### Compliance

- SOC 2 Type II controls
- NIST Cybersecurity Framework alignment
- GDPR data handling support

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## Support

- Documentation: [docs/](docs/)
- Issues: [GitHub Issues](https://github.com/your-org/multi-agent-cyber-ai/issues)
- Email: security@your-org.com
