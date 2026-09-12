# API Reference

## Overview

The Multi-Agent Cybersecurity AI Platform exposes a RESTful API for managing security events, alerts, incidents, and investigations. All endpoints require authentication unless otherwise noted.

## Base URL

```
Production: https://api.soc.your-org.com/api/v1
Development: http://localhost:8000/api/v1
```

## Authentication

### JWT Token Authentication

```bash
# Login to get token
POST /api/v1/auth/login
Content-Type: application/json

{
  "username": "analyst@your-org.com",
  "password": "your-password"
}

# Response
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

### Using the Token

```bash
# Include in Authorization header
curl -H "Authorization: Bearer <token>" https://api.soc.your-org.com/api/v1/events
```

---

## Events API

### Submit Event

```http
POST /api/v1/events
```

Submit a security event for processing.

**Request Body:**

```json
{
  "source": "email_gateway",
  "source_type": "email",
  "event_type": "email_received",
  "severity": "medium",
  "timestamp": "2024-01-15T10:30:00Z",
  "source_ip": "192.168.1.100",
  "raw_data": {
    "subject": "Urgent: Verify your account",
    "sender": "support@suspicious-domain.com",
    "recipient": "user@your-org.com"
  },
  "metadata": {
    "gateway_id": "gw-001"
  }
}
```

**Response:**

```json
{
  "event_id": "evt_abc123def456",
  "status": "accepted",
  "created_at": "2024-01-15T10:30:01Z"
}
```

### Get Event

```http
GET /api/v1/events/{event_id}
```

**Response:**

```json
{
  "event_id": "evt_abc123def456",
  "source": "email_gateway",
  "source_type": "email",
  "event_type": "email_received",
  "severity": "medium",
  "timestamp": "2024-01-15T10:30:00Z",
  "source_ip": "192.168.1.100",
  "normalized_data": {...},
  "findings": [...],
  "created_at": "2024-01-15T10:30:01Z"
}
```

### List Events

```http
GET /api/v1/events?limit=50&offset=0&severity=high&source_type=email
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| limit | int | Max results (default: 50, max: 1000) |
| offset | int | Pagination offset |
| severity | string | Filter by severity |
| source_type | string | Filter by source type |
| start_time | datetime | Events after this time |
| end_time | datetime | Events before this time |

---

## Alerts API

### List Alerts

```http
GET /api/v1/alerts
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| status | string | new, acknowledged, resolved, false_positive |
| severity | string | critical, high, medium, low, info |
| category | string | malware, phishing, intrusion, etc. |
| limit | int | Max results |
| offset | int | Pagination offset |

**Response:**

```json
{
  "alerts": [
    {
      "alert_id": "alert_xyz789",
      "title": "Phishing Email Detected",
      "severity": "high",
      "status": "new",
      "category": "phishing",
      "risk_score": 0.85,
      "created_at": "2024-01-15T10:31:00Z"
    }
  ],
  "total": 150,
  "limit": 50,
  "offset": 0
}
```

### Get Alert

```http
GET /api/v1/alerts/{alert_id}
```

### Update Alert Status

```http
PATCH /api/v1/alerts/{alert_id}
```

**Request Body:**

```json
{
  "status": "acknowledged",
  "assigned_to": "analyst@your-org.com",
  "notes": "Investigating this alert"
}
```

### Acknowledge Alert

```http
POST /api/v1/alerts/{alert_id}/acknowledge
```

**Request Body:**

```json
{
  "acknowledged_by": "analyst@your-org.com"
}
```

### Resolve Alert

```http
POST /api/v1/alerts/{alert_id}/resolve
```

**Request Body:**

```json
{
  "resolved_by": "analyst@your-org.com",
  "resolution_notes": "Confirmed phishing, sender blocked",
  "is_false_positive": false
}
```

---

## Incidents API

### Create Incident

```http
POST /api/v1/incidents
```

**Request Body:**

```json
{
  "title": "Phishing Campaign Targeting Finance",
  "description": "Multiple phishing emails targeting finance department",
  "severity": "high",
  "incident_type": "phishing",
  "alert_ids": ["alert_xyz789", "alert_abc123"],
  "affected_users": ["user1@your-org.com", "user2@your-org.com"],
  "owner": "ir-lead@your-org.com"
}
```

**Response:**

```json
{
  "incident_id": "INC-ABC12345",
  "title": "Phishing Campaign Targeting Finance",
  "status": "new",
  "created_at": "2024-01-15T10:35:00Z"
}
```

### Get Incident

```http
GET /api/v1/incidents/{incident_id}
```

### List Incidents

```http
GET /api/v1/incidents?status=investigating&severity=high
```

### Update Incident Status

```http
PATCH /api/v1/incidents/{incident_id}/status
```

**Request Body:**

```json
{
  "status": "investigating",
  "actor": "ir-lead@your-org.com",
  "notes": "Starting investigation"
}
```

### Add Comment

```http
POST /api/v1/incidents/{incident_id}/comments
```

**Request Body:**

```json
{
  "author": "analyst@your-org.com",
  "content": "Identified 5 additional recipients",
  "is_internal": true
}
```

### Add Task

```http
POST /api/v1/incidents/{incident_id}/tasks
```

**Request Body:**

```json
{
  "title": "Block sender domain",
  "description": "Add suspicious-domain.com to email blocklist",
  "assigned_to": "admin@your-org.com",
  "due_date": "2024-01-15T12:00:00Z"
}
```

### Close Incident

```http
POST /api/v1/incidents/{incident_id}/close
```

**Request Body:**

```json
{
  "root_cause": "Phishing campaign using compromised vendor email",
  "lessons_learned": "Implement additional email authentication checks",
  "closed_by": "ir-lead@your-org.com"
}
```

---

## Investigations API

### Create Investigation

```http
POST /api/v1/investigations
```

**Request Body:**

```json
{
  "title": "Phishing Campaign Investigation",
  "incident_id": "INC-ABC12345",
  "template": "phishing",
  "priority": "high"
}
```

### Add Evidence

```http
POST /api/v1/investigations/{investigation_id}/evidence
```

**Request Body:**

```json
{
  "evidence_type": "log_entry",
  "source": "email_gateway",
  "timestamp": "2024-01-15T10:30:00Z",
  "content": {
    "log_message": "Email blocked: malicious URL detected",
    "url": "https://suspicious-site.com/login"
  },
  "relevance_score": 0.9
}
```

### Add Hypothesis

```http
POST /api/v1/investigations/{investigation_id}/hypotheses
```

**Request Body:**

```json
{
  "statement": "Credentials were harvested via fake login page",
  "reasoning": "Multiple users reported entering credentials on linked page"
}
```

### Update Hypothesis

```http
PATCH /api/v1/investigations/{investigation_id}/hypotheses/{hypothesis_id}
```

**Request Body:**

```json
{
  "status": "supported",
  "confidence": 0.85,
  "supporting_evidence": ["evd_abc123", "evd_def456"]
}
```

### Generate Timeline

```http
POST /api/v1/investigations/{investigation_id}/timeline
```

### Close Investigation

```http
POST /api/v1/investigations/{investigation_id}/close
```

**Request Body:**

```json
{
  "findings_summary": "Confirmed credential phishing targeting 10 users",
  "root_cause": "Compromised vendor email account",
  "impact_assessment": "3 users entered credentials, all reset",
  "recommendations": [
    "Implement MFA for all users",
    "Add suspicious-domain.com to blocklist"
  ]
}
```

---

## Agents API

### Get Agent Status

```http
GET /api/v1/agents/status
```

**Response:**

```json
{
  "agents": [
    {
      "agent_id": "email_001",
      "name": "Email Verification Agent",
      "status": "idle",
      "tasks_processed": 1250,
      "last_active": "2024-01-15T10:30:00Z"
    }
  ],
  "total_agents": 12,
  "active_agents": 12
}
```

### Get Agent Metrics

```http
GET /api/v1/agents/{agent_id}/metrics
```

---

## Reports API

### Generate Report

```http
POST /api/v1/reports
```

**Request Body:**

```json
{
  "report_type": "incident_report",
  "format": "pdf",
  "incident_id": "INC-ABC12345",
  "include_timeline": true,
  "include_evidence": true
}
```

**Response:**

```json
{
  "report_id": "rpt_xyz789",
  "status": "generating",
  "estimated_completion": "2024-01-15T10:36:00Z"
}
```

### Download Report

```http
GET /api/v1/reports/{report_id}/download
```

Returns the report file with appropriate Content-Type header.

---

## Health API

### System Health

```http
GET /api/v1/health
```

**Response:**

```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:35:00Z",
  "components": {
    "api": {"status": "healthy", "latency_ms": 5},
    "database": {"status": "healthy", "latency_ms": 10},
    "redis": {"status": "healthy", "latency_ms": 1},
    "kafka": {"status": "healthy", "latency_ms": 3},
    "agents": {"status": "healthy", "active": 12}
  }
}
```

---

## WebSocket API

### Alert Stream

```javascript
// Connect to alert stream
const ws = new WebSocket('wss://api.soc.your-org.com/ws/alerts');

ws.onmessage = (event) => {
  const alert = JSON.parse(event.data);
  console.log('New alert:', alert);
};

// Message format
{
  "message_type": "alert",
  "payload": {
    "alert_id": "alert_xyz789",
    "title": "Phishing Email Detected",
    "severity": "high"
  },
  "timestamp": "2024-01-15T10:31:00Z"
}
```

---

## Error Responses

All errors follow this format:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid severity value",
    "details": {
      "field": "severity",
      "allowed_values": ["critical", "high", "medium", "low", "info"]
    }
  }
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| VALIDATION_ERROR | 400 | Invalid request data |
| AUTHENTICATION_ERROR | 401 | Invalid or missing token |
| AUTHORIZATION_ERROR | 403 | Insufficient permissions |
| NOT_FOUND | 404 | Resource not found |
| RATE_LIMITED | 429 | Too many requests |
| INTERNAL_ERROR | 500 | Server error |

---

## Rate Limits

| Endpoint | Limit |
|----------|-------|
| POST /events | 1000/minute |
| GET /alerts | 100/minute |
| POST /incidents | 50/minute |
| All other endpoints | 200/minute |

Rate limit headers are included in responses:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1705315860
```
