export * from './health';

export type SeverityLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface BaseEntity {
  id: string;
  created_at: string;
  updated_at: string;
}

export interface SecurityAlert extends BaseEntity {
  title: string;
  severity: SeverityLevel;
  source_domain: string;
  source_ip?: string;
  destination_ip?: string;
  description: string;
  rule_id?: string;
}

export interface IncidentDossier extends BaseEntity {
  title: string;
  severity: SeverityLevel;
  confidence_score: number;
  status: 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'DISMISSED';
  summary: string;
  mitre_techniques: string[];
  evidence_count: number;
}
