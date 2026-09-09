export type HealthStatus = 'healthy' | 'degraded' | 'unhealthy' | 'disabled';

export interface SubsystemStatus {
  status: HealthStatus;
  latency_ms?: number;
  details?: Record<string, unknown>;
}

export interface HealthResponse {
  status: 'healthy' | 'degraded' | 'unhealthy';
  app_name: string;
  version: string;
  environment: string;
  timestamp: string;
  uptime_seconds: number;
  services: Record<string, SubsystemStatus>;
}
