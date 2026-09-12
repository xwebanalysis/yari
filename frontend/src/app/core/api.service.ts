import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

import { environment } from '../../environments/environment';

export type Severity = 'pass' | 'info' | 'low' | 'medium' | 'high' | 'critical';
export type Protocol = 'rest' | 'graphql' | 'grpc';

export interface EndpointParam {
  name?: string;
  in?: string;
  type?: string | null;
  required?: boolean;
  operation?: string;
  [key: string]: unknown;
}

export interface ApiEndpoint {
  id: number;
  protocol: Protocol;
  method: string | null;
  path: string;
  host: string | null;
  params: EndpointParam[] | null;
  auth_required: boolean | null;
  source: string;
  content_types: string[] | null;
  version: string | null;
}

export interface Finding {
  id: number;
  tool: string;
  severity: Severity;
  category: string | null;
  check: string | null;
  title: string;
  description: string | null;
  target_url: string | null;
  evidence: Record<string, unknown> | null;
  cvss_score: number | null;
  confidence: string | null;
  detected_at: string | null;
}

export interface FuzzRun {
  id: number;
  endpoint_id: number | null;
  strategy: string;
  requests_sent: number;
  findings_count: number;
  status: string;
  abort_reason: string | null;
  started_at: string | null;
  finished_at: string | null;
}

export interface AuthTest {
  id: number;
  mechanism: string;
  check: string;
  result: Severity;
  details: Record<string, unknown> | null;
  created_at: string | null;
}

export interface Analysis {
  id: number;
  target: string;
  status: string;
  analysis_type: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  error_message: string | null;
  endpoints: ApiEndpoint[];
  findings: Finding[];
  fuzz_runs: FuzzRun[];
  auth_tests: AuthTest[];
}

export interface AnalysisListItem {
  id: number;
  target: string;
  status: string;
  analysis_type: string;
  created_at: string;
  finished_at: string | null;
  endpoint_count: number;
  finding_count: number;
  high_count: number;
  fuzz_run_count: number;
  auth_test_count: number;
}

export interface DiscoverResponse {
  analysis: Analysis;
  endpoint_count: number;
  finding_count: number;
  by_protocol: Record<string, number>;
}

export interface FuzzResponse {
  analysis_id: number;
  strategy: string;
  requests_sent: number;
  aborted: boolean;
  abort_reason: string | null;
  runs: FuzzRun[];
  findings: Finding[];
}

export interface AuthTestResponse {
  analysis_id: number;
  requests_sent: number;
  tests: AuthTest[];
  findings: Finding[];
}

export interface FuzzRequest {
  endpoint_ids?: number[];
  strategy: string;
  allow_mutations?: boolean;
  auth_token?: string;
  auth_cookie?: string;
}

export interface WsEvent {
  seq: number;
  type: string;
  tool: string;
  analysis_id: string;
  ts: string;
  payload: Record<string, unknown>;
}

export interface HealthResponse {
  status: string;
  database: string;
  version: string;
  tool: string;
}

@Injectable({ providedIn: 'root' })
export class ApiService {
  private readonly http = inject(HttpClient);
  readonly apiUrl = environment.apiBaseUrl;
  private readonly wsUrl = environment.wsBaseUrl;

  health(): Observable<HealthResponse> {
    return this.http.get<HealthResponse>(`${this.apiUrl}/api/health`);
  }

  discover(target: string, maxBundles = 10): Observable<DiscoverResponse> {
    return this.http.post<DiscoverResponse>(`${this.apiUrl}/api/endpoints/discover`, {
      target,
      max_bundles: maxBundles,
    });
  }

  listAnalyses(): Observable<AnalysisListItem[]> {
    return this.http.get<AnalysisListItem[]>(`${this.apiUrl}/api/analyses`);
  }

  getAnalysis(id: number): Observable<Analysis> {
    return this.http.get<Analysis>(`${this.apiUrl}/api/analyses/${id}`);
  }

  deleteAnalysis(id: number): Observable<void> {
    return this.http.delete<void>(`${this.apiUrl}/api/analyses/${id}`);
  }

  deleteAllAnalyses(): Observable<void> {
    return this.http.delete<void>(`${this.apiUrl}/api/analyses`);
  }

  fuzz(id: number, request: FuzzRequest): Observable<FuzzResponse> {
    return this.http.post<FuzzResponse>(`${this.apiUrl}/api/analyses/${id}/fuzz`, request);
  }

  authTest(id: number, token: string | null, cookie: string | null): Observable<AuthTestResponse> {
    return this.http.post<AuthTestResponse>(`${this.apiUrl}/api/analyses/${id}/auth-test`, {
      token: token || null,
      cookie: cookie || null,
    });
  }

  /** Server-side export URL (Content-Disposition attachment). */
  exportUrl(id: number, format: 'json' | 'csv' = 'json'): string {
    return `${this.apiUrl}/api/analyses/${id}/export?format=${format}`;
  }

  /** Live WebSocket endpoint (target URL-encoded). */
  liveUrl(target: string, options: { fuzz?: boolean; strategy?: string } = {}): string {
    const params = new URLSearchParams({ target });
    if (options.fuzz) {
      params.set('fuzz', 'true');
    }
    if (options.strategy) {
      params.set('strategy', options.strategy);
    }
    return `${this.wsUrl}/api/apis/live?${params.toString()}`;
  }
}
