import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';

import { ApiService } from './api.service';

describe('ApiService', () => {
  let service: ApiService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(ApiService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  it('requests health from the configured backend port', () => {
    service.health().subscribe();
    const request = httpMock.expectOne((req) => req.url.endsWith(':8050/api/health'));
    expect(request.request.method).toBe('GET');
    request.flush({ status: 'ok', database: 'ok', version: '0.1.0', tool: 'yari' });
  });

  it('posts safe fuzz requests', () => {
    service.fuzz(7, { endpoint_ids: [1, 2], strategy: 'safe' }).subscribe();
    const request = httpMock.expectOne((req) => req.url.endsWith('/api/analyses/7/fuzz'));
    expect(request.request.method).toBe('POST');
    expect(request.request.body).toEqual({ endpoint_ids: [1, 2], strategy: 'safe' });
    request.flush({
      analysis_id: 7,
      strategy: 'safe',
      requests_sent: 2,
      aborted: false,
      abort_reason: null,
      runs: [],
      findings: [],
    });
  });

  it('builds export and websocket URLs', () => {
    expect(service.exportUrl(3, 'csv')).toContain('/api/analyses/3/export?format=csv');
    expect(service.liveUrl('https://api.example.com', { fuzz: true })).toContain(
      '/api/apis/live?target=https%3A%2F%2Fapi.example.com&fuzz=true',
    );
  });
});
