import { signal, WritableSignal } from '@angular/core';
import { TestBed } from '@angular/core/testing';

import { Analysis, ApiEndpoint } from '../../core/api.service';
import { WorkspaceService } from '../../core/workspace.service';
import { EndpointsComponent } from './endpoints.component';

/** Test-only access to the protected filter signals. */
type FilterSignals = {
  protocolFilter: WritableSignal<string>;
  sourceFilter: WritableSignal<string>;
  search: WritableSignal<string>;
};

const filters = (component: EndpointsComponent) => component as unknown as FilterSignals;

function endpoint(overrides: Partial<ApiEndpoint>): ApiEndpoint {
  return {
    id: 1,
    protocol: 'rest',
    method: 'GET',
    path: '/api/v1/users',
    host: '127.0.0.1',
    params: null,
    auth_required: null,
    source: 'openapi',
    content_types: null,
    version: null,
    ...overrides,
  };
}

const ENDPOINTS: ApiEndpoint[] = [
  endpoint({ id: 1, protocol: 'rest', method: 'GET', path: '/api/v1/users', source: 'openapi' }),
  endpoint({
    id: 2,
    protocol: 'rest',
    method: 'GET',
    path: '/api/v1/users/{user_id}',
    source: 'openapi',
  }),
  endpoint({
    id: 3,
    protocol: 'graphql',
    method: 'POST',
    path: '/graphql',
    source: 'graphql_introspection',
  }),
  endpoint({ id: 4, protocol: 'rest', method: null, path: '/api/echo', source: 'js_crawl' }),
];

describe('EndpointsComponent', () => {
  const workspaceStub = {
    current: signal<Analysis | null>({
      id: 7,
      target: 'http://127.0.0.1:8105',
      status: 'COMPLETED',
      analysis_type: 'api_scan',
      created_at: '2026-09-12T10:00:00',
      started_at: null,
      finished_at: null,
      error_message: null,
      endpoints: ENDPOINTS,
      findings: [],
      fuzz_runs: [],
      auth_tests: [],
    }),
    analyses: signal([]),
    historyLoading: signal(false),
    refreshHistory: () => undefined,
    load: () => undefined,
  };

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [EndpointsComponent],
      providers: [{ provide: WorkspaceService, useValue: workspaceStub }],
    }).compileComponents();
  });

  it('starts with every endpoint visible', () => {
    const component = TestBed.createComponent(EndpointsComponent).componentInstance;
    expect(component.filtered().length).toBe(ENDPOINTS.length);
  });

  it('re-filters when the protocol signal changes (zoneless regression)', () => {
    const component = TestBed.createComponent(EndpointsComponent).componentInstance;

    filters(component).protocolFilter.set('rest');

    const filtered = component.filtered();
    expect(filtered.length).toBe(3);
    expect(filtered.every((item) => item.protocol === 'rest')).toBe(true);
  });

  it('re-filters when the source signal and search term change', () => {
    const component = TestBed.createComponent(EndpointsComponent).componentInstance;

    filters(component).sourceFilter.set('js_crawl');
    expect(component.filtered().map((item) => item.id)).toEqual([4]);

    filters(component).sourceFilter.set('all');
    filters(component).search.set('users');
    expect(component.filtered().map((item) => item.id)).toEqual([1, 2]);
  });
});
