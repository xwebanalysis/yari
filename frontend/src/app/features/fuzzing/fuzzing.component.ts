import { Component, OnInit, computed, effect, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';

import { ApiService, ApiEndpoint, FuzzResponse } from '../../core/api.service';
import { TranslatePipe } from '../../core/translate.pipe';
import { WorkspaceService } from '../../core/workspace.service';
import { MetricCardComponent } from '../../shared/metric-card.component';
import { SeverityTagComponent } from '../../shared/severity-tag.component';
import { StatusBadgeComponent } from '../../shared/status-badge.component';

@Component({
  selector: 'app-fuzzing',
  imports: [
    FormsModule,
    TranslatePipe,
    MetricCardComponent,
    SeverityTagComponent,
    StatusBadgeComponent,
  ],
  templateUrl: './fuzzing.component.html',
  styleUrl: './fuzzing.component.scss',
})
export class FuzzingComponent implements OnInit {
  private readonly api = inject(ApiService);
  readonly workspace = inject(WorkspaceService);

  protected strategy = 'safe';
  protected token = '';
  protected cookie = '';
  protected allowMutations = false;

  protected readonly strategies: { id: string; key: string }[] = [
    { id: 'safe', key: 'STRATEGY_SAFE' },
    { id: 'reflect', key: 'STRATEGY_REFLECT' },
    { id: 'error_based', key: 'STRATEGY_ERROR_BASED' },
    { id: 'authz_matrix', key: 'STRATEGY_AUTHZ_MATRIX' },
    { id: 'rate_limit', key: 'STRATEGY_RATE_LIMIT' },
  ];

  protected readonly running = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly result = signal<FuzzResponse | null>(null);
  private readonly selectedIds = signal<Set<number>>(new Set());

  readonly endpoints = computed<ApiEndpoint[]>(() => this.workspace.current()?.endpoints ?? []);
  readonly findings = computed(() => this.result()?.findings ?? []);
  readonly selectedCount = computed(() => this.selectedIds().size);

  constructor() {
    effect(() => {
      if (this.workspace.current()) {
        this.selectDefaultEndpoints();
      }
    });
  }

  ngOnInit(): void {
    if (!this.workspace.current()) {
      this.workspace.refreshHistory();
    }
  }

  isSelected(id: number): boolean {
    return this.selectedIds().has(id);
  }

  toggle(endpoint: ApiEndpoint): void {
    const next = new Set(this.selectedIds());
    if (next.has(endpoint.id)) {
      next.delete(endpoint.id);
    } else {
      next.add(endpoint.id);
    }
    this.selectedIds.set(next);
  }

  selectAll(): void {
    this.selectedIds.set(new Set(this.endpoints().map((endpoint) => endpoint.id)));
  }

  clearAll(): void {
    this.selectedIds.set(new Set());
  }

  loadSelected(): void {
    const id = this.selectedAnalysisId;
    if (id !== null) {
      this.workspace.load(Number(id));
    }
  }

  protected selectedAnalysisId: number | null = null;

  run(): void {
    const analysis = this.workspace.current();
    if (!analysis || this.running()) {
      return;
    }
    const ids = [...this.selectedIds()];
    if (ids.length === 0) {
      this.error.set('Select at least one endpoint.');
      return;
    }

    this.running.set(true);
    this.error.set(null);
    this.result.set(null);

    this.api
      .fuzz(analysis.id, {
        endpoint_ids: ids,
        strategy: this.strategy,
        allow_mutations: this.allowMutations,
        auth_token: this.token.trim() || undefined,
        auth_cookie: this.cookie.trim() || undefined,
      })
      .subscribe({
        next: (response) => {
          this.result.set(response);
          this.running.set(false);
          this.workspace.load(analysis.id);
        },
        error: (err) => {
          this.error.set(this.messageOf(err));
          this.running.set(false);
        },
      });
  }

  evidenceText(evidence: Record<string, unknown> | null): string {
    if (!evidence) {
      return '—';
    }
    return JSON.stringify(evidence, null, 2);
  }

  private selectDefaultEndpoints(): void {
    const selected = this.endpoints()
      .filter((endpoint) => {
        const method = (endpoint.method ?? 'GET').toUpperCase();
        return ['GET', 'HEAD', 'OPTIONS'].includes(method);
      })
      .slice(0, 10)
      .map((endpoint) => endpoint.id);
    this.selectedIds.set(new Set(selected));
  }

  private messageOf(err: unknown): string {
    const httpError = err as { error?: { error?: { message?: string } }; message?: string };
    return httpError?.error?.error?.message ?? httpError?.message ?? 'Fuzz run failed.';
  }
}
