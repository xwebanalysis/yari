import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';

import { ApiEndpoint } from '../../core/api.service';
import { TranslatePipe } from '../../core/translate.pipe';
import { WorkspaceService } from '../../core/workspace.service';
import {
  XwaChartComponent,
  XwaChartDatum,
} from '../../shared/charts/xwa-chart.component';
import { MetricCardComponent } from '../../shared/metric-card.component';
import { StatusBadgeComponent } from '../../shared/status-badge.component';

const METHOD_ORDER = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE'];

@Component({
  selector: 'app-endpoints',
  imports: [FormsModule, TranslatePipe, XwaChartComponent, MetricCardComponent, StatusBadgeComponent],
  templateUrl: './endpoints.component.html',
  styleUrl: './endpoints.component.scss',
})
export class EndpointsComponent implements OnInit {
  readonly workspace = inject(WorkspaceService);

  protected selectedAnalysisId: number | null = null;
  /**
   * Filters are signals: `filtered` is a computed and only re-evaluates when a
   * tracked dependency changes. Plain properties would keep the memoized value
   * under zoneless change detection (only user events would run CD).
   */
  protected readonly protocolFilter = signal('all');
  protected readonly sourceFilter = signal('all');
  protected readonly search = signal('');

  protected readonly protocols = ['all', 'rest', 'graphql', 'grpc'];

  readonly endpoints = computed<ApiEndpoint[]>(() => this.workspace.current()?.endpoints ?? []);

  readonly sources = computed(() =>
    [...new Set(this.endpoints().map((endpoint) => endpoint.source))].sort(),
  );

  readonly filtered = computed(() => {
    const protocol = this.protocolFilter();
    const source = this.sourceFilter();
    const term = this.search().trim().toLowerCase();
    return this.endpoints().filter((endpoint) => {
      if (protocol !== 'all' && endpoint.protocol !== protocol) {
        return false;
      }
      if (source !== 'all' && endpoint.source !== source) {
        return false;
      }
      if (
        term &&
        !`${endpoint.method ?? ''} ${endpoint.path} ${endpoint.host ?? ''} ${endpoint.source}`
          .toLowerCase()
          .includes(term)
      ) {
        return false;
      }
      return true;
    });
  });

  readonly countRest = computed(
    () => this.endpoints().filter((endpoint) => endpoint.protocol === 'rest').length,
  );
  readonly countGraphql = computed(
    () => this.endpoints().filter((endpoint) => endpoint.protocol === 'graphql').length,
  );
  readonly countGrpc = computed(
    () => this.endpoints().filter((endpoint) => endpoint.protocol === 'grpc').length,
  );
  readonly findingCount = computed(() => this.workspace.current()?.findings.length ?? 0);

  readonly methodsChart = computed<XwaChartDatum[]>(() => {
    const counts = new Map<string, number>();
    for (const endpoint of this.endpoints()) {
      const method = (endpoint.method ?? '—').toUpperCase();
      counts.set(method, (counts.get(method) ?? 0) + 1);
    }
    return [...counts.entries()]
      .sort((a, b) => {
        const ia = METHOD_ORDER.indexOf(a[0]);
        const ib = METHOD_ORDER.indexOf(b[0]);
        return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib);
      })
      .map(([label, value]) => ({ label, value }));
  });

  ngOnInit(): void {
    if (!this.workspace.current()) {
      this.workspace.refreshHistory();
    }
  }

  loadSelected(): void {
    if (this.selectedAnalysisId !== null) {
      this.workspace.load(Number(this.selectedAnalysisId));
    }
  }

  resolveAnalysisId(): number | null {
    return this.workspace.current()?.id ?? null;
  }

  paramCount(endpoint: ApiEndpoint): number {
    return endpoint.params?.length ?? 0;
  }
}
