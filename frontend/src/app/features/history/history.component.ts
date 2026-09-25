import { Component, OnInit, computed, inject } from '@angular/core';
import { TranslatePipe } from '../../core/translate.pipe';

import { Analysis, ApiService } from '../../core/api.service';
import { I18nService } from '../../core/i18n.service';
import { ReportService } from '../../core/report.service';
import { WorkspaceService } from '../../core/workspace.service';
import {
  XwaChartColorKey,
  XwaChartComponent,
  XwaChartDatum,
} from '../../shared/charts/xwa-chart.component';
import { ExportActionsComponent } from '../../shared/export-actions.component';
import { FindingListComponent } from '../../shared/finding-list.component';
import { MetricCardComponent } from '../../shared/metric-card.component';
import { SeverityTagComponent } from '../../shared/severity-tag.component';
import { StatusBadgeComponent } from '../../shared/status-badge.component';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'pass'];
const CATEGORY_ORDER = ['injection', 'auth', 'authz', 'session', 'disclosure', 'misconfig'];

@Component({
  selector: 'app-history',
  imports: [
    TranslatePipe,
    XwaChartComponent,
    ExportActionsComponent,
    FindingListComponent,
    MetricCardComponent,
    SeverityTagComponent,
    StatusBadgeComponent,
  ],
  templateUrl: './history.component.html',
  styleUrl: './history.component.scss',
})
export class HistoryComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly report = inject(ReportService);
  private readonly i18n = inject(I18nService);
  readonly workspace = inject(WorkspaceService);

  readonly analysesPerDay = computed<XwaChartDatum[]>(() => {
    const byDay = new Map<string, number>();
    for (const item of this.workspace.analyses()) {
      const day = String(item.created_at || '').slice(0, 10) || 'UNKNOWN';
      byDay.set(day, (byDay.get(day) ?? 0) + 1);
    }
    return [...byDay.entries()]
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([label, value]) => ({ label, value }));
  });

  readonly statusChart = computed<XwaChartDatum[]>(() => {
    const counts = new Map<string, number>();
    for (const item of this.workspace.analyses()) {
      const status = String(item.status || 'UNKNOWN').toUpperCase();
      counts.set(status, (counts.get(status) ?? 0) + 1);
    }
    return [...counts.entries()].map(([label, value]) => ({
      label,
      value,
      color: this.statusColor(label),
    }));
  });

  readonly severityChart = computed<XwaChartDatum[]>(() => {
    const counts = new Map<string, number>();
    for (const finding of this.workspace.current()?.findings ?? []) {
      const severity = String(finding.severity || 'info').toLowerCase();
      counts.set(severity, (counts.get(severity) ?? 0) + 1);
    }
    return [...counts.entries()]
      .sort((a, b) => SEVERITY_ORDER.indexOf(a[0]) - SEVERITY_ORDER.indexOf(b[0]))
      .map(([label, value]) => ({ label, value, color: this.severityColor(label) }));
  });

  readonly categoryChart = computed<XwaChartDatum[]>(() => {
    const counts = new Map<string, number>();
    for (const finding of this.workspace.current()?.findings ?? []) {
      const category = String(finding.category || 'unknown').toLowerCase();
      counts.set(category, (counts.get(category) ?? 0) + 1);
    }
    return [...counts.entries()]
      .sort((a, b) => {
        const ia = CATEGORY_ORDER.indexOf(a[0]);
        const ib = CATEGORY_ORDER.indexOf(b[0]);
        return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib);
      })
      .map(([label, value]) => ({ label, value }));
  });

  private statusColor(status: string): XwaChartColorKey {
    if (status === 'COMPLETED') return 'success';
    if (status === 'RUNNING' || status === 'PENDING') return 'warning';
    if (status === 'FAILED' || status === 'CANCELLED' || status === 'ERROR') return 'critical';
    return 'neutral-strong';
  }

  private severityColor(severity: string): XwaChartColorKey {
    if (severity === 'critical') return 'critical';
    if (severity === 'high') return 'warning';
    if (severity === 'medium') return 'neutral-strong';
    if (severity === 'low') return 'success';
    return 'interactive';
  }

  ngOnInit(): void {
    this.workspace.refreshHistory();
  }

  open(id: number): void {
    this.workspace.load(id);
  }

  remove(id: number): void {
    if (window.confirm(this.i18n.t('CONFIRM_DELETE'))) {
      this.workspace.remove(id);
    }
  }

  removeAll(): void {
    if (this.workspace.analyses().length && window.confirm(this.i18n.t('CONFIRM_DELETE'))) {
      this.workspace.removeAll();
    }
  }

  exportJson(id: number): void {
    this.download(id, 'json');
  }

  exportCsv(id: number): void {
    this.download(id, 'csv');
  }

  exportPdf(analysis: Analysis): void {
    this.report.exportAnalysisPdf(analysis);
  }

  formatDate(value: string | null): string {
    if (!value) {
      return '—';
    }
    return value.replace('T', ' ').slice(0, 19);
  }

  private download(id: number, format: 'json' | 'csv'): void {
    const link = document.createElement('a');
    link.href = this.api.exportUrl(id, format);
    link.rel = 'noopener';
    document.body.appendChild(link);
    link.click();
    link.remove();
  }
}
