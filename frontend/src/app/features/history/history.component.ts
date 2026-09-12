import { Component, OnInit, inject } from '@angular/core';
import { TranslatePipe } from '../../core/translate.pipe';

import { Analysis, ApiService } from '../../core/api.service';
import { I18nService } from '../../core/i18n.service';
import { ReportService } from '../../core/report.service';
import { WorkspaceService } from '../../core/workspace.service';
import { ExportActionsComponent } from '../../shared/export-actions.component';
import { FindingListComponent } from '../../shared/finding-list.component';
import { MetricCardComponent } from '../../shared/metric-card.component';
import { SeverityTagComponent } from '../../shared/severity-tag.component';
import { StatusBadgeComponent } from '../../shared/status-badge.component';

@Component({
  selector: 'app-history',
  imports: [
    TranslatePipe,
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
