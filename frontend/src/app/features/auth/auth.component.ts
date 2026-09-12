import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';

import { ApiService, AuthTestResponse } from '../../core/api.service';
import { TranslatePipe } from '../../core/translate.pipe';
import { WorkspaceService } from '../../core/workspace.service';
import { MetricCardComponent } from '../../shared/metric-card.component';
import { SeverityTagComponent } from '../../shared/severity-tag.component';
import { StatusBadgeComponent } from '../../shared/status-badge.component';

@Component({
  selector: 'app-auth',
  imports: [
    FormsModule,
    TranslatePipe,
    MetricCardComponent,
    SeverityTagComponent,
    StatusBadgeComponent,
  ],
  templateUrl: './auth.component.html',
  styleUrl: './auth.component.scss',
})
export class AuthComponent implements OnInit {
  private readonly api = inject(ApiService);
  readonly workspace = inject(WorkspaceService);

  protected token = '';
  protected cookie = '';
  protected selectedAnalysisId: number | null = null;

  protected readonly running = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly response = signal<AuthTestResponse | null>(null);

  readonly tests = computed(() => this.response()?.tests ?? []);
  readonly findings = computed(() => this.response()?.findings ?? []);
  readonly problemCount = computed(
    () => this.tests().filter((test) => test.result !== 'pass').length,
  );

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

  run(): void {
    const analysis = this.workspace.current();
    if (!analysis || this.running()) {
      return;
    }
    if (!this.token.trim() && !this.cookie.trim()) {
      this.error.set('Provide a token or a cookie to analyze.');
      return;
    }
    this.running.set(true);
    this.error.set(null);
    this.response.set(null);

    this.api.authTest(analysis.id, this.token.trim() || null, this.cookie.trim() || null).subscribe({
      next: (response) => {
        this.response.set(response);
        this.running.set(false);
        this.workspace.load(analysis.id);
      },
      error: (err) => {
        this.error.set(this.messageOf(err));
        this.running.set(false);
      },
    });
  }

  detailLabel(details: Record<string, unknown> | null): string {
    if (!details) {
      return '—';
    }
    const title = details['title'];
    return typeof title === 'string' ? title : JSON.stringify(details);
  }

  private messageOf(err: unknown): string {
    const httpError = err as { error?: { error?: { message?: string } }; message?: string };
    return httpError?.error?.error?.message ?? httpError?.message ?? 'Auth test failed.';
  }
}
