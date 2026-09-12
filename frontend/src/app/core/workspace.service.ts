import { Injectable, inject, signal } from '@angular/core';

import { Analysis, AnalysisListItem, ApiService } from './api.service';

/** Shared current-analysis state across feature pages. */
@Injectable({ providedIn: 'root' })
export class WorkspaceService {
  private readonly api = inject(ApiService);

  readonly analyses = signal<AnalysisListItem[]>([]);
  readonly current = signal<Analysis | null>(null);
  readonly historyLoading = signal(false);
  readonly detailLoading = signal(false);
  readonly error = signal<string | null>(null);

  refreshHistory(): void {
    this.historyLoading.set(true);
    this.api.listAnalyses().subscribe({
      next: (rows) => {
        this.analyses.set(rows);
        this.historyLoading.set(false);
      },
      error: (err) => {
        this.error.set(this.messageOf(err));
        this.historyLoading.set(false);
      },
    });
  }

  load(id: number): void {
    this.detailLoading.set(true);
    this.api.getAnalysis(id).subscribe({
      next: (analysis) => {
        this.current.set(analysis);
        this.detailLoading.set(false);
      },
      error: (err) => {
        this.error.set(this.messageOf(err));
        this.detailLoading.set(false);
      },
    });
  }

  setCurrent(analysis: Analysis): void {
    this.current.set(analysis);
  }

  remove(id: number): void {
    this.api.deleteAnalysis(id).subscribe({
      next: () => {
        if (this.current()?.id === id) {
          this.current.set(null);
        }
        this.refreshHistory();
      },
      error: (err) => this.error.set(this.messageOf(err)),
    });
  }

  removeAll(): void {
    this.api.deleteAllAnalyses().subscribe({
      next: () => {
        this.current.set(null);
        this.refreshHistory();
      },
      error: (err) => this.error.set(this.messageOf(err)),
    });
  }

  clearError(): void {
    this.error.set(null);
  }

  private messageOf(err: unknown): string {
    const httpError = err as { error?: { error?: { message?: string } }; message?: string };
    return httpError?.error?.error?.message ?? httpError?.message ?? 'Request failed.';
  }
}
