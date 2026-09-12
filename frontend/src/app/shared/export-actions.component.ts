import { Component, input, output } from '@angular/core';

import { TranslatePipe } from '../core/translate.pipe';

@Component({
  selector: 'app-export-actions',
  imports: [TranslatePipe],
  template: `
    <div class="export-actions">
      <button type="button" class="btn-ghost" [disabled]="disabled()" (click)="exportJson.emit()">
        {{ 'EXPORT_JSON' | t }}
      </button>
      <button type="button" class="btn-ghost" [disabled]="disabled()" (click)="exportCsv.emit()">
        {{ 'EXPORT_CSV' | t }}
      </button>
      <button type="button" class="btn-ghost" [disabled]="disabled()" (click)="exportPdf.emit()">
        {{ 'EXPORT_PDF' | t }}
      </button>
    </div>
  `,
  styles: [
    `
      .export-actions {
        display: flex;
        gap: var(--space-sm);
        flex-wrap: wrap;
      }
    `,
  ],
})
export class ExportActionsComponent {
  readonly disabled = input(false);
  readonly exportJson = output<void>();
  readonly exportCsv = output<void>();
  readonly exportPdf = output<void>();
}
