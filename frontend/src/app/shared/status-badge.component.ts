import { Component, computed, input } from '@angular/core';

import { TranslatePipe } from '../core/translate.pipe';

@Component({
  selector: 'app-status-badge',
  imports: [TranslatePipe],
  template: `<span class="tag" [class]="toneClass()">[{{ statusKey() | t }}]</span>`,
  styles: [
    `
      .tag {
        display: inline-block;
        font-family: var(--font-data);
        font-size: 10px;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        padding: 2px 6px;
        border-radius: 3px;
        border: 1px solid var(--border-visible);
        color: var(--text-secondary);
        white-space: nowrap;
      }
      .status-completed { color: var(--success); border-color: var(--success); }
      .status-running { color: var(--warning); border-color: var(--warning); }
      .status-error { color: var(--accent); border-color: var(--accent); }
      .status-cancelled { color: var(--text-disabled); }
      .status-aborted { color: var(--accent); border-color: var(--accent); }
    `,
  ],
})
export class StatusBadgeComponent {
  readonly status = input.required<string>();
  readonly statusKey = computed(() => `ST_${(this.status() || 'PENDING').toUpperCase()}`);
  readonly toneClass = computed(() => `status-${(this.status() || '').toLowerCase()}`);
}
