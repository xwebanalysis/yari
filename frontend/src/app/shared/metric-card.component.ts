import { Component, computed, input } from '@angular/core';

import { TranslatePipe } from '../core/translate.pipe';

@Component({
  selector: 'app-metric-card',
  imports: [TranslatePipe],
  template: `
    <div class="metric-card">
      <span class="t-label">{{ labelKey() | t }}</span>
      <span class="metric-value" [class]="valueClass()">{{ value() }}</span>
      @if (hint()) {
        <span class="t-label metric-hint">{{ hint() }}</span>
      }
    </div>
  `,
  styles: [
    `
      .metric-card {
        display: flex;
        flex-direction: column;
        gap: var(--space-xs);
        padding: var(--space-md);
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 8px;
      }
      .metric-value {
        font-family: var(--font-data);
        font-size: var(--display-md);
        line-height: 1;
        color: var(--text-display);
      }
      .metric-value.tone-accent { color: var(--accent); }
      .metric-value.tone-success { color: var(--success); }
      .metric-value.tone-warning { color: var(--warning); }
      .metric-hint { color: var(--text-disabled); }
    `,
  ],
})
export class MetricCardComponent {
  readonly labelKey = input.required<string>();
  readonly value = input.required<string | number>();
  readonly hint = input<string>('');
  readonly tone = input<'' | 'accent' | 'success' | 'warning'>('');
  readonly valueClass = computed(() => (this.tone() ? `tone-${this.tone()}` : ''));
}
