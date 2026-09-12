import { Component, computed, input } from '@angular/core';

import { TranslatePipe } from '../core/translate.pipe';

@Component({
  selector: 'app-severity-tag',
  imports: [TranslatePipe],
  template: `<span class="tag" [class]="toneClass()">{{ severityKey() | t }}</span>`,
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
      .sev-critical,
      .sev-high {
        color: var(--accent);
        border-color: var(--accent);
      }
      .sev-medium {
        color: var(--warning);
        border-color: var(--warning);
      }
      .sev-low {
        color: var(--interactive);
        border-color: var(--interactive);
      }
      .sev-info,
      .sev-pass {
        color: var(--text-secondary);
      }
    `,
  ],
})
export class SeverityTagComponent {
  readonly severity = input.required<string>();
  readonly toneClass = computed(() => `sev-${(this.severity() || 'info').toLowerCase()}`);
  readonly severityKey = computed(() => `SEV_${(this.severity() || 'info').toUpperCase()}`);
}
