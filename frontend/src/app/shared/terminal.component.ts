import { Component, input } from '@angular/core';

import { TranslatePipe } from '../core/translate.pipe';

export interface TerminalLine {
  ts: string;
  text: string;
  tone?: 'info' | 'success' | 'warning' | 'error';
}

@Component({
  selector: 'app-terminal',
  imports: [TranslatePipe],
  template: `
    <div class="terminal">
      <div class="terminal-head">
        <span class="t-label">{{ titleKey() | t }}</span>
        <span class="t-label">{{ lines().length }} EVENT(S)</span>
      </div>
      <div class="terminal-body">
        @for (line of lines(); track $index) {
          <div class="terminal-line" [class]="'tone-' + (line.tone ?? 'info')">
            <span class="t-data term-ts">{{ line.ts }}</span>
            <span class="t-data term-text">{{ line.text }}</span>
          </div>
        } @empty {
          <div class="t-label term-empty">{{ 'WAITING_EVENTS' | t }}</div>
        }
      </div>
    </div>
  `,
  styles: [
    `
      .terminal {
        border: 1px solid var(--border-visible);
        border-radius: 8px;
        overflow: hidden;
        background: var(--surface);
      }
      .terminal-head {
        display: flex;
        justify-content: space-between;
        padding: var(--space-sm) var(--space-md);
        border-bottom: 1px solid var(--border);
        background: var(--surface-raised);
      }
      .terminal-body {
        max-height: 320px;
        overflow-y: auto;
        padding: var(--space-sm) var(--space-md);
      }
      .terminal-line {
        display: flex;
        gap: var(--space-md);
        padding: 2px 0;
        font-size: var(--caption);
      }
      .term-ts {
        color: var(--text-disabled);
        flex: 0 0 auto;
      }
      .term-text {
        color: var(--text-primary);
        word-break: break-word;
      }
      .tone-success .term-text { color: var(--success); }
      .tone-warning .term-text { color: var(--warning); }
      .tone-error .term-text { color: var(--accent); }
      .term-empty {
        padding: var(--space-md) 0;
        color: var(--text-disabled);
      }
    `,
  ],
})
export class TerminalComponent {
  readonly titleKey = input<string>('DISCOVERY_LOG');
  readonly lines = input<TerminalLine[]>([]);
}
