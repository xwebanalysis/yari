import { Component, input } from '@angular/core';

import { Finding } from '../core/api.service';
import { TranslatePipe } from '../core/translate.pipe';
import { SeverityTagComponent } from './severity-tag.component';

@Component({
  selector: 'app-finding-list',
  imports: [TranslatePipe, SeverityTagComponent],
  template: `
    @if (findings().length > 0) {
      @for (finding of findings(); track finding.id) {
        <div class="finding-row" [class]="'sev-border-' + finding.severity">
          <div class="finding-head">
            <app-severity-tag [severity]="finding.severity" />
            <span class="t-data">{{ finding.check }}</span>
            <span class="t-label">CVSS {{ finding.cvss_score ?? '—' }}</span>
            <span class="t-label">{{ finding.confidence || '—' }}</span>
          </div>
          <p class="finding-title">{{ finding.title }}</p>
          @if (finding.description) {
            <p class="t-data text-secondary">{{ finding.description }}</p>
          }
          <p class="t-data text-secondary target-url">{{ finding.target_url || '—' }}</p>
          @if (showEvidence()) {
            <details class="evidence">
              <summary class="t-label">{{ 'EVIDENCE' | t }}</summary>
              <pre class="evidence-block">{{ evidenceText(finding) }}</pre>
            </details>
          }
        </div>
      }
    } @else {
      <div class="empty-state t-label">{{ 'NO_FINDINGS' | t }}</div>
    }
  `,
  styles: [
    `
      .finding-head {
        display: flex;
        align-items: center;
        gap: var(--space-sm);
        flex-wrap: wrap;
        margin-bottom: var(--space-xs);
      }
      .finding-title {
        margin-bottom: var(--space-xs);
      }
      .target-url {
        word-break: break-all;
        margin-bottom: var(--space-xs);
      }
      .evidence summary {
        cursor: pointer;
      }
    `,
  ],
})
export class FindingListComponent {
  readonly findings = input<Finding[]>([]);
  readonly showEvidence = input(true);

  evidenceText(finding: Finding): string {
    return JSON.stringify(finding.evidence ?? {}, null, 2);
  }
}
