import { Component, OnDestroy, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';

import { ApiService, DiscoverResponse, WsEvent } from '../../core/api.service';
import { TranslatePipe } from '../../core/translate.pipe';
import { WorkspaceService } from '../../core/workspace.service';
import { MetricCardComponent } from '../../shared/metric-card.component';
import { TerminalComponent, TerminalLine } from '../../shared/terminal.component';

@Component({
  selector: 'app-discover',
  imports: [
    FormsModule,
    RouterLink,
    TranslatePipe,
    MetricCardComponent,
    TerminalComponent,
  ],
  templateUrl: './discover.component.html',
  styleUrl: './discover.component.scss',
})
export class DiscoverComponent implements OnDestroy {
  private readonly api = inject(ApiService);
  private readonly workspace = inject(WorkspaceService);

  protected target = '';
  protected maxBundles = 10;
  protected live = true;

  protected readonly loading = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly completed = signal(false);
  protected readonly lines = signal<TerminalLine[]>([]);
  protected readonly endpointCount = signal(0);
  protected readonly findingCount = signal(0);
  protected readonly probes = signal(0);
  protected readonly grpcMode = signal<string | null>(null);
  protected readonly analysisId = signal<number | null>(null);

  private socket: WebSocket | null = null;

  run(): void {
    const target = this.target.trim();
    if (!target || this.loading()) {
      return;
    }
    this.reset();
    this.loading.set(true);
    if (this.live) {
      this.runLive(target);
    } else {
      this.runSync(target);
    }
  }

  stop(): void {
    this.socket?.close();
    this.socket = null;
    this.loading.set(false);
  }

  ngOnDestroy(): void {
    this.socket?.close();
  }

  private runSync(target: string): void {
    this.api.discover(target, this.maxBundles).subscribe({
      next: (response: DiscoverResponse) => {
        this.applyAnalysis(response);
        this.loading.set(false);
      },
      error: (err) => this.fail(err),
    });
  }

  private runLive(target: string): void {
    const socket = new WebSocket(
      this.api.liveUrl(target, { fuzz: false }),
    );
    this.socket = socket;

    socket.onmessage = (message) => {
      this.handleEvent(JSON.parse(message.data as string) as WsEvent);
    };
    socket.onerror = () => {
      this.push('error', 'WEBSOCKET ERROR - TRY SYNC MODE');
      this.loading.set(false);
    };
    socket.onclose = () => {
      this.loading.set(false);
    };
  }

  private handleEvent(event: WsEvent): void {
    const payload = event.payload ?? {};
    switch (event.type) {
      case 'analysis_started':
        this.analysisId.set(Number(event.analysis_id));
        this.push('info', `ANALYSIS #${event.analysis_id} STARTED`);
        break;
      case 'analysis_progress':
        this.probes.update((n) => n + 1);
        this.push('info', `[${String(payload['phase'] ?? '')}] ${String(payload['message'] ?? '')}`);
        break;
      case 'item_found': {
        if (payload['kind'] === 'endpoint') {
          this.endpointCount.update((n) => n + 1);
          const label = [payload['protocol'], payload['method'], payload['path']]
            .filter(Boolean)
            .join(' ');
          this.push('success', `ENDPOINT ${label}`);
        } else if (payload['kind'] === 'finding') {
          this.findingCount.update((n) => n + 1);
          this.push(
            'warning',
            `FINDING [${String(payload['severity'] ?? '').toUpperCase()}] ${String(payload['title'] ?? '')}`,
          );
        }
        break;
      }
      case 'analysis_completed': {
        const id = Number(event.analysis_id);
        this.analysisId.set(id);
        this.grpcMode.set(String(payload['grpc_mode'] ?? 'n/a'));
        this.push(
          'success',
          `COMPLETED: ${payload['endpoint_count']} ENDPOINT(S), ${payload['finding_count']} FINDING(S)`,
        );
        this.completed.set(true);
        this.workspace.load(id);
        this.socket?.close();
        break;
      }
      case 'analysis_error':
        this.push('error', `ERROR: ${String(payload['message'] ?? 'unknown')}`);
        this.error.set(String(payload['message'] ?? 'Discovery failed.'));
        this.socket?.close();
        break;
      default:
        if (event.type === 'log') {
          this.push('info', String(payload['message'] ?? ''));
        }
        break;
    }
  }

  private applyAnalysis(response: DiscoverResponse): void {
    this.workspace.setCurrent(response.analysis);
    this.workspace.refreshHistory();
    this.endpointCount.set(response.endpoint_count);
    this.findingCount.set(response.finding_count);
    this.grpcMode.set(null);
    this.analysisId.set(response.analysis.id);
    this.completed.set(true);
    this.push(
      'success',
      `DISCOVERY COMPLETED: ${response.endpoint_count} ENDPOINT(S), ${response.finding_count} FINDING(S)`,
    );
  }

  private fail(err: unknown): void {
    const httpError = err as { error?: { error?: { message?: string } }; message?: string };
    const message =
      httpError?.error?.error?.message ?? httpError?.message ?? 'Discovery request failed.';
    this.error.set(message);
    this.push('error', `ERROR: ${message}`);
    this.loading.set(false);
  }

  private push(tone: TerminalLine['tone'], text: string): void {
    const ts = new Date().toTimeString().slice(0, 8);
    this.lines.update((lines) => [...lines, { ts, text, tone }]);
  }

  private reset(): void {
    this.error.set(null);
    this.completed.set(false);
    this.lines.set([]);
    this.endpointCount.set(0);
    this.findingCount.set(0);
    this.probes.set(0);
    this.grpcMode.set(null);
    this.analysisId.set(null);
    this.socket?.close();
    this.socket = null;
  }
}
