import { Component, OnDestroy, OnInit, inject, signal } from '@angular/core';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';

import { ApiService } from './core/api.service';
import { I18nService } from './core/i18n.service';
import { ThemeService } from './core/theme.service';
import { TranslatePipe } from './core/translate.pipe';

@Component({
  selector: 'app-root',
  imports: [RouterOutlet, RouterLink, RouterLinkActive, TranslatePipe],
  templateUrl: './app.html',
  styleUrl: './app.scss',
})
export class App implements OnInit, OnDestroy {
  private readonly api = inject(ApiService);
  readonly theme = inject(ThemeService);
  readonly i18n = inject(I18nService);

  readonly backendOnline = signal(false);
  private healthTimer: ReturnType<typeof setInterval> | null = null;

  ngOnInit(): void {
    this.theme.initTheme();
    this.i18n.init();
    this.checkHealth();
    this.healthTimer = setInterval(() => this.checkHealth(), 15000);
  }

  ngOnDestroy(): void {
    if (this.healthTimer !== null) {
      clearInterval(this.healthTimer);
    }
  }

  toggleTheme(): void {
    this.theme.toggleTheme();
  }

  toggleLang(): void {
    this.i18n.toggle();
  }

  private checkHealth(): void {
    this.api.health().subscribe({
      next: () => this.backendOnline.set(true),
      error: () => this.backendOnline.set(false),
    });
  }
}
