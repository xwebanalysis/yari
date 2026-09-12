# Yari Frontend — UI Architecture

Status: current as of the Angular 22 zoneless consolidation.

## Stack

| Layer | Choice |
|-------|--------|
| Framework | Angular 22 (standalone components, zoneless — `zone.js` is not a dependency) |
| State | Signals only: `WorkspaceService` + per-component `signal`/`computed` |
| Build | `@angular/build:application` (esbuild) |
| Tests | `@angular/build:unit-test` + Vitest 4 (jsdom) |
| Language | TypeScript 6 (strict templates) |
| Styling | SCSS + Nothing Design tokens |
| PDF | `jspdf` + `jspdf-autotable` (client report) |

Ports follow the XWA convention: frontend `4250`, backend `8050`
(`src/environments/environment.ts` resolves the hostname at runtime).

## Directory layout

```
frontend/
├── public/fonts/                    # self-hosted woff2 (no Google Fonts at runtime)
├── scripts/test.sh                  # npm test wrapper (`--run` accepted and ignored)
└── src/
    ├── styles.scss                  # Nothing Design tokens + typography utilities
    └── app/
        ├── app.*                    # topbar: nav, health status, language/theme
        ├── app.config.ts            # provideRouter, provideHttpClient, global error listeners
        ├── app.routes.ts            # lazy `loadComponent` routes per feature
        ├── core/                    # singleton, framework-level concerns
        │   ├── api.service.ts       # typed REST client + WS URL builder
        │   ├── workspace.service.ts # shared current analysis + history signals
        │   ├── report.service.ts    # client PDF report
        │   ├── i18n.service.ts      # en/es dictionary, `lang` signal
        │   ├── theme.service.ts     # dark/light `currentTheme` signal
        │   └── translate.pipe.ts    # impure `t` pipe (reads the lang signal)
        ├── shared/                  # presentation-only components
        │   ├── metric-card/         # hero number + label
        │   ├── status-badge/        # [ COMPLETED ] with status color
        │   ├── severity-tag/        # severity/result bracket tag
        │   ├── finding-list/        # finding rows + evidence block
        │   ├── export-actions/      # JSON/CSV/PDF buttons
        │   └── terminal/            # live discovery log
        └── features/                # one folder per route
            ├── discover/            # REST + live WS discovery dashboard
            ├── endpoints/           # endpoint table with protocol/source/search filters
            ├── fuzzing/             # safe fuzzing with endpoint picker + findings
            ├── auth/                # JWT/cookie/API-key passive testing
            └── history/             # persisted analyses, exports and detail
```

Rules:

- `core/` never imports from `features/`; `shared/` only receives signal inputs.
- Every REST call is typed in `ApiService`; components never build URLs.
- `WorkspaceService` is the single owner of "current analysis" and history state.

## Runtime data flow

1. `ApiService` reads `environment.apiBaseUrl`/`wsBaseUrl` and exposes typed
   methods: `health`, `discover`, `listAnalyses`, `getAnalysis`,
   `deleteAnalysis`, `deleteAllAnalyses`, `fuzz`, `authTest`, `exportUrl`,
   `liveUrl`.
2. `WorkspaceService` holds `analyses`, `current`, `historyLoading`,
   `detailLoading` and `error` as signals. Feature components read them through
   `computed()` and never copy the data into local mutable fields.
3. REST callbacks write signals (`this.current.set(analysis)`); WebSocket
   callbacks write signals (`this.push()` → `lines.update()`,
   `endpointCount.update()`). Signals schedule change detection themselves, so
   no `ChangeDetectorRef` is required anywhere in this app (audited: every
   `subscribe`, `socket.onmessage`, `setTimeout` and `await` path).
4. `I18nService.lang` and `ThemeService.currentTheme` are signals; the impure
   `t` pipe reads `lang()` during rendering, so toggles re-render existing data.

## Zoneless change detection (mandatory rule)

Yari runs **without zone.js**: Angular only re-renders a view when a signal it
read changes, when a template event fires, or when the view is explicitly
marked. Two consequences drive this codebase:

1. **Signals first.** Render-relevant state must be a signal (or a `computed`).
   This is already the case for the whole app, which is why async discovery,
   fuzzing, auth tests and history render without extra interaction.

2. **`computed()` only tracks signals.** A computed that reads a plain property
   is memoized forever until one of its *signal* dependencies changes, even if
   the plain property was mutated in an event handler. The endpoint filters were
   migrated to signals for exactly this reason:

   ```typescript
   // BAD: `filtered` never recomputes when protocolFilter changes
   protected protocolFilter = 'all';
   readonly filtered = computed(() => this.endpoints().filter(/* reads plain prop */));

   // GOOD: signal dependencies keep the computed live under zoneless CD
   protected readonly protocolFilter = signal('all');
   readonly filtered = computed(() => this.endpoints().filter(/* reads protocolFilter() */));
   ```

   Template bindings for signal filters use `[ngModel]` + `(ngModelChange)` (or
   direct `signal.set(...)` on buttons), never `[(ngModel)]`.

3. **Plain properties in async callbacks** (HttpClient `subscribe`,
   `WebSocket.onmessage`, `setTimeout`, `await` continuations) do not trigger a
   render. If a component ever needs them, inject `ChangeDetectorRef` and call
   `this.cdr.markForCheck()` after each batch of mutations — the same contract
   documented in [azuma/docs/ui-architecture.md](../../azuma/docs/ui-architecture.md)
   and [kensei/docs/ui-architecture.md](../../kensei/docs/ui-architecture.md).
   The current codebase has no such case; new plain-property async state must
   not be introduced.

## Nothing Design rules in this app

- Tokens live only in `src/styles.scss`; fonts are self-hosted (no external
  providers in `index.html`).
- Labels are Space Mono uppercase (`.t-label`); the display font is reserved
  for hero metrics; the dot-matrix background is the sanctioned exception.
- Errors are inline bracket text (`[ERROR: ...]`), never toasts.

## Testing

`npm test` builds the app for the test target and runs Vitest once
(`scripts/test.sh` maps `--run` for suite consistency):

- `core/api.service.spec.ts` — endpoint URLs, fuzz/auth payloads.
- `core/i18n.service.spec.ts` — dictionary, toggle, persistence.
- `shared/severity-tag.component.spec.ts` — label/tone rendering.
- `features/endpoints/endpoints.component.spec.ts` — signal filters recompute
  (regression guard for the zoneless `computed` trap).
- `app.spec.ts` — shell health, navigation and language toggle.

Real-browser validation lives in `e2e/browser_smoke.py` (Playwright +
`e2e/fixture_server.py`); it drives discovery, filters, fuzzing, auth testing,
history/exports and a live WS run against a deterministic fixture. See
`e2e/README.md`.

## Commands

```bash
export PATH="$HOME/.local/share/mise/installs/node/24/bin:$PATH"
npm ci
npm test
npm run build
npm audit --omit=dev
npm start                      # dev server on 0.0.0.0:4250

# browser smoke (app must be running via ./yari.sh local)
python e2e/browser_smoke.py    # use an interpreter with Playwright + Chromium
```
