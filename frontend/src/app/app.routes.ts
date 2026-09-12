import { Routes } from '@angular/router';

export const routes: Routes = [
  { path: '', pathMatch: 'full', redirectTo: 'discover' },
  {
    path: 'discover',
    loadComponent: () =>
      import('./features/discover/discover.component').then((m) => m.DiscoverComponent),
  },
  {
    path: 'endpoints',
    loadComponent: () =>
      import('./features/endpoints/endpoints.component').then((m) => m.EndpointsComponent),
  },
  {
    path: 'fuzzing',
    loadComponent: () =>
      import('./features/fuzzing/fuzzing.component').then((m) => m.FuzzingComponent),
  },
  {
    path: 'auth',
    loadComponent: () => import('./features/auth/auth.component').then((m) => m.AuthComponent),
  },
  {
    path: 'history',
    loadComponent: () =>
      import('./features/history/history.component').then((m) => m.HistoryComponent),
  },
  { path: '**', redirectTo: 'discover' },
];
