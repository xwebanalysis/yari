import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of } from 'rxjs';

import { App } from './app';
import { ApiService } from './core/api.service';

const apiStub = {
  health: () => of({ status: 'ok', database: 'ok', version: '0.1.0', tool: 'yari' }),
};

describe('App', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [App],
      providers: [provideRouter([]), { provide: ApiService, useValue: apiStub }],
    }).compileComponents();
  });

  it('should create the app', () => {
    const fixture = TestBed.createComponent(App);
    expect(fixture.componentInstance).toBeTruthy();
  });

  it('should render the shell and mark the backend online', async () => {
    const fixture = TestBed.createComponent(App);
    fixture.detectChanges();
    await fixture.whenStable();
    const compiled = fixture.nativeElement as HTMLElement;

    expect(compiled.querySelector('.brand h1')?.textContent).toContain('YARI');
    expect(compiled.querySelector('.nav-links a')?.textContent).toContain('DISCOVER');
    expect(compiled.querySelector('.status-label')?.textContent).toContain('BACKEND ONLINE');
  });

  it('should switch language from the topbar', async () => {
    const fixture = TestBed.createComponent(App);
    fixture.detectChanges();
    await fixture.whenStable();

    const compiled = fixture.nativeElement as HTMLElement;
    const toggle = compiled.querySelector('.lang-toggle-btn') as HTMLButtonElement;
    expect(toggle.textContent).toContain('ES');

    toggle.click();
    fixture.detectChanges();
    await fixture.whenStable();

    expect(compiled.querySelector('.nav-links a')?.textContent).toContain('DESCUBRIR');
    expect(localStorage.getItem('yari-lang')).toBe('es');
  });
});
