import { TestBed } from '@angular/core/testing';

import { SeverityTagComponent } from './severity-tag.component';

describe('SeverityTagComponent', () => {
  it('renders the severity label and tone class', async () => {
    const fixture = TestBed.createComponent(SeverityTagComponent);
    fixture.componentRef.setInput('severity', 'high');
    fixture.detectChanges();
    await fixture.whenStable();

    const element = fixture.nativeElement as HTMLElement;
    const tag = element.querySelector('.tag') as HTMLElement;
    expect(tag.classList.contains('sev-high')).toBe(true);
    expect(tag.textContent).toContain('HIGH');
  });
});
