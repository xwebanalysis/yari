import { TestBed } from '@angular/core/testing';

import { I18nService } from './i18n.service';

describe('I18nService', () => {
  it('translates between english and spanish', () => {
    const service = TestBed.inject(I18nService);
    expect(service.t('NAV_DISCOVER')).toBe('DISCOVER');
    service.toggle();
    expect(service.t('NAV_DISCOVER')).toBe('DESCUBRIR');
    expect(service.t('UNKNOWN_KEY')).toBe('UNKNOWN_KEY');
  });
});
