import { Pipe, PipeTransform, inject } from '@angular/core';

import { I18nService } from './i18n.service';

/**
 * Translation pipe. Impure on purpose: language switches must update every
 * label without requiring an input change on each usage site.
 */
@Pipe({ name: 't', pure: false })
export class TranslatePipe implements PipeTransform {
  private readonly i18n = inject(I18nService);

  transform(key: string): string {
    return this.i18n.t(key);
  }
}
