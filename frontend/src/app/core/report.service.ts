import { Injectable } from '@angular/core';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';

import { Analysis } from './api.service';

/** Client-side PDF report (JSON/CSV come from the server-side export endpoint). */
@Injectable({ providedIn: 'root' })
export class ReportService {
  exportAnalysisPdf(analysis: Analysis): void {
    const doc = new jsPDF({ orientation: 'portrait', unit: 'pt', format: 'a4' });

    doc.setFontSize(16);
    doc.setFont('helvetica', 'bold');
    doc.text('YARI - API SECURITY REPORT', 40, 40);

    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    doc.text(`ANALYSIS #${analysis.id}`, 40, 60);
    doc.text(`TARGET: ${analysis.target}`, 40, 74);
    doc.text(`STATUS: ${analysis.status}`, 40, 88);
    doc.text(`CREATED: ${this.format(analysis.created_at)}`, 40, 102);
    doc.text(
      `ENDPOINTS: ${analysis.endpoints.length}  FINDINGS: ${analysis.findings.length}`,
      40,
      116,
    );

    autoTable(doc, {
      startY: 134,
      head: [['PROTO', 'METHOD', 'PATH', 'SOURCE', 'AUTH']],
      body: analysis.endpoints.map((endpoint) => [
        endpoint.protocol.toUpperCase(),
        endpoint.method ?? '-',
        endpoint.path,
        endpoint.source,
        endpoint.auth_required === null ? '?' : endpoint.auth_required ? 'YES' : 'NO',
      ]),
      styles: { fontSize: 7, cellPadding: 2, overflow: 'linebreak' },
      headStyles: { fillColor: [35, 35, 35] },
    });

    autoTable(doc, {
      head: [['SEVERITY', 'CHECK', 'TITLE', 'TARGET', 'CONF']],
      body: analysis.findings.map((finding) => [
        finding.severity.toUpperCase(),
        finding.check ?? '-',
        finding.title,
        finding.target_url ?? '-',
        finding.confidence ?? '-',
      ]),
      styles: { fontSize: 7, cellPadding: 2, overflow: 'linebreak' },
      headStyles: { fillColor: [35, 35, 35] },
    });

    doc.save(`yari-analysis-${analysis.id}.pdf`);
  }

  private format(value: string | null): string {
    if (!value) {
      return '-';
    }
    return value.replace('T', ' ').slice(0, 19);
  }
}
