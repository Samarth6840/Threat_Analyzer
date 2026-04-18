from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether

DARK_BLUE = colors.HexColor('#0a0d1c')
CYAN = colors.HexColor('#00d4ff')
THREAT_RED = colors.HexColor('#c0392b')
ORANGE = colors.HexColor('#e67e22')
LIGHT_GRAY = colors.HexColor('#f5f7fa')
MID_GRAY = colors.HexColor('#8892a4')
BORDER_GRAY = colors.HexColor('#dde3ec')


def _styles():
    return {
        'title': ParagraphStyle('Title', fontName='Helvetica-Bold', fontSize=22, textColor=DARK_BLUE, alignment=TA_CENTER, spaceAfter=4),
        'subtitle': ParagraphStyle('Subtitle', fontName='Helvetica', fontSize=10, textColor=MID_GRAY, alignment=TA_CENTER, spaceAfter=16),
        'h2': ParagraphStyle('H2', fontName='Helvetica-Bold', fontSize=13, textColor=DARK_BLUE, spaceBefore=14, spaceAfter=8),
        'body': ParagraphStyle('Body', fontName='Helvetica', fontSize=10, textColor=colors.HexColor('#333333'), leading=16),
        'footer': ParagraphStyle('Footer', fontName='Helvetica', fontSize=8, textColor=MID_GRAY, alignment=TA_CENTER),
    }


def _table_style(header_color, row_color=LIGHT_GRAY):
    return TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), header_color),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 9),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [row_color, colors.white]),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_GRAY),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ])


def generate_report(results, output_path='incident_report.pdf'):
    doc = SimpleDocTemplate(output_path, pagesize=A4, rightMargin=2*cm, leftMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm)
    S = _styles()
    story = [
        Paragraph('SECURITY INCIDENT REPORT', S['title']),
        Paragraph(f'MapReduce Threat Analysis Engine  |  {datetime.now().strftime("%Y-%m-%d %H:%M UTC")}', S['subtitle']),
        HRFlowable(width='100%', thickness=2, color=CYAN),
        Spacer(1, 0.5*cm),
        Paragraph('Executive Summary', S['h2']),
    ]
    total = results.get('total_requests', 0)
    threats = results.get('total_threats', 0)
    clean = total - threats
    summary_rows = [
        ['Metric', 'Value'],
        ['Total Requests Analyzed', f'{total:,}'],
        ['MapReduce Workers (parallel)', '4 concurrent threads'],
        ['Unique Threat IPs Identified', str(threats)],
        ['Estimated Clean Requests', f'{max(0, clean):,}'],
        ['Brute Force Attackers', str(len(results['brute_force']['flagged']))],
        ['SQL Injection Sources', str(len(results['sqli']['flagged']))],
        ['DDoS / High-Volume Sources', str(len(results['ddos']['flagged']))],
        ['Vulnerability Scanners', str(len(results['scanner']['flagged']))],
    ]
    t = Table(summary_rows, colWidths=[10*cm, 7*cm])
    t.setStyle(_table_style(DARK_BLUE))
    story.extend([t, Spacer(1, 0.6*cm)])
    bf_flagged = results['brute_force']['flagged']
    section = [Paragraph('Brute Force Attackers', S['h2'])]
    if bf_flagged:
        rows = [['IP Address', 'Failed Attempts', 'Severity']]
        for ip, count in sorted(bf_flagged.items(), key=lambda x: -x[1])[:10]:
            severity = 'CRITICAL' if count >= 30 else ('HIGH' if count >= 15 else 'MEDIUM')
            rows.append([ip, str(count), severity])
        t = Table(rows, colWidths=[7*cm, 5*cm, 5*cm])
        t.setStyle(_table_style(THREAT_RED, colors.HexColor('#fff5f5')))
        section.append(t)
    else:
        section.append(Paragraph('No brute force attacks detected in this log sample.', S['body']))
    story.extend([KeepTogether(section), Spacer(1, 0.5*cm)])
    sqli_flagged = results['sqli']['flagged']
    section = [Paragraph('SQL Injection Attempts', S['h2'])]
    if sqli_flagged:
        rows = [['IP Address', 'Unique Payloads Detected', 'Sample URL']]
        for ip, urls in list(sqli_flagged.items())[:8]:
            sample = urls[0][:55] + '...' if urls and len(urls[0]) > 55 else (urls[0] if urls else 'N/A')
            rows.append([ip, str(len(urls)), sample])
        t = Table(rows, colWidths=[4.5*cm, 4.5*cm, 8*cm])
        t.setStyle(_table_style(ORANGE, colors.HexColor('#fffaf5')))
        section.append(t)
    else:
        section.append(Paragraph('No SQL injection attempts detected.', S['body']))
    story.extend([KeepTogether(section), Spacer(1, 0.5*cm)])
    ddos_flagged = results['ddos']['flagged']
    section = [Paragraph('DDoS / High-Volume Sources', S['h2'])]
    if ddos_flagged:
        rows = [['IP Address', 'Peak Requests/Minute', 'Classification']]
        for ip, rpm in sorted(ddos_flagged.items(), key=lambda x: -x[1])[:10]:
            cls = 'Volumetric DDoS' if rpm >= 60 else 'Rate Abuse'
            rows.append([ip, str(rpm), cls])
        t = Table(rows, colWidths=[7*cm, 5*cm, 5*cm])
        t.setStyle(_table_style(colors.HexColor('#8e44ad'), colors.HexColor('#fdf5ff')))
        section.append(t)
    else:
        section.append(Paragraph('No high-volume flooding detected.', S['body']))
    story.extend([KeepTogether(section), Spacer(1, 0.5*cm)])
    scan_flagged = results['scanner']['flagged']
    section = [Paragraph('Vulnerability Scanners', S['h2'])]
    if scan_flagged:
        rows = [['IP Address', 'Sensitive Paths Probed', 'Sample Paths']]
        for ip, paths in list(scan_flagged.items())[:8]:
            sample = ', '.join(paths[:3])
            rows.append([ip, str(len(paths)), sample])
        t = Table(rows, colWidths=[4.5*cm, 4*cm, 8.5*cm])
        t.setStyle(_table_style(colors.HexColor('#16a085'), colors.HexColor('#f0fafa')))
        section.append(t)
    else:
        section.append(Paragraph('No automated scanning activity detected.', S['body']))
    story.extend([KeepTogether(section), Spacer(1, 0.6*cm)])
    story.append(HRFlowable(width='100%', thickness=1, color=BORDER_GRAY))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph('Recommended Actions', S['h2']))
    recs = []
    if bf_flagged:
        recs.append(f'Block {len(bf_flagged)} IP(s) at the firewall or nginx level. Enable account lockout after 5 failed login attempts.')
    if sqli_flagged:
        recs.append(f'Deploy a WAF rule blocking SQL keywords in query parameters. Audit database queries for parameterization — {len(sqli_flagged)} active attacker IP(s) found.')
    if ddos_flagged:
        recs.append(f'Enable rate limiting for {len(ddos_flagged)} IP(s) exceeding 20 requests/minute. Consider Cloudflare or AWS Shield.')
    if scan_flagged:
        recs.append(f'Block {len(scan_flagged)} scanner IP(s). Remove or protect sensitive paths like .env, /admin, /phpmyadmin.')
    if not recs:
        recs.append('No critical threats detected. Continue monitoring and retain logs for baseline analysis.')
    for i, rec in enumerate(recs, 1):
        story.append(Paragraph(f'{i}.  {rec}', S['body']))
        story.append(Spacer(1, 0.2*cm))
    story.append(Spacer(1, 0.8*cm))
    story.append(HRFlowable(width='100%', thickness=1, color=BORDER_GRAY))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph('Auto-generated by the MapReduce Threat Analysis Engine. Analysis performed across 4 parallel MapReduce worker jobs.', S['footer']))
    doc.build(story)
    return output_path
