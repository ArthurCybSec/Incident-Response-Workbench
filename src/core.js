/* Incident Response Workbench — parser and detection engine.
 * No network access or third-party dependencies. All analysis is local.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.IRWCore = api;
})(typeof window !== 'undefined' ? window : null, function () {
  'use strict';

  const MAX_EVENTS = 10000;
  const MAX_FILE_BYTES = 5 * 1024 * 1024;
  const severityRank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

  function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, char => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    })[char]);
  }

  function decodeXml(value) {
    return String(value ?? '').replace(/&#(x[0-9a-f]+|\d+);|&(amp|lt|gt|quot|apos);/gi, (match, numeric, named) => {
      if (numeric) {
        const code = numeric[0].toLowerCase() === 'x' ? parseInt(numeric.slice(1), 16) : parseInt(numeric, 10);
        return Number.isFinite(code) && code <= 0x10ffff ? String.fromCodePoint(code) : match;
      }
      return { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" }[named.toLowerCase()] || match;
    });
  }

  function parseTimestamp(value, year = new Date().getFullYear()) {
    if (!value) return null;
    const raw = String(value).trim();
    const brazilian = raw.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?/);
    if (brazilian && Number(brazilian[2]) <= 12) {
      const [, day, month, yyyy, hour, minute, second = '00'] = brazilian;
      const date = new Date(Number(yyyy), Number(month) - 1, Number(day), Number(hour), Number(minute), Number(second));
      return Number.isNaN(date.getTime()) ? null : date.toISOString();
    }
    const syslog = raw.match(/^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})$/);
    const date = new Date(syslog ? `${syslog[1]} ${syslog[2]} ${year} ${syslog[3]}` : raw);
    return Number.isNaN(date.getTime()) ? null : date.toISOString();
  }

  function extractIp(message) {
    const match = String(message).match(/(?:\b(?:\d{1,3}\.){3}\d{1,3}\b)/);
    if (!match) return '';
    const octets = match[0].split('.').map(Number);
    return octets.every(n => n <= 255) ? match[0] : '';
  }

  function extractUser(message) {
    const text = String(message);
    const linux = text.match(/(?:Failed|Accepted) password for (?:invalid user )?([^\s]+) from/i);
    if (linux) return linux[1];
    const generic = text.match(/(?:Account Name|TargetUserName|user(?:name)?)[\s:=]+([^\s,;]+)/i);
    return generic ? generic[1] : '';
  }

  function makeEvent(data) {
    return {
      timestamp: data.timestamp || null,
      source: data.source || 'unknown',
      file: data.file || '',
      line: data.line || 0,
      host: data.host || '',
      code: String(data.code || ''),
      message: String(data.message || '').trim(),
      user: String(data.user || ''),
      ip: String(data.ip || ''),
      raw: String(data.raw || ''),
      findings: [],
      severity: 'info'
    };
  }

  function detectDelimiter(line) {
    const choices = [',', ';', '\t'];
    return choices.map(delimiter => ({ delimiter, count: line.split(delimiter).length - 1 }))
      .sort((a, b) => b.count - a.count)[0].delimiter;
  }

  function parseCsvRows(text) {
    const delimiter = detectDelimiter(String(text).split(/\r?\n/, 1)[0]);
    const rows = [];
    let row = [], value = '', quoted = false;
    const input = String(text).replace(/^\uFEFF/, '');
    for (let i = 0; i < input.length; i++) {
      const char = input[i];
      if (char === '"') {
        if (quoted && input[i + 1] === '"') { value += '"'; i++; }
        else quoted = !quoted;
      } else if (char === delimiter && !quoted) {
        row.push(value); value = '';
      } else if ((char === '\n' || char === '\r') && !quoted) {
        if (char === '\r' && input[i + 1] === '\n') i++;
        row.push(value); value = '';
        if (row.some(cell => cell.trim())) rows.push(row);
        row = [];
      } else value += char;
    }
    row.push(value);
    if (quoted) throw new Error('CSV com aspas não fechadas.');
    if (row.some(cell => cell.trim())) rows.push(row);
    return rows;
  }

  function normalizeHeader(value) {
    return String(value).normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/[^a-z0-9]/g, '');
  }

  function parseWindowsCsv(text, file) {
    const rows = parseCsvRows(text);
    if (rows.length < 2) throw new Error('CSV sem linhas de eventos.');
    const headers = rows[0].map(normalizeHeader);
    const find = (...names) => names.map(name => headers.indexOf(name)).find(index => index >= 0) ?? -1;
    const columns = {
      time: find('timecreated', 'datetime', 'dateandtime', 'timestamp', 'dataehora', 'date'),
      code: find('eventid', 'id', 'codigo'),
      message: find('message', 'mensagem', 'description'),
      level: find('level', 'nivel'),
      host: find('computer', 'computername', 'computador', 'machine', 'host'),
      user: find('targetusername', 'username', 'user', 'usuario'),
      ip: find('ipaddress', 'sourceip', 'ip')
    };
    if (columns.time < 0 || (columns.code < 0 && columns.message < 0)) {
      throw new Error('CSV não reconhecido. Exporte o Visualizador de Eventos com Data/Hora e ID ou Mensagem.');
    }
    return rows.slice(1).map((row, index) => {
      const get = key => columns[key] >= 0 ? (row[columns[key]] || '').trim() : '';
      const message = get('message');
      return makeEvent({
        source: 'Windows', file, line: index + 2, timestamp: parseTimestamp(get('time')),
        code: get('code'), message: message || `Evento ${get('code')}`,
        host: get('host'), user: get('user') || extractUser(message), ip: get('ip') || extractIp(message),
        raw: row.join(' | ')
      });
    });
  }

  function xmlTag(xml, name) {
    const match = xml.match(new RegExp(`<(?:(?:[\\w-]+):)?${name}\\b[^>]*>([\\s\\S]*?)<\\/(?:(?:[\\w-]+):)?${name}>`, 'i'));
    return match ? decodeXml(match[1].replace(/<[^>]*>/g, ' ').trim()) : '';
  }

  function parseWindowsXml(text, file) {
    const blocks = String(text).match(/<Event\b[^>]*>[\s\S]*?<\/Event>/gi) || [];
    if (!blocks.length) throw new Error('XML sem elementos <Event> reconhecíveis.');
    return blocks.map((block, index) => {
      const time = block.match(/<TimeCreated\b[^>]*SystemTime=["']([^"']+)/i);
      const fields = {};
      for (const match of block.matchAll(/<Data\b[^>]*Name=["']([^"']+)["'][^>]*>([\s\S]*?)<\/Data>/gi)) {
        fields[match[1].toLowerCase()] = decodeXml(match[2].replace(/<[^>]*>/g, ''));
      }
      const code = xmlTag(block, 'EventID');
      const message = xmlTag(block, 'Message') || Object.entries(fields).map(([key, value]) => `${key}: ${value}`).join('; ') || `Evento ${code}`;
      return makeEvent({
        source: 'Windows', file, line: index + 1, timestamp: parseTimestamp(time?.[1]),
        code, host: xmlTag(block, 'Computer'), message,
        user: fields.targetusername || fields.subjectusername || extractUser(message),
        ip: fields.ipaddress || extractIp(message), raw: block.slice(0, 3000)
      });
    });
  }

  function parseLinuxLog(text, file, year = new Date().getFullYear()) {
    const events = [];
    for (const [index, original] of String(text).split(/\r?\n/).entries()) {
      const line = original.trim();
      if (!line) continue;
      let timestamp = null, host = '', message = line;
      const iso = line.match(/^(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?)\s+([^\s]+)\s+(.+)$/);
      const syslog = line.match(/^([A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)\s+([^\s]+)\s+(.+)$/);
      if (iso) { timestamp = parseTimestamp(iso[1]); host = iso[2]; message = iso[3]; }
      else if (syslog) { timestamp = parseTimestamp(syslog[1], year); host = syslog[2]; message = syslog[3]; }
      events.push(makeEvent({
        source: 'Linux', file, line: index + 1, timestamp, host, message,
        user: extractUser(message), ip: extractIp(message), raw: original
      }));
    }
    return events;
  }

  function parseJson(text, file) {
    let data;
    try { data = JSON.parse(text); } catch { throw new Error('JSON inválido.'); }
    const rows = Array.isArray(data) ? data : (Array.isArray(data.events) ? data.events : null);
    if (!rows) throw new Error('JSON deve conter uma lista de eventos ou uma propriedade events.');
    return rows.map((row, index) => {
      if (!row || typeof row !== 'object') return null;
      const message = row.message || row.Message || row.description || '';
      return makeEvent({
        source: row.source || 'Windows', file, line: index + 1,
        timestamp: parseTimestamp(row.timestamp || row.TimeCreated || row.time || row.date),
        code: row.code || row.EventID || row.event_id || '',
        host: row.host || row.Computer || '', message,
        user: row.user || row.TargetUserName || extractUser(message),
        ip: row.ip || row.IpAddress || extractIp(message), raw: JSON.stringify(row)
      });
    }).filter(Boolean);
  }

  function parseFile(file, text, year) {
    const name = String(file || 'arquivo');
    const extension = name.split('.').pop().toLowerCase();
    let events;
    if (extension === 'xml' || /^\s*(?:<\?xml|<Events?\b)/i.test(text)) events = parseWindowsXml(text, name);
    else if (extension === 'csv') events = parseWindowsCsv(text, name);
    else if (extension === 'json') events = parseJson(text, name);
    else events = parseLinuxLog(text, name, year);
    if (events.length > MAX_EVENTS) throw new Error(`Limite de ${MAX_EVENTS.toLocaleString('pt-BR')} eventos por arquivo excedido.`);
    const warnings = [];
    const undated = events.filter(event => !event.timestamp).length;
    if (undated) warnings.push(`${undated} evento(s) sem data válida; serão exibidos ao final da linha do tempo.`);
    return { events, warnings };
  }

  function addFinding(event, ruleId, severity, title, rationale) {
    event.findings.push({ ruleId, severity, title, rationale });
    if (severityRank[severity] > severityRank[event.severity]) event.severity = severity;
  }

  function analyze(input) {
    const events = input.map((item, index) => ({ ...item, uid: index + 1, findings: [], severity: 'info' }));
    events.sort((a, b) => (a.timestamp || '9999').localeCompare(b.timestamp || '9999') || a.uid - b.uid);
    const failures = new Map();
    for (const event of events) {
      const text = event.message;
      const windows = event.source === 'Windows';
      const failed = (windows && event.code === '4625') || (!windows && /Failed password|authentication failure|invalid user/i.test(text));
      const success = (windows && event.code === '4624') || (!windows && /Accepted (?:password|publickey)/i.test(text));
      const identity = `${event.host || 'unknown'}|${event.ip || '-'}|${event.user || '-'}`.toLowerCase();
      const eventTime = event.timestamp ? Date.parse(event.timestamp) : NaN;

      if (failed) {
        addFinding(event, 'AUTH-001', 'medium', 'Falha de autenticação', 'Acesso negado; isoladamente não comprova ataque.');
        if (Number.isFinite(eventTime)) {
          const history = (failures.get(identity) || []).filter(time => eventTime - time <= 10 * 60 * 1000 && eventTime >= time);
          history.push(eventTime);
          failures.set(identity, history);
          if (history.length >= 5) addFinding(event, 'AUTH-002', 'high', 'Múltiplas falhas em 10 minutos', `${history.length} falhas relacionadas à mesma origem/conta. Verifique se há tentativa de força bruta.`);
        }
      }
      if (success && Number.isFinite(eventTime)) {
        const recent = (failures.get(identity) || []).filter(time => eventTime - time <= 15 * 60 * 1000 && eventTime >= time);
        if (recent.length >= 3) addFinding(event, 'AUTH-003', 'high', 'Acesso após falhas', `Login aceito após ${recent.length} falhas relacionadas em até 15 minutos.`);
      }
      if (windows) {
        if (event.code === '1102') addFinding(event, 'WIN-001', 'critical', 'Log de auditoria limpo', 'O registro de segurança foi limpo; preserve outras fontes de evidência.');
        if (event.code === '7045') addFinding(event, 'WIN-002', 'high', 'Novo serviço instalado', 'Revise origem, binário, conta de execução e autorização da mudança.');
        if (event.code === '4720') addFinding(event, 'WIN-003', 'high', 'Conta de usuário criada', 'Confirme solicitação, responsável e privilégios concedidos.');
        if (event.code === '4728') addFinding(event, 'WIN-004', 'high', 'Inclusão em grupo privilegiado', 'Verifique o grupo, a conta adicionada e a aprovação.');
        if (['4104', '4688'].includes(event.code) && /-enc(?:odedcommand)?\b|frombase64string|downloadstring|invoke-expression|\biex\b/i.test(text)) {
          addFinding(event, 'WIN-005', 'high', 'Comando potencialmente suspeito', 'Indicador heurístico em comando/script; examine o contexto antes de concluir.');
        }
      } else {
        if (/\bsudo(?:\[\d+\])?:/i.test(text)) addFinding(event, 'LNX-001', 'medium', 'Uso de sudo', 'Comando privilegiado registrado; valide usuário e justificativa.');
        if (/\b(?:useradd|adduser)\b/i.test(text)) addFinding(event, 'LNX-002', 'high', 'Criação de usuário', 'Confirme se a criação de conta foi autorizada.');
      }
    }
    return events;
  }

  function summarize(events) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const event of events) counts[event.severity]++;
    return { total: events.length, flagged: events.filter(event => event.findings.length).length, counts,
      sources: [...new Set(events.map(event => event.file))],
      start: events.find(event => event.timestamp)?.timestamp || null,
      end: [...events].reverse().find(event => event.timestamp)?.timestamp || null };
  }

  function quoteCsv(value) {
    let text = String(value ?? '');
    if (/^\s*[=+\-@]/.test(text)) text = `'${text}`; // Prevent spreadsheet formula execution.
    return `"${text.replace(/"/g, '""')}"`;
  }
  function exportCsv(events) {
    const header = ['timestamp', 'severity', 'source', 'file', 'host', 'event_id', 'user', 'ip', 'message', 'rules'];
    return [header.join(','), ...events.map(event => [event.timestamp, event.severity, event.source, event.file,
      event.host, event.code, event.user, event.ip, event.message, event.findings.map(item => item.ruleId).join(';')]
      .map(quoteCsv).join(','))].join('\r\n');
  }

  function buildReportHtml(events, notes = '') {
    const summary = summarize(events);
    const flagged = events.filter(event => event.findings.length);
    const rows = flagged.slice(0, 1000).map(event => `<tr><td>${escapeHtml(event.timestamp || 'Sem data')}</td><td>${escapeHtml(event.severity.toUpperCase())}</td><td>${escapeHtml(event.source)}</td><td>${escapeHtml(event.host || '—')}</td><td>${escapeHtml(event.code || '—')}</td><td>${escapeHtml(event.message)}</td><td>${escapeHtml(event.findings.map(finding => `${finding.ruleId}: ${finding.title}`).join('; '))}</td></tr>`).join('');
    return `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Relatório de investigação — IR Workbench</title><style>body{font:15px/1.55 system-ui,sans-serif;max-width:1100px;margin:40px auto;padding:0 24px;color:#152234}h1{color:#123b4a}h2{margin-top:36px;border-bottom:2px solid #d8e5e9;padding-bottom:8px}.meta,.note{background:#f1f6f7;padding:16px;border-radius:8px}table{border-collapse:collapse;width:100%;font-size:12px}th,td{border:1px solid #d1dbe0;padding:8px;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#e8f0f2}@media print{body{margin:0;max-width:none}tr{break-inside:avoid}}</style></head><body><h1>Relatório de investigação</h1><p>Incident Response Workbench · Gerado em ${escapeHtml(new Date().toLocaleString('pt-BR'))}</p><div class="meta"><strong>Escopo:</strong> ${summary.total} eventos de ${summary.sources.length} arquivo(s); ${summary.flagged} sinalizados.<br><strong>Janela:</strong> ${escapeHtml(summary.start || 'indefinida')} — ${escapeHtml(summary.end || 'indefinida')}<br><strong>Severidades:</strong> ${summary.counts.critical} críticos, ${summary.counts.high} altos, ${summary.counts.medium} médios.<br><strong>Fontes:</strong> ${escapeHtml(summary.sources.join(', ') || 'nenhuma')}</div><h2>Notas do analista</h2><div class="note">${escapeHtml(notes || 'Nenhuma nota registrada.').replace(/\n/g, '<br>')}</div><h2>Eventos sinalizados</h2><p>${flagged.length > 1000 ? 'Exibindo os primeiros 1.000 eventos sinalizados. Exporte o JSON para o conjunto completo.' : 'A severidade indica prioridade de triagem, não confirmação de incidente.'}</p><table><thead><tr><th>Data</th><th>Prioridade</th><th>Origem</th><th>Host</th><th>ID</th><th>Mensagem</th><th>Regras</th></tr></thead><tbody>${rows || '<tr><td colspan="7">Nenhum evento sinalizado.</td></tr>'}</tbody></table><h2>Metodologia e limites</h2><p>Triagem heurística baseada em IDs de eventos Windows e padrões textuais de logs Linux. Correlações de autenticação usam origem/conta e janelas de tempo. A ferramenta não confirma invasões, não enriquece indicadores externamente e não substitui a análise de evidências originais. Valide fuso horário e o ano de logs syslog antes de tirar conclusões.</p></body></html>`;
  }

  const DEMO_WINDOWS_CSV = `TimeCreated,EventID,Computer,TargetUserName,IpAddress,Message
2026-09-18T09:00:00-03:00,4625,LAB-WS01,arthur,192.0.2.10,"Failed logon for arthur"
2026-09-18T09:01:00-03:00,4625,LAB-WS01,arthur,192.0.2.10,"Failed logon for arthur"
2026-09-18T09:02:00-03:00,4625,LAB-WS01,arthur,192.0.2.10,"Failed logon for arthur"
2026-09-18T09:03:00-03:00,4625,LAB-WS01,arthur,192.0.2.10,"Failed logon for arthur"
2026-09-18T09:04:00-03:00,4625,LAB-WS01,arthur,192.0.2.10,"Failed logon for arthur"
2026-09-18T09:05:00-03:00,4624,LAB-WS01,arthur,192.0.2.10,"Successful logon for arthur"
2026-09-18T09:08:00-03:00,7045,LAB-WS01,,,"New service installed: LabUpdater"
2026-09-18T09:12:00-03:00,1102,LAB-WS01,,,"The audit log was cleared"`;
  const DEMO_LINUX_LOG = `2026-09-18T09:00:30-03:00 lab-srv sshd[1200]: Failed password for admin from 198.51.100.24 port 52210 ssh2
2026-09-18T09:01:30-03:00 lab-srv sshd[1201]: Failed password for admin from 198.51.100.24 port 52211 ssh2
2026-09-18T09:02:30-03:00 lab-srv sshd[1202]: Failed password for admin from 198.51.100.24 port 52212 ssh2
2026-09-18T09:03:30-03:00 lab-srv sshd[1203]: Failed password for admin from 198.51.100.24 port 52213 ssh2
2026-09-18T09:04:30-03:00 lab-srv sshd[1204]: Failed password for admin from 198.51.100.24 port 52214 ssh2
2026-09-18T09:05:30-03:00 lab-srv sshd[1205]: Accepted password for admin from 198.51.100.24 port 52215 ssh2
2026-09-18T09:09:30-03:00 lab-srv sudo: admin : TTY=pts/0 ; PWD=/home/admin ; COMMAND=/usr/sbin/useradd tempuser
2026-09-18T09:15:30-03:00 lab-srv CRON[1300]: (root) CMD (/usr/bin/backup)`;

  function demo() {
    return analyze([
      ...parseWindowsCsv(DEMO_WINDOWS_CSV, 'demo-windows.csv'),
      ...parseLinuxLog(DEMO_LINUX_LOG, 'demo-linux-auth.log', 2026)
    ]);
  }

  return { MAX_EVENTS, MAX_FILE_BYTES, escapeHtml, parseTimestamp, parseCsvRows, parseWindowsCsv,
    parseWindowsXml, parseLinuxLog, parseJson, parseFile, analyze, summarize, exportCsv,
    buildReportHtml, demo, DEMO_WINDOWS_CSV, DEMO_LINUX_LOG };
});
