const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const core = require('../src/core.js');

test('demo is a real, reproducible case with Windows and Linux findings', () => {
  const events = core.demo();
  const summary = core.summarize(events);
  assert.equal(summary.total, 16);
  assert.equal(summary.sources.length, 2);
  assert.equal(summary.counts.critical, 1);
  assert.ok(events.some(event => event.findings.some(finding => finding.ruleId === 'AUTH-002')));
  assert.ok(events.some(event => event.findings.some(finding => finding.ruleId === 'AUTH-003')));
  assert.ok(events.every((event, index) => index === 0 || events[index - 1].timestamp <= event.timestamp));
});

test('Windows CSV supports quoted commas and UTF-8 headers', () => {
  const result = core.parseFile('events.csv', 'Data e hora;ID;Computador;Mensagem\n18/09/2026 09:00:00;4625;LAB01;"Falha, usuário teste"', 2026);
  assert.equal(result.events.length, 1);
  assert.equal(result.events[0].code, '4625');
  assert.equal(result.events[0].message, 'Falha, usuário teste');
  assert.equal(result.events[0].host, 'LAB01');
  assert.ok(result.events[0].timestamp);
});

test('Windows XML extracts ID, timestamp, computer and event data', () => {
  const xml = '<Events><Event><System><EventID>4625</EventID><TimeCreated SystemTime="2026-09-18T12:00:00Z"/><Computer>LAB01</Computer></System><EventData><Data Name="TargetUserName">alice</Data><Data Name="IpAddress">192.0.2.5</Data></EventData></Event></Events>';
  const event = core.parseFile('Security.xml', xml, 2026).events[0];
  assert.equal(event.source, 'Windows');
  assert.equal(event.code, '4625');
  assert.equal(event.user, 'alice');
  assert.equal(event.ip, '192.0.2.5');
  assert.equal(event.host, 'LAB01');
});

test('Linux syslog uses the selected year and preserves line numbers', () => {
  const event = core.parseFile('auth.log', 'Sep 18 09:00:00 lab sshd[1]: Failed password for admin from 198.51.100.2 port 42 ssh2', 2024).events[0];
  assert.equal(new Date(event.timestamp).getFullYear(), 2024);
  assert.equal(event.line, 1);
  assert.equal(event.user, 'admin');
  assert.equal(event.ip, '198.51.100.2');
});

test('five failures and subsequent success correlate on host, account and IP', () => {
  const lines = Array.from({ length: 5 }, (_, i) => `2026-09-18T09:0${i}:00Z server sshd[1]: Failed password for alice from 192.0.2.8 port 22 ssh2`);
  lines.push('2026-09-18T09:06:00Z server sshd[2]: Accepted password for alice from 192.0.2.8 port 22 ssh2');
  const events = core.analyze(core.parseLinuxLog(lines.join('\n'), 'auth.log'));
  assert.ok(events[4].findings.some(finding => finding.ruleId === 'AUTH-002'));
  assert.ok(events[5].findings.some(finding => finding.ruleId === 'AUTH-003'));
});

test('a success for another user does not inherit failed-login history', () => {
  const lines = Array.from({ length: 5 }, (_, i) => `2026-09-18T09:0${i}:00Z server sshd[1]: Failed password for alice from 192.0.2.8 port 22 ssh2`);
  lines.push('2026-09-18T09:06:00Z server sshd[2]: Accepted password for bob from 192.0.2.8 port 22 ssh2');
  const events = core.analyze(core.parseLinuxLog(lines.join('\n'), 'auth.log'));
  assert.equal(events[5].severity, 'info');
});

test('old failures do not trigger a new brute-force alert', () => {
  const lines = ['2026-09-18T09:00:00Z server sshd: Failed password for alice from 192.0.2.8 port 22 ssh2',
    '2026-09-18T10:00:00Z server sshd: Accepted password for alice from 192.0.2.8 port 22 ssh2'];
  const events = core.analyze(core.parseLinuxLog(lines.join('\n'), 'auth.log'));
  assert.equal(events[1].severity, 'info');
});

test('audit log clear is critical; ordinary cron entry is not flagged', () => {
  const win = core.parseWindowsCsv('TimeCreated,EventID,Computer,Message\n2026-09-18T09:00:00Z,1102,LAB01,Audit log cleared', 'events.csv');
  const linux = core.parseLinuxLog('Sep 18 09:00:00 lab CRON[2]: (root) CMD (/usr/bin/backup)', 'syslog', 2026);
  const events = core.analyze([...win, ...linux]);
  assert.equal(events.find(event => event.code === '1102').severity, 'critical');
  assert.equal(events.find(event => event.source === 'Linux').severity, 'info');
});

test('CSV rejects missing headers and unclosed quotes', () => {
  assert.throws(() => core.parseFile('bad.csv', 'foo,bar\n1,2', 2026), /não reconhecido/);
  assert.throws(() => core.parseCsvRows('a,b\n"unclosed,b'), /aspas não fechadas/);
});

test('invalid timestamps are surfaced as warnings, not silently discarded', () => {
  const result = core.parseFile('auth.log', 'undated message', 2026);
  assert.equal(result.events.length, 1);
  assert.equal(result.events[0].timestamp, null);
  assert.equal(result.warnings.length, 1);
});

test('HTML report escapes untrusted log content and analyst notes', () => {
  const events = core.analyze(core.parseLinuxLog('2026-09-18T09:00:00Z lab sshd: Failed password for <img src=x onerror=alert(1)> from 192.0.2.2 port 22 ssh2', 'auth.log'));
  const report = core.buildReportHtml(events, '<script>alert(1)</script>');
  assert.ok(report.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
  assert.ok(!report.includes('<script>alert(1)</script>'));
  assert.ok(report.includes('&lt;img'));
});

test('CSV export neutralizes spreadsheet formulas from untrusted logs', () => {
  const events = core.analyze(core.parseJson(JSON.stringify([{ timestamp: '2026-09-18T09:00:00Z', message: '=HYPERLINK("https://example.com")' }]), 'events.json'));
  const csv = core.exportCsv(events);
  assert.ok(csv.includes("'=HYPERLINK"));
});

test('JSON arrays can be imported without external packages', () => {
  const parsed = core.parseFile('events.json', JSON.stringify([{ TimeCreated: '2026-09-18T09:00:00Z', EventID: 4720, Computer: 'LAB01', Message: 'User created' }]), 2026);
  assert.equal(parsed.events[0].code, '4720');
  assert.equal(core.analyze(parsed.events)[0].severity, 'high');
});

test('both downloadable example files parse and reproduce the demo case', () => {
  const windows = fs.readFileSync(path.join(__dirname, '../examples/windows-events.csv'), 'utf8');
  const linux = fs.readFileSync(path.join(__dirname, '../examples/linux-auth.log'), 'utf8');
  const events = core.analyze([
    ...core.parseFile('windows-events.csv', windows, 2026).events,
    ...core.parseFile('linux-auth.log', linux, 2026).events
  ]);
  assert.equal(events.length, core.demo().length);
  assert.equal(core.summarize(events).counts.critical, 1);
});
