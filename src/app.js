(function () {
  'use strict';
  const core = window.IRWCore;
  if (!core) throw new Error('O motor de análise não foi carregado.');

  const $ = id => document.getElementById(id);
  const elements = {
    dropZone: $('dropZone'), fileInput: $('fileInput'), demoTop: $('demoTop'), demoButton: $('demoButton'),
    syslogYear: $('syslogYear'), fileSummary: $('fileSummary'), metricTotal: $('metricTotal'),
    metricFlagged: $('metricFlagged'), metricHigh: $('metricHigh'), metricSources: $('metricSources'),
    searchInput: $('searchInput'), severityFilter: $('severityFilter'), sourceFilter: $('sourceFilter'),
    timelineSubtitle: $('timelineSubtitle'), resultCount: $('resultCount'), eventList: $('eventList'),
    eventDetail: $('eventDetail'), showMore: $('showMore'), analystNotes: $('analystNotes'),
    downloadReport: $('downloadReport'), downloadJson: $('downloadJson'), downloadCsv: $('downloadCsv'),
    clearCase: $('clearCase'), toast: $('toast')
  };
  let rawEvents = [];
  let events = [];
  let selectedUid = null;
  let visibleLimit = 250;
  let toastTimer;
  const severityLabel = { critical: 'CRÍTICA', high: 'ALTA', medium: 'MÉDIA', low: 'BAIXA', info: 'SEM ALERTA' };

  function toast(message, error = false) {
    elements.toast.textContent = message;
    elements.toast.classList.toggle('error', error);
    elements.toast.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => elements.toast.classList.remove('show'), 5000);
  }

  function formatDate(value) {
    if (!value) return 'Sem data';
    return new Date(value).toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'medium' });
  }

  function download(name, content, mime) {
    const url = URL.createObjectURL(new Blob([content], { type: mime }));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = name;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function renderMetrics() {
    const summary = core.summarize(events);
    elements.metricTotal.textContent = summary.total.toLocaleString('pt-BR');
    elements.metricFlagged.textContent = summary.flagged.toLocaleString('pt-BR');
    elements.metricHigh.textContent = (summary.counts.critical + summary.counts.high).toLocaleString('pt-BR');
    elements.metricSources.textContent = summary.sources.length.toLocaleString('pt-BR');
    elements.timelineSubtitle.textContent = summary.total ? `${formatDate(summary.start)} → ${formatDate(summary.end)} · Horários exibidos no fuso do seu navegador.` : 'Os eventos aparecem em ordem cronológica e podem ser filtrados.';
    for (const key of ['downloadReport', 'downloadJson', 'downloadCsv', 'clearCase']) elements[key].disabled = !summary.total;
  }

  function filteredEvents() {
    const query = elements.searchInput.value.trim().toLowerCase();
    const severity = elements.severityFilter.value;
    const source = elements.sourceFilter.value;
    return events.filter(event => {
      if (severity !== 'all' && event.severity !== severity) return false;
      if (source !== 'all' && event.source !== source) return false;
      if (!query) return true;
      return [event.timestamp, event.source, event.file, event.host, event.code, event.message, event.user, event.ip,
        ...event.findings.map(finding => `${finding.ruleId} ${finding.title}`)].join(' ').toLowerCase().includes(query);
    });
  }

  function renderList() {
    const matches = filteredEvents();
    elements.resultCount.textContent = `${matches.length.toLocaleString('pt-BR')} RESULTADO${matches.length === 1 ? '' : 'S'}`;
    if (!events.length) {
      elements.eventList.innerHTML = '<div class="empty-state"><span>◇</span><strong>Seu caso começa aqui</strong><p>Importe um arquivo ou abra a demonstração para explorar a linha do tempo.</p></div>';
      elements.showMore.hidden = true;
      return;
    }
    if (!matches.length) {
      elements.eventList.innerHTML = '<div class="empty-state"><span>⌕</span><strong>Nenhum evento encontrado</strong><p>Ajuste a busca ou os filtros para continuar.</p></div>';
      elements.showMore.hidden = true;
      return;
    }
    elements.eventList.innerHTML = matches.slice(0, visibleLimit).map(event => `<button type="button" class="event-row ${event.uid === selectedUid ? 'selected' : ''}" data-uid="${event.uid}" aria-label="${core.escapeHtml(`${severityLabel[event.severity]}: ${event.message}`)}"><span class="event-dot ${event.severity}"></span><span class="event-text"><strong>${core.escapeHtml(event.message || `Evento ${event.code}`)}</strong><small>${core.escapeHtml(formatDate(event.timestamp))} · ${core.escapeHtml(event.source)}${event.code ? ` · ID ${core.escapeHtml(event.code)}` : ''} · ${core.escapeHtml(event.host || event.file)}</small></span><span class="badge ${event.severity}">${severityLabel[event.severity]}</span></button>`).join('');
    elements.showMore.hidden = matches.length <= visibleLimit;
    elements.showMore.textContent = `Mostrar mais eventos (${Math.min(250, matches.length - visibleLimit)} de ${matches.length - visibleLimit} restantes) ↓`;
  }

  function detailField(label, value) {
    return `<div class="detail-field"><span>${core.escapeHtml(label)}</span><strong>${core.escapeHtml(value || '—')}</strong></div>`;
  }

  function renderDetail() {
    const event = events.find(item => item.uid === selectedUid);
    if (!event) {
      elements.eventDetail.innerHTML = '<div class="detail-empty"><span>◎</span><strong>Detalhes da evidência</strong><p>Selecione um evento para ver os campos e a justificativa dos alertas.</p></div>';
      return;
    }
    const findings = event.findings.length ? event.findings.map(finding => `<div class="finding ${finding.severity}"><strong>${core.escapeHtml(finding.ruleId)} · ${core.escapeHtml(finding.title)}</strong><p>${core.escapeHtml(finding.rationale)}</p></div>`).join('') : '<p class="detail-message">Nenhuma regra desta versão sinalizou o evento. Isso não garante que seja benigno.</p>';
    elements.eventDetail.innerHTML = `<div class="detail-top"><span class="section-index">EVIDÊNCIA / ${String(event.uid).padStart(4, '0')}</span><span class="badge ${event.severity}">${severityLabel[event.severity]}</span></div><h3 class="detail-heading">${core.escapeHtml(event.code ? `Evento ${event.code}` : event.source)}</h3><div class="detail-sub">${core.escapeHtml(formatDate(event.timestamp))}</div><div class="detail-grid">${detailField('Origem', event.source)}${detailField('Host', event.host)}${detailField('Usuário', event.user)}${detailField('IP', event.ip)}${detailField('Arquivo', event.file)}${detailField('Linha / evento', event.line)}</div><div class="detail-section-title">MENSAGEM</div><div class="detail-message">${core.escapeHtml(event.message)}</div><div class="detail-section-title">REGRAS ACIONADAS</div>${findings}<details><summary class="detail-section-title" style="cursor:pointer">VER REGISTRO ORIGINAL</summary><pre class="detail-message">${core.escapeHtml(event.raw)}</pre></details>`;
  }

  function renderAll() { renderMetrics(); renderList(); renderDetail(); }

  async function importFiles(files) {
    if (!files.length) return;
    const year = Number(elements.syslogYear.value);
    if (!Number.isInteger(year) || year < 2000 || year > 2100) { toast('Informe um ano entre 2000 e 2100 para logs syslog.', true); return; }
    const accepted = [], warnings = [];
    for (const file of files) {
      if (!/\.(?:csv|xml|json|log|txt)$/i.test(file.name)) { warnings.push(`${file.name}: formato não suportado.`); continue; }
      if (file.size > core.MAX_FILE_BYTES) { warnings.push(`${file.name}: acima de 5 MB.`); continue; }
      try {
        const result = core.parseFile(file.name, await file.text(), year);
        if (rawEvents.length + accepted.length + result.events.length > core.MAX_EVENTS) {
          warnings.push(`${file.name}: limite total de 10.000 eventos excedido.`); continue;
        }
        accepted.push(...result.events);
        warnings.push(...result.warnings.map(message => `${file.name}: ${message}`));
      } catch (error) { warnings.push(`${file.name}: ${error.message}`); }
    }
    if (accepted.length) {
      rawEvents.push(...accepted);
      events = core.analyze(rawEvents);
      selectedUid = events.find(event => event.findings.length)?.uid || events[0]?.uid || null;
      visibleLimit = 250;
      elements.fileSummary.textContent = `${core.summarize(events).sources.length} arquivo(s) · ${events.length.toLocaleString('pt-BR')} eventos. ${warnings.join(' ')}`;
      renderAll();
      toast(`${accepted.length.toLocaleString('pt-BR')} evento(s) importado(s).${warnings.length ? ' Confira os avisos abaixo.' : ''}`);
      document.getElementById('timeline').scrollIntoView({ behavior: 'smooth' });
    } else {
      elements.fileSummary.textContent = warnings.join(' ') || 'Nenhum evento importado.';
      toast('Nenhum evento pôde ser importado. Confira os avisos.', true);
    }
    elements.fileInput.value = '';
  }

  function loadDemo() {
    if (rawEvents.length && !window.confirm('Substituir o caso atual pela demonstração?')) return;
    events = core.demo();
    rawEvents = events.map(({ uid, findings, severity, ...rest }) => rest);
    selectedUid = events.find(event => event.severity === 'critical')?.uid || events[0]?.uid;
    visibleLimit = 250;
    elements.searchInput.value = '';
    elements.severityFilter.value = 'all';
    elements.sourceFilter.value = 'all';
    elements.syslogYear.value = '2026';
    elements.analystNotes.value = '';
    elements.fileSummary.textContent = 'Caso de demonstração sintético carregado: demo-windows.csv + demo-linux-auth.log. Endereços IP pertencem a faixas reservadas para documentação.';
    renderAll();
    toast('Demonstração pronta. Selecione um evento para investigar.');
    document.getElementById('timeline').scrollIntoView({ behavior: 'smooth' });
  }

  elements.dropZone.addEventListener('click', () => elements.fileInput.click());
  elements.dropZone.addEventListener('keydown', event => {
    if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); elements.fileInput.click(); }
  });
  elements.fileInput.addEventListener('change', event => importFiles([...event.target.files]));
  for (const type of ['dragenter', 'dragover']) elements.dropZone.addEventListener(type, event => {
    event.preventDefault(); elements.dropZone.classList.add('dragging');
  });
  for (const type of ['dragleave', 'drop']) elements.dropZone.addEventListener(type, event => {
    event.preventDefault(); elements.dropZone.classList.remove('dragging');
  });
  elements.dropZone.addEventListener('drop', event => importFiles([...event.dataTransfer.files]));
  elements.demoTop.addEventListener('click', loadDemo);
  elements.demoButton.addEventListener('click', loadDemo);
  for (const key of ['searchInput', 'severityFilter', 'sourceFilter']) {
    elements[key].addEventListener(key === 'searchInput' ? 'input' : 'change', () => {
      visibleLimit = 250;
      const matches = filteredEvents();
      if (!matches.some(event => event.uid === selectedUid)) selectedUid = matches[0]?.uid || null;
      renderList(); renderDetail();
    });
  }
  elements.eventList.addEventListener('click', event => {
    const row = event.target.closest('[data-uid]');
    if (!row) return;
    selectedUid = Number(row.dataset.uid);
    renderList(); renderDetail();
  });
  elements.showMore.addEventListener('click', () => { visibleLimit += 250; renderList(); });
  elements.downloadReport.addEventListener('click', () => download('ir-workbench-relatorio.html', core.buildReportHtml(events, elements.analystNotes.value), 'text/html;charset=utf-8'));
  elements.downloadJson.addEventListener('click', () => download('ir-workbench-eventos.json', JSON.stringify({
    meta: { application: 'Incident Response Workbench', version: '1.0.0', generatedAt: new Date().toISOString(), note: 'Alertas heurísticos não confirmam incidentes.' },
    summary: core.summarize(events), events
  }, null, 2), 'application/json;charset=utf-8'));
  elements.downloadCsv.addEventListener('click', () => download('ir-workbench-eventos.csv', '\uFEFF' + core.exportCsv(events), 'text/csv;charset=utf-8'));
  elements.clearCase.addEventListener('click', () => {
    if (!window.confirm('Limpar os eventos e notas deste caso? Arquivos originais não serão excluídos.')) return;
    rawEvents = []; events = []; selectedUid = null; visibleLimit = 250;
    elements.analystNotes.value = ''; elements.searchInput.value = '';
    elements.severityFilter.value = 'all'; elements.sourceFilter.value = 'all';
    elements.fileSummary.textContent = 'Nenhum arquivo carregado. Use a demonstração para conhecer a ferramenta.';
    renderAll(); toast('Caso local limpo.');
  });
  renderAll();
})();
