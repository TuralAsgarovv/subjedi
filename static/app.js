(() => {
  'use strict';

  const PAGE_CHUNK_SIZE = 500;
  const PROBE_BATCH_SIZE = 25;

  const state = {
    apex: '',
    rows: [],
    filteredRows: [],
    probes: new Map(),
    probingSet: new Set(),
    statusFilter: 'all',
    renderedLimit: PAGE_CHUNK_SIZE,
    loading: false,
    probing: false,
    cached: false,
    stale: false,
    elapsedMs: null,
    activeController: null,
    probeController: null,
  };

  const els = {
    form: document.getElementById('search-form'),
    domainInput: document.getElementById('domain-input'),
    submitBtn: document.getElementById('search-submit'),
    submitLabel: document.getElementById('search-submit-label'),
    spinner: document.getElementById('search-spinner'),
    sampleBtns: document.querySelectorAll('.sample-chip'),
    statsMeta: document.getElementById('stats-meta'),
    speedSep: document.getElementById('speed-sep'),
    speedMeta: document.getElementById('speed-meta'),
    errorBanner: document.getElementById('error-banner'),
    errorMessage: document.getElementById('error-message'),
    filterInput: document.getElementById('filter-input'),
    resultsCounter: document.getElementById('results-counter'),
    probeBtn: document.getElementById('probe-btn'),
    probeBtnLabel: document.getElementById('probe-btn-label'),
    probeSpinner: document.getElementById('probe-spinner'),
    statusFilterBar: document.getElementById('status-filter-bar'),
    statusFilterBtns: document.querySelectorAll('.status-filter-btn'),
    probeSummary: document.getElementById('probe-summary'),
    copyAllBtn: document.getElementById('copy-all-btn'),
    downloadTxtBtn: document.getElementById('download-txt-btn'),
    downloadJsonBtn: document.getElementById('download-json-btn'),
    stateReady: document.getElementById('state-ready'),
    stateLoading: document.getElementById('state-loading'),
    stateEmpty: document.getElementById('state-empty'),
    emptyTitle: document.getElementById('empty-title'),
    emptySubtitle: document.getElementById('empty-subtitle'),
    resetFilterBtn: document.getElementById('reset-filter-btn'),
    tableWrapper: document.getElementById('table-wrapper'),
    tbody: document.getElementById('results-tbody'),
    loadMoreBar: document.getElementById('load-more-bar'),
    renderedInfo: document.getElementById('rendered-info'),
    loadMoreBtn: document.getElementById('load-more-btn'),
  };

  function cleanClientInput(raw) {
    let value = (raw || '').trim().toLowerCase();
    if (!value) return '';

    const schemeIdx = value.indexOf('://');
    if (schemeIdx !== -1) {
      value = value.slice(schemeIdx + 3);
    }

    for (const sep of ['/', '?', '#']) {
      const idx = value.indexOf(sep);
      if (idx !== -1) {
        value = value.slice(0, idx);
      }
    }

    const atIdx = value.lastIndexOf('@');
    if (atIdx !== -1) {
      value = value.slice(atIdx + 1);
    }

    if (value.startsWith('[') && value.includes(']')) {
      value = value.slice(1, value.indexOf(']'));
    } else if (value.includes(':')) {
      const lastColon = value.lastIndexOf(':');
      const hostPart = value.slice(0, lastColon);
      const portPart = value.slice(lastColon + 1);
      if (portPart === '' || /^\d+$/.test(portPart)) {
        value = hostPart;
      }
    }

    while (value.startsWith('*.')) {
      value = value.slice(2);
    }

    return value.replace(/^\*+/, '').replace(/^\.+|\.+$/g, '');
  }

  function showError(message) {
    els.errorMessage.textContent = message;
    els.errorBanner.classList.remove('hidden');
  }

  function clearError() {
    els.errorMessage.textContent = '';
    els.errorBanner.classList.add('hidden');
  }

  function stopProbing() {
    if (state.probeController) {
      state.probeController.abort();
      state.probeController = null;
    }
    state.probing = false;
    state.probingSet.clear();
    els.probeSpinner.classList.add('hidden');
    els.probeBtnLabel.textContent = 'Statusları yoxla';
  }

  function setLoading(isLoading) {
    state.loading = isLoading;
    els.submitBtn.disabled = isLoading;

    if (isLoading) {
      els.spinner.classList.remove('hidden');
      els.submitLabel.textContent = 'Axtarılır...';
      els.filterInput.disabled = true;
      els.probeBtn.disabled = true;
      els.copyAllBtn.disabled = true;
      els.downloadTxtBtn.disabled = true;
      els.downloadJsonBtn.disabled = true;
      els.statusFilterBar.classList.add('hidden');
      els.stateReady.classList.add('hidden');
      els.stateEmpty.classList.add('hidden');
      els.tableWrapper.classList.add('hidden');
      els.stateLoading.classList.remove('hidden');
    } else {
      els.spinner.classList.add('hidden');
      els.submitLabel.textContent = 'Axtar';
      els.stateLoading.classList.add('hidden');
      updateToolbarState();
    }
  }

  function updateActiveSampleChip(apex) {
    els.sampleBtns.forEach((btn) => {
      const sample = btn.getAttribute('data-sample');
      if (apex && sample === apex) {
        btn.classList.add('border-emerald-400/60', 'text-emerald-400');
        btn.classList.remove('border-zinc-800', 'text-zinc-300');
      } else {
        btn.classList.remove('border-emerald-400/60', 'text-emerald-400');
        btn.classList.add('border-zinc-800', 'text-zinc-300');
      }
    });
  }

  async function refreshStats() {
    try {
      const res = await fetch('/v1/stats', { headers: { Accept: 'application/json' } });
      if (!res.ok) return;
      const data = await res.json();
      const apexes = Number(data.total_apexes || 0);
      const subs = Number(data.total_subdomains || 0);
      els.statsMeta.textContent = `İndeks: ${apexes.toLocaleString('en-US')} apex · ${subs.toLocaleString('en-US')} subdomen`;
    } catch {
      // Stats refresh failure stays silent
    }
  }

  function updateProbeSummary() {
    if (state.rows.length === 0) {
      els.statusFilterBar.classList.add('hidden');
      els.probeSummary.textContent = '';
      return;
    }

    els.statusFilterBar.classList.remove('hidden');

    let checked = 0;
    let active = 0;
    let restricted = 0;
    let dead = 0;

    for (const row of state.rows) {
      const probe = state.probes.get(row.subdomain);
      if (!probe) continue;
      checked++;
      if (probe.state === 'live' || probe.state === 'redirect') {
        active++;
      } else if (probe.state === 'restricted' || probe.state === 'error') {
        restricted++;
      } else {
        dead++;
      }
    }

    if (checked === 0) {
      els.probeSummary.textContent = 'Statuslar hələ yoxlanılmayıb';
    } else {
      els.probeSummary.textContent = `Yoxlanılıb: ${checked} · Aktiv: ${active} · Cavab: ${restricted} · İşləməyən: ${dead}`;
    }
  }

  function updateStatusFilterButtons() {
    els.statusFilterBtns.forEach((btn) => {
      const key = btn.getAttribute('data-status-filter');
      const isActive = key === state.statusFilter;
      btn.setAttribute('aria-pressed', String(isActive));
      if (isActive) {
        btn.classList.add('bg-zinc-800', 'text-zinc-100');
        btn.classList.remove('text-zinc-400', 'hover:text-zinc-200');
      } else {
        btn.classList.remove('bg-zinc-800', 'text-zinc-100');
        btn.classList.add('text-zinc-400', 'hover:text-zinc-200');
      }
    });
  }

  function updateToolbarState() {
    const hasRows = state.rows.length > 0;
    const hasFiltered = state.filteredRows.length > 0;

    els.filterInput.disabled = !hasRows || state.loading;
    els.probeBtn.disabled = !hasRows || state.loading;
    els.copyAllBtn.disabled = !hasFiltered || state.loading;
    els.downloadTxtBtn.disabled = !hasFiltered || state.loading;
    els.downloadJsonBtn.disabled = !hasFiltered || state.loading;

    els.resultsCounter.textContent = `${state.filteredRows.length.toLocaleString('en-US')} / ${state.rows.length.toLocaleString('en-US')}`;
    updateStatusFilterButtons();
    updateProbeSummary();
  }

  function copyText(text, buttonEl, defaultLabel) {
    const onSuccess = () => {
      buttonEl.textContent = 'Kopyalandı';
      buttonEl.classList.add('text-emerald-400', 'border-emerald-400/50');
      window.setTimeout(() => {
        buttonEl.textContent = defaultLabel;
        buttonEl.classList.remove('text-emerald-400', 'border-emerald-400/50');
      }, 1500);
    };

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(onSuccess).catch(() => {
        fallbackCopy(text);
        onSuccess();
      });
    } else {
      fallbackCopy(text);
      onSuccess();
    }
  }

  function fallbackCopy(text) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.setAttribute('readonly', '');
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    try {
      document.execCommand('copy');
    } finally {
      document.body.removeChild(textarea);
    }
  }

  function getStatusCellStyle(probe, isProbing) {
    if (isProbing) {
      return { text: 'Yoxlanılır...', cls: 'text-zinc-400' };
    }
    if (!probe) {
      return { text: '—', cls: 'text-zinc-600' };
    }
    switch (probe.state) {
      case 'live':
        return { text: probe.label, cls: 'text-emerald-400' };
      case 'redirect':
        return { text: probe.label, cls: 'text-sky-400' };
      case 'restricted':
        return { text: probe.label, cls: 'text-amber-400' };
      case 'error':
        return { text: probe.label, cls: 'text-rose-400' };
      default:
        return { text: probe.label, cls: 'text-zinc-500' };
    }
  }

  function matchesStatusFilter(subdomain) {
    if (state.statusFilter === 'all') return true;
    const probe = state.probes.get(subdomain);
    if (!probe) return false;
    if (state.statusFilter === 'active') {
      return probe.state === 'live' || probe.state === 'redirect';
    }
    if (state.statusFilter === 'reachable') {
      return (
        probe.state === 'live' ||
        probe.state === 'redirect' ||
        probe.state === 'restricted' ||
        probe.state === 'error'
      );
    }
    if (state.statusFilter === 'dead') {
      return probe.state === 'dead' || probe.state === 'timeout' || probe.state === 'down';
    }
    return true;
  }

  function renderTable() {
    els.tbody.textContent = '';

    if (state.rows.length === 0) {
      els.tableWrapper.classList.add('hidden');
      els.stateReady.classList.add('hidden');
      els.stateEmpty.classList.remove('hidden');
      els.emptyTitle.textContent = `${state.apex} üçün subdomen qeydi tapılmadı`;
      els.emptySubtitle.textContent =
        'Bu domen üzrə aktiv və ya tarixi subdomen qeydi aşkarlanmadı.';
      els.resetFilterBtn.classList.add('hidden');
      updateToolbarState();
      return;
    }

    if (state.filteredRows.length === 0) {
      els.tableWrapper.classList.add('hidden');
      els.stateReady.classList.add('hidden');
      els.stateEmpty.classList.remove('hidden');
      els.emptyTitle.textContent = 'Süzgəcə uyğun subdomen tapılmadı';
      els.emptySubtitle.textContent =
        state.statusFilter !== 'all'
          ? 'Seçilən status kateqoriyası üzrə hələ uyğun nəticə yoxdur və ya əvvəlcə statusları yoxlayın.'
          : 'Axtarış açar sözünü dəyişdirin və ya süzgəci sıfırlayın.';
      els.resetFilterBtn.classList.remove('hidden');
      updateToolbarState();
      return;
    }

    els.stateReady.classList.add('hidden');
    els.stateEmpty.classList.add('hidden');
    els.tableWrapper.classList.remove('hidden');

    const visibleSlice = state.filteredRows.slice(0, state.renderedLimit);
    const fragment = document.createDocumentFragment();

    visibleSlice.forEach((item, index) => {
      const tr = document.createElement('tr');
      tr.className = 'h-10 hover:bg-zinc-900/75 transition-colors';

      const tdIndex = document.createElement('td');
      tdIndex.className =
        'py-2 pl-4 pr-3 text-right font-mono tabular-nums text-xs text-zinc-500';
      tdIndex.textContent = String(index + 1);

      const tdSub = document.createElement('td');
      tdSub.className =
        'py-2 px-3 font-mono text-xs sm:text-sm text-zinc-100 whitespace-nowrap';
      tdSub.textContent = item.subdomain;

      const tdStatus = document.createElement('td');
      const probe = state.probes.get(item.subdomain);
      const isPending = state.probingSet.has(item.subdomain);
      const statusMeta = getStatusCellStyle(probe, isPending);
      tdStatus.className = `py-2 px-3 font-mono tabular-nums text-xs whitespace-nowrap ${statusMeta.cls}`;
      tdStatus.textContent = statusMeta.text;

      const tdDate = document.createElement('td');
      tdDate.className =
        'py-2 px-3 font-mono tabular-nums text-xs text-zinc-400 whitespace-nowrap';
      tdDate.textContent = item.first_seen || '—';

      const tdAction = document.createElement('td');
      tdAction.className = 'py-1.5 pl-3 pr-4 text-right';

      const copyBtn = document.createElement('button');
      copyBtn.type = 'button';
      copyBtn.className =
        'rounded-md border border-zinc-800 bg-zinc-950/70 px-2.5 py-1 text-xs font-medium text-zinc-300 hover:border-emerald-400/50 hover:text-emerald-400 transition-colors whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400';
      copyBtn.textContent = 'Kopyala';
      copyBtn.setAttribute('aria-label', `${item.subdomain} kopyala`);
      copyBtn.addEventListener('click', () => copyText(item.subdomain, copyBtn, 'Kopyala'));

      tdAction.appendChild(copyBtn);
      tr.appendChild(tdIndex);
      tr.appendChild(tdSub);
      tr.appendChild(tdStatus);
      tr.appendChild(tdDate);
      tr.appendChild(tdAction);
      fragment.appendChild(tr);
    });

    els.tbody.appendChild(fragment);

    if (state.filteredRows.length > state.renderedLimit) {
      els.loadMoreBar.classList.remove('hidden');
      const remaining = state.filteredRows.length - state.renderedLimit;
      els.renderedInfo.textContent = `Göstərilir: ${state.renderedLimit.toLocaleString('en-US')} / ${state.filteredRows.length.toLocaleString('en-US')}`;
      els.loadMoreBtn.textContent = `Daha çox göstər (+${Math.min(PAGE_CHUNK_SIZE, remaining)})`;
    } else {
      els.loadMoreBar.classList.add('hidden');
    }

    updateToolbarState();
  }

  function applyFilter(resetLimit = true) {
    const query = (els.filterInput.value || '').trim().toLowerCase();
    if (resetLimit) {
      state.renderedLimit = PAGE_CHUNK_SIZE;
    }
    state.filteredRows = state.rows.filter((item) => {
      if (query && !item.subdomain.toLowerCase().includes(query)) {
        return false;
      }
      return matchesStatusFilter(item.subdomain);
    });
    renderTable();
  }

  function triggerDownload(filename, content, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function runProbeAll() {
    if (state.probing) {
      stopProbing();
      renderTable();
      return;
    }

    const targets = state.filteredRows
      .map((r) => r.subdomain)
      .filter((sub) => !state.probes.has(sub));

    const queue =
      targets.length > 0 ? targets : state.filteredRows.map((r) => r.subdomain);

    if (queue.length === 0) return;

    const controller = new AbortController();
    state.probeController = controller;
    state.probing = true;
    els.probeSpinner.classList.remove('hidden');

    let done = 0;
    const total = queue.length;
    els.probeBtnLabel.textContent = `Dayandır (0/${total})`;

    try {
      for (let i = 0; i < queue.length; i += PROBE_BATCH_SIZE) {
        if (controller.signal.aborted) break;

        const batch = queue.slice(i, i + PROBE_BATCH_SIZE);
        batch.forEach((s) => state.probingSet.add(s));
        renderTable();

        const res = await fetch('/v1/probe', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Accept: 'application/json',
          },
          body: JSON.stringify({ subdomains: batch }),
          signal: controller.signal,
        });

        batch.forEach((s) => state.probingSet.delete(s));

        if (!res.ok) {
          const errPayload = await res.json().catch(() => ({}));
          showError(
            typeof errPayload.detail === 'string'
              ? errPayload.detail
              : `Status yoxlanışı zamanı xəta (HTTP ${res.status}).`
          );
          break;
        }

        const data = await res.json();
        const resultMap = data.results || {};
        for (const [sub, probeResult] of Object.entries(resultMap)) {
          state.probes.set(sub, probeResult);
        }

        done += batch.length;
        els.probeBtnLabel.textContent = `Dayandır (${Math.min(done, total)}/${total})`;
        applyFilter(false);
      }
    } catch (err) {
      if (!err || err.name !== 'AbortError') {
        showError('Status yoxlanışı zamanı bağlantı xətası baş verdi.');
      }
    } finally {
      if (state.probeController === controller) {
        stopProbing();
        applyFilter(false);
      }
    }
  }

  async function runSearch(rawInput) {
    const cleaned = cleanClientInput(rawInput);
    els.domainInput.value = cleaned;

    if (!cleaned) {
      showError('Zəhmət olmasa domen adı daxil edin (məs: example.com).');
      els.domainInput.focus();
      return;
    }

    stopProbing();
    if (state.activeController) {
      state.activeController.abort();
    }
    const controller = new AbortController();
    state.activeController = controller;

    clearError();
    setLoading(true);
    const clientStart = performance.now();

    try {
      const url = `/v1/search?apex=${encodeURIComponent(cleaned)}&format=json&dates=1`;
      const response = await fetch(url, {
        headers: { Accept: 'application/json' },
        signal: controller.signal,
      });

      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        const msg =
          typeof payload.detail === 'string' && payload.detail
            ? payload.detail
            : `Sorğu zamanı xəta baş verdi (HTTP ${response.status}).`;
        showError(msg);
        if (state.rows.length > 0) {
          renderTable();
        } else {
          els.stateReady.classList.remove('hidden');
        }
        return;
      }

      const clientElapsed = Math.round(performance.now() - clientStart);
      const serverElapsed =
        typeof payload.elapsed_ms === 'number' ? Math.round(payload.elapsed_ms) : clientElapsed;

      state.apex = payload.apex || cleaned;
      state.rows = Array.isArray(payload.subdomains) ? payload.subdomains : [];
      state.probes = new Map();
      for (const row of state.rows) {
        if (row && row.probe) {
          state.probes.set(row.subdomain, row.probe);
        }
      }
      state.statusFilter = 'all';
      state.cached = Boolean(payload.cached);
      state.stale = Boolean(payload.stale);
      state.elapsedMs = serverElapsed;

      els.domainInput.value = state.apex;
      els.filterInput.value = '';
      state.filteredRows = state.rows.slice();
      state.renderedLimit = PAGE_CHUNK_SIZE;

      const cacheLabel = state.stale ? 'Köhnə keş' : state.cached ? 'Keş' : 'Canlı';
      els.speedMeta.textContent = `${serverElapsed} ms · ${cacheLabel}`;
      els.speedSep.classList.remove('hidden');
      els.speedMeta.classList.remove('hidden');

      updateActiveSampleChip(state.apex);
      renderTable();
      refreshStats();
    } catch (err) {
      if (err && err.name === 'AbortError') {
        return;
      }
      showError('Serverlə əlaqə qurulmadı. Şəbəkə bağlantısını yoxlayın.');
      if (state.rows.length > 0) {
        renderTable();
      } else {
        els.stateReady.classList.remove('hidden');
      }
    } finally {
      if (state.activeController === controller) {
        state.activeController = null;
        setLoading(false);
      }
    }
  }

  // Event wiring
  els.form.addEventListener('submit', (event) => {
    event.preventDefault();
    runSearch(els.domainInput.value);
  });

  els.domainInput.addEventListener('blur', () => {
    const cleaned = cleanClientInput(els.domainInput.value);
    if (cleaned) {
      els.domainInput.value = cleaned;
    }
  });

  els.sampleBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      const sample = btn.getAttribute('data-sample') || '';
      els.domainInput.value = sample;
      runSearch(sample);
    });
  });

  els.filterInput.addEventListener('input', () => applyFilter(true));

  els.statusFilterBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      const next = btn.getAttribute('data-status-filter') || 'all';
      state.statusFilter = next;
      applyFilter(true);
    });
  });

  els.probeBtn.addEventListener('click', runProbeAll);

  els.resetFilterBtn.addEventListener('click', () => {
    els.filterInput.value = '';
    state.statusFilter = 'all';
    applyFilter(true);
    els.filterInput.focus();
  });

  els.loadMoreBtn.addEventListener('click', () => {
    state.renderedLimit += PAGE_CHUNK_SIZE;
    renderTable();
  });

  els.copyAllBtn.addEventListener('click', () => {
    if (state.filteredRows.length === 0) return;
    const text = state.filteredRows.map((r) => r.subdomain).join('\n');
    copyText(text, els.copyAllBtn, 'Kopyala');
  });

  els.downloadTxtBtn.addEventListener('click', () => {
    if (state.filteredRows.length === 0) return;
    const text = state.filteredRows.map((r) => r.subdomain).join('\n') + '\n';
    triggerDownload(`${state.apex || 'subdomains'}.txt`, text, 'text/plain;charset=utf-8');
  });

  els.downloadJsonBtn.addEventListener('click', () => {
    if (state.filteredRows.length === 0) return;
    const payload = {
      apex: state.apex,
      count: state.filteredRows.length,
      exported_at: new Date().toISOString(),
      subdomains: state.filteredRows.map((row) => ({
        subdomain: row.subdomain,
        first_seen: row.first_seen,
        probe: state.probes.get(row.subdomain) || null,
      })),
    };
    triggerDownload(
      `${state.apex || 'subdomains'}.json`,
      JSON.stringify(payload, null, 2),
      'application/json;charset=utf-8'
    );
  });

  // Init
  updateToolbarState();
  refreshStats();
})();
