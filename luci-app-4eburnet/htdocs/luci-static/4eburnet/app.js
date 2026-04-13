// ── API клиент ────────────────────────────────────────────────────
// EB_API и EB_PAGE инжектируются из base.htm через window.*

const ebApi = async (path, method, body) => {
  try {
    const r = await fetch((window.EB_API || '') + path, {
      method: method || 'GET',
      credentials: 'include',
      headers: body ? {'Content-Type':'application/json'} : {},
      body: body ? JSON.stringify(body) : undefined
    });
    if (!r.ok) return {error: 'HTTP ' + r.status};
    return await r.json();
  } catch(e) { return {error: e.message}; }
};
const ebGet  = p      => ebApi(p);
const ebPost = (p, b) => ebApi(p, 'POST', b || {});

// ── Tooltip ────────────────────────────────────────────────────────
const ttEl = document.getElementById('eb-tt');
let ttTimer;
document.addEventListener('mouseover', e => {
  const t = e.target.closest('[data-tip]');
  if (!t) return;
  clearTimeout(ttTimer);
  ttTimer = setTimeout(() => {
    if (!ttEl) return;
    ttEl.textContent = t.dataset.tip;
    ttEl.style.display = 'block';
    const r = t.getBoundingClientRect();
    let left = r.left + r.width / 2 - 110;
    let top  = r.top - ttEl.offsetHeight - 8;
    if (top < 4) top = r.bottom + 8;
    left = Math.max(6, Math.min(left, window.innerWidth - 228));
    ttEl.style.left = left + 'px';
    ttEl.style.top  = Math.max(4, top) + 'px';
  }, 160);
});
document.addEventListener('mouseout', e => {
  if (e.target.closest('[data-tip]')) {
    clearTimeout(ttTimer);
    if (ttEl) ttEl.style.display = 'none';
  }
});

// ── Notification ───────────────────────────────────────────────────
let ntTimer;
function ebNotify(msg, type) {
  const el = document.getElementById('eb-notif');
  if (!el) return;
  el.textContent = (type==='ok' ? '✓ ' : type==='er' ? '✕ ' : '⚠ ') + msg;
  el.className = 'eb-notif show ' + (type || 'ok');
  clearTimeout(ntTimer);
  ntTimer = setTimeout(() => el.classList.remove('show'), 2800);
}

// ── Status polling ─────────────────────────────────────────────────
async function ebPollStatus() {
  const d = await ebGet('/status');
  if (d.error) return;

  const badge = document.getElementById('eb-daemon');
  const dtxt  = document.getElementById('eb-dtxt');
  const pulse = document.getElementById('eb-pulse');
  if (badge) badge.className = 'eb-daemon ' + (d.running ? 'on' : 'off');
  if (pulse) pulse.style.animation = d.running
    ? 'ebpulse 1.8s ease-in-out infinite' : 'none';

  const uptimeStr = d.running ? ebFmtUptime(d.uptime) : '—';
  if (dtxt) dtxt.textContent = d.running ? 'Запущен · ' + uptimeStr : 'Остановлен';

  // Overview page elements
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  set('s-status', d.running ? 'Активен' : 'Стоп');
  set('s-uptime', 'Аптайм: ' + uptimeStr);
  set('s-mode',   d.mode || '—');
  set('hero-uptime', 'Аптайм: ' + uptimeStr);
  set('hero-mode',   d.mode || '—');

  const hs = document.getElementById('hero-status');
  if (hs) {
    hs.textContent = d.running ? '● Активен' : '● Остановлен';
    hs.style.color = d.running ? 'var(--eb-ok)' : 'var(--eb-er)';
  }
}

function ebFmtUptime(sec) {
  sec = sec || 0;
  const h = Math.floor(sec / 3600);
  const m = Math.floor(sec % 3600 / 60);
  const s = sec % 60;
  return h + 'ч ' + m + 'м ' + s + 'с';
}

// ── WAN IP + VLESS QR ──────────────────────────────────────────────
let ebWanIp = '';
let ebVlessUrl = '';

async function ebRefreshWan() {
  const d = await ebGet('/wan_ip');
  if (d.ip && d.ip !== 'unknown') {
    ebWanIp = d.ip;
    const el = document.getElementById('wan-ip-disp');
    if (el) el.textContent = ebWanIp;
  }
  ebBuildVless();
}

async function ebBuildVless() {
  const el = document.getElementById('vless-url-disp');
  const box = document.getElementById('qr-box');

  /* Найти первый VLESS+Reality сервер из кон��ига */
  const d = await ebGet('/server_list');
  const servers = (d && d.servers) || [];
  let srv = null;
  for (let i = 0; i < servers.length; i++) {
    if (servers[i].protocol === 'vless' && servers[i].reality_pbk) {
      srv = servers[i]; break;
    }
  }
  if (!srv) {
    if (el) el.textContent = '—';
    if (box) box.innerHTML = '<span style="color:#545d68;font-size:10px">Нет VLESS+Reality серверов</span>';
    return;
  }

  const host = ebWanIp || srv.address || '';
  const port = srv.port || 443;
  const uuid = srv.uuid || '';
  const sni  = srv.address || host;
  const pbk  = srv.reality_pbk || '';
  const sid  = srv.reality_sid || '';
  const name = encodeURIComponent(srv.name || '4eburNet');

  ebVlessUrl = 'vless://' + uuid + '@' + host + ':' + port
    + '?type=tcp&security=reality&fp=chrome'
    + '&sni=' + encodeURIComponent(sni)
    + '&pbk=' + encodeURIComponent(pbk)
    + '&sid=' + encodeURIComponent(sid)
    + '#' + name;

  if (el) el.textContent = ebVlessUrl;
  ebGenQR(ebVlessUrl);
}

function ebGenQR(text) {
  const box = document.getElementById('qr-box');
  if (!box) return;
  box.innerHTML = '';
  if (window.QRCode) {
    new QRCode(box, {text: text, width: 80, height: 80,
      colorDark: '#000', colorLight: '#fff',
      correctLevel: QRCode.CorrectLevel.M});
  } else {
    box.innerHTML = '<div style="font-size:9px;color:#545d68;text-align:center;padding:6px">QR<br>' + ebEsc(ebWanIp || '—') + '</div>';
  }
}

function ebCopyUrl() {
  try { navigator.clipboard.writeText(ebVlessUrl); }
  catch(e) {
    const t = document.createElement('textarea');
    t.value = ebVlessUrl;
    document.body.appendChild(t);
    t.select();
    document.execCommand('copy');
    document.body.removeChild(t);
  }
  ebNotify('Ссылка скопирована', 'ok');
}

// ── Groups mini view ───────────────────────────────────────────────
async function ebLoadGroupsMini() {
  const box = document.getElementById('groups-mini');
  if (!box) return;
  const d = await ebGet('/groups');
  if (d.error || !d.groups) {
    box.innerHTML = '<div class="eb-xs">Нет данных</div>';
    return;
  }
  /* B4-06: available/latency на уровне сервера, не группы */
  box.innerHTML = d.groups.slice(0, 3).map(g => {
    const srvs = g.servers || [];
    const avail = srvs.some(s => s.available);
    const sel = srvs[g.selected] || srvs[0] || {};
    const lat = sel.latency_ms || 0;
    return `
    <div class="eb-srow ${g.selected ? 'sel' : ''}">
      <div class="eb-sdot ${avail ? 'ok' : 'er'}"></div>
      <div>
        <div class="eb-bold" style="font-size:11px">${ebEsc(g.name || '—')}</div>
        <div class="eb-xs">${ebEsc(String(g.type || ''))}</div>
      </div>
      <div class="eb-ml eb-slat ${lat < 100 ? 'ok' : lat < 250 ? 'wn' : 'er'}">
        ${lat ? lat + ' мс' : '—'}
      </div>
    </div>`;
  }).join('');
}

// ── Accordion ──────────────────────────────────────────────────────
document.addEventListener('click', e => {
  const h = e.target.closest('.eb-acc-h');
  if (h) h.closest('.eb-acc').classList.toggle('open');
});

// ── Page init ──────────────────────────────────────────────────────
/* P8-03: сохранить ID интервалов для cleanup при навигации */
let ebStatusTimer = null;

function ebStopPolling() {
  if (ebStatusTimer) { clearInterval(ebStatusTimer); ebStatusTimer = null; }
  if (ebLogInterval)  { clearInterval(ebLogInterval); ebLogInterval = null; }
}

async function ebInitPage(pageId) {
  await ebPollStatus();
  ebStatusTimer = setInterval(ebPollStatus, 2000);

  if (pageId === 'overview') {
    ebRefreshWan();
    ebLoadGroupsMini();
  }
  if (pageId === 'logs')    ebStartLogPolling();
  if (pageId === 'devices') ebLoadDevices();
  if (pageId === 'groups')  ebLoadGroups();
}

// ── Logs page ──────────────────────────────────────────────────────
let ebLogInterval;
async function ebFetchLogs() {
  const d = await ebGet('/logs?lines=100');
  const area = document.getElementById('eb-log-area');
  if (!area || !d.lines) return;
  const lvFilter = (document.getElementById('eb-log-lf')   || {}).value || '';
  const search   = ((document.getElementById('eb-log-search') || {}).value || '').toLowerCase();
  const filtered = d.lines.filter(l =>
    (!lvFilter || l.toLowerCase().includes('[' + lvFilter + ']')) &&
    (!search   || l.toLowerCase().includes(search))
  );
  area.innerHTML = filtered.map(l => {
    const lv   = l.match(/\[(DEBUG|INFO|WARN|ERROR)\]/i);
    const lvCd = lv ? lv[1].toLowerCase()[0] : 'i';
    const ts   = l.match(/^(\d{2}:\d{2}:\d{2})/);
    return `<div class="eb-ll">
      <span class="eb-lt">${ts ? ts[1] : ''}</span>
      <span class="eb-lv ${lvCd}">${lv ? lv[1] : 'INFO'}</span>
      <span class="eb-lm">${ebEsc(l.replace(/^\d{2}:\d{2}:\d{2}\s+\[\w+\]\s*/, ''))}</span>
    </div>`;
  }).join('');
  area.scrollTop = area.scrollHeight;
}
function ebStartLogPolling() {
  ebFetchLogs();
  ebLogInterval = setInterval(ebFetchLogs, 3000);
}
function ebEsc(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
          .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

// ── Devices page ───────────────────────────────────────────────────
async function ebLoadDevices() {
  const tbody = document.getElementById('eb-devices-tbody');
  if (!tbody) return;
  const d = await ebGet('/devices');
  if (d.error || !d.devices) return;
  tbody.innerHTML = d.devices.map(dev => `
    <tr>
      <td><div class="eb-sdot ok" style="display:inline-block"></div></td>
      <td class="eb-mono">${ebEsc(dev.mac || '')}</td>
      <td class="eb-mono">${ebEsc(dev.ip || '')}</td>
      <td>${ebEsc(dev.iface || '—')}</td>
      <td>
        <select class="eb-select" style="padding:3px 7px;font-size:11px;width:auto">
          <option>default</option>
          <option>proxy</option>
          <option>bypass</option>
          <option>block</option>
        </select>
      </td>
      <td><button class="eb-btn eb-btn-g" style="padding:2px 7px;font-size:10px">✏️</button></td>
    </tr>`).join('');
}

// ── Groups page ────────────────────────────────────────────────────
async function ebLoadGroups() {
  const box = document.getElementById('eb-groups-grid');
  if (!box) return;
  const d = await ebGet('/groups');
  if (d.error || !d.groups) {
    box.innerHTML = '<div class="eb-xs">Нет данных от демона</div>';
    return;
  }
  box.innerHTML = d.groups.map(g => `
    <div class="eb-card">
      <div class="eb-card-h">
        <div>
          <div class="eb-bold">${ebEsc(g.name || '')}</div>
          <div class="eb-xs">${ebEsc(String(g.type || ''))} · ${g.interval || 60}с</div>
        </div>
        <div style="display:flex;gap:6px;align-items:center">
          <span class="eb-badge eb-bin">${ebEsc(String(g.type || ''))}</span>
          <button class="eb-btn eb-btn-g" style="padding:3px 7px"
            data-action="test" data-group="${ebEsc(g.name || '')}">⟳</button>
        </div>
      </div>
      <div>${(g.servers || []).map((s, i) => `
        <div class="eb-srow ${s.selected ? 'sel' : ''}"
             data-action="select" data-group="${ebEsc(g.name || '')}" data-idx="${i}"
             data-sname="${ebEsc(s.name || '')}">
          <div class="eb-sdot ${s.available ? 'ok' : 'er'}"></div>
          <div class="eb-snm">${ebEsc(s.name || '')}</div>
          <div class="eb-slat ${s.latency_ms < 100 ? 'ok' : s.latency_ms < 250 ? 'wn' : 'er'}">
            ${s.latency_ms ? s.latency_ms + 'мс' : 'timeout'}
          </div>
        </div>`).join('')}
      </div>
    </div>`).join('');
  box.addEventListener('click', function(e) {
    const test = e.target.closest('[data-action="test"]');
    if (test) {
      ebPost('/groups', {action:'test', group: test.dataset.group})
        .then(r => ebNotify('HC ' + (r.ok || 'done'), 'ok'))
        .catch(e => ebNotify('HC ошибка: ' + e, 'err'));
      return;
    }
    const sel = e.target.closest('[data-action="select"]');
    if (sel) {
      ebPost('/groups/select', {group: sel.dataset.group, idx: parseInt(sel.dataset.idx, 10)})
        .then(() => { ebNotify(sel.dataset.sname + ' выбран', 'ok'); ebLoadGroups(); })
        .catch(e => ebNotify('Select ошибка: ' + e, 'err'));
    }
  });
}
