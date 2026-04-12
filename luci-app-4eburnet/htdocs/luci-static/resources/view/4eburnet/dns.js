'use strict';
'require view';
'require rpc';
'require ui';

var callDnsGet = rpc.declare({ object: '4eburnet', method: 'dns_get' });
var callDnsSet = rpc.declare({ object: '4eburnet', method: 'dns_set' });

/* Получить значение поля формы */
function getVal(id) {
    var el = document.getElementById(id);
    if (!el) return null;
    return el.type === 'checkbox' ? (el.checked ? '1' : '0') : el.value;
}

/* Поле ввода текста/числа */
function mkField(label, id, value, inputType, placeholder, tip) {
    return E('div', {style: 'margin-bottom:10px'}, [
        E('label', {
            style: 'display:flex;align-items:center;gap:4px;'
                 + 'font-size:11px;color:#8d96a0;margin-bottom:4px',
            'for': id
        }, [
            label,
            tip ? E('span', {
                title: tip,
                style: 'display:inline-flex;align-items:center;justify-content:center;'
                     + 'width:14px;height:14px;background:#21262d;border:1px solid #30363d;'
                     + 'border-radius:50%;font-size:9px;color:#545d68;cursor:help;flex-shrink:0'
            }, ['?']) : null
        ].filter(Boolean)),
        E('input', {
            id: id,
            type: inputType || 'text',
            value: value || '',
            placeholder: placeholder || '',
            style: 'width:100%;padding:6px 10px;background:#21262d;'
                 + 'border:1px solid #30363d;border-radius:4px;color:#e6edf3;'
                 + 'font-size:12px;font-family:monospace;outline:none;box-sizing:border-box'
        })
    ]);
}

/* Чекбокс с подписью */
function mkToggle(label, id, checked, tip) {
    return E('div', {style: 'display:flex;align-items:center;gap:8px;margin-bottom:10px'}, [
        E('input', {
            type: 'checkbox', id: id,
            checked: checked ? '' : null,
            style: 'width:16px;height:16px;cursor:pointer;accent-color:#4aa8f0'
        }),
        E('label', {
            'for': id,
            style: 'display:flex;align-items:center;gap:4px;font-size:12px;color:#e6edf3;cursor:pointer'
        }, [
            label,
            tip ? E('span', {
                title: tip,
                style: 'display:inline-flex;align-items:center;justify-content:center;'
                     + 'width:14px;height:14px;background:#21262d;border:1px solid #30363d;'
                     + 'border-radius:50%;font-size:9px;color:#545d68;cursor:help;flex-shrink:0'
            }, ['?']) : null
        ].filter(Boolean))
    ]);
}

/* Карточка-секция */
function mkSection(title, children) {
    return E('div', {
        style: 'background:#161b22;border:1px solid #30363d;'
             + 'border-radius:5px;padding:14px;margin-bottom:12px'
    }, [
        E('div', {
            style: 'font-size:11px;font-weight:600;color:#8d96a0;'
                 + 'text-transform:uppercase;letter-spacing:.7px;margin-bottom:12px'
        }, [title]),
        E('div', {}, children)
    ]);
}

/* Сетка из N колонок */
function grid(cols, children) {
    return E('div', {
        style: 'display:grid;grid-template-columns:repeat(' + cols + ',1fr);'
             + 'gap:10px'
    }, children);
}

return view.extend({

    load: function() {
        return callDnsGet();
    },

    render: function(dns) {
        dns = dns || {};

        var statusEl = E('div', {
            style: 'font-size:11px;min-height:16px;margin-top:8px'
        }, ['']);

        function doSave() {
            statusEl.textContent = _('Сохранение…');
            statusEl.style.color = '#8d96a0';

            var values = {
                upstream_bypass:   getVal('dns-bypass'),
                upstream_proxy:    getVal('dns-proxy'),
                upstream_default:  getVal('dns-default'),
                upstream_fallback: getVal('dns-fallback'),
                upstream_port:     getVal('dns-uport'),
                listen_port:       getVal('dns-lport'),
                parallel_query:    getVal('dns-parallel'),
                cache_size:        getVal('dns-cache'),
                bogus_nxdomain:    getVal('dns-bogus'),
                doh_enabled:       getVal('doh-enabled'),
                doh_url:           getVal('doh-url'),
                doh_ip:            getVal('doh-ip'),
                doh_sni:           getVal('doh-sni'),
                doh_port:          getVal('doh-port'),
                dot_enabled:       getVal('dot-enabled'),
                dot_server_ip:     getVal('dot-ip'),
                dot_port:          getVal('dot-port'),
                dot_sni:           getVal('dot-sni'),
                doq_enabled:       getVal('doq-enabled'),
                doq_server_ip:     getVal('doq-ip'),
                doq_server_port:   getVal('doq-port'),
                doq_sni:           getVal('doq-sni'),
                fake_ip_enabled:   getVal('fakeip-enabled'),
                fake_ip_range:     getVal('fakeip-range'),
                fake_ip_ttl:       getVal('fakeip-ttl')
            };

            callDnsSet(values).then(function(r) {
                if (r && r.ok) {
                    statusEl.textContent = '✓ ' + _('Сохранено');
                    statusEl.style.color = '#3ecf6a';
                } else {
                    statusEl.textContent = '✕ ' + ((r && r.error) || _('ошибка'));
                    statusEl.style.color = '#f85149';
                }
            }).catch(function(e) { ui.addNotification(null, E('p', {}, ['RPC: ' + e]), 'danger'); });
        }

        return E('div', {}, [
            E('div', {
                style: 'font-size:15px;font-weight:600;color:#e6edf3;margin-bottom:14px'
            }, [_('DNS настройки')]),

            mkSection(_('Upstream серверы'), [
                grid(2, [
                    mkField(_('Bypass DNS (RU домены)'), 'dns-bypass',
                        dns.upstream_bypass, 'text', '77.88.8.8',
                        'DNS для *.ru и *.рф — напрямую, без прокси'),
                    mkField(_('Proxy DNS'), 'dns-proxy',
                        dns.upstream_proxy, 'text', '8.8.8.8',
                        'DNS для заблокированных доменов (через прокси)'),
                    mkField(_('Default DNS'), 'dns-default',
                        dns.upstream_default, 'text', '1.1.1.1',
                        'Для доменов без явного правила'),
                    mkField(_('Fallback DNS'), 'dns-fallback',
                        dns.upstream_fallback, 'text', '9.9.9.9',
                        'Резервный DNS (Quad9 — с фильтрацией вредоносных)'),
                    mkField(_('Порт upstream (UDP)'), 'dns-uport',
                        dns.upstream_port, 'number', '53',
                        'Порт DNS серверов. Стандарт: 53'),
                    mkField(_('Порт прослушивания'), 'dns-lport',
                        dns.listen_port, 'number', '53',
                        '4eburnetd принимает запросы клиентов на этом порту')
                ]),
                mkToggle(_('Параллельные запросы (primary + fallback одновременно)'),
                    'dns-parallel', dns.parallel_query === '1',
                    'Отвечает первый ответивший сервер — снижает задержку')
            ]),

            mkSection(_('DNS over HTTPS (DoH)'), [
                mkToggle(_('Включить DoH'), 'doh-enabled', dns.doh_enabled === '1',
                    'Зашифрованный DNS через HTTPS/443. Только для PROXY доменов.'),
                grid(2, [
                    mkField(_('DoH URL'), 'doh-url',
                        dns.doh_url, 'text', 'https://dns.google/dns-query',
                        'Примеры: https://dns.google/dns-query, https://dns.adguard.com/dns-query'),
                    mkField(_('Pre-resolved IP (bootstrap)'), 'doh-ip',
                        dns.doh_ip, 'text', '8.8.8.8',
                        'IP DoH сервера — решает DNS bootstrap проблему'),
                    mkField(_('SNI'), 'doh-sni',
                        dns.doh_sni, 'text', 'dns.google',
                        'Server Name Indication для TLS'),
                    mkField(_('Порт (0 = авто)'), 'doh-port',
                        dns.doh_port, 'number', '443',
                        'Стандартный DoH порт: 443')
                ])
            ]),

            mkSection(_('DNS over TLS (DoT)'), [
                mkToggle(_('Включить DoT'), 'dot-enabled', dns.dot_enabled === '1',
                    'DNS over TLS порт 853. При включённых DoH+DoT — сначала DoH.'),
                grid(3, [
                    mkField(_('IP сервера'), 'dot-ip',
                        dns.dot_server_ip, 'text', '8.8.8.8',
                        'IP DoT: 8.8.8.8 (Google), 1.1.1.1 (CF), 9.9.9.9 (Quad9)'),
                    mkField(_('Порт'), 'dot-port',
                        dns.dot_port, 'number', '853',
                        'Стандартный DoT порт: 853'),
                    mkField(_('SNI'), 'dot-sni',
                        dns.dot_sni, 'text', 'dns.google',
                        'Примеры: dns.google, cloudflare-dns.com, dns.quad9.net')
                ])
            ]),

            mkSection(_('DNS over QUIC (DoQ) — RFC 9250'), [
                E('div', {
                    style: 'background:rgba(157,124,239,.06);border:1px solid rgba(157,124,239,.2);'
                         + 'border-radius:4px;padding:8px 10px;margin-bottom:10px;'
                         + 'font-size:11px;color:#bc8cff'
                }, ['⚡ ' + _('DoQ требует сборки с CONFIG_EBURNET_DOQ=1 (wolfSSL --enable-quic)')]),
                mkToggle(_('Включить DoQ (RFC 9250)'), 'doq-enabled', dns.doq_enabled === '1',
                    'QUIC+TLS 1.3 поверх UDP/853. Максимальная защита DNS.'),
                grid(3, [
                    mkField(_('IP сервера'), 'doq-ip',
                        dns.doq_server_ip, 'text', '94.140.14.14',
                        'AdGuard DNS: 94.140.14.14 / 94.140.15.15'),
                    mkField(_('Порт'), 'doq-port',
                        dns.doq_server_port, 'number', '853',
                        'Стандартный DoQ порт: 853/UDP'),
                    mkField(_('SNI'), 'doq-sni',
                        dns.doq_sni, 'text', 'dns.adguard.com',
                        'SNI для TLS 1.3 внутри QUIC. Обязательно.')
                ])
            ]),

            mkSection(_('Fake-IP режим'), [
                mkToggle(_('Включить Fake-IP'), 'fakeip-enabled',
                    dns.fake_ip_enabled === '1',
                    'Возвращает фиктивный IP вместо реального. Эффективно скрывает DNS от DPI.'),
                grid(2, [
                    mkField(_('IP пул (CIDR)'), 'fakeip-range',
                        dns.fake_ip_range, 'text', '198.18.0.0/16',
                        'Рекомендуется: 198.18.0.0/16 (RFC 5735)'),
                    mkField(_('TTL (сек)'), 'fakeip-ttl',
                        dns.fake_ip_ttl, 'number', '60',
                        'Время жизни fake-IP в кэше клиента')
                ])
            ]),

            mkSection(_('Кэш DNS'), [
                grid(2, [
                    mkField(_('Размер кэша (записей)'), 'dns-cache',
                        dns.cache_size, 'number', '256',
                        '0 = авто по профилю устройства. NORMAL: 256-1024'),
                    mkField(_('Bogus NXDOMAIN (IP через пробел)'), 'dns-bogus',
                        dns.bogus_nxdomain, 'text', '',
                        'IP-заглушки ISP. Если DNS ответ содержит их — отвечать NXDOMAIN')
                ])
            ]),

            E('div', {style: 'display:flex;gap:8px;align-items:center;flex-wrap:wrap'}, [
                E('button', {
                    class: 'btn cbi-button',
                    click: function() { doSave(); }
                }, [_('💾 Сохранить DNS')]),
                statusEl
            ])
        ]);
    },

    handleSaveApply: null,
    handleSave: null,
    handleReset: null
});
