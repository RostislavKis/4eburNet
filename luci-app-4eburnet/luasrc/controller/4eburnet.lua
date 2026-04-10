-- Контроллер LuCI для 4eburNet
-- Регистрирует страницы в меню и связывает их с шаблонами

module("luci.controller.4eburnet", package.seeall)

-- Путь к статике (логотип, JS, CSS)
local STATIC_PATH = "/luci-static/4eburnet/"
local LOGO_PATH   = STATIC_PATH .. "logo.png"

function index()
  -- TOP-LEVEL меню "4eburNet" между Network(50) и System(60)
  entry({"admin","services","4eburnet"},
        alias("admin","services","4eburnet","overview"),
        "4eburNet", 55)

  entry({"admin","services","4eburnet","overview"},
        call("page_overview"), "Обзор", 1)

  entry({"admin","services","4eburnet","logs"},
        call("page_logs"), "Логи", 2)

  entry({"admin","services","4eburnet","servers"},
        call("page_servers"), "Серверы", 10)

  entry({"admin","services","4eburnet","groups"},
        call("page_groups"), "Группы", 11)

  entry({"admin","services","4eburnet","subscriptions"},
        call("page_subscriptions"), "Подписки", 12)

  entry({"admin","services","4eburnet","rules"},
        call("page_rules"), "Правила", 20)

  entry({"admin","services","4eburnet","devices"},
        call("page_devices"), "Устройства", 21)

  entry({"admin","services","4eburnet","dns"},
        call("page_dns"), "DNS", 22)

  entry({"admin","services","4eburnet","adblock"},
        call("page_adblock"), "Блокировка рекламы", 23)

  entry({"admin","services","4eburnet","settings"},
        call("page_settings"), "Настройки", 30).leaf = true

  -- JSON API (leaf — не отображаются в меню)
  local api_nodes = {
    "status","stats","reload","stop","restart",
    "groups","logs","wan_ip","devices","config"
  }
  for _, n in ipairs(api_nodes) do
    entry({"admin","services","4eburnet","api",n},
          call("api_"..n)).leaf = true
  end
  entry({"admin","services","4eburnet","api","groups","select"},
        call("api_group_select")).leaf = true
end

-- Хелпер: рендерить страницу через шаблон
local function render_page(page_id)
  luci.template.render("4eburnet/" .. page_id, {
    page_id = page_id,
    static  = STATIC_PATH
  })
end

function page_overview()      render_page("overview")      end
function page_logs()          render_page("logs")           end
function page_servers()       render_page("servers")        end
function page_groups()        render_page("groups")         end
function page_subscriptions() render_page("subscriptions")  end
function page_rules()         render_page("rules")          end
function page_devices()       render_page("devices")        end
function page_dns()           render_page("dns")            end
function page_adblock()       render_page("adblock")        end
function page_settings()      render_page("settings")       end

-- Хелперы JSON API
local function json_out(data)
  luci.http.prepare_content("application/json")
  luci.http.write(require("luci.jsonc").stringify(data))
end

local function ipc(cmd, payload)
  return require("luci.lib.4eburnet.ipc").call(cmd, payload)
end

local function ipc_json(cmd, payload)
  local r, e = ipc(cmd, payload)
  if e then return {error=e} end
  local ok, d = pcall(require("luci.jsonc").parse, r or "")
  return (ok and d) or {raw=r}
end

-- API: статус демона
function api_status()
  local h = require "luci.lib.4eburnet.uci_helper"
  local running = h.is_running()
  local data = running and ipc_json(1) or {}
  json_out({
    running   = running,
    uptime    = data.uptime or 0,
    mode      = data.mode or h.get("main","mode","rules"),
    timestamp = os.time()
  })
end

-- API: статистика (соединения, DNS, и т.д.)
function api_stats()
  json_out(ipc_json(4))
end

-- API: перезагрузить конфигурацию
function api_reload()
  local r, e = ipc(2)
  json_out({ok=(e==nil), error=e})
end

-- API: остановить демон
function api_stop()
  local r, e = ipc(3)
  json_out({ok=(e==nil), error=e})
end

-- API: перезапустить демон через init.d
function api_restart()
  os.execute("/etc/init.d/4eburnet stop 2>/dev/null; sleep 1; /etc/init.d/4eburnet start 2>/dev/null")
  json_out({ok=true})
end

-- API: список proxy групп
function api_groups()
  json_out(ipc_json(20))
end

-- API: выбрать сервер в группе
function api_group_select()
  local b = luci.http.content()
  local r, e = ipc(21, b)
  json_out({ok=(e==nil), error=e})
end

-- API: последние строки лога
function api_logs()
  local n = tonumber(luci.http.formvalue("lines")) or 50
  if n > 500 then n = 500 end
  local lines = {}
  local f = io.open("/tmp/4eburnet.log","r")
  if f then
    local all = {}
    for l in f:lines() do all[#all+1] = l end
    f:close()
    local s = math.max(1, #all - n + 1)
    for i = s, #all do lines[#lines+1] = all[i] end
  end
  json_out({lines=lines, count=#lines})
end

-- API: WAN IP роутера
function api_wan_ip()
  local ip = nil
  local f = io.popen(
    "ip route get 8.8.8.8 2>/dev/null | awk 'NR==1{for(i=1;i<=NF;i++)if($i==\"src\")print $(i+1)}'"
  )
  if f then ip = f:read("*l"); f:close() end
  json_out({ip=ip or "unknown", timestamp=os.time()})
end

-- API: устройства в сети (из ARP таблицы)
function api_devices()
  local devs = {}
  local f = io.open("/proc/net/arp","r")
  if f then
    f:read("*l")  -- пропустить заголовок
    for l in f:lines() do
      local ip, _, _, mac, _, iface = l:match(
        "(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)"
      )
      if ip and mac and mac ~= "00:00:00:00:00:00" then
        devs[#devs+1] = {ip=ip, mac=mac:upper(), iface=iface}
      end
    end
    f:close()
  end
  json_out({devices=devs, count=#devs})
end

-- API: чтение/запись основной конфигурации
function api_config()
  local h = require "luci.lib.4eburnet.uci_helper"
  if luci.http.getenv("REQUEST_METHOD") == "POST" then
    local ok, p = pcall(require("luci.jsonc").parse, luci.http.content())
    if ok and p then
      for _, k in ipairs({"enabled","mode","log_level","lan_interface"}) do
        if p[k] then h.set("main", k, tostring(p[k])) end
      end
      json_out({ok=true})
    else
      json_out({error="invalid JSON"})
    end
  else
    json_out({
      enabled   = h.get("main","enabled","1"),
      mode      = h.get("main","mode","rules"),
      log_level = h.get("main","log_level","info"),
      lan_iface = h.get("main","lan_interface","br-lan"),
    })
  end
end
