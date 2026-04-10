-- UCI хелпер для 4eburnet
-- Чтение/запись конфигурации /etc/config/4eburnet
local uci = require "luci.model.uci"
local M = {}

local UCI_CONFIG = "4eburnet"

-- Читает опцию из UCI. Возвращает значение или default.
function M.get(section, option, default)
  local c = uci.cursor()
  local v = c:get(UCI_CONFIG, section, option)
  return v or default
end

-- Записывает опцию в UCI и коммитит.
function M.set(section, option, value)
  local c = uci.cursor()
  c:set(UCI_CONFIG, section, option, value)
  c:commit(UCI_CONFIG)
end

-- Возвращает true если 4eburnetd запущен (проверяет PID файл).
function M.is_running()
  local f = io.open("/var/run/4eburnet.pid", "r")
  if not f then return false end
  local pid = f:read("*l")
  f:close()
  if not pid or pid == "" then return false end
  -- Проверить что процесс живёт
  local proc = io.open("/proc/" .. pid .. "/status", "r")
  if proc then
    proc:close()
    return true
  end
  return false
end

return M
