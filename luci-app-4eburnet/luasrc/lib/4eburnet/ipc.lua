-- IPC клиент для 4eburnet — unix socket
-- Протокол: 4-байт little-endian длина + JSON payload
local nixio = require "nixio"
local M = {}

local SOCKET_PATH = "/var/run/4eburnet.sock"
local TIMEOUT_SEC = 3

-- Отправить команду, получить ответ. Возвращает (ответ_строка, nil) или (nil, ошибка_строка)
function M.call(cmd_id, payload)
  local sock = nixio.socket("unix", "stream")
  if not sock then
    return nil, "nixio: не удалось создать сокет"
  end
  sock:setopt("socket", "sndtimeo", TIMEOUT_SEC)
  sock:setopt("socket", "rcvtimeo", TIMEOUT_SEC)

  local ok, err = sock:connect(SOCKET_PATH)
  if not ok then
    sock:close()
    return nil, "connect: " .. (err or "?")
  end

  -- Сформировать JSON запрос
  local body
  if payload then
    body = '{"cmd":' .. tostring(cmd_id) .. ',"data":' .. tostring(payload) .. '}'
  else
    body = '{"cmd":' .. tostring(cmd_id) .. '}'
  end

  -- 4-байт length prefix (little-endian)
  local n = #body
  local prefix = string.char(
    n % 256,
    math.floor(n / 256) % 256,
    math.floor(n / 65536) % 256,
    math.floor(n / 16777216) % 256
  )

  local sent, serr = sock:send(prefix .. body)
  if not sent then
    sock:close()
    return nil, "send: " .. (serr or "?")
  end

  -- Прочитать 4-байт префикс ответа
  local hdr = ""
  while #hdr < 4 do
    local chunk, rerr = sock:recv(4 - #hdr)
    if not chunk or #chunk == 0 then
      sock:close()
      return nil, "recv hdr: " .. (rerr or "eof")
    end
    hdr = hdr .. chunk
  end
  local rlen = string.byte(hdr,1)
             + string.byte(hdr,2) * 256
             + string.byte(hdr,3) * 65536
             + string.byte(hdr,4) * 16777216

  -- Прочитать тело ответа
  local resp = ""
  while #resp < rlen do
    local chunk, rerr = sock:recv(rlen - #resp)
    if not chunk or #chunk == 0 then
      sock:close()
      return nil, "recv body: " .. (rerr or "eof")
    end
    resp = resp .. chunk
  end

  sock:close()
  return resp, nil
end

return M
