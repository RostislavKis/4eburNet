-- Контроллер LuCI для 4eburnet-router
-- Регистрирует страницы в меню и связывает их с моделями

module("luci.controller.4eburnet", package.seeall)

-- Путь к статике (логотип, JS, CSS)
local STATIC_PATH = "/luci-static/4eburnet/"
local LOGO_PATH   = STATIC_PATH .. "logo.png"

function index()
    -- TODO: регистрация страниц:
    -- entry({"admin", "services", "4eburnet"}, ...)
    -- entry({"admin", "services", "4eburnet", "servers"}, ...)
    -- entry({"admin", "services", "4eburnet", "routing"}, ...)
    -- entry({"admin", "services", "4eburnet", "dns"}, ...)
    -- entry({"admin", "services", "4eburnet", "stats"}, ...)
end
