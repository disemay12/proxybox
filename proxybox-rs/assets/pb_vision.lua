-- proxybox vision publisher для RakSAMP Lite.
-- Установка: положить в <RakSAMP Lite>/scripts/pb_vision.lua.
-- Ничего не рисует: раз в 200 мс отправляет состояние бота по UDP
-- на 127.0.0.1:<PB_VISION_PORT>, proxybox показывает его в тайле.
--
-- Переменные окружения задаёт proxybox при запуске копии:
--   PB_VISION_PORT, PB_VISION_TOKEN
-- Если их нет (запуск вручную), скрипт молча выключается.

local PORT = tonumber(os.getenv("PB_VISION_PORT") or "")
local TOKEN = os.getenv("PB_VISION_TOKEN")
if not PORT or PORT <= 0 or not TOKEN or TOKEN == "" then
    return
end

-- PB_PROXY задаёт proxybox: socks5://[user:pass@]host:port.
-- RakLite умеет SOCKS5 сам; pbhook для UDP бесполезен.
local function parse_proxy(raw)
    if not raw or raw == "" then
        return nil
    end
    local scheme, rest = raw:match("^(%w+)://(.+)$")
    if not rest then
        scheme, rest = "socks5", raw
    end
    scheme = scheme:lower()
    if scheme ~= "socks5" and scheme ~= "socks5h" then
        return nil
    end
    local auth, host_port = rest:match("^(.*)@([^@]+)$")
    if not host_port then
        host_port = rest
        auth = nil
    end
    local user, pass
    if auth then
        user, pass = auth:match("^([^:]+):(.*)$")
    end
    return { addr = host_port, user = user, pass = pass }
end

local PROXY = parse_proxy(os.getenv("PB_PROXY"))
if PROXY and type(proxyConnect) ~= "function" then
    print("[pb_vision] proxyConnect недоступен — нативный прокси выключен")
    PROXY = nil
end

local ok_ffi, ffi = pcall(require, "ffi")
if not ok_ffi then
    print("[pb_vision] LuaJIT FFI недоступен")
    return
end

if not _G.__pb_vision_cdef then
    ffi.cdef[[
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned int SOCKET;
struct sockaddr_in {
    uint16_t sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    char sin_zero[8];
};
SOCKET socket(int af, int type, int protocol);
int sendto(SOCKET s, const char *buf, int len, int flags,
           const struct sockaddr_in *to, int tolen);
uint16_t htons(uint16_t hostshort);
uint32_t inet_addr(const char *cp);
int closesocket(SOCKET s);
]]
    _G.__pb_vision_cdef = true
end

local ok_ws, ws2 = pcall(ffi.load, "ws2_32")
if not ok_ws then
    print("[pb_vision] ws2_32 не загрузился")
    return
end

local AF_INET, SOCK_DGRAM = 2, 2
local sock = ws2.socket(AF_INET, SOCK_DGRAM, 0)
if sock == nil or tonumber(sock) == 4294967295 then
    print("[pb_vision] socket() failed")
    return
end

local addr = ffi.new("struct sockaddr_in")
addr.sin_family = AF_INET
addr.sin_port = ws2.htons(PORT)
addr.sin_addr = ws2.inet_addr("127.0.0.1")
local addr_ptr = ffi.cast("const struct sockaddr_in*", addr)

local RANGE = 300.0          -- метров вокруг бота
local MAX_PLAYERS = 80
local MAX_VEHICLES = 60
local MAX_PICKUPS = 40
local MAX_LABELS = 24
local MAX_CHAT = 8

local chat = {}
local dialog = nil
local dialog_at = 0
local errors = 0

local function esc(value)
    local text = tostring(value or "")
    text = text:gsub("\\", "\\\\")
    text = text:gsub('"', '\\"')
    text = text:gsub("[%c]", " ")
    return text
end

local function num(value, digits)
    if type(value) ~= "number" then
        value = 0
    end
    return string.format("%." .. (digits or 1) .. "f", value)
end

local function integer(value)
    if type(value) ~= "number" then
        value = 0
    end
    return string.format("%d", math.floor(value))
end

local function safe(fn, ...)
    if type(fn) ~= "function" then
        return nil
    end
    local ok, value = pcall(fn, ...)
    if ok then
        return value
    end
    return nil
end

local function send(body)
    local payload = TOKEN .. "\n" .. body
    pcall(function()
        ws2.sendto(sock, payload, #payload, 0, addr_ptr, ffi.sizeof(addr))
    end)
end

local function on_server_message(_, text)
    if type(text) ~= "string" then
        return
    end
    chat[#chat + 1] = text
    while #chat > MAX_CHAT do
        table.remove(chat, 1)
    end
end

local function on_show_dialog(id, _, title, b1, b2, text)
    dialog = {
        id = id or 0,
        title = title or "",
        text = text or "",
        b1 = b1 or "",
        b2 = b2 or "",
    }
    dialog_at = os.time()
end

if type(registerHandler) == "function" then
    pcall(registerHandler, "onServerMessage", on_server_message)
    pcall(registerHandler, "onShowDialog", on_show_dialog)
else
    local ok_events, events = pcall(require, "samp.events")
    if ok_events and type(events) == "table" then
        events.onServerMessage = on_server_message
        events.onShowDialog = on_show_dialog
    end
end

local function dialog_json()
    if not dialog or os.time() - dialog_at > 20 then
        return "null"
    end
    return '{"id":' .. integer(dialog.id)
        .. ',"title":"' .. esc(dialog.title)
        .. '","text":"' .. esc(dialog.text)
        .. '","b1":"' .. esc(dialog.b1)
        .. '","b2":"' .. esc(dialog.b2) .. '"}'
end

local function build_body()
    local bot_id = safe(getBotId) or -1
    local bx, by, bz = 0, 0, 0
    local ok_pos, px, py, pz = pcall(getBotPosition)
    if ok_pos then
        bx, by, bz = px or 0, py or 0, pz or 0
    end

    local players = {}
    for id, player in pairs(safe(getAllPlayers) or {}) do
        local pos = player.position
        if id ~= bot_id and pos and player.exist ~= false then
            local dx, dy = (pos.x or 0) - bx, (pos.y or 0) - by
            local d2 = dx * dx + dy * dy
            if d2 <= RANGE * RANGE then
                players[#players + 1] = { id = id, p = player, d2 = d2 }
            end
        end
    end
    table.sort(players, function(a, b) return a.d2 < b.d2 end)

    local player_json = {}
    for i = 1, math.min(#players, MAX_PLAYERS) do
        local item = players[i]
        local p = item.p
        local pos = p.position
        player_json[#player_json + 1] = "["
            .. integer(item.id) .. ","
            .. num(pos.x) .. "," .. num(pos.y) .. "," .. num(pos.z) .. ','
            .. '"' .. esc(p.nick) .. '",'
            .. integer(p.color or 0) .. "]"
    end

    local vehicles = {}
    for id, vehicle in pairs(safe(getAllVehicles) or {}) do
        local pos = vehicle.position
        if pos then
            local dx, dy = (pos.x or 0) - bx, (pos.y or 0) - by
            local d2 = dx * dx + dy * dy
            if d2 <= RANGE * RANGE then
                vehicles[#vehicles + 1] = { id = id, v = vehicle, d2 = d2 }
            end
        end
    end
    table.sort(vehicles, function(a, b) return a.d2 < b.d2 end)

    local vehicle_json = {}
    for i = 1, math.min(#vehicles, MAX_VEHICLES) do
        local item = vehicles[i]
        local v = item.v
        local pos = v.position
        vehicle_json[#vehicle_json + 1] = "["
            .. integer(item.id) .. ","
            .. num(pos.x) .. "," .. num(pos.y) .. "," .. num(pos.z) .. ","
            .. integer(v.model) .. ',"' .. esc(v.name) .. '"]'
    end

    local pickups = {}
    for id, pickup in pairs(safe(getAllPickups) or {}) do
        local pos = pickup.position
        if pos then
            local dx, dy = (pos.x or 0) - bx, (pos.y or 0) - by
            local d2 = dx * dx + dy * dy
            if d2 <= RANGE * RANGE then
                pickups[#pickups + 1] = { id = id, k = pickup, d2 = d2 }
            end
        end
    end
    table.sort(pickups, function(a, b) return a.d2 < b.d2 end)

    local pickup_json = {}
    for i = 1, math.min(#pickups, MAX_PICKUPS) do
        local item = pickups[i]
        local pos = item.k.position
        pickup_json[#pickup_json + 1] = "["
            .. integer(item.id) .. ","
            .. num(pos.x) .. "," .. num(pos.y) .. "," .. num(pos.z) .. ","
            .. integer(item.k.model) .. "]"
    end

    local labels = {}
    for _, label in pairs(safe(getAllLabels) or {}) do
        local pos = label.position
        if pos then
            local dx, dy = (pos.x or 0) - bx, (pos.y or 0) - by
            local d2 = dx * dx + dy * dy
            if d2 <= RANGE * RANGE then
                labels[#labels + 1] = { l = label, d2 = d2 }
            end
        end
    end
    table.sort(labels, function(a, b) return a.d2 < b.d2 end)

    local label_json = {}
    for i = 1, math.min(#labels, MAX_LABELS) do
        local label = labels[i].l
        local pos = label.position
        label_json[#label_json + 1] = "["
            .. num(pos.x) .. "," .. num(pos.y) .. "," .. num(pos.z) .. ','
            .. '"' .. esc(label.text) .. '"]'
    end

    local chat_json = {}
    for _, line in ipairs(chat) do
        chat_json[#chat_json + 1] = '"' .. esc(line) .. '"'
    end

    return '{"t":' .. os.time()
        .. ',"nick":"' .. esc(safe(getBotNick) or "") .. '"'
        .. ',"srv":"' .. esc(safe(getServerName) or "") .. '"'
        .. ',"ping":' .. integer(safe(getBotPing) or 0)
        .. ',"money":' .. integer(safe(getBotMoney) or 0)
        .. ',"hp":' .. num(safe(getBotHealth) or 0)
        .. ',"arm":' .. num(safe(getBotArmor) or 0)
        .. ',"pos":[' .. num(bx) .. ',' .. num(by) .. ',' .. num(bz) .. ']'
        .. ',"rot":' .. num(safe(getBotRotation) or 0)
        .. ',"int":' .. integer(safe(getBotInterior) or 0)
        .. ',"veh":' .. integer(safe(getBotVehicle) or 0)
        .. ',"conn":true'
        .. ',"p":[' .. table.concat(player_json, ",") .. ']'
        .. ',"v":[' .. table.concat(vehicle_json, ",") .. ']'
        .. ',"k":[' .. table.concat(pickup_json, ",") .. ']'
        .. ',"l":[' .. table.concat(label_json, ",") .. ']'
        .. ',"chat":[' .. table.concat(chat_json, ",") .. ']'
        .. ',"dlg":' .. dialog_json() .. '}'
end

function onLoad()
    if PROXY and type(proxyConnect) == "function" then
        local ok, err
        if PROXY.user then
            ok, err = pcall(proxyConnect, PROXY.addr, PROXY.user, PROXY.pass or "")
        else
            ok, err = pcall(proxyConnect, PROXY.addr)
        end
        print("[pb_vision] proxy " .. PROXY.addr .. (ok and "" or (" error: " .. tostring(err))))
    elseif os.getenv("PB_PROXY") and not PROXY then
        print("[pb_vision] PB_PROXY не SOCKS5 — нативный прокси выключен")
    end
    if type(setRate) == "function" and RATE_LUA ~= nil then
        pcall(setRate, RATE_LUA, 200)
    end
    print("[pb_vision] publisher -> 127.0.0.1:" .. PORT)
end

-- Не пускаем бота на сервер, пока SOCKS5 не поднялся: иначе реальный IP.
function onRequestConnect()
    if PROXY and type(isProxyConnected) == "function" then
        return isProxyConnected()
    end
end

function onUpdate()
    local connected = safe(isBotConnected)
    if connected == false then
        return
    end
    local ok, body = pcall(build_body)
    if not ok then
        errors = errors + 1
        if errors == 1 then
            print("[pb_vision] build error: " .. tostring(body))
        end
        return
    end
    send(body)
end

function onUnload()
    pcall(function()
        ws2.closesocket(sock)
    end)
end
