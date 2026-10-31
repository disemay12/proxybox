local ffi = require("ffi")

pcall(ffi.cdef, [[
    void * __stdcall GetModuleHandleA(const char *name);
    int __stdcall VirtualProtect(void *address, size_t size, uint32_t protect, uint32_t *old);
    int __stdcall FlushInstructionCache(void *process, const void *address, size_t size);
    void * __stdcall GetCurrentProcess(void);
]])

local PAGE_EXECUTE_READWRITE = 0x40
local IMAGE_BASE = 0x400000

local function hex(s)
    return (s:gsub("%s", ""):gsub("..", function(b) return string.char(tonumber(b, 16)) end))
end

local patches = {
    {
        name = "udp associate dst",
        va = 0x45BED2,
        original = hex("68 70 9E 57 00 FF 15 E0 C2 48 00 89 44 24 20 0F B7 05 70 A0 57 00 50 FF 15 E8 C2 48 00"),
        patched = hex("31 C0 89 44 24 20" .. string.rep(" 90", 23)),
    },
    {
        name = "relay address",
        va = 0x45BF4F,
        original = hex("B8 02 00 00 00 C6 47 1A 01 66 89 47 04 83 C4 04 66 8B 44 24 34 66 89 47 06 8B 44 24 30 89 47 08 B0 01"),
        patched = hex("83 C4 04 8B 44 24 32 66 B8 02 00 89 47 04 8B 44 24 30 85 C0 0F 44 47 14 89 47 08 C6 47 1A 01 B0 01 90"),
    },
    {
        name = "connect retry interval",
        va = 0x40BCFD,
        original = hex("05 96 00 00 00"),
        patched = hex("05 E8 03 00 00"),
    },
    {
        name = "direct query",
        va = 0x40387E,
        original = hex("74 77"),
        patched = hex("EB 77"),
    },
}

local base = ffi.cast("uintptr_t", ffi.C.GetModuleHandleA(nil))

local function apply(p)
    local addr = ffi.cast("uint8_t *", base + (p.va - IMAGE_BASE))
    local current = ffi.string(addr, #p.original)
    if current == p.patched then return "already applied" end
    if current ~= p.original then return "skipped, unexpected bytes" end
    local old = ffi.new("uint32_t[1]")
    if ffi.C.VirtualProtect(addr, #p.patched, PAGE_EXECUTE_READWRITE, old) == 0 then
        return "skipped, VirtualProtect failed"
    end
    ffi.copy(addr, p.patched, #p.patched)
    ffi.C.VirtualProtect(addr, #p.patched, old[0], old)
    ffi.C.FlushInstructionCache(ffi.C.GetCurrentProcess(), addr, #p.patched)
    return "ok"
end

for _, p in ipairs(patches) do
    print(string.format("[proxy-patch] %s: %s", p.name, apply(p)))
end

local RETRY_INTERVAL_VA = 0x40BCFE

local function poke_retry_interval(ms)
    ms = math.floor(math.min(math.max(ms, 150), 3000))
    local addr = ffi.cast("uint32_t *", base + (RETRY_INTERVAL_VA - IMAGE_BASE))
    local old = ffi.new("uint32_t[1]")
    if ffi.C.VirtualProtect(addr, 4, PAGE_EXECUTE_READWRITE, old) == 0 then return end
    addr[0] = ms
    ffi.C.VirtualProtect(addr, 4, old[0], old)
    return ms
end

math.randomseed(os.time() + math.floor(os.clock() * 1000000))

local rtt
local connect_started

local real_proxyConnect = proxyConnect
function proxyConnect(...)
    connect_started = os.clock()
    return real_proxyConnect(...)
end

registerHandler("onProxyConnect", function()
    if not connect_started then return end
    local sample = (os.clock() - connect_started) * 1000
    connect_started = nil
    rtt = rtt and (rtt * 0.7 + sample * 0.3) or sample
    local jitter = 1.1 + math.random() * 0.1
    local applied = poke_retry_interval((rtt + 150) * jitter)
    if applied then
        print(string.format("[proxy-patch] retry interval: %d ms (rtt %d ms, avg %d ms)", applied, math.floor(sample), math.floor(rtt)))
    end
end)
