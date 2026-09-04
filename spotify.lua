--[[
    Spotify for Neverlose ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â authentication

    Phase 2. Everything here rests on results proven in phases 0 and 1:

      * network.get is binary-safe and takes custom headers
      * network.post form-encodes natively, which is what Spotify's token
        endpoint requires
      * a loopback listener on 127.0.0.1 works inside CS:GO
      * SHA-256 / base64url in pure Lua pass the RFC 7636 vectors

    Nothing is hosted. The only external service touched is Spotify.

    Flow:
        Connect  ->  verifier + S256 challenge
                 ->  listener opens on 127.0.0.1:8888
                 ->  browser opens Spotify's consent page
        user approves
                 ->  Spotify redirects to the listener
                 ->  we serve "Connected" and close the port
                 ->  POST /api/token, store refresh token in db

    THE RULE (learned the hard way): nothing reached from events.render may
    block. Every socket read is gated behind select() with a zero timeout.
]]

local ffi = ffi or require("ffi")
local bit = rawget(_G, "bit") or require("bit")

--------------------------------------------------------------------------------
-- configuration
--------------------------------------------------------------------------------

local PORT         = 8888
local CALLBACK     = "/callback"
local REDIRECT_URI = "http://127.0.0.1:" .. PORT .. CALLBACK

-- user-read-private is only here so /me returns `product`. Without it we cannot
-- tell a Free user why the controls don't work, and they get silent 403s
-- instead of an explanation.
local SCOPES = table.concat({
    "user-read-playback-state",
    "user-modify-playback-state",
    "user-read-currently-playing",
    "user-read-private",
}, " ")

-- No Client ID ships with this script, deliberately. Spotify Development Mode
-- allows five authenticated users per app, so a shared one would be exhausted
-- by the first five strangers who installed it. Everyone registers their own Ã¢â‚¬â€
-- see the Auth tab.

--------------------------------------------------------------------------------
-- logging
--------------------------------------------------------------------------------

-- Every menu item lives in here rather than as its own local: a Lua chunk may
-- declare at most 208 locals and the settings alone would blow past it.
--
-- Declared up here, not beside the menu, because drawing code reads from it and
-- the menu is built further down the file. log() below reads it too, so it has
-- to exist before anything else.
local UI = {}

-- Console only. The on-screen debug panel was useful while probing and is just
-- clutter now.
--
-- Pass `verbose` for routine chatter â€” poll cycles, token refreshes, clantag
-- frames, font probing. That is wanted while something is being diagnosed and
-- is noise the rest of the time, so it sits behind the Debug logging switch.
-- Anything the user needs to see, failures above all, logs plainly.
--
-- UI.opt_debug does not exist until the menu is built further down, hence the
-- guard; nothing logged before then is verbose anyway.
local function log(msg, verbose)
    if verbose and not (UI.opt_debug and UI.opt_debug:get()) then return end
    print("[spotify] " .. msg)
end

-- A combo's :get() may hand back the selected index rather than the label, and
-- comparing an index to a string silently fails every branch without erroring.
-- That is exactly how the clantag kept showing the track while set to the
-- signature. Resolve to the label whichever shape comes back.
-- Resolves a combo to its label without relying on the API at all.
--
-- The previous attempt went through item:list(), and when that returns nothing
-- useful the fallback was tostring(index) Ã¢â‚¬â€ a value that matches no branch, so
-- every comparison silently failed and the default won. Passing the option
-- table in means the only thing we need from the API is a number or a string,
-- and both are handled.
-- Menu text can carry inline colour escapes: "\aRRGGBBAA" before a character
-- sets its colour, and "\a{Style Name}" references a theme colour. They are
-- invisible in the console, because print renders them rather than showing
-- them.
--
-- This matters because the sidebar name is animated per character, and a combo
-- option carrying the same text ("spotify.lua") comes back wearing that
-- animation Ã¢â‚¬â€ 110 bytes of escapes instead of 11 plain ones. Comparing it to a
-- plain literal then fails forever, silently.
local function strip_colours(text)
    if type(text) ~= "string" then return text end

    text = text:gsub("\a%x%x%x%x%x%x%x%x", "")   -- \aRRGGBBAA
    text = text:gsub("\a%x%x%x%x%x%x", "")       -- \aRRGGBB
    text = text:gsub("\a{[^}]*}", "")            -- \a{Style Name}
    text = text:gsub("\a", "")

    return text
end

local function combo_label(item, options)
    local value = item:get()

    if type(value) == "string" then
        return strip_colours(value)
    end

    if type(value) == "number" then
        -- Indexing is undocumented; accept either base.
        return options[value] or options[value + 1] or options[1]
    end

    return options[1]
end

--------------------------------------------------------------------------------
-- PKCE  (verified against FIPS 180-4, RFC 4648 and RFC 7636 ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â see lua/pkce.lua)
--------------------------------------------------------------------------------

local band, bor, bxor, bnot = bit.band, bit.bor, bit.bxor, bit.bnot
local lshift, rshift, ror, tobit = bit.lshift, bit.rshift, bit.ror, bit.tobit

local K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

local function be_bytes(v)
    return string.char(band(rshift(v, 24), 255), band(rshift(v, 16), 255), band(rshift(v, 8), 255), band(v, 255))
end

local function sha256(msg)
    local h0, h1, h2, h3 = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
    local h4, h5, h6, h7 = 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

    local bitlen = #msg * 8
    msg = msg .. "\128"
    msg = msg .. string.rep("\0", (56 - (#msg % 64)) % 64)
    msg = msg .. be_bytes(math.floor(bitlen / 4294967296)) .. be_bytes(bitlen % 4294967296)

    local w = {}

    for chunk = 1, #msg, 64 do
        for j = 0, 15 do
            local at = chunk + (j * 4)
            local a, b, c, d = msg:byte(at, at + 3)
            w[j] = bor(lshift(a, 24), lshift(b, 16), lshift(c, 8), d)
        end

        for j = 16, 63 do
            local x, y = w[j - 15], w[j - 2]
            local s0 = bxor(ror(x, 7), ror(x, 18), rshift(x, 3))
            local s1 = bxor(ror(y, 17), ror(y, 19), rshift(y, 10))
            w[j] = tobit(w[j - 16] + s0 + w[j - 7] + s1)
        end

        local a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7

        for j = 0, 63 do
            local S1 = bxor(ror(e, 6), ror(e, 11), ror(e, 25))
            local ch = bxor(band(e, f), band(bnot(e), g))
            local t1 = tobit(h + S1 + ch + K[j + 1] + w[j])
            local S0 = bxor(ror(a, 2), ror(a, 13), ror(a, 22))
            local maj = bxor(band(a, b), band(a, c), band(b, c))
            local t2 = tobit(S0 + maj)

            h = g; g = f; f = e
            e = tobit(d + t1)
            d = c; c = b; b = a
            a = tobit(t1 + t2)
        end

        h0 = tobit(h0 + a); h1 = tobit(h1 + b); h2 = tobit(h2 + c); h3 = tobit(h3 + d)
        h4 = tobit(h4 + e); h5 = tobit(h5 + f); h6 = tobit(h6 + g); h7 = tobit(h7 + h)
    end

    return be_bytes(h0) .. be_bytes(h1) .. be_bytes(h2) .. be_bytes(h3)
        .. be_bytes(h4) .. be_bytes(h5) .. be_bytes(h6) .. be_bytes(h7)
end

local B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

local function base64url(data)
    local out = {}
    for i = 1, #data, 3 do
        local a, b, c = data:byte(i), data:byte(i + 1), data:byte(i + 2)
        local packed = (a * 65536) + ((b or 0) * 256) + (c or 0)
        local c1 = math.floor(packed / 262144) % 64
        local c2 = math.floor(packed / 4096) % 64
        local c3 = math.floor(packed / 64) % 64
        local c4 = packed % 64
        out[#out + 1] = B64URL:sub(c1 + 1, c1 + 1)
        out[#out + 1] = B64URL:sub(c2 + 1, c2 + 1)
        if b then out[#out + 1] = B64URL:sub(c3 + 1, c3 + 1) end
        if c then out[#out + 1] = B64URL:sub(c4 + 1, c4 + 1) end
    end
    return table.concat(out)
end

local function random_bytes(n)
    local out = {}
    for i = 1, n do
        out[i] = string.char(utils.random_int(0, 255))
    end
    return table.concat(out)
end

local function urlencode(s)
    return (tostring(s):gsub("[^%w%-%.%_%~]", function(c)
        return string.format("%%%02X", c:byte())
    end))
end

--------------------------------------------------------------------------------
-- Winsock
--
-- FFI declarations persist across script reloads, so one cdef per item: a
-- single block aborts at the first already-defined name and silently loses
-- everything after it.
--------------------------------------------------------------------------------

local function cdef(decl) pcall(ffi.cdef, decl) end

cdef [[ typedef intptr_t SOCKET; ]]
cdef [[ struct in_addr { unsigned long s_addr; }; ]]
cdef [[ struct sockaddr_in { short sin_family; unsigned short sin_port; struct in_addr sin_addr; char sin_zero[8]; }; ]]
cdef [[ struct sockaddr { unsigned short sa_family; char sa_data[14]; }; ]]
cdef [[ typedef struct fd_set_t { unsigned int fd_count; SOCKET fd_array[64]; } fd_set_t; ]]
cdef [[ struct timeval_t { long tv_sec; long tv_usec; }; ]]
cdef [[ int    __stdcall WSAStartup(unsigned short wVersionRequested, void *lpWSAData); ]]
cdef [[ int    __stdcall WSAGetLastError(void); ]]
cdef [[ SOCKET __stdcall socket(int af, int type, int protocol); ]]
cdef [[ int    __stdcall bind(SOCKET s, const struct sockaddr *name, int namelen); ]]
cdef [[ int    __stdcall listen(SOCKET s, int backlog); ]]
cdef [[ SOCKET __stdcall accept(SOCKET s, struct sockaddr *addr, int *addrlen); ]]
cdef [[ int    __stdcall recv(SOCKET s, char *buf, int len, int flags); ]]
cdef [[ int    __stdcall send(SOCKET s, const char *buf, int len, int flags); ]]
cdef [[ int    __stdcall closesocket(SOCKET s); ]]
cdef [[ int    __stdcall ioctlsocket(SOCKET s, long cmd, unsigned long *argp); ]]
cdef [[ int    __stdcall setsockopt(SOCKET s, int level, int optname, const char *optval, int optlen); ]]
cdef [[ int    __stdcall select(int nfds, fd_set_t *readfds, fd_set_t *writefds, fd_set_t *exceptfds, const struct timeval_t *timeout); ]]
cdef [[ unsigned short __stdcall htons(unsigned short hostshort); ]]
cdef [[ unsigned long  __stdcall inet_addr(const char *cp); ]]
cdef [[ void*  __stdcall GetModuleHandleA(const char *lpModuleName); ]]
cdef [[ void*  __stdcall GetProcAddress(void *hModule, const char *lpProcName); ]]
cdef [[ typedef void* (__stdcall *ShellExecuteFn)(void*, const char*, const char*, const char*, const char*, int); ]]

-- Clipboard, so the redirect URI can be pasted into Spotify's dashboard rather
-- than copied by eye. It has to match exactly or the whole flow fails.
cdef [[ int   __stdcall OpenClipboard(void *hWndNewOwner); ]]
cdef [[ int   __stdcall EmptyClipboard(void); ]]
cdef [[ void* __stdcall SetClipboardData(unsigned int uFormat, void *hMem); ]]
cdef [[ int   __stdcall CloseClipboard(void); ]]
cdef [[ void* __stdcall GlobalAlloc(unsigned int uFlags, unsigned long dwBytes); ]]
cdef [[ void* __stdcall GlobalLock(void *hMem); ]]
cdef [[ int   __stdcall GlobalUnlock(void *hMem); ]]

-- true if the text made it onto the clipboard. Everything here can fail --
-- another process can hold the clipboard open -- so the caller reports rather
-- than assumes.
local function set_clipboard(text)
    return pcall(function()
        if ffi.C.OpenClipboard(nil) == 0 then error("clipboard is held by another program") end

        ffi.C.EmptyClipboard()

        -- GMEM_MOVEABLE. On success the system takes ownership of this block,
        -- so it must not be freed here.
        local handle = ffi.C.GlobalAlloc(0x0002, #text + 1)
        if handle == nil then
            ffi.C.CloseClipboard()
            error("could not allocate clipboard memory")
        end

        -- #text + 1 carries the terminating NUL, which Lua strings already have.
        ffi.copy(ffi.C.GlobalLock(handle), text, #text + 1)
        ffi.C.GlobalUnlock(handle)

        ffi.C.SetClipboardData(1, handle)   -- CF_TEXT
        ffi.C.CloseClipboard()
    end)
end

local AF_INET, SOCK_STREAM, IPPROTO_TCP = 2, 1, 6
local FIONBIO = -2147195266
local SOL_SOCKET, SO_REUSEADDR = 0xFFFF, 0x0004

local ws2 = nil

local function is_invalid(s) return tonumber(s) == -1 end

-- Zero-timeout select: returns immediately by construction, so accept() and
-- recv() can never block the game thread.
local function is_readable(s)
    local set = ffi.new("fd_set_t")
    set.fd_count = 1
    set.fd_array[0] = s
    local tv = ffi.new("struct timeval_t")
    tv.tv_sec, tv.tv_usec = 0, 0
    return ws2.select(0, set, nil, nil, tv) > 0
end

local function open_url(url)
    local ok, err = pcall(function()
        local module = ffi.C.GetModuleHandleA("shell32.dll")
        local proc = ffi.C.GetProcAddress(module, "ShellExecuteA")
        -- SW_SHOWNOACTIVATE: taking focus from a fullscreen D3D game hangs it.
        ffi.cast("ShellExecuteFn", proc)(nil, "open", url, nil, nil, 4)
    end)
    if not ok then
        log("could not open browser: " .. tostring(err))
    end
    return ok
end

--------------------------------------------------------------------------------
-- listener
--------------------------------------------------------------------------------

local server, client = nil, nil
local listening, pump_disabled = false, false
local client_age = 0
local CLIENT_TIMEOUT_FRAMES = 600

local on_callback = nil   -- function(params_table)

local function page(title, message, accent)
    local body = table.concat({
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>", title, "</title></head>",
        "<body style=\"background:#17131c;color:#ede6f2;font:16px system-ui,sans-serif;",
        "display:flex;align-items:center;justify-content:center;height:100vh;margin:0\">",
        "<div style=\"text-align:center;max-width:420px;padding:0 24px\">",
        "<div style=\"font-size:44px;color:", accent, "\">&#9835;</div>",
        "<h1 style=\"font-weight:600;margin:.4em 0\">", title, "</h1>",
        "<p style=\"color:#b3a8be;line-height:1.5\">", message, "</p>",
        "</div></body></html>",
    })

    return table.concat({
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n",
        "Content-Length: ", tostring(#body), "\r\nConnection: close\r\n\r\n", body,
    })
end

local PAGE_OK = page("Connected", "You can close this tab and go back to the game.", "#e879c4")
local PAGE_NO = page("Not connected", "Authorisation was cancelled or failed. Try again from the menu.", "#e4707e")

local function close_socket(s)
    if s ~= nil and not is_invalid(s) then ws2.closesocket(s) end
end

local function stop_listener()
    if client ~= nil then close_socket(client); client = nil end
    if server ~= nil then close_socket(server); server = nil end
    if listening then
        listening = false
        log("listener closed, port released", true)
    end
end

local function start_listener()
    if listening then return true end
    if pump_disabled then
        log("pump disabled by an earlier error ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â reload the script")
        return false, "The listener is disabled.", "Reload the script."
    end

    if not pcall(ffi.new, "fd_set_t") or not pcall(ffi.new, "struct timeval_t") then
        log("poll types unavailable ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â refusing to open a socket we can't poll")
        return false, "Cannot poll a socket here.", "FFI types are unavailable."
    end

    if ws2 == nil then
        local ok = pcall(function() ws2 = ffi.load("ws2_32") end)
        if not ok or ws2 == nil then
            log("could not load ws2_32")
            return false, "Could not load Winsock.", "ws2_32 did not load."
        end
    end

    if not pcall(function() return ws2.select end) then
        log("select() unavailable ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â refusing to open a socket we can't poll")
        return false, "Cannot poll a socket here.", "select() is unavailable."
    end

    local wsadata = ffi.new("char[?]", 512)
    if ws2.WSAStartup(0x0202, wsadata) ~= 0 then
        log("WSAStartup failed")
        return false, "Winsock failed to start.", "WSAStartup returned an error."
    end

    server = ws2.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
    if is_invalid(server) then
        log("socket() failed: " .. ws2.WSAGetLastError())
        server = nil
        return false, "Could not create a socket.", "Winsock refused it."
    end

    local yes = ffi.new("int[1]", 1)
    ws2.setsockopt(server, SOL_SOCKET, SO_REUSEADDR, ffi.cast("const char*", yes), ffi.sizeof("int"))

    local addr = ffi.new("struct sockaddr_in")
    addr.sin_family = AF_INET
    addr.sin_port = ws2.htons(PORT)
    addr.sin_addr.s_addr = ws2.inet_addr("127.0.0.1")   -- loopback only, never 0.0.0.0

    if ws2.bind(server, ffi.cast("struct sockaddr*", addr), ffi.sizeof("struct sockaddr_in")) ~= 0 then
        local e = ws2.WSAGetLastError()
        log("bind failed: " .. e)
        close_socket(server); server = nil

        -- WSAEADDRINUSE. The port cannot simply move: it is baked into the
        -- redirect URI registered with Spotify, so the only fix is freeing it.
        if e == 10048 then
            return false, "Port 8888 is already in use.", "Close whatever is using it, then retry."
        end

        return false, "Could not open port 8888.", "Winsock error " .. e .. "."
    end

    if ws2.listen(server, 4) ~= 0 then
        log("listen failed: " .. ws2.WSAGetLastError())
        close_socket(server); server = nil
        return false, "Could not listen on port 8888.", "Winsock error " .. ws2.WSAGetLastError() .. "."
    end

    local mode = ffi.new("unsigned long[1]", 1)
    ws2.ioctlsocket(server, FIONBIO, mode)

    listening = true
    return true
end

local function parse_query(path)
    local params = {}
    local query = path:match("%?(.*)$")
    if not query then return params end

    for key, value in query:gmatch("([^&=?]+)=([^&=?]*)") do
        -- Plus-to-space FIRST, then percent-decoding. The other way round turns
        -- an encoded plus (%2B) into a literal + and then into a space, which is
        -- silent corruption. Nothing Spotify sends us contains either â€” the
        -- code and state are both base64url â€” so this is correctness rather
        -- than a fix for anything observed.
        params[key] = value:gsub("%+", " "):gsub("%%(%x%x)", function(h)
            return string.char(tonumber(h, 16))
        end)
    end

    return params
end

local function pump_inner()
    if not listening or server == nil then return end

    if client == nil then
        if not is_readable(server) then return end

        local incoming = ws2.accept(server, nil, nil)
        if is_invalid(incoming) then return end

        client = incoming
        client_age = 0
        local mode = ffi.new("unsigned long[1]", 1)
        ws2.ioctlsocket(client, FIONBIO, mode)
        return
    end

    client_age = client_age + 1
    if client_age > CLIENT_TIMEOUT_FRAMES then
        close_socket(client); client = nil
        return
    end

    if not is_readable(client) then return end

    local buf = ffi.new("char[?]", 8192)
    local n = ws2.recv(client, buf, 8192, 0)

    if n > 0 then
        local request = ffi.string(buf, n)
        local path = request:match("^%u+%s+(%S+)") or ""

        -- Browsers also fetch /favicon.ico; only the callback matters.
        if path:find(CALLBACK, 1, true) == 1 then
            local params = parse_query(path)
            ws2.send(client, params.code and PAGE_OK or PAGE_NO, #(params.code and PAGE_OK or PAGE_NO), 0)

            close_socket(client); client = nil
            if on_callback then
                local handler = on_callback
                on_callback = nil
                handler(params)
            end
            return
        end

        ws2.send(client, PAGE_OK, #PAGE_OK, 0)
    end

    close_socket(client); client = nil
end

local function pump()
    if pump_disabled or not listening then return end
    local ok, err = pcall(pump_inner)
    if not ok then
        pump_disabled = true
        log("PUMP ERROR (disabled): " .. tostring(err))
        pcall(stop_listener)
    end
end

--------------------------------------------------------------------------------
-- sealing the refresh token to this machine
--
-- The token is kept in `db`, which Neverlose stores in the cloud against the
-- account rather than in a file. There is therefore no config file anyone can
-- hand over by accident â€” but whether Neverlose's own config sharing carries
-- `db` along with menu values is undocumented, and this is going out publicly.
--
-- So the token is encrypted under a key derived from the machine it was
-- authorised on. A copy that reaches anyone else decrypts to nothing, fails its
-- check, and is discarded â€” they are asked to connect their own account, which
-- is exactly what should happen. The Client ID is left in the clear: it is
-- public by design in PKCE, and keeping it means a new machine needs a
-- reconnect rather than a re-setup.
--
-- This is not protection against someone with access to the machine. It stops
-- a token being usable somewhere else, which is the failure that matters.
--
-- Everything hangs off one table because a Lua chunk may declare only 200
-- locals and this one is at the ceiling.
--------------------------------------------------------------------------------

cdef [[ int __stdcall GetVolumeInformationA(const char *root, char *nameBuf, unsigned long nameSize, unsigned long *serial, unsigned long *maxComp, unsigned long *flags, char *fsBuf, unsigned long fsSize); ]]
cdef [[ int __stdcall GetComputerNameA(char *buf, unsigned long *size); ]]

local SEAL = {}

-- Stable across reboots and reinstalls, different on anyone else's machine.
-- Both lookups are optional: if neither works the constant still yields a
-- usable key, and the token simply stops being machine-bound rather than
-- breaking.
function SEAL.key()
    local parts = { "spotify.lua/token/v1" }

    pcall(function()
        local serial = ffi.new("unsigned long[1]")
        if ffi.C.GetVolumeInformationA("C:\\", nil, 0, serial, nil, nil, nil, 0) ~= 0 then
            parts[#parts + 1] = tostring(serial[0])
        end
    end)

    pcall(function()
        local size = ffi.new("unsigned long[1]", 256)
        local buf = ffi.new("char[?]", 256)
        if ffi.C.GetComputerNameA(buf, size) ~= 0 then
            parts[#parts + 1] = ffi.string(buf, size[0])
        end
    end)

    return sha256(table.concat(parts, "|"))
end

-- XOR against a keystream of chained SHA-256 blocks. Symmetric, so the same
-- call both seals and opens.
function SEAL.crypt(key, text)
    local out, block, stream, at = {}, 0, "", 1

    for i = 1, #text do
        if at > #stream then
            stream = sha256(key .. "|ks|" .. block)
            block, at = block + 1, 1
        end

        out[i] = string.char(bxor(text:byte(i), stream:byte(at)))
        at = at + 1
    end

    return table.concat(out)
end

-- Distinguishes "this token is not ours" from "this token decrypted to
-- rubbish". Without it a foreign token would be handed to Spotify as garbage
-- and fail with a confusing error instead of a clear one.
function SEAL.tag(key, text)
    return sha256(key .. "|tag|" .. text):sub(1, 8)
end

function SEAL.hex(s)
    return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

function SEAL.unhex(s)
    if s:find("[^0-9a-f]") or (#s % 2) ~= 0 then return nil end
    return (s:gsub("%x%x", function(h) return string.char(tonumber(h, 16)) end))
end

function SEAL.wrap(token)
    if type(token) ~= "string" or token == "" then return nil end

    local key = SEAL.key()
    return "v1:" .. SEAL.hex(SEAL.tag(key, token) .. SEAL.crypt(key, token))
end

-- nil for anything that is not ours: another machine, a corrupted value, or a
-- token written by a version that stored it in the clear.
function SEAL.open(blob)
    if type(blob) ~= "string" or blob:sub(1, 3) ~= "v1:" then return nil end

    local raw = SEAL.unhex(blob:sub(4))
    if raw == nil or #raw <= 8 then return nil end

    local key = SEAL.key()
    local token = SEAL.crypt(key, raw:sub(9))

    if SEAL.tag(key, token) ~= raw:sub(1, 8) then return nil end
    return token
end

-- The desktop harness sets this global before loading, so it can seal a token
-- exactly the way the script does instead of reimplementing the crypto. Nothing
-- in Neverlose defines it, so in game this is nil and nothing is exposed.
if rawget(_G, "__spotify_test") then rawget(_G, "__spotify_test").seal = SEAL end

--------------------------------------------------------------------------------
-- Spotify
--------------------------------------------------------------------------------

-- What db holds is sealed; `auth` is the opened, in-memory copy.
--
-- Copied into a FRESH table rather than mutating what db handed back. A store
-- backed by Lua tables returns a live reference, so writing the opened token
-- into it puts the plaintext straight back into storage and undoes the sealing
-- entirely â€” and when the seal does not open, writing nil there destroys the
-- stored token without anyone asking.
local auth = {}

do
    local stored = db.spotify_auth

    if type(stored) == "table" then
        auth.client_id = stored.client_id
        auth.refresh_token = SEAL.open(stored.refresh_token)

        if stored.refresh_token ~= nil and auth.refresh_token == nil then
            log("the saved Spotify login belongs to another machine, press Connect to use this one")
        end
    end
end

local session = {
    access_token = nil,
    expires_at = 0,
    display_name = nil,
    product = nil,

    -- Only one refresh may be in flight; see refresh() for why. Callers that
    -- arrive while one is running wait in `waiters` for its result.
    refreshing = false,
    refresh_at = 0,
    waiters = {},
}

local pending = nil   -- { verifier, state }

local function save()
    -- Built fresh rather than storing `auth` itself, so the plaintext token
    -- held in memory can never be written out by accident.
    db.spotify_auth = {
        client_id = auth.client_id,
        refresh_token = SEAL.wrap(auth.refresh_token),
    }
end

local function is_connected()
    return auth.refresh_token ~= nil
end

local function client_id()
    return auth.client_id or ""
end

local function describe_error(parsed, raw)
    if parsed then
        if parsed.error_description then return tostring(parsed.error_description) end
        if type(parsed.error) == "table" and parsed.error.message then return tostring(parsed.error.message) end
        if parsed.error then return tostring(parsed.error) end
    end
    return (raw or ""):sub(1, 180)
end

local function fetch_profile()
    if not session.access_token then return end

    network.get("https://api.spotify.com/v1/me",
        { Authorization = "Bearer " .. session.access_token },
        function(body)
            local ok, parsed = pcall(json.parse, body)
            if not ok or type(parsed) ~= "table" or not parsed.id then
                log("profile lookup failed: " .. tostring(body):sub(1, 160))
                return
            end

            session.display_name = parsed.display_name or parsed.id
            session.product = parsed.product

            log("signed in as " .. tostring(session.display_name)
                .. " (" .. tostring(session.product or "tier unknown") .. ")")

            -- product is absent unless the token carries user-read-private, so
            -- absent means "we didn't ask", NOT "not premium". Saying otherwise
            -- would tell a Premium user their controls won't work.
            if session.product == nil then
                log("tier not reported ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â reconnect to pick up the user-read-private scope")
            elseif session.product ~= "premium" then
                log("NOTE: playback CONTROLS need Premium. Track info will still show.")
            end
        end)
end

local function apply_token(parsed)
    session.access_token = parsed.access_token
    session.expires_at = common.get_unixtime() + (tonumber(parsed.expires_in) or 3600)

    -- Spotify may or may not return a new refresh token; keep the old one when
    -- it doesn't, or the connection silently dies on the next refresh.
    if parsed.refresh_token then
        auth.refresh_token = parsed.refresh_token
        save()
    end
end

-- Only ever one refresh in flight.
--
-- Spotify ROTATES the refresh token: each refresh consumes the old one. Two
-- overlapping refreshes therefore present the same spent token, and the loser
-- comes back invalid_grant â€” indistinguishable from a real revocation, so the
-- handler below clears the stored login. Being logged out because two requests
-- overlapped is not a tolerable failure.
--
-- Overlap is easy to reach: the poll chain schedules the next poll on a timer
-- rather than on the previous response, so any refresh slower than the poll
-- interval gets overtaken, and pressing a control during a refresh does it too.
-- Latecomers wait for the result instead of starting their own.
local function refresh(callback)
    if not is_connected() then
        log("not connected")
        return
    end

    -- The timeout is a deadlock guard: a callback the host never fires would
    -- otherwise wedge every future refresh permanently.
    if session.refreshing and (common.get_timestamp() - session.refresh_at) < 20000 then
        -- Capped. The poll chain keeps arriving every few seconds, so a refresh
        -- that is merely slow queues a handful and a connection that is down
        -- queues them for as long as it stays down. They all do the same thing
        -- anyway, so past a few there is nothing gained by keeping more.
        if callback and #session.waiters < 8 then
            session.waiters[#session.waiters + 1] = callback
        end
        return
    end

    -- Starting fresh, which means the previous attempt timed out. Anything
    -- still queued was waiting on a request that is never coming back.
    session.waiters = {}
    session.refreshing = true
    session.refresh_at = common.get_timestamp()

    log("refreshing access token...", true)

    network.post("https://accounts.spotify.com/api/token",
        {
            client_id = client_id(),
            grant_type = "refresh_token",
            refresh_token = auth.refresh_token,
        },
        { ["Content-Type"] = "application/x-www-form-urlencoded" },
        function(body)
            -- Cleared first, so nothing below can leave the guard stuck on.
            session.refreshing = false

            local waiting = session.waiters
            session.waiters = {}

            local ok, parsed = pcall(json.parse, body)

            if not ok or type(parsed) ~= "table" or not parsed.access_token then
                log("refresh FAILED: " .. describe_error(ok and parsed or nil, body))

                -- invalid_grant means the refresh token itself is dead: revoked
                -- from the Spotify account page, or its app deleted. Nothing
                -- will ever make it work again, so drop it rather than retrying
                -- against it forever and reporting a failure every time.
                if ok and type(parsed) == "table" and parsed.error == "invalid_grant" then
                    auth.refresh_token = nil
                    save()
                    log("that login has been revoked, press Connect Spotify to authorise again")
                end

                return
            end

            apply_token(parsed)
            log("access token refreshed, valid ~" .. math.floor((session.expires_at - common.get_unixtime()) / 60) .. " min", true)

            if callback then callback() end

            -- Everyone who arrived mid-refresh now has a usable token. Each is
            -- isolated: one throwing must not strand the rest.
            for _, waiter in ipairs(waiting) do pcall(waiter) end
        end)
end

local function exchange(code, verifier)
    log("exchanging code for tokens...", true)

    network.post("https://accounts.spotify.com/api/token",
        {
            client_id = client_id(),
            grant_type = "authorization_code",
            code = code,
            redirect_uri = REDIRECT_URI,
            code_verifier = verifier,
        },
        { ["Content-Type"] = "application/x-www-form-urlencoded" },
        function(body)
            local ok, parsed = pcall(json.parse, body)

            if not ok or type(parsed) ~= "table" or not parsed.access_token then
                log("token exchange FAILED: " .. describe_error(ok and parsed or nil, body))
                return
            end

            apply_token(parsed)
            log("CONNECTED ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â refresh token stored")
            fetch_profile()
        end)
end

-- Runs fn once a usable access token is in hand, refreshing first if the
-- current one is gone or about to expire. The 60s margin stops a call from
-- failing because the token died between the check and the request.
local function with_token(fn)
    if not is_connected() then
        log("not connected")
        return
    end

    if session.access_token and common.get_unixtime() < (session.expires_at - 60) then
        fn()
        return
    end

    refresh(fn)
end

local function mmss(ms)
    local total = math.floor((tonumber(ms) or 0) / 1000)
    return string.format("%d:%02d", math.floor(total / 60), total % 60)
end

-- Returns false plus two lines of explanation when it cannot even begin.
-- Every failure here used to produce nothing but a console line, so pressing
-- Connect with the port already taken looked identical to the button being
-- broken.
local function connect()
    local id = client_id()

    if id == "" then
        log("enter your Client ID first")
        return false, "No Client ID set.", "Paste it in the box below first."
    end

    if #id ~= 32 or id:match("[^%x]") then
        log("that Client ID looks wrong, expected 32 hex characters, got " .. #id)
        return false, "That Client ID looks wrong.",
            "Expected 32 hex characters, got " .. #id .. "."
    end

    local ready, why, detail = start_listener()
    if not ready then
        return false, why or "Could not start the listener.", detail or ""
    end

    local verifier = base64url(random_bytes(64))
    local state = base64url(random_bytes(16))

    pending = { verifier = verifier, state = state }

    on_callback = function(params)
        stop_listener()

        if params.error then
            log("Spotify said: " .. tostring(params.error))
            pending = nil
            return
        end

        if not pending or params.state ~= pending.state then
            log("state mismatch ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â ignoring this callback")
            pending = nil
            return
        end

        if not params.code then
            log("callback carried no code")
            pending = nil
            return
        end

        local verifier_used = pending.verifier
        pending = nil
        exchange(params.code, verifier_used)
    end

    local url = table.concat({
        "https://accounts.spotify.com/authorize",
        "?client_id=", urlencode(id),
        "&response_type=code",
        "&redirect_uri=", urlencode(REDIRECT_URI),
        "&code_challenge_method=S256",
        "&code_challenge=", base64url(sha256(verifier)),
        "&state=", urlencode(state),
        "&scope=", urlencode(SCOPES),
    })

    log("opening Spotify ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â approve in your browser")
    if not open_url(url) then
        stop_listener()
        pending = nil
        on_callback = nil
        return false, "Could not open your browser.",
            "Open the Spotify authorise page manually, or retry."
    end

    return true
end

local function disconnect()
    auth.refresh_token = nil
    save()
    session.access_token = nil
    session.display_name = nil
    session.product = nil
    stop_listener()
    log("disconnected ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â refresh token cleared")
end

--------------------------------------------------------------------------------
-- PUT bridge
--
-- Spotify's controls (play, pause, seek, volume, shuffle, repeat) are all PUT,
-- and Neverlose's network library has only get and post. Panorama's
-- $.AsyncWebRequest can issue PUT, so it fills exactly that one gap.
--
-- Approach credited to @Brotgeschmack, seen in the public grenade-helper
-- script. Reworked here: headers are a parameter rather than two hardcoded
-- JSON values, since we need Authorization on every call.
--
-- Probe result: options.data must be a key->value table, never a pre-encoded
-- string, and the bridge sends no Content-Type. Everything we need goes in the
-- query string anyway.
--------------------------------------------------------------------------------

local Bridge = {
    js = nil,
    pending = {},
    next_id = 0,
    broken = false,
}

if rawget(_G, "__spotify_test") then rawget(_G, "__spotify_test").bridge = Bridge end

local function bridge_ready()
    if Bridge.broken then return false end
    if Bridge.js ~= nil then return true end

    local ok, result = pcall(function()
        return panorama.loadstring([[
            let requests = {};
            return {
                send: function(id, url, options) {
                    requests[id] = { complete: false, value: null };
                    options.complete = function(response) {
                        requests[id].complete = true;
                        requests[id].value = response;
                    };
                    $.AsyncWebRequest(url, options);
                },
                get: function(id) { return requests[id]; },
                remove: function(id) { delete requests[id]; }
            };
        ]])()
    end)

    if not ok or result == nil then
        Bridge.broken = true
        log("panorama bridge unavailable ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â controls disabled")
        return false
    end

    Bridge.js = result
    return true
end

local function bridge_put(url, headers, callback)
    if not bridge_ready() then return end

    local id = Bridge.next_id
    Bridge.next_id = id + 1

    -- Guarded, because this runs from a click handler inside events.render:
    -- an error escaping here takes the rest of the frame's drawing with it.
    local sent = pcall(Bridge.js.send, id, url, {
        type = "PUT",
        timeout = 15000,
        headers = headers or {},
    })

    if not sent then
        log("the panorama bridge refused a request")
        return
    end

    Bridge.pending[#Bridge.pending + 1] =
        { id = id, callback = callback, at = common.get_timestamp() }
end

-- The JS side cannot call back into Lua, so completions are polled. Cheap: it
-- only iterates while a request is actually outstanding.
local function bridge_pump()
    if Bridge.js == nil or #Bridge.pending == 0 then return end

    local now = common.get_timestamp()

    for i = #Bridge.pending, 1, -1 do
        local request = Bridge.pending[i]

        -- Guarded because this runs at the top of every frame. If the Panorama
        -- side is ever torn down under us, an unprotected call here would throw
        -- once a frame forever and take the whole render callback â€” and so the
        -- entire player â€” down with it.
        local read, state = pcall(Bridge.js.get, request.id)
        if not read then state = nil end

        if state and state.complete then
            local value = state.value
            table.remove(Bridge.pending, i)
            pcall(Bridge.js.remove, request.id)

            if request.callback then
                pcall(request.callback, value)
            end

        -- Abandoned after comfortably longer than the request's own 15s
        -- timeout. Without this, anything the bridge never reports on stays in
        -- the list for the rest of the session â€” walked every single frame, and
        -- growing with every control press. A `state` of nil is the same story:
        -- there is nothing left to wait for.
        elseif (now - (request.at or 0)) > 30000 then
            table.remove(Bridge.pending, i)
            pcall(Bridge.js.remove, request.id)
        end
    end
end

--------------------------------------------------------------------------------
-- player state
--------------------------------------------------------------------------------

local player = {
    ok = false,
    is_playing = false,
    title = "",
    artist = "",
    album = "",
    release = "",
    art_url = nil,
    art_px = 0,           -- pixel width of art_url, for load_image
    art_choices = {},     -- every size the API offered, preferred first
    progress_ms = 0,
    duration_ms = 0,
    fetched_at = 0,       -- common.get_timestamp(), milliseconds
    shuffle = false,
    repeat_state = "off",
    volume = 0,
    device = "",
}

-- Polling every few seconds would make the progress bar jump in steps. Instead
-- the bar is advanced locally from the last known position and corrected on
-- each poll, which is what makes it move smoothly at frame rate.
local function current_progress()
    if not player.ok then return 0 end
    if not player.is_playing then return player.progress_ms end

    local elapsed = common.get_timestamp() - player.fetched_at
    return math.min(player.progress_ms + elapsed, player.duration_ms)
end

-- Spotify offers each cover in three sizes, normally 640, 300 and 64 px, and
-- hands them back largest first. We draw the cover somewhere between 40 and
-- 140 px, so taking the 640 is pure waste: roughly five times the bytes over
-- the wire and, at vector(640, 640), five times the texture memory for pixels
-- nobody can see. 300 has headroom for every scale the HUD allows.
--
-- The sizes are separate objects on the CDN, so one of them failing says
-- nothing about the others. That is why the rest are kept as fallbacks rather
-- than discarded.
--
-- Constants live in a table, not as locals, because a Lua chunk may declare
-- only 200 of those and this one is already close to the line.
local ART = {
    PREFERRED_PX = 300,

    CACHE_MAX = 10,
    INFLIGHT_TIMEOUT = 20000,   -- ms; a callback that never fires must not wedge us

    MAX_ATTEMPTS = 3,
    RETRY_MS = 4000,

    -- After a burst of failures, sit out this long and then allow a fresh
    -- burst. The first version gave up on a URL permanently once the burst was
    -- spent, which is what made covers "randomly" stop showing: three failures
    -- inside half a minute -- one alt-tab, one hiccup, one reconnect -- and
    -- that album had no artwork for the rest of the session, every time it came
    -- round again. Nothing ever cleared the record.
    COOLDOWN_MS = 60000,
}

local function pick_art(images)
    local sizes = {}
    for _, img in ipairs(images or {}) do
        if type(img.url) == "string" then
            sizes[#sizes + 1] = { url = img.url, px = tonumber(img.width) or 0 }
        end
    end

    -- Nearest to what we draw first; the remainder stay in sensible fallback
    -- order behind it.
    table.sort(sizes, function(a, b)
        return math.abs(a.px - ART.PREFERRED_PX) < math.abs(b.px - ART.PREFERRED_PX)
    end)

    return sizes
end

local function apply_state(state)
    local item = state and state.item

    if not item then
        player.ok = false
        -- Drop the cover too, or the last track's artwork keeps showing behind
        -- the "nothing playing" message.
        player.art_url = nil
        player.art_choices = {}
        return
    end

    -- Tracks and episodes are shaped differently. An episode has no `album` and
    -- no `artists`: its cover hangs off the item, and the name a listener
    -- expects on the second line is the show's. Without these fallbacks a
    -- podcast draws a placeholder cover and a blank artist line while it is
    -- quite clearly playing.
    local show = item.show or {}

    local artists = {}
    for _, a in ipairs(item.artists or {}) do
        artists[#artists + 1] = a.name
    end

    local album = item.album or {}

    player.ok = true
    player.is_playing = state.is_playing and true or false
    player.title = item.name or ""
    player.artist = (#artists > 0) and table.concat(artists, ", ") or (show.name or "")
    player.album = album.name or show.publisher or ""
    player.release = album.release_date or item.release_date or ""
    player.progress_ms = tonumber(state.progress_ms) or 0
    player.duration_ms = tonumber(item.duration_ms) or 0
    player.fetched_at = common.get_timestamp()
    player.shuffle = state.shuffle_state and true or false
    player.repeat_state = state.repeat_state or "off"

    local device = state.device or {}
    player.volume = tonumber(device.volume_percent) or 0
    player.device = device.name or ""

    -- The whole ordered list is kept and art_texture reads it. `art_url` is the
    -- preferred size, and doubles as the track's identity for the cover
    -- cross-fade â€” which is why it must not be rewritten when a size fails.
    local choices = pick_art(album.images or item.images or show.images)

    player.art_choices = choices
    player.art_url     = choices[1] and choices[1].url or nil
    player.art_px      = choices[1] and choices[1].px or 0

    -- Behind Debug logging. Says whether the track offered any artwork at all,
    -- which is the one thing a silent blank cover cannot tell you apart from a
    -- fetch that is failing.
    if player.art_url ~= player.art_logged then
        player.art_logged = player.art_url

        local sizes = {}
        for _, c in ipairs(choices) do sizes[#sizes + 1] = tostring(c.px) end

        log(("art: %s offers %d size(s) [%s] %s"):format(
            tostring(item.name):sub(1, 28),
            #choices,
            table.concat(sizes, ","),
            tostring(player.art_url)), true)
    end
end

--------------------------------------------------------------------------------
-- polling
--
-- A generation counter guards the timer chain: toggling the poll off, or a
-- script reload, must not leave an old chain running alongside the new one.
--------------------------------------------------------------------------------

local poll_generation = 0
local polling = false
local last_poll_error = nil

-- Development mode apps draw on a QUOTA, which Spotify counts per developer
-- account across every app that account owns and groups into endpoint buckets.
-- Every /v1/me/player call lands in one bucket. It is a separate mechanism from
-- the rolling 30-second rate limit, which is why a few requests a minute can
-- still be refused with QUOTA_EXCEEDED, and why making a second app under the
-- same account does nothing at all.
--
-- Nobody using this script will ever leave development mode: extended quota is
-- organisations only, 250k monthly users minimum, since May 2025. So the number
-- of player requests is the only lever that exists.
--
-- A flat 3s interval spent about 70 requests on a three-and-a-half minute
-- track, essentially all of them confirming nothing had changed. Instead:
-- cruise through the middle of a track, and tighten only around the moment it
-- is about to end, which is the one instant a poll is actually informative.
-- Same track, about 24 requests, and the track change is picked up FASTER than
-- before, because 2s at the boundary beats the old flat 3s.
--
-- The cost is that something done on another device -- skipping from your phone
-- -- can take up to a cruise interval to appear. Anything done from this script
-- updates locally at once and never waits for a poll.
--
-- Grouped in a table rather than kept as four locals: the chunk sits at the
-- 200-local ceiling.
local POLL = {
    cruise = 10.0,          -- mid-track
    edge = 2.0,             -- approaching the end of a track
    idle = 15.0,            -- paused, or nothing playing at all
    edge_window_ms = 6000,  -- how early to switch to the edge rate
}

-- Extra seconds added to the poll interval after Spotify pushes back. The
-- network API hands us only a response body, so the `Retry-After` header is not
-- visible; the interval doubles instead, and the first success clears it.
--
-- The cap used to be 60s, on the assumption that a limit we tripped ourselves
-- would clear in about that long. That assumption was wrong. Spotify's limit is
-- per APPLICATION, not per user: everyone sharing a Client ID draws on one
-- budget, apps in development mode get a small one, and once tripped the block
-- refuses every request under that ID until its own cooldown expires. Measured
-- live: three requests in sixty seconds, still answered "Too many requests".
--
-- So a 60s cap does the worst possible thing. It cannot outlast the block, and
-- each probe spends from the budget it is waiting on. Escalating to five
-- minutes keeps recovery from a genuine blip quick — the first few steps are
-- unchanged — while a real block costs a handful of requests instead of thirty
-- an hour. Toggling the player off and on resets it immediately for anyone not
-- willing to wait.
local poll_penalty = 0
local POLL_PENALTY_MAX = 300

-- Timestamps of recent /me/player requests, kept so a 429 can report the rate
-- that actually earned it instead of the rate we intended.
--
-- This exists because a run of 429s on light use looked like a bug in here, and
-- the old message discarded every piece of evidence that could have said
-- otherwise. Spotify's limit is per APPLICATION, not per user: everyone sharing
-- a Client ID spends from one budget, and apps still in development mode get a
-- much smaller one. A count near 20 per minute here means this script is inside
-- its intended rate and the limit was earned somewhere else.
-- On `session` rather than as two file locals: the chunk is at the 200-local
-- ceiling and adding a pair here pushed it over.
session.poll_times = {}

function session.note_poll()
    local now = common.get_timestamp()
    local keep = { now }

    for _, at in ipairs(session.poll_times) do
        if now - at <= 60000 then keep[#keep + 1] = at end
    end

    session.poll_times = keep
    return #keep
end

-- `once` fetches without re-arming.
--
-- Skipping a track wants an immediate catch-up read, and without this flag that
-- one-shot re-armed itself into a SECOND permanent poll chain â€” one more per
-- skip, each doubling down on the request rate until Spotify starts answering
-- 429. The generation counter cannot help: the extra chains share the current
-- generation, so they look entirely legitimate.
local function poll_once(generation, once)
    if generation ~= poll_generation then return end

    with_token(function()
        if generation ~= poll_generation then return end

        session.note_poll()

        network.get("https://api.spotify.com/v1/me/player",
            { Authorization = "Bearer " .. session.access_token },
            function(body)
                if generation ~= poll_generation then return end

                if body == nil or body == "" then
                    player.ok = false
                    player.art_url = nil   -- else the last cover lingers
                    player.art_choices = {}
                    last_poll_error = nil
                    return
                end

                local ok, state = pcall(json.parse, body)
                if not ok or type(state) ~= "table" then
                    last_poll_error = "bad JSON from /me/player"
                    return
                end

                if state.error then
                    local err = (type(state.error) == "table") and state.error or {}
                    local status = tonumber(err.status)

                    if status == 429 then
                        poll_penalty = math.min(
                            (poll_penalty > 0) and (poll_penalty * 2) or 5,
                            POLL_PENALTY_MAX)

                        -- `reason` separates the two quite different things
                        -- Spotify answers 429 for, and the message text is
                        -- identical for both. QUOTA_EXCEEDED is the development
                        -- mode quota: counted per DEVELOPER ACCOUNT across every
                        -- app that account owns, grouped into endpoint buckets,
                        -- and not something a second app or a quieter thirty
                        -- seconds can do anything about. A bare 429 is the
                        -- rolling rate limit, which backing off genuinely fixes.
                        local quota = (err.reason == "QUOTA_EXCEEDED")

                        -- Drawn in the panel, not just logged. A quota block
                        -- otherwise looks exactly like nothing playing, which is
                        -- how an evening gets spent hunting a rendering bug that
                        -- was never there.
                        last_poll_error = quota
                            and "Spotify quota reached, retrying"
                            or "Spotify is rate limiting, retrying"

                        log("rate limited by Spotify, backing off to "
                            .. poll_penalty .. "s")

                        log(("  %d requests from here in the last 60s | Spotify: %s / %s")
                            :format(#session.poll_times,
                                tostring(err.message or "no message"),
                                tostring(err.reason or "no reason given")))

                    elseif status == 401 then
                        -- The access token died early, or was revoked. Dropping
                        -- it makes the next poll refresh before asking again;
                        -- if the refresh token is gone too, refresh() says so.
                        session.access_token = nil
                        session.expires_at = 0
                        last_poll_error = "access token rejected, refreshing"

                    else
                        last_poll_error = describe_error(state, body)
                    end
                    return
                end

                poll_penalty = 0
                last_poll_error = nil
                apply_state(state)
            end)
    end)

    if once then return end

    local delay

    if not (player.ok and player.is_playing) then
        -- Paused, or nothing playing. Nothing can change here except someone
        -- pressing play on another device.
        delay = POLL.idle
    elseif player.duration_ms <= 0 then
        -- No duration to reason about, so there is no boundary to aim at.
        delay = POLL.cruise
    else
        local remaining = player.duration_ms - current_progress()

        if remaining <= POLL.edge_window_ms then
            delay = POLL.edge
        else
            -- Deliberately land just inside the edge window rather than
            -- overshooting it. Cruising blindly would routinely step straight
            -- over a track change and report it a full interval late, which is
            -- the failure that makes slow polling feel broken.
            delay = math.min(POLL.cruise, (remaining - POLL.edge_window_ms) / 1000)
            delay = math.max(delay, POLL.edge)
        end
    end

    if poll_penalty > 0 then
        delay = math.max(delay, poll_penalty)
    end

    utils.execute_after(delay, function() poll_once(generation) end)
end

local function set_polling(on)
    poll_generation = poll_generation + 1
    polling = on and true or false

    if polling then
        -- Cleared on every start: a penalty earned before the player was
        -- switched off would otherwise still be throttling it when it came
        -- back, with nothing on screen to say why.
        poll_penalty = 0

        log(("polling every %ss, %ss near a track change")
            :format(POLL.cruise, POLL.edge), true)
        poll_once(poll_generation)
    else
        player.ok = false
    end
end

--------------------------------------------------------------------------------
-- controls
--
-- Every control updates the local state immediately and then tells Spotify.
-- Waiting for the next poll to reflect a click makes the buttons feel broken
-- even when they work.
--------------------------------------------------------------------------------

local API = "https://api.spotify.com/v1/me/player"

local function control_headers()
    return { Authorization = "Bearer " .. session.access_token }
end

local function report_control(what, body)
    -- Spotify answers 204 with an empty body on success.
    if body == nil or body == "" then return end

    local ok, parsed = pcall(json.parse, body)
    if ok and type(parsed) == "table" and parsed.error then
        local message = describe_error(parsed, body)
        log(what .. " failed: " .. message)

        if tostring(message):lower():find("premium") then
            log("  controls require Spotify Premium")
        end
    end
end

local function put_control(what, path, query)
    with_token(function()
        bridge_put(API .. path .. (query or ""), control_headers(), function(reply)
            if reply and reply.responseText then
                report_control(what, reply.responseText)
            end
        end)
    end)
end

local function post_control(what, path)
    with_token(function()
        network.post(API .. path, {}, control_headers(), function(body)
            report_control(what, body)
        end)
    end)
end

local function toggle_play()
    if not player.ok then return end

    if player.is_playing then
        player.is_playing = false
        player.progress_ms = current_progress()
        player.fetched_at = common.get_timestamp()
        put_control("pause", "/pause")
    else
        player.is_playing = true
        player.fetched_at = common.get_timestamp()
        put_control("play", "/play")
    end
end

local function skip_next()
    post_control("next", "/next")
    -- Ask again shortly; the new track won't be in the current poll cycle.
    utils.execute_after(0.6, function() poll_once(poll_generation, true) end)
end

local function skip_previous()
    post_control("previous", "/previous")
    utils.execute_after(0.6, function() poll_once(poll_generation, true) end)
end

local function toggle_shuffle()
    player.shuffle = not player.shuffle
    put_control("shuffle", "/shuffle", "?state=" .. tostring(player.shuffle))
end

local REPEAT_CYCLE = { off = "context", context = "track", track = "off" }

local function cycle_repeat()
    local next_state = REPEAT_CYCLE[player.repeat_state] or "off"
    player.repeat_state = next_state
    put_control("repeat", "/repeat", "?state=" .. next_state)
end

local function seek_to(fraction)
    if not player.ok or player.duration_ms <= 0 then return end

    local target = math.floor(math.clamp(fraction, 0, 1) * player.duration_ms)

    player.progress_ms = target
    player.fetched_at = common.get_timestamp()

    put_control("seek", "/seek", "?position_ms=" .. target)
end

-- Dragging the volume bar would fire a PUT every frame, which is both rude to
-- Spotify's rate limits and pointless. Move the local value freely, send only
-- once the value settles.
local volume_dirty_at = nil
local VOLUME_SETTLE = 250   -- ms

local function set_volume(fraction)
    if not player.ok then return end

    player.volume = math.floor(math.clamp(fraction, 0, 1) * 100)
    volume_dirty_at = common.get_timestamp()
end

local function flush_volume()
    if volume_dirty_at == nil then return end
    if (common.get_timestamp() - volume_dirty_at) < VOLUME_SETTLE then return end

    volume_dirty_at = nil
    put_control("volume", "/volume", "?volume_percent=" .. player.volume)
end

--------------------------------------------------------------------------------
-- album art
--
-- Cached by URL so a poll every few seconds doesn't refetch the same image.
-- render.load_image is deferred to the render callback to keep every
-- render-namespace call where the docs say it is valid.
--------------------------------------------------------------------------------

-- art_texture() runs from the draw path, i.e. every frame. The first version
-- re-requested on every cache miss, so a single failed fetch became a request
-- per frame Ã¢â‚¬â€ a hundred a second, until the CDN throttled us and every
-- subsequent fetch failed too. That is why art went blank and stayed blank
-- after a long session.
--
-- So: one request in flight at a time, a cooldown after each failure, and a cap
-- on attempts per URL.

local art_cache = {}
local art_order = {}          -- insertion order, for eviction

local art_inflight = nil
local art_inflight_at = 0

local art_ready = nil         -- { url, data, px } waiting to be turned into a texture

local art_failures = {}       -- url -> { count, next_try }

--------------------------------------------------------------------------------
-- baseline greyscale JPEG decoder
--
-- render.load_image cannot draw single-component JPEGs. It does not report that
-- as a failure either: it hands back an ordinary-looking texture that renders as
-- nothing. Spotify serves black-and-white covers this way, so one album in a
-- playlist is enough to look like a broken script.
--
-- The only route to arbitrary pixels is render.load_image_rgba, which wants a
-- raw RGBA buffer â€” so the decoding has to happen here. This handles exactly the
-- case that is broken and nothing more: baseline (SOF0), 8-bit, one component.
-- Everything else is left to load_image, which handles it perfectly well.
--
-- Verified against a real Spotify cover decoded by System.Drawing; see the
-- fixture test in the harness.
--------------------------------------------------------------------------------

local JPEG = {}

-- Zig-zag position -> natural position, both 1-based.
JPEG.ZIGZAG = {
     1, 2, 9,17,10, 3, 4,11,18,25,33,26,19,12, 5, 6,
    13,20,27,34,41,49,42,35,28,21,14, 7, 8,15,22,29,
    36,43,50,57,58,51,44,37,30,23,16,24,31,38,45,52,
    59,60,53,46,39,32,40,47,54,61,62,55,48,56,63,64,
}

-- K[u][x] folds the normalisation constant into the cosine, so each IDCT pass
-- is a plain dot product.
JPEG.K = (function()
    local k = {}
    for u = 0, 7 do
        k[u] = {}
        local c = (u == 0) and math.sqrt(0.5) or 1
        for x = 0, 7 do
            k[u][x] = 0.5 * c * math.cos(((2 * x + 1) * u * math.pi) / 16)
        end
    end
    return k
end)()

-- RGBA bytes for each grey level, so expanding the plane is a lookup per pixel
-- rather than three string.char calls.
JPEG.RGBA = (function()
    local t = {}
    for v = 0, 255 do t[v] = string.char(v, v, v, 255) end
    return t
end)()

-- Number of colour components in a JPEG, or nil if it cannot be read.
--
-- One component means greyscale, and render.load_image cannot draw those: it
-- returns a perfectly ordinary-looking texture object that renders as nothing.
-- Spotify serves black-and-white covers this way, so this is not exotic â€” one
-- album in a playlist is enough to look like a bug.
--
-- Walks segment by segment using each header's own length, which is what keeps
-- it out of the entropy-coded data where stray FF bytes live.
function JPEG.components(data)
    if #data < 4 or data:byte(1) ~= 0xFF or data:byte(2) ~= 0xD8 then return nil end

    local i = 3
    while i < #data - 9 do
        if data:byte(i) ~= 0xFF then
            i = i + 1
        else
            local marker = data:byte(i + 1)

            if marker == 0xD8 or marker == 0x01 or (marker >= 0xD0 and marker <= 0xD7) then
                i = i + 2
            elseif marker == 0xDA then
                return nil          -- start of scan, and no frame header seen
            else
                -- SOF0..SOF15, excluding the three that are not frame headers.
                if marker >= 0xC0 and marker <= 0xCF
                    and marker ~= 0xC4 and marker ~= 0xC8 and marker ~= 0xCC then
                    return data:byte(i + 9)
                end

                i = i + 2 + ((data:byte(i + 2) * 256) + data:byte(i + 3))
            end
        end
    end

    return nil
end

function JPEG.huffman(counts, values)
    local lookup, code, k = {}, 0, 1

    for length = 1, 16 do
        lookup[length] = {}
        for _ = 1, counts[length] do
            lookup[length][code] = values[k]
            code, k = code + 1, k + 1
        end
        code = code * 2
    end

    return lookup
end

-- Returns an RGBA buffer, width and height, or nil plus a reason.
function JPEG.decode(data)
    local quant, huff_dc, huff_ac = {}, {}, {}
    local width, height, restart_interval = 0, 0, 0
    local comp_id, comp_quant, comp_dc, comp_ac = nil, 0, 0, 0

    local at = 3
    if data:byte(1) ~= 0xFF or data:byte(2) ~= 0xD8 then return nil, "not a JPEG" end

    -- Header pass. Every segment carries its own length, which is what keeps
    -- this out of the entropy-coded bytes where stray FFs live.
    while at < #data - 3 do
        if data:byte(at) ~= 0xFF then at = at + 1
        else
            local marker = data:byte(at + 1)

            if marker == 0x01 or (marker >= 0xD0 and marker <= 0xD8) then
                at = at + 2
            else
                local length = (data:byte(at + 2) * 256) + data:byte(at + 3)
                local body = at + 4

                if marker == 0xDB then                      -- quantisation tables
                    local stop = at + 2 + length
                    while body < stop do
                        local spec = data:byte(body)
                        if math.floor(spec / 16) ~= 0 then return nil, "16-bit quant table" end

                        local table_ = {}
                        for i = 1, 64 do table_[JPEG.ZIGZAG[i]] = data:byte(body + i) end
                        quant[spec % 16] = table_
                        body = body + 65
                    end

                elseif marker == 0xC4 then                  -- huffman tables
                    local stop = at + 2 + length
                    while body < stop do
                        local spec = data:byte(body)
                        local counts, total = {}, 0

                        for i = 1, 16 do
                            counts[i] = data:byte(body + i)
                            total = total + counts[i]
                        end

                        local values = {}
                        for i = 1, total do values[i] = data:byte(body + 16 + i) end

                        local built = JPEG.huffman(counts, values)
                        if math.floor(spec / 16) == 0 then huff_dc[spec % 16] = built
                        else huff_ac[spec % 16] = built end

                        body = body + 17 + total
                    end

                elseif marker == 0xC0 or marker == 0xC1 then   -- baseline frame
                    if data:byte(body) ~= 8 then return nil, "not 8-bit" end

                    height = (data:byte(body + 1) * 256) + data:byte(body + 2)
                    width  = (data:byte(body + 3) * 256) + data:byte(body + 4)

                    if data:byte(body + 5) ~= 1 then return nil, "not single-component" end

                    comp_id = data:byte(body + 6)
                    comp_quant = data:byte(body + 8)

                elseif marker == 0xDD then                  -- restart interval
                    restart_interval = (data:byte(body) * 256) + data:byte(body + 1)

                elseif marker == 0xDA then                  -- start of scan
                    if data:byte(body) ~= 1 then return nil, "interleaved scan" end
                    comp_dc = math.floor(data:byte(body + 2) / 16)
                    comp_ac = data:byte(body + 2) % 16
                    at = at + 2 + length
                    break

                elseif marker >= 0xC2 and marker <= 0xCF and marker ~= 0xC4 and marker ~= 0xC8 then
                    return nil, "not baseline"
                end

                at = at + 2 + length
            end
        end
    end

    if width == 0 or comp_id == nil then return nil, "no frame header" end

    local qt = quant[comp_quant]
    local dc_table, ac_table = huff_dc[comp_dc], huff_ac[comp_ac]
    if qt == nil or dc_table == nil or ac_table == nil then return nil, "missing tables" end

    ----------------------------------------------------------------------------
    -- entropy-coded data
    ----------------------------------------------------------------------------

    local bitbuf, bitcount, ended = 0, 0, false

    local function bit_read()
        if bitcount == 0 then
            if at > #data then ended = true; return 0 end

            local byte = data:byte(at)
            at = at + 1

            if byte == 0xFF then
                local next_byte = data:byte(at)
                if next_byte == 0 then at = at + 1
                elseif next_byte ~= nil and next_byte >= 0xD0 and next_byte <= 0xD7 then
                    -- A restart marker reached mid-read means the scan is out of
                    -- step; the caller resynchronises rather than reading on.
                    ended = true; return 0
                else
                    ended = true; return 0
                end
            end

            bitbuf, bitcount = byte, 8
        end

        bitcount = bitcount - 1
        return bit.band(bit.rshift(bitbuf, bitcount), 1)
    end

    local function huff_read(lookup)
        local code, length = 0, 0

        for _ = 1, 16 do
            code = (code * 2) + bit_read()
            length = length + 1

            local row = lookup[length]
            local value = row and row[code]
            if value ~= nil then return value end

            if ended then return nil end
        end

        return nil
    end

    local function receive_extend(count)
        if count == 0 then return 0 end

        local value = 0
        for _ = 1, count do value = (value * 2) + bit_read() end

        -- Values below the midpoint of the range are negative.
        if value < (2 ^ (count - 1)) then return value - (2 ^ count) + 1 end
        return value
    end

    local cols, rows = math.ceil(width / 8), math.ceil(height / 8)
    local plane = {}
    local coeffs, block = {}, {}
    local predictor, since_restart = 0, 0

    for row = 0, rows - 1 do
        for col = 0, cols - 1 do
            if restart_interval > 0 and since_restart == restart_interval then
                -- Byte-align, step over the marker, reset the DC predictor.
                bitcount = 0
                while at < #data and not (data:byte(at) == 0xFF
                    and data:byte(at + 1) ~= nil
                    and data:byte(at + 1) >= 0xD0 and data:byte(at + 1) <= 0xD7) do
                    at = at + 1
                end
                at = at + 2
                predictor, since_restart, ended = 0, 0, false
            end

            for i = 1, 64 do coeffs[i] = 0 end

            local size = huff_read(dc_table)
            if size == nil then size = 0 end

            predictor = predictor + receive_extend(size)
            coeffs[1] = predictor * qt[1]

            local index = 2
            while index <= 64 do
                local symbol = huff_read(ac_table)
                if symbol == nil then break end

                local run, magnitude = math.floor(symbol / 16), symbol % 16

                if magnitude == 0 then
                    if run ~= 15 then break end     -- end of block
                    index = index + 16
                else
                    index = index + run
                    if index > 64 then break end

                    local natural = JPEG.ZIGZAG[index]
                    coeffs[natural] = receive_extend(magnitude) * qt[natural]
                    index = index + 1
                end
            end

            since_restart = since_restart + 1

            -- Rows first, then columns; separable, so 8x8 twice rather than 64x64.
            for y = 0, 7 do
                local base = y * 8
                for x = 0, 7 do
                    local sum = 0
                    for u = 0, 7 do
                        local c = coeffs[base + u + 1]
                        if c ~= 0 then sum = sum + (c * JPEG.K[u][x]) end
                    end
                    block[base + x + 1] = sum
                end
            end

            for x = 0, 7 do
                for y = 0, 7 do
                    local sum = 0
                    for v = 0, 7 do
                        sum = sum + (block[(v * 8) + x + 1] * JPEG.K[v][y])
                    end

                    local px = (col * 8) + x
                    local py = (row * 8) + y

                    if px < width and py < height then
                        local level = math.floor(sum + 128.5)
                        if level < 0 then level = 0 elseif level > 255 then level = 255 end
                        plane[(py * width) + px + 1] = JPEG.RGBA[level]
                    end
                end
            end
        end
    end

    return table.concat(plane), width, height
end

if rawget(_G, "__spotify_test") then rawget(_G, "__spotify_test").jpeg = JPEG end

local function art_note_failure(url, why)
    local record = art_failures[url] or { count = 0 }
    record.count = record.count + 1
    record.next_try = common.get_timestamp() + (ART.RETRY_MS * record.count)
    art_failures[url] = record

    -- Every attempt, not just the last. Only logging once the burst was spent
    -- meant the first two failures were silent, which is precisely the window
    -- where a cover that never appears looks like nothing happened at all.
    log(("art: attempt %d failed (%s)"):format(record.count, why), true)

    if record.count < ART.MAX_ATTEMPTS then return end

    -- Nothing is rewritten on the player here. art_texture picks the best size
    -- that is not sitting out a cooldown, so recording the failure is enough to
    -- move it on to the next one.
    log("album art (" .. why .. "), that size is out for a minute", true)
end

local function art_may_request(url)
    local record = art_failures[url]
    if record == nil then return true end

    local now = common.get_timestamp()

    if record.count >= ART.MAX_ATTEMPTS then
        if now < record.next_try + ART.COOLDOWN_MS then return false end
        art_failures[url] = nil   -- cooled off, let it try again from scratch
        return true
    end

    return now >= record.next_try
end

local function cache_art(url, image)
    art_cache[url] = image
    art_order[#art_order + 1] = url

    -- Evict oldest rather than wiping wholesale, so the current cover is never
    -- thrown away just because the cache filled up.
    while #art_order > ART.CACHE_MAX do
        local oldest = table.remove(art_order, 1)
        if oldest ~= url then
            art_cache[oldest] = nil
        end
    end
end

local function request_art(url, px)
    if url == nil or art_cache[url] ~= nil then
        return
    end

    -- A fetch for a cover we no longer want is dead weight. Waiting out the
    -- full timeout for it means the new cover arrives seconds late, or never
    -- while someone is skipping tracks. Drop it and move on -- its callback
    -- checks the slot before touching it, so releasing it early is safe.
    if art_inflight ~= nil and art_inflight ~= url then
        art_inflight = nil
    end

    if art_inflight ~= nil then
        if (common.get_timestamp() - art_inflight_at) < ART.INFLIGHT_TIMEOUT then
            return
        end
        art_inflight = nil   -- previous request never came back
    end

    if not art_may_request(url) then
        return
    end

    art_inflight = url
    art_inflight_at = common.get_timestamp()

    log(("art: fetching %spx"):format(tostring(px)), true)

    network.get(url, {}, function(data)
        if art_inflight == url then art_inflight = nil end

        if type(data) ~= "string" or #data == 0 then
            art_note_failure(url, "empty response")
            return
        end

        log(("art: got %d bytes for %spx"):format(#data, tostring(px)), true)
        art_ready = { url = url, data = data, px = px }
    end)
end

-- The texture for the current track, from whichever size is actually available.
--
-- The candidate list is read, never rewritten. Falling back used to work by
-- writing the chosen size onto the player â€” and apply_state rebuilds those
-- fields from the API on every poll, so the fallback was undone within three
-- seconds while the preferred size sat out its cooldown. The cover stayed blank
-- for the full minute even though a perfectly good 64px copy was sitting there.
local function art_texture()
    local choices = player.art_choices
    if choices == nil or #choices == 0 then return nil end

    -- Anything already decoded, in preference order.
    for _, choice in ipairs(choices) do
        local hit = art_cache[choice.url]
        if hit ~= nil then return hit end
    end

    -- Otherwise fetch the best one that is not cooling off. Requesting the
    -- preferred size while it is already in flight is a no-op, so this does not
    -- skip ahead to a smaller copy while the good one is still coming.
    for _, choice in ipairs(choices) do
        if art_may_request(choice.url) then
            request_art(choice.url, choice.px)
            return nil
        end
    end

    return nil
end

--------------------------------------------------------------------------------
-- fonts
--
-- The `u` flag ("extra symbol support") is documented only on the vector-size
-- overload, and track titles are frequently non-Latin. Nothing in the reference
-- dump uses it, so there is no precedent ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â hence the fallback chain.
--
-- Font families are chosen from ones actually seen in shipped scripts; Segoe UI
-- appears in none of them and is not safe to assume.
--
-- Loading fonts is expensive, so this only reruns when the scale changes.
--------------------------------------------------------------------------------

-- Tried in order. Verdana has no note glyph and patchy coverage beyond Latin-1,
-- which is where the replacement diamonds come from. Shipped scripts prove
-- load_font accepts a filesystem path, so we can reach for faces that actually
-- carry the glyphs instead of hoping a family name resolves to one that does.
--
--   seguisym  Segoe UI Symbol Ã¢â‚¬â€ musical notes, arrows, dingbats
--   segoeui   broad Latin/Cyrillic/Greek coverage
--   msgothic  CJK, for Japanese and Chinese titles
--
-- Whichever loads first wins; the family names at the end are the fallback for
-- a machine missing all of them.
local FONT_CANDIDATES = {
    "C:\\Windows\\Fonts\\seguisym.ttf",
    "C:\\Windows\\Fonts\\segoeui.ttf",
    "C:\\Windows\\Fonts\\msgothic.ttc",
    "Verdana",
    "Tahoma",
    "Arial",
}

local font_source = nil     -- the candidate that worked, logged once

local fonts = { hud = nil, bar = nil }
local fonts_at = { hud = nil, bar = nil }

local function load_font(size, flags)
    for _, candidate in ipairs(FONT_CANDIDATES) do
        -- The `u` flag ("extra symbol support") is documented only on the
        -- vector-size overload, so try that shape first for every candidate.
        local ok, result = pcall(render.load_font, candidate,
            vector(size * 0.88, size, 0), flags .. "u")

        if ok and result then
            if font_source ~= candidate then
                font_source = candidate
                log("font: " .. candidate .. " (unicode)", true)
            end
            return result
        end

        ok, result = pcall(render.load_font, candidate, size, flags)
        if ok and result then
            if font_source ~= candidate then
                font_source = candidate
                log("font: " .. candidate .. " (no unicode flag)", true)
            end
            return result
        end
    end

    return nil
end

local function build_set(scale)
    return {
        big   = load_font(19 * scale, "ab") or 4,
        title = load_font(15 * scale, "ab") or 4,
        body  = load_font(12.5 * scale, "a") or 1,
        small = load_font(11 * scale, "a") or 2,
    }
end

-- Text scale is separate from the overall scale, and the two surfaces scale
-- independently. Rebuilds only when a scale actually changes, since loading
-- fonts is expensive.
local function ensure_fonts(which, scale)
    if fonts[which] ~= nil and fonts_at[which] == scale then
        return fonts[which]
    end

    fonts_at[which] = scale
    fonts[which] = build_set(scale)
    return fonts[which]
end

--------------------------------------------------------------------------------
-- shared drawing helpers
--------------------------------------------------------------------------------

--------------------------------------------------------------------------------
-- icons
--
-- render.load_image accepts SVG source directly, so icons ship as markup rather
-- than as files or hand-drawn polygons. Crisp at any size, and no external
-- assets for a single-file script.
--
-- TO REPLACE ONE: paste the SVG here. It must be white on transparent (the
-- colour comes from render.texture's tint) and use a square viewBox so it
-- centres. Strip width/height attributes; the viewBox does the scaling.
--
-- The drawn polygons further down stay as a fallback in case SVG rasterising
-- isn't available.
--------------------------------------------------------------------------------

-- Every icon is straight lines only: M, L, Z. No arcs, no curves.
--
-- Spotify's own paths render lopsided here Ã¢â‚¬â€ the rasteriser mangles arc
-- commands (shuffle, repeat and speaker came out as angular blobs) and even the
-- mostly-polygonal ones came out asymmetric. Rather than keep guessing at which
-- subset it handles, these are authored so there is nothing left to get wrong.
--
-- All on a 24x24 viewBox with content inset to roughly 4..20, and each shape
-- deliberately balanced about x=12 or y=12 so it reads square at any size.

-- Rasterised once at this size and scaled down when drawn. It must be well
-- above the largest on-screen size: the icons are drawn around 20-30px, and
-- rasterising at the SVG's authored 16px and scaling UP is what turned them to
-- mush. The intrinsic width/height in each SVG is set to match.
-- Icons come from an icon FONT, not from images.
--
-- This is how the original script got clean symmetric controls: Neverlose
-- renders FontAwesome in its own menu, but that font isn't on disk for us to
-- load. Segoe MDL2 Assets is, on every Windows 10/11 install, and it carries
-- purpose-built transport controls. Glyphs are vector, hinted, and symmetric by
-- construction Ã¢â‚¬â€ none of which was true of anything we fed the SVG rasteriser.
-- Only the shapes that are genuinely hard to draw come from the font. MDL2's
-- transport glyphs are hollow line art, and play/pause/prev/next want to be
-- solid Ã¢â‚¬â€ which is also how Spotify's own set works: those four are filled,
-- while shuffle and repeat are stroked.
--
-- Anything absent here falls through to the drawn polygon, which for a triangle
-- and a couple of rectangles is exact, solid and symmetric by construction.
local ICON_GLYPH = {
    shuffle    = "\u{E8B1}",
    ["repeat"] = "\u{E8EE}",
    repeat_one = "\u{E8ED}",
    speaker    = "\u{E767}",
}

local ICON_FONT_FILES = {
    "C:\\Windows\\Fonts\\segmdl2.ttf",     -- Segoe MDL2 Assets
    "C:\\Windows\\Fonts\\SegoeIcons.ttf",  -- Windows 11 successor
    "C:\\Windows\\Fonts\\seguisym.ttf",    -- Segoe UI Symbol, weaker but present
}

-- Fraction of the measured line height to lift a glyph by so its ink lands on
-- the requested centre.
--
-- Measured against a centre crosshair in the debug preview and then dialled in
-- against the live control strip. render.text already places an icon glyph's
-- ink close to the given y, so this is a small correction rather than the half
-- line height the earlier values assumed.
local ICON_V_CENTRE = 0.04

local icon_fonts = {}       -- pixel size -> font object (or false once failed)
local icon_font_note = false

local function icon_font(size)
    local key = math.max(6, math.floor(size + 0.5))

    local cached = icon_fonts[key]
    if cached ~= nil then
        return cached or nil
    end

    for _, path in ipairs(ICON_FONT_FILES) do
        local ok, font = pcall(render.load_font, path, key, "a")
        if ok and font then
            icon_fonts[key] = font
            if not icon_font_note then
                icon_font_note = true
                log("icons: " .. path, true)
            end
            return font
        end
    end

    icon_fonts[key] = false
    if not icon_font_note then
        icon_font_note = true
        log("icons: no icon font found, drawing them instead")
    end
    return nil
end

-- Wraps a drawn fallback so callers don't care which path was taken.
local function glyph(name, fallback)
    return function(cx, cy, s, clr, variant)
        local character = ICON_GLYPH[variant or name]
        local font = icon_font(s * 2.1)

        if font ~= nil and character ~= nil then
            -- "c" centres horizontally. Vertical has to be done by hand, since
            -- text draws from its top edge.
            --
            -- Not half the measured height: that centres the LINE BOX, and an
            -- icon-font glyph sits entirely above the baseline, so the box
            -- carries descender space the glyph never occupies. Centring on it
            -- lifts every icon visibly. The fraction below centres the ink
            -- instead, and is calibrated by eye Ã¢â‚¬â€ adjust it here if the icons
            -- ever sit high or low again.
            local height = s * 2.1
            -- Flags slot passed explicitly; the two-argument form measures
            -- nothing. This silently fell back to the estimate below, which is
            -- why the icon centring had to be dialled in by hand.
            local ok, measured = pcall(render.measure_text, font, "", character)
            if ok and measured and measured.y and measured.y > 0 then
                height = measured.y
            end

            render.text(font, vector(cx, cy - (height * ICON_V_CENTRE)), clr, "c", character)
            return
        end

        fallback(cx, cy, s, clr, variant ~= nil)
    end
end

local function inside(mouse, x1, y1, x2, y2)
    return mouse.x >= x1 and mouse.x <= x2 and mouse.y >= y1 and mouse.y <= y2
end

local function mmss(ms)
    local total = math.floor((tonumber(ms) or 0) / 1000)
    return string.format("%d:%02d", math.floor(total / 60), total % 60)
end

-- The reference menu bar shows time remaining as a negative, not elapsed.
local function remaining(progress, duration)
    local left = math.max(0, (duration or 0) - (progress or 0))
    return "-" .. mmss(left)
end

-- Icons are drawn, not typed. ui.get_icon returns FontAwesome code points,
-- which would need that font loaded and would break if it moved.

local function icon_play(cx, cy, s, clr)
    render.poly(clr,
        vector(cx - s * 0.32, cy - s * 0.58),
        vector(cx - s * 0.32, cy + s * 0.58),
        vector(cx + s * 0.58, cy))
end

local function icon_pause(cx, cy, s, clr)
    local w = math.max(1.5, s * 0.24)
    render.rect(vector(cx - s * 0.42, cy - s * 0.58), vector(cx - s * 0.42 + w, cy + s * 0.58), clr, 1)
    render.rect(vector(cx + s * 0.42 - w, cy - s * 0.58), vector(cx + s * 0.42, cy + s * 0.58), clr, 1)
end

local function icon_next(cx, cy, s, clr)
    render.poly(clr,
        vector(cx - s * 0.6, cy - s * 0.52),
        vector(cx - s * 0.6, cy + s * 0.52),
        vector(cx + s * 0.12, cy))
    render.rect(vector(cx + s * 0.26, cy - s * 0.52), vector(cx + s * 0.44, cy + s * 0.52), clr, 1)
end

local function icon_prev(cx, cy, s, clr)
    render.poly(clr,
        vector(cx + s * 0.6, cy - s * 0.52),
        vector(cx + s * 0.6, cy + s * 0.52),
        vector(cx - s * 0.12, cy))
    render.rect(vector(cx - s * 0.44, cy - s * 0.52), vector(cx - s * 0.26, cy + s * 0.52), clr, 1)
end

local function icon_shuffle(cx, cy, s, clr)
    render.line(vector(cx - s * 0.6, cy - s * 0.38), vector(cx + s * 0.55, cy + s * 0.38), clr)
    render.line(vector(cx - s * 0.6, cy + s * 0.38), vector(cx + s * 0.55, cy - s * 0.38), clr)
    render.poly(clr,
        vector(cx + s * 0.62, cy - s * 0.38),
        vector(cx + s * 0.22, cy - s * 0.5),
        vector(cx + s * 0.3, cy - s * 0.05))
    render.poly(clr,
        vector(cx + s * 0.62, cy + s * 0.38),
        vector(cx + s * 0.22, cy + s * 0.5),
        vector(cx + s * 0.3, cy + s * 0.05))
end

local function icon_repeat(cx, cy, s, clr, single)
    render.rect_outline(
        vector(cx - s * 0.55, cy - s * 0.38),
        vector(cx + s * 0.55, cy + s * 0.38), clr, 1, 4)
    render.poly(clr,
        vector(cx + s * 0.18, cy - s * 0.68),
        vector(cx + s * 0.18, cy - s * 0.08),
        vector(cx + s * 0.66, cy - s * 0.38))

    if single then
        render.rect(vector(cx - s * 0.07, cy - s * 0.15), vector(cx + s * 0.07, cy + s * 0.15), clr, 1)
    end
end

local function icon_speaker(cx, cy, s, clr)
    render.poly(clr,
        vector(cx - s * 0.55, cy - s * 0.22),
        vector(cx - s * 0.55, cy + s * 0.22),
        vector(cx - s * 0.2, cy + s * 0.22),
        vector(cx - s * 0.2, cy - s * 0.22))
    render.poly(clr,
        vector(cx - s * 0.2, cy - s * 0.22),
        vector(cx - s * 0.2, cy + s * 0.22),
        vector(cx + s * 0.2, cy + s * 0.6),
        vector(cx + s * 0.2, cy - s * 0.6))
    render.circle_outline(vector(cx + s * 0.2, cy), clr, s * 0.5, 300, 0.22, 1)
end

--------------------------------------------------------------------------------
-- interaction
--
-- Immediate mode: hit test, hover tint and click all happen where the control
-- is drawn, so there is no widget tree to keep in sync with the drawing.
--------------------------------------------------------------------------------

-- Drag state in one table rather than loose locals: a Lua chunk may declare
-- only 200 of those and this one runs close to the line. `w`/`h` are last
-- frame's measured panel size, which is what lets the position be clamped
-- before drawing rather than after.
local drag = { active = false, offset = vector(0, 0), w = 0, h = 0 }
local volume_dragging = false

-- Keeps a dragged panel on screen, and lets the edges actually be reached:
-- within 14px of one, it sits flush against it. Landing a panel exactly in a
-- corner by hand is not something anyone manages, and being a few pixels out
-- is very visible against a screen edge.
local function snap_to_screen(origin, w, h)
    local screen = render.screen_size()
    local max_x = math.max(0, screen.x - w)
    local max_y = math.max(0, screen.y - h)

    local x = math.clamp(origin.x, 0, max_x)
    local y = math.clamp(origin.y, 0, max_y)

    if x <= 14 then x = 0 elseif x >= max_x - 14 then x = max_x end
    if y <= 14 then y = 0 elseif y >= max_y - 14 then y = max_y end

    return vector(x, y)
end
local mouse_was_down = false

-- Spotify refuses every playback command from a free account with a 403. The
-- buttons used to look live and do nothing, which reads as the script being
-- broken rather than the account not allowing it.
--
-- `product` is only known once /me has answered, so an unknown tier counts as
-- allowed: better a button that turns out to fail than a working one greyed out
-- on a guess.
local function can_control()
    return session.product == nil or session.product == "premium"
end

local function hit_button(ctx, cx, cy, reach, active, accent, draw, action)
    local locked = not can_control()
    local hovered = not locked and ctx.interactive
        and inside(ctx.mouse, cx - reach, cy - reach, cx + reach, cy + reach)

    -- Every shade here inherits the accent's alpha. The menu bar hands in an
    -- accent already faded to match the menu, and a button painted at a fixed
    -- 255 would sit there at full strength while everything around it went, and
    -- then snap out.
    local strength = accent.a or 255
    local tint = active and accent or color(210, 202, 220, strength)

    if locked then
        tint = color(150, 150, 158, math.floor(90 * strength / 255))
    elseif hovered then
        tint = color(255, 255, 255, strength)
        render.circle(vector(cx, cy), color(255, 255, 255, math.floor(20 * strength / 255)), reach, 0, 1)
    end

    draw(tint)

    if hovered and ctx.clicked then
        ctx.consumed = true
        action()
    end
end

local g_play    = glyph("play", icon_play)
local g_pause   = glyph("pause", icon_pause)
local g_prev    = glyph("prev", icon_prev)
local g_next    = glyph("next", icon_next)
local g_shuffle = glyph("shuffle", icon_shuffle)
local g_repeat  = glyph("repeat", icon_repeat)
local g_speaker = glyph("speaker", icon_speaker)

local function control_row(ctx, cx, cy, spacing, size, accent, compact)
    -- Shuffle and repeat come from the icon font, whose glyphs carry more
    -- padding than the drawn triangles, so at a matched nominal size they read
    -- noticeably larger than the skip buttons. Trim them to compensate.
    local outer = size * 0.82

    hit_button(ctx, cx - spacing * 2, cy, spacing * 0.5, player.shuffle, accent,
        function(c) g_shuffle(cx - spacing * 2, cy, outer, c) end, toggle_shuffle)

    hit_button(ctx, cx - spacing, cy, spacing * 0.5, false, accent,
        function(c) g_prev(cx - spacing, cy, size, c) end, skip_previous)

    hit_button(ctx, cx, cy, spacing * 0.55, false, accent,
        function(c)
            if not compact then
                render.circle_outline(vector(cx, cy), c, size * 1.5, 0, 1, 1)
            end
            if player.is_playing then
                g_pause(cx, cy, size * 0.8, c)
            else
                g_play(cx, cy, size * 0.8, c)
            end
        end, toggle_play)

    hit_button(ctx, cx + spacing, cy, spacing * 0.5, false, accent,
        function(c) g_next(cx + spacing, cy, size, c) end, skip_next)

    hit_button(ctx, cx + spacing * 2, cy, spacing * 0.5, player.repeat_state ~= "off", accent,
        function(c)
            g_repeat(cx + spacing * 2, cy, outer, c,
                player.repeat_state == "track" and "repeat_one" or nil)
        end,
        cycle_repeat)
end

-- Returns the fraction the pointer is at, or nil when not being used.
local function progress_bar(ctx, x1, y, x2, height, fill_a, fill_b, track)
    local progress = current_progress()
    local fraction = 0
    if player.duration_ms > 0 then
        fraction = math.clamp(progress / player.duration_ms, 0, 1)
    end

    -- A 4px bar is unclickable in practice, so the reach is deliberately taller
    -- than the bar itself. Seeking is a playback command, so a free account
    -- gets the bar to look at but not to scrub.
    local hovered = can_control() and ctx.interactive
        and inside(ctx.mouse, x1, y - 7, x2, y + height + 9)

    render.rect(vector(x1, y), vector(x2, y + height), track, height * 0.5)

    if fraction > 0 then
        local fill = x1 + ((x2 - x1) * fraction)
        render.gradient(vector(x1, y), vector(fill, y + height),
            fill_a, fill_b, fill_a, fill_b, height * 0.5)

        if hovered then
            render.circle(vector(fill, y + height * 0.5), color(255, 255, 255), height * 1.6, 0, 1)
        end
    end

    -- `consumed` matters here: a control button drawn earlier in the frame may
    -- already have taken this click. The two do not overlap at the shipped
    -- sizes, but the scale sliders can move them into each other, and one click
    -- doing two things is a nasty way to find that out.
    if hovered and ctx.clicked and not ctx.consumed then
        ctx.consumed = true
        seek_to((ctx.mouse.x - x1) / math.max(1, x2 - x1))
    end

    return progress
end

local function volume_bar(ctx, x1, y, x2, accent)
    local height = 4
    local locked = not can_control()
    local hovered = not locked and ctx.interactive
        and inside(ctx.mouse, x1 - 4, y - 8, x2 + 4, y + height + 10)
    local fraction = math.clamp((player.volume or 0) / 100, 0, 1)

    -- Same idea as hit_button: the accent carries the menu's fade, so the track
    -- and the grab dot take their alpha from it rather than a fixed value.
    local strength = accent.a or 255

    render.rect(vector(x1, y), vector(x2, y + height),
        color(255, 255, 255, math.floor(38 * strength / 255)), 2)

    local fill = x1 + ((x2 - x1) * fraction)
    render.rect(vector(x1, y), vector(fill, y + height),
        locked and color(150, 150, 158, math.floor(90 * strength / 255)) or accent, 2)

    if hovered or volume_dragging then
        render.circle(vector(fill, y + height * 0.5), color(255, 255, 255, strength), 5, 0, 1)
    end

    if hovered and ctx.clicked and not ctx.consumed then
        volume_dragging = true
    end

    if volume_dragging then
        ctx.consumed = true
        if ctx.held then
            set_volume((ctx.mouse.x - x1) / math.max(1, x2 - x1))
        else
            volume_dragging = false
        end
    end
end

--------------------------------------------------------------------------------
-- styles
--------------------------------------------------------------------------------

--------------------------------------------------------------------------------
-- placeholder cover art
--
-- Shown in the cover slot when nothing is playing, in place of the drawn note.
--
-- Embedded rather than loaded from disk: the script has to be one file to ship
-- on the marketplace, so there is nowhere for a loose asset to live.
--
-- It ships as a colour PALETTE plus one index per pixel, not as a JPEG, because
-- the hue has to be adjustable. render.texture's colour argument multiplies,
-- and multiply cannot rotate a hue â€” it scales toward the given colour, so
-- white becomes that colour and anything already coloured collapses toward
-- black. That is a mask, not a recolour.
--
-- render.load_image_rgba takes a hex-encoded RGBA buffer, so the pixels are
-- built here instead. Only the few hundred palette entries get rotated; the
-- 16k pixels are then a lookup each. In HSV a hue rotation leaves saturation
-- and value alone, which is exactly why white stays white and black stays
-- black â€” neither has a hue for it to act on.
--
-- To replace it: drop a square image in lua/placeholders and run
-- lua/embed_placeholders.ps1, which regenerates the data block below.
--------------------------------------------------------------------------------

local PH = { cache = {}, order = {} }

-- Standard base64. Anything outside the alphabet is skipped, which is what
-- lets the blobs below be wrapped across lines for readability.
function PH.decode(text)
    if PH.alphabet == nil then
        PH.alphabet = {}
        local chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        for i = 1, #chars do PH.alphabet[chars:sub(i, i)] = i - 1 end
    end

    local out, bits, held = {}, 0, 0

    for i = 1, #text do
        local value = PH.alphabet[text:sub(i, i)]

        if value ~= nil then
            bits = bit.bor(bit.lshift(bits, 6), value)
            held = held + 6

            if held >= 8 then
                held = held - 8
                out[#out + 1] = string.char(bit.band(bit.rshift(bits, held), 0xFF))
            end
        end
    end

    return table.concat(out)
end

-- Rotates one RGB triple's hue, leaving saturation and value exactly as they
-- were. Greys return untouched: with no chroma there is no hue to move, which
-- is what keeps the white lettering white and the black background black.
function PH.rotate(r, g, b, shift)
    local high = math.max(r, g, b)
    local low = math.min(r, g, b)
    local chroma = high - low

    if chroma == 0 then return r, g, b end

    local hue
    if high == r then hue = ((g - b) / chroma) % 6
    elseif high == g then hue = ((b - r) / chroma) + 2
    else hue = ((r - g) / chroma) + 4 end

    hue = ((hue * 60) + shift) % 360

    local sector = hue / 60
    local mid = chroma * (1 - math.abs((sector % 2) - 1))
    local nr, ng, nb

    if sector < 1 then nr, ng, nb = chroma, mid, 0
    elseif sector < 2 then nr, ng, nb = mid, chroma, 0
    elseif sector < 3 then nr, ng, nb = 0, chroma, mid
    elseif sector < 4 then nr, ng, nb = 0, mid, chroma
    elseif sector < 5 then nr, ng, nb = mid, 0, chroma
    else nr, ng, nb = chroma, 0, mid end

    return nr + low, ng + low, nb + low
end

-- The texture for a given hue shift, nil if it cannot be built.
--
-- Cached per shift, because the HUD player and the menu bar can be set to
-- different hues and this runs from the draw path â€” rebuilding on every frame
-- because the two surfaces disagree would be ruinous. The cache is capped, so
-- dragging the slider cannot accumulate textures without limit.
function PH.image(shift)
    shift = math.floor((tonumber(shift) or 0) % 360)

    if PH.cache[shift] ~= nil then return PH.cache[shift] or nil end

    if PH.bytes == nil then PH.bytes = PH.decode(PH.data) end
    local bytes = PH.bytes

    local count = (bytes:byte(1) * 256) + bytes:byte(2)

    -- Each palette entry becomes the four RAW bytes of one RGBA pixel up front,
    -- so expanding the image costs a table lookup per pixel and no maths.
    --
    -- Raw, not hex. The documentation calls this a hex-encoded buffer, but a
    -- hex string handed over gets read as pixel bytes: the ASCII codes for
    -- "0"-"9" and "A"-"F" all land in 0x30-0x46, which draws as a very dark
    -- square with a regular stripe every few pixels. That is what it did.
    local swatch = {}
    for i = 0, count - 1 do
        local at = 3 + (i * 3)
        local r, g, b = PH.rotate(bytes:byte(at), bytes:byte(at + 1), bytes:byte(at + 2), shift)

        swatch[i] = string.char(
            math.clamp(math.floor(r + 0.5), 0, 255),
            math.clamp(math.floor(g + 0.5), 0, 255),
            math.clamp(math.floor(b + 0.5), 0, 255),
            255)
    end

    local pixels = {}
    for i = 3 + (count * 3), #bytes do
        pixels[#pixels + 1] = swatch[bytes:byte(i)]
    end

    local ok, image = pcall(render.load_image_rgba,
        table.concat(pixels), vector(PH.size, PH.size))

    if not ok then log("the placeholder image failed to build") end

    PH.cache[shift] = (ok and image) or false
    PH.order[#PH.order + 1] = shift

    while #PH.order > 6 do
        local oldest = table.remove(PH.order, 1)
        if oldest ~= shift then PH.cache[oldest] = nil end
    end

    return PH.cache[shift] or nil
end

-- Exposed to the desktop harness only, the same way SEAL is: nothing in
-- Neverlose defines this global, so in game nothing is handed over.
if rawget(_G, "__spotify_test") then rawget(_G, "__spotify_test").placeholders = PH end

--------------------------------------------------------------------------------
-- PLACEHOLDER DATA â€” generated by lua/embed_placeholders.ps1, do not hand-edit.
-- 128px, 256-colour palette plus one index a pixel, base64, wrapped.
--------------------------------------------------------------------------------

PH.size = 128
PH.data = [[
AQAEBAT8/PwEBBQEBAwEBBwEDCwEDDQEBCQEFEwEBCwEFFQEBDQEDDwEDCQEFEQEDEQEHFwEHFQEFDxMfPwEBDwEDEwEFDQMJGQMFDQMFDwEHGQEFFwM
HFxUhPwEBEQMHEQMFEQMJGwEJGQEDBwMHEwMHFQEHEwEJGwUJFwMHGRchPwMLGwMDCxEdPwMFFQEDFQMFEwULGwEBEwMHDwMLHQMJFwUJGREfPz09PwE
LGwEHGwUJFSkvPwEJFwEJHQUJGwMFCy8zPwUHEwELGQMFFxEbNwULHQcLGxkbJwMHGwEFCwMNHQMDDTs9PwULGQkPJwELHQMJHQMPIQUHFwMLHxEbNQE
BFQEFGQEDFwMLGRUfPwEHEQELFwMFGQMNHzM1NwMNIQMPHwEJFQUHFQENGQMBExkdJwMDFwEJHxEZNQUHEQ8ZMxkjPwMFGy0xPwkPIxkbKQEHHQENGwc
JFwMPIwMJHwUJHQkPJQMDDw8dPwMDFQMDEwUNHwENHQ8ZNQMDGQMHHQkRJwcLHQEFGwcJGQMDCQEDBQEDGQ8TIRkdKQMDGwMRIQMHHw8bNQkPIQMLIQU
NIQULHwkTKQ8bNwMBFQMDET0/PxcjPwcLGRcbJwEJEwELFQMBEREbOQUDFyEpPycpLysxPwULFzc5PwENHxMhPwsTKQcLFw8XLw8XLQMRIwMNIwUDGQU
BFwEHHwMFHRUjPyUnLQkRIwkRJQMHDSkrMQUJEyctPxslPzk7PxMfPTMzNwUPIwUPIQMJIQENFw0VLwcNHS0zPyEjKS0xPSUnKz09PRcZIRcZIxcZJTc
3OQEDGwcNGzs7PTM3PzE1PzMzNQ0VKzs7PxEdPQELHysvPwUNHQsTKwkTKw0VLQcRJwUNIw8XMw8bOQMNGwMPHQMBFwUBFQEJEQEFCQMLFwsTLQcNIxE
dOwULIysvOycnLScpMScnKw8RGR0fJwMJFRkbIQ0RHTEzNw8THzU1ORMXIxkZJxcZJxUZJQMBDzk5OxkbJQkNGwkPKS0tMyUrPQAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwMDAwMAAAADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMDAAAAAAADAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAwMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAAAAAAAAAAADAAADAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAMDAAAAAAAAAAAAAAAAAAMDAAAAAAAAAAAAAAAAAAMAAAADAAAAAAAAAAAAAAAAAgQAAAAAAAADAwMDAAAAAAAAAAMAAAAA
AAAAAAAAAAAAAAMDAAAAAAAAAAAAAAAAAAAAAAADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAAMCAwMAIwIDAAAAAwADAAADAwMA
AAAAAAAAAAAAAAAAAAAAAAAABAMADQYMBRIHBA0NDQQCAAAAAwADAwMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAD4wMAAAIjAgMAAwAAAwMCAwADAAMAAwADAAAAAAAAAAAAAAAAAAAAAAAAAAACDQUaBAIDAgMDAwMEBAkNSgICAwMDAwAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwMCAAMAAgMDAAADAAAAAAADAAMAAwADAwMAAAMAAwAA
AAAAAwADAwMAAAMAAwMEBiYGIwMCAgMCAwIDAgIFBQYNDQICAgMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAADAAAAAwAAAwMDAwMAAwADAwMAAwADAAMAAwAAAwADAAMAAwADAAMDAwMDAwMCAwIDBBYmBQcCAgQCAgMEAwIDBCMWBgUSDQIDAwMAAAAA
AAAAAAAAAAAAAAADAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwMAAAAAAwADAwIDAgMDAAMDAwMDAwMDAwMAAAADAAMAAwADAwMDAwMAAgMCAwID
AgMCAgMCAwQDBAIHAgdbmwkEBAIEAgQDAgMCAAMCBwUGBgkHBAIDAwMAAAAAAAAAAAMDAgIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAgIDAAAD
AAMAAwACAAMAAwADAAMDAwAAAwMDAwIDAgIEBAQEAgQCBAIEAgQDBAICAgICAwQDBAMEAgQCBAIJDlsEAgQCAgMCAwIDAgMDAgQFBgsLCwkHBwcEAgIC
AgMCAgMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACMjBAQCAwMAAwADAAMAAwADAAMDAwMCAgIEBA0NBgUWEhISDg4SDhISBhIFBgcNBAQEAgQC
BAMEAwcCBAIHBAQEFgwFBAIEAgICAgICAgICAgMCBAcJFB4UHhQLBwQEAgMDAwMAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABgYNDSMHAgICAwMD
AwACAwMDAgIEIw0FBhYGEg4IDiYOCAgREQ4ICBEOJg4IDg4ODAYNBwQJAgcCBwIHAgcEBwIEBQ4GDQQCBAIEAgIDAgICAwMDAwIEBwkLCwsLCwkJCQcE
AgICAwMDAwMAAAAAAAMDAwMDAgQCAgMDAAAAAAAMChIWBQ0FDSMEAgICAgIjDQ0FBQYWEg4OCA4RCGIOCg4OEhISElsOECZcCBAIEREREQgIDBQEFAQJ
AgcCBAIEAgQCAg0GEg0jAgICAgICAwICAwICAgICAgIEBwcJCQkLCQsHBwQEAgICAgIEBAQHCQkJCQcJCwkJBwcHAgAAAAYSDg4PDgYGBQUFBQUFBQYS
EiYODggRCA4OEg4GFgUGBQUGBQYFDAUPDBUSCggKEQo9EREIJhIGIwUEBwIEAwICAgICAgIGDAwEIwQEBAICBAICAgICAgICAgICAgQEBwQHBwkLCQkJ
CQkJCQsUCwsUCwcHAgIDAwMCAgcLBwMAIw0FDg8IFQgPDAwMDhISDA4IEA4IJiYOFgYFBg0FBQYGBgYFDAUPBQ8FDwYPEggOCBEmCggQCAoSEg0FIwcC
AgMCAwICAgIjDAwFBAIEBAQEAgQCAgICAgICAgICAgICAgQEBwcJCQsLCwsLCQkHBwQCAwMDAwMDAwAAAwMJFAADBAQjBQYOCA4ICA8mCAgOEQgKDhIG
BQYFBg0GBQwGEg4OCA4KDhEOChIIEg4GEhIMDg4KCD0IGwgQEgYNDSMCAgICAgICAiMEDQYUCQQEBAQEBAQCAgICAgICAgICAgICAgIEBAQEBAcHBwQE
BAICAgMCAwMDAwMDAwMDAwMECwMCAwICBA0FBgwOEg4ODhISDAwGBQUFBgUMBg4SCggKESYmDgoSERIQDj0IEA4ODAwSEg4SCAgICBAIGwwFDSMCAgIC
AgICBAQEBAseFAkEBAQEBAQEBAQEBAICAgICAgICBAICAgQCAgICBAICAgICAgMDAwMDAwMDAwMDAwMHAwMDAgIEBCMNDQUFBQUMBQYFBQUFBQUMBRUS
GxERDw4VDA8GFQUPBQwFDAYPDhEmJhISFhYSDggOCggbFQgGBQ0jAgICAgICBAQEBAceMgkHBAQEBAQEBAQCBAQEBAQCAgICAgQEBAQCAgQCAgICAgID
AwMDAwMDAwMDAwMDAwIDAgICAgICBAQNDQ0FDQYFBgUGBgUMBggSGgobDg8MDA8MBgUMBQwFBgUMBQYFDBImCAgOEgwSEg4ICBsVGxUMBQ0NAgICAgIE
IyMEBwcHZR4HBwQEBAQEBAQEBAQEBAQEBAQCAgICAgICAgICAgICAgICAgMDAwIDAwMDAwMDAwMCAgICBAQjBAQNDQYFBgUGBgYMFggOEAgiDg4GDwYG
DAYGBQYFBgUMDQwFDAUGBQYWDhEIDhISDA4OFRUbClgMBQUNI4YChiMjBAQHBwcJFJQLBwcHBAQHBwQEBAQEBAQCBAQCAgQEAgICAgICAgICAgICAgIC
AwMCAgMDAwICAgICBAQNDQ0FDQYFBgUMDAwOEggOGwgiEggGDwYODAwGDAYFDAUGBQYFBg0FDQUFBQUFBg4KCgwMDAwPFS8VWC8vBQUNIyMjIyMNDQ0N
BwcHHh6cCQcHBwcHBAQEBAQEBAQEBAQEBAQEBAIEBAICAgICAgICAgICAgIDAgICAgICBAQNDQUFBQUFDAYPDA8ODggOEAo6DgoSCgYVBgwFBgUFBQUG
BgYFBQUFDQUFBQ0FBQUGBhIILwgODA8IFS8vWIcPBgUNDSMjIyMNDQ0NDQkHCWUeCwkHBwcHBwQEBAQEBAQEBAQEBAQEBAQEAgIEAgQEAgICAgICAgIC
AgICAgQHBwUFBQYGDAYODgoICBEREAgbDgoWDwYPFhIWDAUMBgYGBgYGFkoFBUoFBQUFDQUFBQUGFgYICggODg4ICC9YG1gvBgYFDSMNIw0NDQ0FDQUF
BQxnCwkJBwcHBwcHBAQHDQQEBAcEBAQEBAQEBAQCBAQEAgICAgICAgICAgICBwUFBQUFDAYOEggIChEREBERDggWCBYSSg8FEgYPFg4WDBYWBQYWFkpK
FgUGBUoFBkoWBRYWFhYSGwoODg8ILwovWFgPBgYFDQ0NDQ0NDQ0FBQUFBQwPDAUNCQkNDQ0NDQcHDQ0HBwcEBAQEBAQEBAQEAgQCBAICBAQCAgICAgIG
BgUFDAUVBggSCg4K5EMKDgoSCBIIEg4WDhYOFhIGEhYWFhYWFhYWFhYWShZKSkoWFhYWFhYWFhIOCBsICAgICi8bWFgVDAYFBQ0NDQ0FBQUFBQUFBQwP
Dw8FBQ0NBQ0NDQ0NDQcHBAQEBAQEBAQEBAQEBAQEBAQEBAQCAgICBA8MDwYPBg4GChIKDhsIChFiCA4OEg4SDhISFhIWEhYSFhIWEhYSFhYWFhYWFhYW
FhYWFhYWGBgYGRkgRC4KCAouCkREXS4PDAYsBQUFBQUFBQUFBQUFBgYVFQ8MBQUFBQUNBQ0NDQ0HBAcHBwQHBAQEBAQEBAQEBwcHBAQEBAQEGwgVBhUG
FQYKBggSCA4IDiYICA4ICAgICA4ODhIOEg4SEhISEhISEhISEhISEhgYGRYYGBgYGRkZICAOLkQwMC4uRC5dRDAgGRZKSkpKBQUFBQUFBQYFBgwMGwgG
BgUFBQUFDQUNBQcHBwcHBwcHBwcHBwcHBwcHBwcHBwQEBAQ6CggSCAYIBggFCBYOFggSCA4ICAomEREREAoQCgoKCggwMDAIICAgICAgGRkZGRkZGRkZ
GRkZGRkZICAwSS4uLi5ELl1dXTAgGRgYQEBKSkoWSgYWFhYSFgwSDg8MDAYGBQYFBQUFBQkNBQkHBwcHBwcHBwcHBwcHBwcHBAQEBK4KGwgbEgoWCgYI
Bg4WDhYOFg4SEg4ODw4OCAgICggKCi4uRERdLi4wMDAwICAgICAZGRkZGRkZIDMgICAuREQuLkREXURtRCAgGRgYGBgYFhgWFhYWFhYWDBIOCAoaChsP
DwYGBQUFCQkJCQkJCQkHCQkJCQkJCQkJCQcHBAQNaAobCAgSDgwOEg4MEgYWBhISEhISEhISDg4ODggICDAuLi5ERF1EXS4uLjAwMDAgIBkgIBkZGSAf
Hx8fHyQcXRwlHBxdRG1dLiAgGRkYGBgWFhYWFhYWFhYSEhIODwgPCg8VDAYGBgYJCQkJCQkJCQcJCQkLCxQUCwkJBQ0NBw0iEQgODg4ODg4MDgwSDAwM
EgwSDAwMEgwPDw8OIAgwMDAuLi4uLl2vREQuLi4lJCQfHyAfHx8fHx8fHx8kJByAHBwcHCkcgCkcJTAfGRgZGRgWGBIWEhYSFhYSFhYMBgYMDy8MDA8M
CwsJCQkLCQkJCQsLFB4eHh4UCwUFBQ0JDRAKDg4ODgwPEhISDAYMBgYGBgwMDAwMDw8PDg4wMDAwMC4uLi5EHBxJSRwcHCUlJSQkJCQkJCQfJCQfJCQl
JRwpHBwcKRxJKYwcJSQfMzMzGRkZGRkZFhIWEhISEhIGBgYMFQ8elDILCwsLCQsLCwsUFFZYDxUvMg8MBgUGDQUNDwgMDgYMBgYGBgYGBgYGBgwMDAwP
Dw8PlRUVFTAwMC4uLi5ERBwpKYBJHBwcHBwcJSUlJCQkJCQkJCQkJCUlHCkXHCkpKSEpURwlJSQfHzMfHzMZGRIWEhISFhYMDAwMBgYMDBQyVgsLCwsJ
CQsLCx4eDw8PDy8VDw8MBQUHBQ0GDAYFBQYFBgYGBgwMDAwMDA8PDw8VFRUVe3svLy4uLi5ELl0pSSlJSUkcHBwcHBw1NSUlJSUkJCQkJCQkJSU1IVEX
FxcXIRd1KRclJSQfIB8fMyAZGRISEhIWFgYGBgYGBgwMFB4yHhQLCwsLCwsLHh4MDw8PFQ9YCgYFBQ0FDQUGBQUFBgYGBgwMDAwMDwwPDxUVFXt7Ly8v
wEVFRUVFRZ3lbSlJKSkcHBwcHCgcNTU1NTskwUVFRUVFRUVFjTEhdhcXPxzmnedFnUVFRUVpOzMzGRkZGRIWFhYGBgYGBgYGCwYGCxRWHhQLCwsLCwsM
FQ8PDA8PDxsbBgUFDQUNBQYFCwsLCwsUFAwPDxUPng8VDw8VlXt7exVFsB0dEzc3NzfoHhUVJVMcHDU1KCgoNigoKCWOHR0dHTctNzctSQpXGyk/HHcd
HR0dNzc3Ny0RCwYLEhkZGRISBgYGBgYGBgYGBgYLCxQUMhQUFBQLDAwVDwwMDw8PL1cMBgYFBQUJDAsLCxQUHh4UFBQUFAwMDAwMDAwMlZUgDGkdEy2f
wm5uwumx6sMlJTsoKCgoKCg2KCgoJY5aExMdPG5ubsTrsaCgiCkcdx0TEx2hbm5uxKDFxeztDBkZGBIMBgYGBgYGBgYGBgsLBgsvFQ8PDAYVDw8MDAwP
Dw8bVwwGBgUGBQsUFAsLFBQUFAsLCwkLBgYGBgZMTHh4GRkZaR0TeaEBAQEBAQEBAe4VKDsoKCgoKDY2NjbvjloTEyqWAQEBAQEBAQFmVxd3HRMTlwEB
AQEBAQEBAfALIBkZGQwGBgYGBgYGBgUGBgsGBlgvLw8VDxUMDAwPDA4PDxAQBgYGBQUFCxQLCQkJCQcHBAcHBwQNDQ0NDSwsLCwYQEBpHRMtPAEBAQEB
AQEBxvEROzsoKCgoTk5OTihvHRMTKk0BAQEBAQEBAUgaF08dExMqOAEBAQEBAQEBxwsgGRkZeAYGBgYGBgYGBgYGBQYMGy8bDwoPDwwPDA8PCA8VEBAG
BgUNBQUHBAQCAgICBAQEBwcHCQYMDAYMlXggIBkZGWkdEy08AQEBAQEBAQEB8hw1KKIook5OTk5OKG8dExMqTQEBAQEBAQEBSDo2Tx0TEyo4AQEBAQEB
AQHHFCAgICB4eAwGBgYGBgYGBgYGDw8bCAgPDAwPDA8MDg8IDxUbGwYGBQ0GBQICAgIEBAQEBwcJBwQFBQYGDCwsLBgYGS4ZaR0TLTwBAQEBAQEBAQEB
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
IyMjIw0NhSwsLCxMGBgYGBgYGBgYGRkZIB8kJCQlHBwcHBw1FxcXFxcXFyEhSyuQNLwrdDRhS15hXr1Lqit0K4srUiteKzQrWSE1FxAiERwmESYmCAgm
DgoIEQgQCCIIQxE+EUMRQxAaAwMDAwMDAwICAgICAgICAgICAgICAoaGIyMjDQ2FBSxMLExMTCwsTEwYGBgYGRkgICAwJCQlJRwcHBwpNRcXFyEXUSFU
K6srUit0NGFeYGFhUjSLK3QrUllgK0srNBcXITUXERcREBEQERAREBARGhEiEScROSY5EVARZBFDERADAwMDAwMCAgICAgICAgICAgICAgICAoYjIyMN
DQUFBUxMTEwsLCwsLEwYGBgYGSAgIDAwJCUlHBwcHCkcFykpISE0IVQhqyF0K1IrYUthYUtgK4tZUllhF1RZSysrFxcXPSIQIhEXESIRPRA9IhAnEDkR
UBF9EXImciZDJmIICgMDAwMDAwMDAwMDAwMDAwMCAgICAgICBAQEDQ0FBQUGBkxMTCxMLEwsLExMGBgZGSAgMDAkJSUcJRwcKRwpHCkhFyshUitSK4sr
UitSS2FeS14rUllSF0sXNBcrF1krFys1KxArESsQOT0iGj1QGlAQfRGkEUsRciY5Jj0KCggKAwMDAwMDAwMDAwMDAwMDAwMCAgICAgIEBAcNDQUFBgYG
BgZMBQYFBSwsBUwWFhgZICAgMCQuJSUlJRwcHDUcKSEXNCGrIXQrUit03oteUmFLYCtSWWAXYRdLFysXFysXKxA0EFAQURo+Gj4+J1A6UBCkEFAROSY5
ESImEAoKCAgDAwMDAwMDAwMDAwMDAwMDAwMCAgICBAQEBwkJBQYGBgYGBgYGBQUFBQUFBQYWGBYSDiAgMDAlJSUlJRwcKRwXISFUIWAhdCGqWao0i0tS
XktgK1IXYBd0IWAhVCEhNCJUEFQQjxBoGmgaPicnUBrUEH0QfRF9JjkRQwgRCAoICAMDAwMDAAAAAAAAAwMDAwMDAgICAgQEBwcHCQkJCwsLBgYMBgYG
BQUFBQUGBhYWFhISDg4gMC4RERwlHBwpHBchF15RYBd0InRZUitSNEteNF4XYBdgF6sXVCE0USE0F3UQdRC+EHUaPho+JyI5GlA9chFQEXIROSZDEWII
CAgIAwMAAAAAAAAAAAAAAwMDAwICAgQEBAQHBwkJCQsLFBQUFBQGBgYGBQUFBQUGBgYWEhIODggICgoKEBEpECk9FyEiXiFeIlIiUhdSIV4rSzQrNBdU
KVQ1VCk0FyEhIVEQaBBUED4QPho6ECcnIicQPhA5EVAmZCY5EUMRXAgmCAgAAAAAAAAAAAAAAAADAwMCAgICBAQHBwcJCQkLFAseFBQUCwYGBgYFBQUF
BQUGBhYSEg4SDggICggRChARIhAiIRdUIY8ijylgF2AXVBc0USE0KVQcVBBUED4XIScaJxAnECcRPhEnECcaOjoaOhA+EDkKPiY5JjkRQxE9EREICAAA
AAAAAAAAAAADAwMDAwICAgQEBAcHBwsLCQsLCwsLFBQUDAYGBgYFBQUFBQUWFgwSEg4OCAgKChEKEBEaECInImg6vhqPGo8pjyl1FyEhKVEcjBxRHFEQ
PhoiGhAnECcRJwpoED4QcRo6GhonGycROQpQJjkmQxFcET1iYhERAAAAAAAAAAAAAwMDAwMCAgIEBAcHBwcJCQsJCQsLCwsLFAwMDAYGBgYFBQUGBQYG
BhISDg4ICAgICgoQChoQGjoiaDp1Gr4bdRx1KVEpSUkpgESALoAbSRw6KRoaECcQJwonCnEbPhs6EBoaECIbIhE5CjkmQyY5JkMRPWI9YmIAAAAAAAAA
AAMDAwMDAgICAgQHBwcJCQkJCQkJCwsLCwsLCxQMBgYGBgYFBQUGBgYWEhISDggICAgRCBsKEBAQGhBxGnEbrhuMG4xESV2KbURtRG0urwqDChobVxoQ
GhE6CicKJwo6ChoRGhobIhEiEUMIOQhyCHImQyZcET1iYgAAAAAAAAADAwMDAwMDAwICAgQHBwcJCQkJCQkLCQkJCwsLCwYMBgYGBgYFBgUGBgYWEgwM
Dg4OCAgICggQChsbG4NXOhtxCq9nimeKZ39/Z39nf3qKClcKVwobGgoaCjoKJwpxCiIKGhEQEAoaCjoKJwgnCDkmOSZDJlxiXJtcAAAAAAADAwMDAwMD
AwMDAgICBAQHBwkJCQkJCQkJCQkLCwYGBgYMDAYGBgUFBQYFBgYSBgYSDw8PCAgKCAoKGxsbVxuDL4Mvinp/eqxnZ2d6f3p/e4cvhwpXChsQChoIGgga
CDoKGgoaGxAQEBoKGhEiCDkIQyZDJkMmQxFcm0MAAAADAwMDAwMDAwMDAwMDAgIEBAcJCQkJCQkJCQcJCQkJBgYGBgYMBgYGBgYFBgUFBgYGBgwMDw8O
FQgVLy8KLy9YL38vinqse6x6nnpnZ3p/L4cVhy+HChsKChsKEAgaCBoIGgoaChobGhAbEAo9JiIIJwg5CGQmZCZcJlwmQwMDAwMDAwMDAwMDAwMDAwMC
AgIEBAcJCQkHCQkHBwkJCQkJCwYGBgwMDAwGBgYGBQUFBgYGBgYMDw8PFQ8vFS8vLy8vWBWeZaxlrGWeeuCt4WcVhxVYFVgvGwoKGwobCBAIGggaChoI
GwoQGhA9ESImQwhDCCdbXA5DW1wmv5pkAAMDAwMDAwMDAwMDAwMDAwICAgQEBwkHBwkHBwcJCQkFBQUGBgYGBgwMDAYGBQUFBQUFBQUFBgwMDx4eDxUP
MhVWMjJWMpRlrWWtZeFllK1l4DJWMlgVLxUvLy8KFQoVEAgQCBoIEAoQCBAbET0RGgoiJkMOciZkDmRbQ5pDmmQDAwMDAwMDAwMDAwMDAwMDAgICAgQH
CQcHBwcHBwcJBwUFBQUFBgYGBgYMBgYFBQUFBQUFBQUGBhQUFB4eMh4yHh4eHjIeMh5WnJScZWVlZR5WHlYeVjJWFS8VFS8VChUbCBAIGggQCBAKGwoR
ESZiJj0mIgg5W3Jbv1tcJlxbZAMDAwMDAwMDAwMDAwMDAwMCAgIEBAcHBwcHBwcHBwcJCQkFCQsGBgYLBgYGCwYFBQkFCQkJCQkJCxQUFBQeFB4UHh4e
Mh4eFFYUMh4yHjIyHjIeVh5WHlYyLxUVChUKFRAIEA8QCBAIEAgKCBEIDiYOJg4RDhAOIltyW2Rbm+JkAwMDAwMDAwMDAwMDAwMDAwICAgIEBwcHBwcH
BwcHBwcJCQkJCQYGCwsLCwsLFAsLCQkJCQkJCQkJCwsUFBQUHhQUFBQeFB4UMhQyFB4eHjIeMh4yHlYeVjJWFRUKCAoVCggRDxsOGw4RDg4ODhIODhII
Eg4SCBIIEj0Ov5pkW2QDAwMDAwMDAwMDAwMDAwMDAwICAgQEBwcHBwcHBwcHBwcJCQUJCwYLFAsLCwsLCwsLCQkJCQkJCQkLCwsLCwsUCwsUCxQUFAse
Cx4UHhQeHhQeHjIUVh5WHhUVFS8VCg8bFRsPEA8IDw4MDhISFhISFgwGDAwOEggSCg5iW1ziZAMDAwMDAwMDAwMDAwMDAwMCAgICBAQHBwQEBwQEBwcH
BwcJCQkJCwsUCxQLCwsLCwsJCQkJCQkJCQkJCQkLCQsLCwsLCwsUCxQLFAsUCxQUFB4UMhQyHjIPFQ8VFQ8KCAoPCg8KDggODhISBhIGBgwGDAYPFggS
DhYIDAoOEZpkAwMDAwMDAwMDAwMDAwMDAwICAgIEBAQEBAQHBAQEBAcHBwkJCQkLCxQUFBQUCwsLCwsLCQkHCQkJCQkJCQkJCQkJBwkJCQsJCwkLCwsL
FBQUHhQyFDIUMh4yFRUIFQgOCg8KDwoPDhIOBgYGBgwMDAwMBgwGDwUSBg8GDhIODhEDAwMDAwMDAwMDAwMDAwMCAwICAgQEBAQEBAQEBAQEBAcHBwcJ
CQkLCxQUFBQLCwsLCwkJCQkHCQcHBwcHBwcHBwcHBwkJCQkLCQsJCwsUFBQeFB4UMh4yHhUPFRUVCA8KDwoPCAwSDBIGDAYGBQYGBQYGBgUGBQYFDAUG
BhIWDgMDAwMDAwMDAwMDAwMDAwICAgIEBAQEBAQEBAQEBAQEBAQHBwcJCQkLFAsLCwsLCwsJCQkJBwcHBwcHBwQEBAcHBwcHBwcJBwkHCwkLCxQUFBQU
HhQyFDIPFQ8VCBUKFQoPCg8IDBIGBgUWBgYGBgYGDAYMBgwGDAUMBQwGFgUWAwMDAwMDAwMDAwMDAwMDAgICAgQEBAQEBAQEBAIEBAQEBAQHBwcJCQkL
CwsLCwkJCQkJBwcHBAQEBAQEBAQEBAQEBAQHBwcHCQcJCQsLCwsLFBQyFB4eFR4VDxUVFRUPCg8RDw4MEgYWBQYGDAYGBgYMBQYFDAUGBQYFBgUGBQYD
AwMDAwMDAwMDAwMDAwMCAgICAgQEBAQEBAICAgQEBAQEBAQHBwcJCQkJCQkJCQcHBwcEBAQEBAQCAgICAgIEAgQEBAQEBAQJBwkJCwsLFAseFB4UHhQy
DxUPCBUVCA8KDyYODgwSBgYFDAUMBQYFBQUFBg0FDQYFBQ0FBQUFBQMDAwMDAwMDAwMDAwMDAgICBAQCBAQEBAQCAgICAgICAgICBAQHBwcJCQkJBwcH
BwcEBAQCAgICAgICAgICAgICAgICBAQHBAcHCQcJCwsUCxQLHhQyFB4PFQ8IFQ8KFSYOEQ4ODBYGBgUFBQUFDQ0FDQ0NDQ0NDQ0NDQUNBQ0FAwMDAwMD
AwMDAwMCAgICAgICBAICAgQEAgICAgICAgICAgICBAQHBwcHBwcHBwcEBAICAgIDAwMDAwMDAwMDAgMCAgIEBAQEBwcJCQkLCwsLFBQeFB4UDwwVDxUI
DwgICg8KDg4MBgUFBQUFBQUNDQ0NDQ0NDQ0NBw0NDQ0FBwUDAwMDAwMDAwMDAgICAgICAgICAgQCAgICAgICAgICAgICAgICBAQEBwcHBAQEBAQCAgID
AgMDAwMDAwMDAwMDAwMCAgQEBAQHBwkJCQkJCwsUCx4UHhQVDBUPFRUPCBUIDxEODgwGBQUFBQ0NDQ0NDQ0NIyMjBA0EBwcHBwcJCQMDAwMDAwMDAwIC
AgICAgICAgICAgICAgICAgICAgICAgICAgICAgQEBAQCAgQCAgIDAwMDAwMDAwAAAwMDAwMDAwICAgQEBAcHCQcJCQsLCwsLFAsPFA8UFQ8VFRUIFSYO
Cg8ODAYFBQUFDQ0NDQ0FBQ0NBAQEBAQHBwcHBwcHAwMDAwMDAwICAgICAgICAgICAgICAgICAgICAgIDAwICAgICAgICAgICAgICAwMDAwMAAAMAAAAA
AAAAAAMDAwMCAgICBAQEBwcJBwkJCwkLFAsUCw8UDwwPDxUPDwgPCA8KDw8MBgUFBQ0NBw0NBwcEBAcEBAQEBAQHBwcHBwcDAwMDAwICAgMCAgICAgIC
AgICAgICAwICAwMDAwMCAgICAgICAgICAgIDAgMDAwMAAAAAAAAAAAAAAAAAAAMDAwICAgQEBwcJBwkJCQkJCwkLCxQLFBQPFA8MDw8PDw8vDy8PDwwG
BQUHDQcHBwQEBAQEBAQEBAQEBAQEBwcHBwMDAwMCAwMCAgICAgICAgICAgICAgICAgIDAwICAgMDAwMDAwMDAwMDAwMDAwMAAwAAAAAAAAAAAAAAAAAA
AwMDAgICBAQHBwkJCQkJCQkJCQsJCwsUCw8UDxQPDB4VDxUPLx4eFAYJCQkHBwcHBwQEBAQEBAQEBAQEBAQHBwcHAwIDAwMDAwICAgICAgICAwMCAgID
AwMCAwMCAgMDAwICAwMDAwMDAwMDAAAAAAAAAAAAAAAAAAAAAAAAAAADAwMCAgIEBAcHBwkJCQkJCwkJCwkLCRQLDAsUFA8UHh4eMh4yHh4UFAsJBwcH
BwcHBAQEBAQEBAQEAgQEBAQHBwcDAgIDAwMCAgIDAwICAgMDAwMDAwICAwMCAwICAwMDAwMDAwMDAwMDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAwIC
BAQHBwkJCQsJCwkLCQkJCQsJCwkLCxQUFBQUHhQyHjIUHhQUCwkHBwcHBwQEBAQEBAICAgIEBAQEBAQHBwMDAwMCAgMCAwMCAwICAwMDAgIDAwMDAwMD
AgMDAwMDAwMDAwMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAwMCAgQEBwcJCQsLCwsUCwsLCQsJCwkLCQsLFAsUHh4eHjIeMh4eFBQLCQkJCQkHBwQE
BAQEAgQEBAQEBAQEBwcH]]
-- Text that will not fit scrolls instead of being cut off.
--
-- The string is drawn twice with a gap between the passes, so the loop reads as
-- a repeat rather than snapping back at the end. Overflow is hidden by the clip
-- rect the caller has already pushed Ã¢â‚¬â€ every call site clips its text column
-- anyway Ã¢â‚¬â€ so this only has to decide the offset.
local function flowing_text(font, x, y, limit, tint, text)
    local room = limit - x

    -- The flags slot is passed explicitly, empty.
    --
    -- render.measure_text is (font, [flags], text). Handed only two arguments
    -- the binding cannot tell the flags slot from the string, and the width
    -- comes back as zero â€” which reads as "this already fits" and is exactly
    -- why long titles were being clipped instead of scrolling.
    local width = 0
    local ok, measured = pcall(render.measure_text, font, "", text)
    if ok and measured and measured.x then width = measured.x end

    if width <= room or room <= 0 then
        render.text(font, vector(x, y), tint, nil, text)
        return
    end

    -- 36px of clear space between passes, so the tail of one and the head of
    -- the next never read as a single run-on string.
    local span = width + 36

    -- Each pass sits still at the start before moving, the way a car radio
    -- does: the beginning of a title is the part worth reading, and something
    -- permanently in motion is hard to catch.
    local speed = 27          -- px a second
    local hold = 2100         -- ms parked at the start of every pass

    local cycle = hold + ((span / speed) * 1000)
    local at = common.get_timestamp() % cycle

    -- Travelling exactly `span` puts the second copy where the first began, so
    -- the wrap back to zero is seamless.
    local offset = (at <= hold) and 0
        or math.min(span, ((at - hold) / 1000) * speed)

    render.text(font, vector(x - offset, y), tint, nil, text)
    render.text(font, vector(x - offset + span, y), tint, nil, text)
end

-- Cover transitions.
--
-- Two problems being solved together. A new track sets a new art URL some
-- hundreds of milliseconds before that image has downloaded, and the cover slot
-- fell back to the placeholder for exactly that long â€” a flash of the NL logo
-- between every song. And when the image did arrive it replaced the old one in
-- a single frame.
--
-- So the previous cover is held until the next has actually decoded, and then
-- the two are cross-faded.
local COVER = { shown = nil, prev = nil, url = nil, at = 0, gap = 0, ms = 260 }

-- Returns what to draw underneath, what to fade in over it, and how far that
-- fade has got.
--
-- The outgoing cover is drawn fully opaque and the incoming one over it at
-- rising alpha, which composites to new*t + old*(1-t) â€” a true cross-fade.
-- Fading both toward transparent instead would let the panel background show
-- through the middle of every transition.
local function cover_frames(idle_hue)
    local now = common.get_timestamp()
    local ready = (player.art_url ~= nil) and art_texture() or nil

    if player.art_url == nil then
        -- Spotify reports no item at all for a beat while it changes track, so
        -- a short gap is not the same as having stopped. Riding through it is
        -- half of what keeps the placeholder out of song changes.
        if COVER.gap == 0 then COVER.gap = now end

        if (now - COVER.gap) > 1500 then
            COVER.shown, COVER.prev, COVER.url = nil, nil, nil
        end
    else
        COVER.gap = 0

        if ready ~= nil and COVER.url ~= player.art_url then
            COVER.prev = COVER.shown or PH.image(idle_hue)
            COVER.shown = ready
            COVER.url = player.art_url
            COVER.at = now

            -- Says a texture actually reached the screen. A cover that is
            -- fetched and decoded but never shown looks identical in the log to
            -- one that was simply never fetched.
            log("art: now showing " .. tostring(player.art_url):sub(-12), true)
        end
    end

    local current = COVER.shown or PH.image(idle_hue)
    if COVER.prev == nil or current == nil then return current, nil, 1 end

    local mix = math.clamp((now - COVER.at) / COVER.ms, 0, 1)
    if mix >= 1 then
        COVER.prev = nil
        return current, nil, 1
    end

    return COVER.prev, current, mix
end

-- `opacity` is 0-255 and defaults to opaque. The menu bar passes its own fade
-- through, so the cover disappears with the rest of the bar instead of hanging
-- there at full strength and snapping out at the end.
local function draw_cover(url, x, y, size, rounding, outline, f, tint, idle_hue, opacity)
    opacity = opacity or 255

    -- The placeholder is built already rotated, so both it and real artwork are
    -- drawn plain. Nothing is multiplied here beyond that opacity: multiplying
    -- by a colour is what was turning white into the tint and the rest black.
    local texture, incoming, mix = cover_frames(idle_hue)

    if texture ~= nil then
        render.texture(texture, vector(x, y), vector(size, size),
            color(255, 255, 255, opacity), nil, rounding)

        if incoming ~= nil then
            render.texture(incoming, vector(x, y), vector(size, size),
                color(255, 255, 255, math.floor(mix * opacity)), nil, rounding)
        end
    else
        -- A plate with a note, so an idle player still reads as a player rather
        -- than as a broken box.
        render.rect(vector(x, y), vector(x + size, y + size),
            color(255, 255, 255, math.floor(16 * opacity / 255)), rounding)

        if f ~= nil then
            render.text(f.big, vector(x + size * 0.5, y + (size * 0.5) - (size * 0.28)),
                tint or color(255, 255, 255, 90), "c", "\u{266A}")
        end
    end

    if outline ~= nil then
        render.rect_outline(vector(x, y), vector(x + size, y + size), outline, 1, rounding)
    end
end

-- nil when a track is playing normally; otherwise the line to show in place of
-- the track details.
local function idle_message()
    if not is_connected() then
        return "Authenticate Spotify in the menu"
    end

    -- Only while actually backing off. Gating on the penalty rather than on the
    -- error alone means a single failed poll cannot flash a message over a track
    -- that is playing perfectly well, while a real block — which always carries
    -- a penalty — says so immediately.
    --
    -- This deliberately takes precedence over player.ok. Being blocked partway
    -- through a track otherwise leaves the last known track on screen with its
    -- progress bar running off the end, which is worse than saying nothing:
    -- it looks like it still works.
    if poll_penalty > 0 and last_poll_error ~= nil then
        return last_poll_error
    end

    if not player.ok then
        return "Nothing playing"
    end

    return nil
end

-- The large panel: cover, title, artist, album line, controls, progress.
local function draw_full(origin, ctx, theme, scale, max_width, opts, f)
    local pad = 16 * scale
    local W = math.min(max_width, 560 * scale)
    local H = (opts.controls and 168 or 132) * scale
    local cover = H - (pad * 2)

    local far = origin + vector(W, H)

    render.shadow(origin, far, theme.glow, 24 * scale, 0, 8)
    render.rect(origin, far, theme.container, 8)

    local tx = origin.x + pad
    if opts.cover then
        draw_cover(player.art_url, origin.x + pad, origin.y + pad, cover, 6, nil, f, theme.duration, theme.idle)
        tx = origin.x + pad + cover + (18 * scale)
    end

    local right = origin.x + W - pad

    local idle = idle_message()

    if idle ~= nil then
        render.push_clip_rect(vector(tx, origin.y), vector(right, origin.y + H))
        render.text(f.title, vector(tx, origin.y + (H * 0.5) - (16 * scale)), theme.title, nil, "Spotify")
        render.text(f.body, vector(tx, origin.y + (H * 0.5) + (4 * scale)), theme.duration, nil, idle)
        render.pop_clip_rect()
        return W, H
    end

    render.push_clip_rect(vector(tx, origin.y), vector(right, origin.y + H))

    flowing_text(f.big, tx, origin.y + (16 * scale), right, theme.title,
        (player.is_playing and "\u{266A} " or "\u{2016} ") .. player.title)

    flowing_text(f.body, tx, origin.y + (44 * scale), right, theme.artist, player.artist)

    local album_line = player.album
    if player.release ~= "" then
        album_line = album_line .. "  |  " .. player.release
    end
    render.text(f.small, vector(tx, origin.y + (66 * scale)), theme.duration, nil, album_line)

    render.pop_clip_rect()

    if opts.controls then
        -- Centred in the text column, not pinned to its left edge.
        control_row(ctx, (tx + right) * 0.5, origin.y + (106 * scale), 34 * scale, 13 * scale, theme.accent, false)
    end

    local bar_y = origin.y + H - (30 * scale)
    local time_w = 42 * scale
    local progress = progress_bar(ctx, tx + time_w, bar_y, right - time_w, 4 * scale,
        theme.bar1, theme.bar2, color(255, 255, 255, 30))

    if opts.duration then
        render.text(f.small, vector(tx, bar_y - (5 * scale)), theme.duration, nil, mmss(progress))
        render.text(f.small, vector(right, bar_y - (5 * scale)), theme.duration, "r", mmss(player.duration_ms))
    end

    return W, H
end

-- The compact bar: cover, title, artist, combined time, hairline progress.
local function draw_minimal(origin, ctx, theme, scale, max_width, opts, f)
    local pad = 8 * scale
    local W = math.min(max_width, 420 * scale)
    local H = 62 * scale
    local cover = H - (pad * 2)

    local far = origin + vector(W, H)

    -- Square, no corner rounding: the minimal style is meant to read as a hard
    -- rectangle, like the reference.
    render.rect(origin, far, theme.min_container, 0)

    local tx = origin.x + pad
    if opts.cover then
        draw_cover(player.art_url, origin.x + pad, origin.y + pad, cover, 0, theme.min_outline, f, theme.min_text, theme.idle)
        tx = origin.x + pad + cover + (12 * scale)
    end

    local right = origin.x + W - pad

    local idle = idle_message()
    if idle ~= nil then
        render.push_clip_rect(vector(tx, origin.y), vector(right, origin.y + H))
        render.text(f.title, vector(tx, origin.y + (12 * scale)), theme.min_text, nil, "Spotify")
        render.text(f.small, vector(tx, origin.y + (32 * scale)), theme.min_text:alpha_modulate(170), nil, idle)
        render.pop_clip_rect()
        return W, H
    end

    local text_limit = right - (72 * scale)

    render.push_clip_rect(vector(tx, origin.y), vector(text_limit, origin.y + H))
    flowing_text(f.title, tx, origin.y + (10 * scale), text_limit, theme.min_text, player.title)
    flowing_text(f.small, tx, origin.y + (30 * scale), text_limit,
        theme.min_text:alpha_modulate(170), player.artist)
    render.pop_clip_rect()

    local progress = current_progress()

    if opts.duration then
        render.text(f.body, vector(right, origin.y + (20 * scale)), theme.min_text, "r",
            mmss(progress) .. "/" .. mmss(player.duration_ms))
    end

    -- Hairline along the bottom edge, spanning the full panel. The track itself
    -- is transparent, so only the filled portion shows Ã¢â‚¬â€ a bar that stopped at
    -- 55% of the width made a finished song look half played.
    progress_bar(ctx, origin.x, origin.y + H - (4 * scale), origin.x + W, 4 * scale,
        theme.bar1, theme.bar2, color(0, 0, 0, 0))

    return W, H
end

-- Docked under the Neverlose menu, spanning its width. Only meaningful while
-- the menu is open, so it fades with it.
local function draw_menubar(ctx, theme, opts, f)
    local menu_pos = ui.get_position()
    local menu_size = ui.get_size()
    local alpha = ui.get_alpha() or 0

    if alpha <= 0 then return end

    local H = opts.height or 78
    -- Flush against the menu, no gap.
    local origin = vector(menu_pos.x, menu_pos.y + menu_size.y)
    local W = menu_size.x

    -- Everything above the progress strip is centred in the space that's left,
    -- so the bar can be resized without the contents drifting.
    local strip = 18
    local mid = origin.y + ((H - strip) * 0.5)
    local far = origin + vector(W, H)

    -- ui.get_alpha() tops out a hair under 1 while the menu settles, which is
    -- enough to leave a container set to full alpha faintly see-through. Treat
    -- the top of the range as fully open, so max opacity really is opaque.
    local a01 = (alpha >= 0.99) and 1 or alpha

    local fade = math.floor(255 * a01)
    local container_a = math.floor((theme.container.a or 255) * a01)

    render.rect(origin, far, theme.container:alpha_modulate(container_a), 4)

    local pad = 8
    local cover = H - (pad * 2)

    if opts.cover then
        draw_cover(player.art_url, origin.x + pad, origin.y + pad, cover, 3, nil, f,
            theme.duration:alpha_modulate(fade), theme.idle, fade)
    end

    local tx = origin.x + pad + (opts.cover and (cover + 12) or 0)

    -- Geometry shared by the volume row and the progress row, so the two line
    -- up. The progress bar stops short of the right edge to leave room for the
    -- remaining-time text; the volume bar ends at the same x, and the speaker
    -- sits out in that same margin.
    local time_w = opts.duration and 40 or 0

    -- Both rails stop at the same x so the volume bar and the progress bar line
    -- up. The speaker then sits out in the margin the remaining-time text
    -- occupies on the row below Ã¢â‚¬â€ far enough that the bar's end never runs into
    -- it, which it did when the icon sat only 16px clear.
    --
    -- With duration switched off that margin is zero, and the speaker was
    -- landing 22px past the right edge of the bar, outside it entirely. So the
    -- margin is whichever is wider: the time column, or room for the icon.
    local right_margin = time_w
    if opts.volume and right_margin < 34 then right_margin = 34 end

    local rail_right = origin.x + W - pad - right_margin
    local vol_left = rail_right - 118
    local speaker_x = rail_right + 22

    -- Text may run right up to whatever comes next, rather than stopping at an
    -- arbitrary fraction of the width. Previously it clipped at 32% and cut
    -- titles that had plenty of room left.
    local text_limit = origin.x + W - pad
    if opts.controls then
        -- Leftmost control is the shuffle button at centre - 2*spacing, minus
        -- its click radius.
        text_limit = math.min(text_limit, (origin.x + W * 0.5) - 64 - 16 - 10)
    elseif opts.volume then
        text_limit = math.min(text_limit, vol_left - 12)
    end

    local idle = idle_message()

    local title_y = mid - 17
    local artist_y = mid + 2

    render.push_clip_rect(vector(tx, origin.y), vector(text_limit, origin.y + H))
    if idle ~= nil then
        render.text(f.body, vector(tx, title_y), theme.text:alpha_modulate(fade), nil, "Spotify")
        render.text(f.small, vector(tx, artist_y),
            theme.text:alpha_modulate(math.floor(fade * 0.62)), nil, idle)
    else
        flowing_text(f.body, tx, title_y, text_limit,
            theme.text:alpha_modulate(fade), player.title)
        flowing_text(f.small, tx, artist_y, text_limit,
            theme.text:alpha_modulate(math.floor(fade * 0.62)), player.artist)
    end
    render.pop_clip_rect()

    -- Controls and progress mean nothing with no track, so an idle bar shows
    -- just the identity and the reason.
    if idle ~= nil then return end

    -- `mid` is already the centre of the region above the progress strip; the
    -- -4 nudges that used to be here were lifting the whole row off centre on
    -- top of whatever the glyphs were doing.
    if opts.controls then
        control_row(ctx, origin.x + W * 0.5, mid, 32, 12, theme.accent:alpha_modulate(fade), false)
    end

    if opts.volume then
        volume_bar(ctx, vol_left, mid - 2, rail_right, theme.accent:alpha_modulate(fade))
        g_speaker(speaker_x, mid, 11, theme.text:alpha_modulate(fade))
    end

    -- Elapsed left, negative remaining right, as in the reference.
    local bar_y = origin.y + H - strip + 4

    local progress = progress_bar(ctx, tx + time_w, bar_y, rail_right, 4,
        theme.accent:alpha_modulate(fade), theme.accent:alpha_modulate(fade),
        color(255, 255, 255, math.floor(28 * a01)))

    if opts.duration then
        local time_tint = theme.duration:alpha_modulate(math.floor(fade * 0.85))
        -- -7 rather than -5: the glyphs sat a touch below the bar's centreline.
        render.text(f.small, vector(tx, bar_y - 7), time_tint, nil, mmss(progress))
        render.text(f.small, vector(origin.x + W - pad, bar_y - 7), time_tint, "r",
            remaining(progress, player.duration_ms))
    end
end

--------------------------------------------------------------------------------
-- menu
--------------------------------------------------------------------------------

-- Distinct `tab` strings become the pages along the top. THREE tabs render as
-- buttons; a fourth collapses the lot into a dropdown, which is why HUD player
-- and Menu bar share "Settings" rather than getting a page each.
ui.sidebar("Spotify.lua", "music")

-- Tab titles carry a Font Awesome icon, the way the built-in pages and the
-- shipped marketplace scripts do: ui.get_icon returns the glyph as a string and
-- it is simply concatenated into the title. `\a{Link Active}` tints the icon
-- from the user's own Neverlose theme, so it matches whatever they run, and
-- `\aDEFAULT` puts the label text back to the normal colour.
--
-- Renaming a tab orphans every setting stored under it, so these are final.
--
-- One table rather than three locals: a Lua chunk may declare only 200 of those
-- and this one is at the ceiling.
local TAB = {
    AUTH     = "\a{Link Active}" .. ui.get_icon("lock") .. "\aDEFAULT  Auth",
    SETTINGS = "\a{Link Active}" .. ui.get_icon("gear") .. "\aDEFAULT  Settings",
    MISC     = "\a{Link Active}" .. ui.get_icon("tag") .. "\aDEFAULT  Misc",
}

--- Auth page ------------------------------------------------------------------

-- Two label lines that get rewritten in place. Whether the connection actually
-- worked used to be answerable only by opening the console, or by waiting to
-- see whether the player drew anything -- neither is something to ask of
-- someone who has just finished pasting a Client ID.
local function auth_status(first, second)
    if UI.auth_a ~= nil then UI.auth_a:name(first or "") end
    if UI.auth_b ~= nil then UI.auth_b:name(second or "") end
end

local function check_auth()
    if client_id() == "" then
        auth_status("No Client ID set.", "Paste it below, then press Connect.")
        return
    end

    if not is_connected() then
        auth_status("Not connected.", "Press Connect Spotify.")
        return
    end

    auth_status("Checking...", "")

    with_token(function()
        network.get("https://api.spotify.com/v1/me",
            { Authorization = "Bearer " .. session.access_token },
            function(body)
                local ok, me = pcall(json.parse, body)

                if not ok or type(me) ~= "table" or me.id == nil then
                    auth_status("Spotify rejected the token.",
                        "Press Connect Spotify and approve again.")
                    return
                end

                local who = me.display_name or me.id

                -- Record what came back, not just report it: the tier decides
                -- whether the transport controls are live, so a status check
                -- that noticed a change and kept it to itself would leave the
                -- buttons contradicting the line right above them.
                session.display_name = who
                session.product = me.product

                -- Free accounts authenticate fine and then 403 on every
                -- control, so saying "connected" alone would be misleading.
                if me.product == "premium" then
                    auth_status("Connected as " .. who .. ".", "Premium: controls work.")
                else
                    auth_status("Connected as " .. who .. ".",
                        "Free account: track info only, controls blocked.")
                end
            end)
    end)
end

-- Left column is the disclaimer and then the account controls; the setup walk-
-- through sits on its own on the right. Groups stack in the order they are
-- created within a column, so this must come before "Spotify account".
--
-- Labels do not wrap, so the text is broken by hand at roughly the width of the
-- longest step in the walkthrough.
local disclaimer = ui.create(TAB.AUTH, "DISCLAIMER", 1)
disclaimer:label("Spotify Premium is required for")
disclaimer:label("app creation and for controlling")
disclaimer:label("Spotify, but 5 non-Premium users")
disclaimer:label("can be added to the app and get")
disclaimer:label("their own track info by using the")
disclaimer:label("same Client ID.")

local howto = ui.create(TAB.AUTH, "Setup", 2)
howto:label("1. developer.spotify.com/dashboard")
howto:button("Copy dashboard link", function()
    if set_clipboard("https://developer.spotify.com/dashboard") then
        auth_status("Dashboard link copied.", "Paste it into your browser.")
    else
        auth_status("Could not reach the clipboard.", "Type the address in by hand.")
    end
end)
howto:label("2. Create app, name it anything")
howto:label("3. Redirect URI must be exactly:")
howto:label("   " .. REDIRECT_URI)
howto:button("Copy redirect URI", function()
    if set_clipboard(REDIRECT_URI) then
        auth_status("Redirect URI copied.", "Paste it into the Spotify dashboard.")
    else
        auth_status("Could not reach the clipboard.", "Type the URI in by hand.")
    end
end)
howto:label("4. Tick Web API, then save")
howto:label("5. Copy the Client ID across")
howto:label("6. Press Connect and approve")
howto:label("   in your browser")

local setup = ui.create(TAB.AUTH, "Spotify account", 1)

UI.id_input = setup:input("Client ID", auth.client_id or "")
UI.id_input:set_callback(function(item)
    auth.client_id = item:get()
    save()
end)

setup:button("Connect Spotify", function()
    local ok, why, detail = connect()

    if ok == false then
        auth_status(why, detail)
    else
        auth_status("Approve access in your browser,", "then press Check auth status.")
    end
end)
setup:button("Refresh token now", function() refresh() end)
setup:button("Check auth status", check_auth)
setup:button("Disconnect", function()
    disconnect()
    auth_status("Disconnected.", "")
end, true)

UI.auth_a = setup:label("")
UI.auth_b = setup:label("")

auth_status(
    is_connected() and "Saved login found." or "Not connected.",
    is_connected() and "Press Check auth status to confirm." or "Paste a Client ID and press Connect."
)

--- Settings page, left column: HUD player -------------------------------------

local window = ui.create(TAB.SETTINGS, "HUD player", 1)

UI.opt_enable    = window:switch("Enable", false)
UI.opt_minimal   = window:switch("Minimalist style", false)
-- Default off. On, combined with entity.get_local_player() returning nil
-- anywhere outside a live round, this hides the player with no indication why.
UI.opt_hide_menu = window:switch("Hide in main menu", false)
UI.opt_cover     = window:switch("Cover art", true)
UI.opt_duration  = window:switch("Show duration", true)
UI.opt_controls  = window:switch("Show controls", true)

local layout = ui.create(TAB.SETTINGS, "HUD player layout", 1)

-- The two styles size independently. They are different shapes -- a 560x136
-- panel against a 420x62 strip -- so one set of numbers cannot suit both, and
-- sharing them meant re-tuning every time the style was switched. Only the set
-- belonging to the active style is shown.
UI.opt_scale     = layout:slider("Scale", 50, 200, 85, 1, "%")
UI.opt_textscale = layout:slider("Text scale", 50, 200, 150, 1, "%")
UI.opt_maxwidth  = layout:slider("Max width", 260, 900, 600)

UI.min_scale     = layout:slider("Minimalist scale", 50, 200, 115, 1, "%")
UI.min_textscale = layout:slider("Minimalist text scale", 50, 200, 150, 1, "%")
UI.min_maxwidth  = layout:slider("Minimalist max width", 200, 900, 400)

-- Position stays shared: it is about where on the screen you want the player,
-- which does not change with how it is drawn. Top-left by default, since that
-- is a corner rather than an arbitrary offset.
UI.opt_x         = layout:slider("Position X", 0, 2560, 0)
UI.opt_y         = layout:slider("Position Y", 0, 1440, 0)

local colours = ui.create(TAB.SETTINGS, "HUD player color", 1)

-- These match the fixed colours in hud_theme() exactly, so turning Custom
-- colors on changes nothing until something is actually moved.
UI.col_custom     = colours:switch("Custom colors", false)
UI.col_title      = colours:color_picker("Title color", color(255, 255, 255))
UI.col_artist     = colours:color_picker("Artist color", color(210, 200, 220))
UI.col_duration   = colours:color_picker("Duration color", color(165, 155, 180))
UI.col_container  = colours:color_picker("Container color", color(7, 20, 33, 247))
UI.col_bar1       = colours:color_picker("Progressbar1 color", color(10, 20, 32))
UI.col_bar2       = colours:color_picker("Progressbar2 color", color(61, 133, 224))
UI.col_min_text   = colours:color_picker("Minimalist text color", color(255, 255, 255))
UI.col_min_bg     = colours:color_picker("Minimalist container color", color(3, 13, 26))
UI.col_min_line   = colours:color_picker("Minimalist outline color", color(252, 252, 252))

-- The soft glow behind the full panel. It used to be driven by Progressbar2,
-- which meant the two could never be set apart; this keeps that colour as its
-- default so nothing looks different until it is moved.
UI.col_glow       = colours:color_picker("Glow color", color(61, 133, 224))

-- Multiplies the placeholder image, so it can be knocked back or pulled toward
-- the theme. White leaves it exactly as it is; the alpha channel dims it.
UI.opt_idle_hue   = colours:slider("Nothing playing hue", 0, 355, 0, 5, " deg")

--- Settings page, right column: menu bar --------------------------------------

local barmenu = ui.create(TAB.SETTINGS, "Menu bar", 2)

UI.bar_enable    = barmenu:switch("Enable", false)
UI.bar_controls  = barmenu:switch("Controls", true)
UI.bar_volume    = barmenu:switch("Volume slider", true)
UI.bar_cover     = barmenu:switch("Cover art", true)
UI.bar_duration  = barmenu:switch("Show duration", true)
UI.bar_height    = barmenu:slider("Height", 56, 110, 90)
UI.bar_textscale = barmenu:slider("Text scale", 50, 200, 168, 1, "%")

local barcolours = ui.create(TAB.SETTINGS, "Menu bar color", 2)

-- Its own toggle: the bar and the HUD player are themed independently.
UI.bar_custom     = barcolours:switch("Custom colors", false)
UI.col_bar_bg     = barcolours:color_picker("Container color", color(8, 17, 30))
UI.col_bar_text   = barcolours:color_picker("Text color", color(255, 255, 255))
UI.col_bar_time   = barcolours:color_picker("Duration color", color(189, 189, 189))
UI.col_bar_accent = barcolours:color_picker("Accent color", color(61, 133, 224))
UI.bar_idle_hue   = barcolours:slider("Nothing playing hue", 0, 355, 0, 5, " deg")

--- Misc page ------------------------------------------------------------------

local misc = ui.create(TAB.MISC, "Clantag", 1)

UI.opt_clantag = misc:switch("Enable", false)
-- Options kept in Lua as well as handed to the combo, so a selection can be
-- resolved back to its label without asking the API what the list was.
--
-- Named as well as listed. The comparisons used to be against src_options[1]
-- and [2], which is the kind of positional coupling that silently inverts the
-- moment the list is reordered â€” as it is here, to make the signature the
-- default choice.
UI.SRC_SIGNATURE   = "Spotify.lua"
UI.SRC_TRACK       = "Now playing"
UI.src_options     = { UI.SRC_SIGNATURE, UI.SRC_TRACK }
UI.content_options = { "Title", "Artist", "Title - Artist", "Artist - Title" }

UI.tag_source  = misc:combo("Clantag style", UI.src_options[1], UI.src_options[2])
UI.tag_content = misc:combo("Show", UI.content_options[1], UI.content_options[2],
    UI.content_options[3], UI.content_options[4])
-- Anything above ~3 is unreadable on a clan tag.
UI.tag_speed   = misc:slider("Speed", 1, 3, 2, 1, " fps")
UI.tag_width   = misc:slider("Width", 4, 15, 15, 1, " chars")
UI.tag_fallback = misc:switch("Spotify.lua when nothing playing", true)

local diagnostics = ui.create(TAB.MISC, "Diagnostics", 1)

-- Routine chatter goes to the console only while this is on. Failures always
-- log, so leaving it off never hides a problem.
UI.opt_debug = diagnostics:switch("Debug logging", false)

-- Only surface settings that currently do something. Rebuilt whenever anything
-- that gates another control changes.
local function refresh_visibility()
    local on = UI.opt_enable:get()
    local minimal = UI.opt_minimal:get()
    local bar = UI.bar_enable:get()

    UI.opt_minimal:visibility(on)
    UI.opt_hide_menu:visibility(on)
    UI.opt_cover:visibility(on)
    UI.opt_duration:visibility(on)
    UI.opt_controls:visibility(on and not minimal)

    -- Only the active style's sizing. Showing both sets means half the sliders
    -- on screen do nothing, with no indication which half.
    UI.opt_scale:visibility(on and not minimal)
    UI.opt_textscale:visibility(on and not minimal)
    UI.opt_maxwidth:visibility(on and not minimal)

    UI.min_scale:visibility(on and minimal)
    UI.min_textscale:visibility(on and minimal)
    UI.min_maxwidth:visibility(on and minimal)

    UI.opt_x:visibility(on)
    UI.opt_y:visibility(on)

    UI.bar_controls:visibility(bar)
    UI.bar_volume:visibility(bar)
    UI.bar_cover:visibility(bar)
    UI.bar_duration:visibility(bar)
    UI.bar_height:visibility(bar)
    UI.bar_textscale:visibility(bar)

    -- With custom colours off the accent comes from the album cover, so none of
    -- that side's pickers apply. The two sides toggle independently.
    local hud_custom = UI.col_custom:get() and on
    local full_colours = hud_custom and not minimal
    local min_colours = hud_custom and minimal

    UI.col_custom:visibility(on)
    UI.col_title:visibility(full_colours)
    UI.col_artist:visibility(full_colours)
    UI.col_duration:visibility(full_colours)
    UI.col_container:visibility(full_colours)

    -- Both styles draw a progress bar, so these belong to neither alone.
    UI.col_bar1:visibility(hud_custom)
    UI.col_bar2:visibility(hud_custom)

    UI.col_glow:visibility(full_colours)
    UI.col_min_text:visibility(min_colours)
    UI.col_min_bg:visibility(min_colours)
    UI.col_min_line:visibility(min_colours)

    -- The placeholder is drawn by both styles, so it follows the group's own
    -- toggle rather than either style's.
    UI.opt_idle_hue:visibility(hud_custom)

    local bar_colours = UI.bar_custom:get() and bar

    UI.bar_custom:visibility(bar)
    UI.col_bar_bg:visibility(bar_colours)
    UI.col_bar_text:visibility(bar_colours)
    UI.col_bar_time:visibility(bar_colours)
    UI.col_bar_accent:visibility(bar_colours)
    UI.bar_idle_hue:visibility(bar_colours)

    -- Clantag: only surface the options the chosen source and animation use.
    local tag_on = UI.opt_clantag:get()
    local source = combo_label(UI.tag_source, UI.src_options)

    local now_playing = source == UI.SRC_TRACK

    UI.tag_source:visibility(tag_on)

    -- The signature animates on fixed frames at a fixed rate so that it stays
    -- in step between users, so none of these apply to it.
    UI.tag_content:visibility(tag_on and now_playing)
    UI.tag_width:visibility(tag_on and now_playing)
    UI.tag_speed:visibility(tag_on and now_playing)
    UI.tag_fallback:visibility(tag_on and now_playing)
end

for _, item in ipairs({
    UI.opt_enable, UI.opt_minimal, UI.bar_enable, UI.col_custom, UI.bar_custom,
    UI.opt_clantag, UI.tag_source,
}) do
    item:set_callback(refresh_visibility)
end


-- Switching the tag off clears it on the next frame: update_clantag sees the
-- switch is off and pushes an empty tag once.

UI.opt_enable:set_callback(function(item)
    refresh_visibility()
    set_polling(item:get() or UI.bar_enable:get())
end)

UI.bar_enable:set_callback(function(item)
    refresh_visibility()
    set_polling(item:get() or UI.opt_enable:get())
end)

-- Callbacks fire on interaction and nothing else. Neither script load nor a
-- config switch fires them, so anything derived from a menu value has to be
-- recomputed by hand or it silently goes stale.
local function sync_from_menu()
    refresh_visibility()

    local wanted = UI.opt_enable:get() or UI.bar_enable:get()

    -- Only on an actual change. set_polling bumps the generation every call,
    -- so re-asserting the state it is already in would abandon the running
    -- chain and start a fresh one -- and a config switch landing mid-request
    -- would leave that in-flight callback writing into a generation nothing
    -- reads any more.
    if wanted ~= polling then
        set_polling(wanted)
    end
end

sync_from_menu()

-- Switching Neverlose configs restores every menu value without firing a
-- single callback, and without re-running this chunk. Without this hook the
-- player just stops: the switches still read "on", auth still reports
-- connected because it lives in db rather than in the config, and yet nothing
-- polls, so player.ok stays false and nothing draws. Reported from a live
-- session -- changed config, changed back, empty player, "authed".
events.config_state:set(function(state)
    if state == "post_load" then
        sync_from_menu()
    end
end)

--------------------------------------------------------------------------------
-- theme
--------------------------------------------------------------------------------

-- Two independent themes, each with its own Custom colors toggle.
--
-- The fixed colours below are the shipped look, picked to sit with Neverlose's
-- own theme. They are duplicated in the colour pickers' defaults on purpose:
-- switching Custom colors on must not change how anything looks, it should just
-- hand over the controls.
--
-- `accent` is the bright end of the progress gradient, not the dark end. It
-- tints the transport icons and the volume fill, so taking it from bar1 â€” which
-- is the near-black start of the gradient â€” made them almost invisible.

local function hud_theme()
    if UI.col_custom:get() then
        return {
            accent        = UI.col_bar2:get(),
            title         = UI.col_title:get(),
            artist        = UI.col_artist:get(),
            duration      = UI.col_duration:get(),
            container     = UI.col_container:get(),
            bar1          = UI.col_bar1:get(),
            bar2          = UI.col_bar2:get(),
            min_text      = UI.col_min_text:get(),
            min_container = UI.col_min_bg:get(),
            min_outline   = UI.col_min_line:get(),
            glow          = UI.col_glow:get(),
            idle          = UI.opt_idle_hue:get(),
        }
    end

    return {
        accent        = color(61, 133, 224),
        title         = color(255, 255, 255),
        artist        = color(210, 200, 220),
        duration      = color(165, 155, 180),
        container     = color(7, 20, 33, 247),
        bar1          = color(10, 20, 32),
        bar2          = color(61, 133, 224),
        min_text      = color(255, 255, 255),
        min_container = color(3, 13, 26),
        min_outline   = color(252, 252, 252),
        glow          = color(61, 133, 224),
        idle          = 0,
    }
end

local function bar_theme()
    if UI.bar_custom:get() then
        return {
            container = UI.col_bar_bg:get(),
            text      = UI.col_bar_text:get(),
            duration  = UI.col_bar_time:get(),
            accent    = UI.col_bar_accent:get(),
            idle      = UI.bar_idle_hue:get(),
        }
    end

    return {
        container = color(8, 17, 30),
        text      = color(255, 255, 255),
        duration  = color(189, 189, 189),
        accent    = color(61, 133, 224),
        idle      = 0,
    }
end

--------------------------------------------------------------------------------
-- clantag
--------------------------------------------------------------------------------

--------------------------------------------------------------------------------
-- sidebar name
--
-- "\aRRGGBB" before a character sets its colour, so a gradient is built one
-- character at a time and the whole string handed to ui.sidebar. Sweeping the
-- phase with the clock and re-calling ui.sidebar animates it Ã¢â‚¬â€ the same
-- approach the shipped scripts use for their own sidebar entries.
--------------------------------------------------------------------------------

local SIDEBAR_NAME = "Spotify.lua"
local SIDEBAR_ICON = "music"

-- Fixed identity. The name always sweeps between these two greens; not a
-- setting, and not intended to become one.
local SIDEBAR_A = color("20FF00FF")
local SIDEBAR_B = color("144428FF")

-- Cycles of the wave across the whole word. Under one, so the sweep reads as a
-- single band travelling through the name rather than a ripple.
local SIDEBAR_WAVE = 3.0

local sidebar_last = 0

local function update_sidebar()
    -- ~20fps is plenty for a sweep this size and keeps it off the hot path.
    local now = common.get_timestamp()
    if (now - sidebar_last) < 50 then return end
    sidebar_last = now

    local phase = (now / 1000) * 2.4
    local length = #SIDEBAR_NAME

    local out = {}
    for i = 1, length do
        local along = (i - 1) / math.max(1, length - 1)
        local weight = (math.sin((along * SIDEBAR_WAVE) - phase) + 1) * 0.5
        -- to_hex() returns RRGGBBAA. Emitting only six digits makes the parser
        -- swallow the next two characters as part of the colour and spill the
        -- remainder as literal text.
        out[#out + 1] = string.format("\a%s%s",
            SIDEBAR_A:lerp(SIDEBAR_B, weight):to_hex(), SIDEBAR_NAME:sub(i, i))
    end

    pcall(ui.sidebar, table.concat(out), SIDEBAR_ICON)
end

local clantag_shown = nil

-- Track titles are frequently non-Latin, and byte slicing would cut multibyte
-- characters in half and emit garbage. Everything below works on characters.
local function utf8_chars(s)
    local chars = {}
    local i = 1

    while i <= #s do
        local b = s:byte(i)
        local width = 1
        if b >= 240 then width = 4
        elseif b >= 224 then width = 3
        elseif b >= 192 then width = 2 end

        chars[#chars + 1] = s:sub(i, i + width - 1)
        i = i + width
    end

    return chars
end

local function chars_sub(chars, from, count)
    local out = {}
    for i = from, from + count - 1 do
        out[#out + 1] = chars[i] or ""
    end
    return table.concat(out)
end

-- The game caps clan tags in BYTES, not characters, and truncates without
-- regard for encoding. A multibyte character cut in half is invalid UTF-8 and
-- renders as a replacement diamond Ã¢â‚¬â€ which is why a tag containing "Ã¢â„¢Â«" (3
-- bytes) or "ÃƒÂ¡" (2) breaks while scrolling but looks fine on its own.
--
-- So the last thing that happens to any tag is dropping whole characters until
-- it fits the byte budget.
local CLANTAG_MAX_BYTES = 15

local function fit_bytes(s, max)
    if #s <= max then return s end

    local out, used = {}, 0
    for _, c in ipairs(utf8_chars(s)) do
        if used + #c > max then break end
        out[#out + 1] = c
        used = used + #c
    end

    return table.concat(out)
end

-- The whole trick behind tags that line up between players: nothing is sent
-- anywhere. Every client derives the frame from the server's own tick number,
-- which the server hands to all of them alike.
--
-- The latency term that used to be added here has been removed. Everyone on a
-- server is simulating the same tick stream, so their tickcounts already agree
-- to within a tick or two â€” around 15-30ms. Adding each client's own ping put
-- the *difference* between their pings back into the result, which on a mixed
-- lobby is far larger than the error it was meant to correct. At 6 fps a frame
-- lasts 166ms, so untouched tick numbers land everyone on the same frame and
-- ping compensation was actively pushing them apart.
--
-- Reasoned from how the tick stream works, not measured across two clients.
--
-- The server clock is used to set the PHASE, not read every frame. tickcount is
-- not a smooth clock: the engine retargets it during prediction, so consecutive
-- reads within one second can sit still and then jump. Deriving the animation
-- frame straight from it made the steps uneven.
--
-- So the difference between the server clock and the local one is tracked as a
-- slowly-moving offset, and the animation runs off the local clock plus that
-- offset. The local clock is smooth, and the offset still comes from the
-- server, so everyone lands on the same frame as before.
local tick_clock = { seen = nil, at = 0, offset = nil }

local function shared_frame(fps)
    local ok, tickcount = pcall(function() return globals.tickcount end)
    local got, interval = pcall(function() return globals.tickinterval end)

    local now = common.get_timestamp()
    local seconds = now / 1000

    if ok and got and tickcount and interval and interval > 0 then
        if tickcount ~= tick_clock.seen then
            tick_clock.seen = tickcount
            tick_clock.at = now
        end

        -- A valid tickinterval is not proof the clock is running. In the main
        -- menu, on the loading screen and while disconnected, tickinterval
        -- stays perfectly valid while tickcount sits still â€” so this branch was
        -- returning a constant and the tag froze mid-scroll. Only trust the
        -- server clock while it is demonstrably moving.
        if (now - tick_clock.at) < 1000 then
            local sample = (tickcount * interval) - seconds

            -- Snap on the first sample and on a real discontinuity (map change,
            -- reconnect); otherwise ease, so prediction jitter averages out
            -- instead of shunting the animation back and forth.
            if tick_clock.offset == nil or math.abs(sample - tick_clock.offset) > 2 then
                tick_clock.offset = sample
            else
                tick_clock.offset = tick_clock.offset + (sample - tick_clock.offset) * 0.02
            end

            return math.floor((seconds + tick_clock.offset) * fps)
        end
    end

    -- Nothing to sync with, so animate off the local clock alone and re-acquire
    -- the offset when a server clock comes back.
    tick_clock.offset = nil
    return math.floor(seconds * fps)
end

local TAG = {}
TAG.SIGNATURE = "Spotify.lua"
TAG.NOTE = "\u{266B} "

-- The signature tag is a hand-authored frame table, the way Neverlose's own is.
-- Each new character arrives in leet form and then resolves Ã¢â‚¬â€ 5 becomes s, 0
-- becomes o, |= becomes f Ã¢â‚¬â€ which reads as the word assembling itself rather
-- than as a plain typewriter.
--
-- Deliberately NOT configurable. Everyone running the script has to be on the
-- same frames at the same rate, or two people in a server never line up, and
-- syncing was the entire point of this tag.
TAG.FPS = 6

TAG.FRAMES = {
    "|",
    "5",
    "S",
    "S|>",
    "Sp",
    "Sp0",
    "Spo",
    "Spo7",
    "Spot",
    "Spot1",
    "Spoti",
    "Spoti|=",
    "Spotif",
    "Spotif`/",
    "Spotify",
    "Spotify.",
    "Spotify.|",
    "Spotify.l",
    "Spotify.l_|",
    "Spotify.lu",
    "Spotify.lu4",
    "Spotify.lua",
    "Spotify.lua",
    "Spotify.lua",
    "Spotify.lua",
    "Spotify.lua",
    "Spotify.lu4",
    "Spotify.lu",
    "Spotify.l_|",
    "Spotify.l",
    "Spotify.|",
    "Spotify.",
    "Spotify",
    "Spotif`/",
    "Spotif",
    "Spoti|=",
    "Spoti",
    "Spot1",
    "Spot",
    "Spo7",
    "Spo",
    "Sp0",
    "Sp",
    "S|>",
    "S",
    "5",
    "|",
    "",
    "",
}


local function clantag_text()
    -- Compared against the exact string the combo was built from, not against a
    -- second literal that merely looks the same. Two identical-looking strings
    -- failing to compare equal is what kept this branch unreachable, and this
    -- removes the possibility entirely.
    if combo_label(UI.tag_source, UI.src_options) == UI.SRC_SIGNATURE then
        return TAG.SIGNATURE, false
    end

    -- Now playing, with nothing playing: either the signature or nothing.
    if not player.ok then
        return (UI.tag_fallback:get() and TAG.SIGNATURE or ""), false
    end

    local which = combo_label(UI.tag_content, UI.content_options)
    local body

    if which == UI.content_options[1] then body = player.title
    elseif which == UI.content_options[2] then body = player.artist
    elseif which == UI.content_options[4] then body = player.artist .. " - " .. player.title
    else body = player.title .. " - " .. player.artist end

    -- The note marks where each pass begins, so the loop reads as
    -- "Ã¢â„¢Â« artist - song      Ã¢â„¢Â« artist - song" rather than one run-on string.
    return TAG.NOTE .. body, true
end

-- Track titles only ever scroll: the other modes existed for the signature,
-- which now has its own fixed frame table.
local function scroll_text(text, width, frame)
    local chars = utf8_chars(text)
    local n = #chars

    if n == 0 then return "" end

    -- Short titles scroll too. There used to be an early return here for
    -- anything that already fitted the window, which is why "â™« 6 For 6" sat
    -- perfectly still while the frame counter ticked happily along underneath
    -- it: nine characters into a fifteen-character window, so it never entered
    -- the scrolling path at all. The pass is meant to read the same either way
    -- â€” lead in, run through, clear out, blank beat, repeat.

    -- The title runs through the window, off the far side, and then the
    -- tag sits completely empty for a beat before the note leads the next pass
    -- back in.
    --
    -- The window only reads as empty once it fits entirely inside the run of
    -- spaces, so the gap has to be wider than the window itself. width + 2
    -- gives three fully blank frames Ã¢â‚¬â€ enough to register as a break, short
    -- enough not to look like the tag broke.
    local gap = width + 2

    local loop = {}
    for _, c in ipairs(chars) do loop[#loop + 1] = c end
    for _ = 1, gap do loop[#loop + 1] = " " end

    local total = #loop
    local offset = frame % total

    local out = {}
    for i = 0, width - 1 do
        out[#out + 1] = loop[((offset + i) % total) + 1]
    end
    return table.concat(out)
end

local function update_clantag()
    if not UI.opt_clantag:get() then
        -- Compared against "" rather than nil on purpose. `clantag_shown` starts
        -- as nil on every script load, so the old test skipped the clear
        -- whenever the script had not set a tag *this* session â€” which is
        -- exactly the case after a reload. A tag left behind by the previous
        -- session then stayed on screen forever, and turning the clantag off or
        -- reloading did nothing to shift it.
        if clantag_shown ~= "" then
            pcall(common.set_clan_tag, "")
            clantag_shown = ""
        end
        return
    end

    local text, is_track = clantag_text()

    local wanted = ""

    if not is_track then
        -- Signature: fixed frames, fixed rate, no settings. Anything adjustable
        -- here breaks the sync between users.
        if text ~= "" then
            local frame = shared_frame(TAG.FPS)
            wanted = TAG.FRAMES[(frame % #TAG.FRAMES) + 1] or TAG.SIGNATURE
        end
    elseif text ~= "" then
        wanted = scroll_text(text, UI.tag_width:get(), shared_frame(UI.tag_speed:get()))
    end

    wanted = fit_bytes(wanted, CLANTAG_MAX_BYTES)

    -- Clan tags are networked state. Only push when the frame actually changes,
    -- or this floods the server every tick.
    if wanted ~= clantag_shown then
        clantag_shown = wanted
        pcall(common.set_clan_tag, wanted)
        log("clantag -> '" .. wanted .. "'", true)
    end
end

--------------------------------------------------------------------------------
-- events
--------------------------------------------------------------------------------

local function in_main_menu()
    local ok, me = pcall(function() return entity.get_local_player() end)
    return not (ok and me ~= nil)
end

events.render:set(function()
    pump()
    bridge_pump()
    flush_volume()

    -- Turning fetched bytes into a texture is deferred here so every render.*
    -- call happens inside the render callback.
    if art_ready ~= nil then
        local ready = art_ready
        art_ready = nil

        -- Decode at the size we actually fetched. Claiming 640 for a 300px
        -- JPEG allocates a texture four times larger than the pixels in it.
        local px = (ready.px ~= nil and ready.px > 0) and ready.px or 640
        -- Checked before decoding, because load_image does not report this as a
        -- failure: it returns a texture that simply draws nothing. Greyscale
        -- covers go through our own decoder and in as raw RGBA instead.
        if JPEG.components(ready.data) == 1 then
            local pixels, w, h = JPEG.decode(ready.data)

            if pixels == nil then
                art_note_failure(ready.url, "greyscale decode: " .. tostring(w))
            else
                local ok, image = pcall(render.load_image_rgba, pixels, vector(w, h))

                if ok and image then
                    cache_art(ready.url, image)
                    log(("art: decoded %dx%d greyscale into a texture"):format(w, h), true)
                else
                    art_note_failure(ready.url, "load_image_rgba refused the greyscale buffer")
                end
            end
        else
            local ok, image = pcall(render.load_image, ready.data, vector(px, px))

            if ok and image then
                cache_art(ready.url, image)
                log(("art: decoded %spx into a texture"):format(tostring(px)), true)
            else
                art_note_failure(ready.url,
                    "load_image " .. (ok and "returned nothing" or ("threw: " .. tostring(image))))
            end
        end
    end

    update_sidebar()
    update_clantag()

    local want_window = UI.opt_enable:get()
    local want_bar = UI.bar_enable:get()

    if not (want_window or want_bar) then
        mouse_was_down = false
        drag.active = false
        volume_dragging = false
        return
    end

    -- Interaction only while the menu is open: otherwise the mouse is aiming
    -- and every shot would also press a button.
    local interactive = (ui.get_alpha() or 0) > 0

    -- With nothing playing the HUD player becomes a placeholder, which is
    -- useful while configuring and clutter the rest of the time. So show it
    -- idle only while the menu is open; the bar is menu-only anyway.
    if not player.ok and not interactive then
        mouse_was_down = false
        drag.active = false
        volume_dragging = false
        return
    end
    local held = interactive and common.is_button_down(1) and true or false

    local ctx = {
        mouse = ui.get_mouse_position(),
        held = held,
        clicked = held and not mouse_was_down,
        interactive = interactive,
        consumed = false,
    }

    -- The menu bar is only ever visible while the menu is open, so "hide in
    -- main menu" is meaningless for it and must not gate it.
    if want_bar then
        draw_menubar(ctx, bar_theme(), {
            controls = UI.bar_controls:get(),
            volume = UI.bar_volume:get(),
            cover = UI.bar_cover:get(),
            duration = UI.bar_duration:get(),
            height = UI.bar_height:get(),
        }, ensure_fonts("bar", UI.bar_textscale:get() / 100))
    end

    if want_window and UI.opt_hide_menu:get() and in_main_menu() then
        want_window = false
    end

    -- A drag cannot survive the thing being dragged going away. "Hide in main
    -- menu" stops the panel being drawn mid-drag, and the frames in between are
    -- simply skipped â€” so on return the first frame would compute a position
    -- from wherever the mouse had got to and teleport the panel there. Same for
    -- the volume slider when the bar stops drawing.
    if not want_window then drag.active = false end
    if not want_bar then volume_dragging = false end

    local theme = hud_theme()

    -- Each style reads its own sliders. ensure_fonts rebuilds when the scale it
    -- is handed changes, so switching styles picks up the other text scale.
    local minimal = UI.opt_minimal:get()
    local scale = (minimal and UI.min_scale or UI.opt_scale):get() / 100
    local max_width = (minimal and UI.min_maxwidth or UI.opt_maxwidth):get()

    if want_window then
        local f = ensure_fonts("hud",
            (minimal and UI.min_textscale or UI.opt_textscale):get() / 100)
        local origin = vector(UI.opt_x:get(), UI.opt_y:get())
        local moving = false

        if drag.active then
            -- The release frame moves the panel too. Bailing out here without
            -- reading the mouse threw away the last frame of movement, so a
            -- quick flick into a corner settled short of it and looked like the
            -- panel had bounced back.
            origin = ctx.mouse - drag.offset
            moving = true
            if not held then drag.active = false end
        end

        -- Clamped before drawing, not after, using the size measured last
        -- frame. Clamping afterwards let the panel render past the screen edge
        -- for a frame and then jump, which is the "bounce" itself.
        if moving then
            origin = snap_to_screen(origin, drag.w, drag.h)
        end

        local opts = {
            cover = UI.opt_cover:get(),
            duration = UI.opt_duration:get(),
            controls = UI.opt_controls:get() and not minimal,
        }

        local W, H
        if minimal then
            W, H = draw_minimal(origin, ctx, theme, scale, max_width, opts, f)
        else
            W, H = draw_full(origin, ctx, theme, scale, max_width, opts, f)
        end

        drag.w, drag.h = W, H

        if ctx.clicked and not ctx.consumed and not drag.active
            and inside(ctx.mouse, origin.x, origin.y, origin.x + W, origin.y + H) then
            drag.active = true
            drag.offset = ctx.mouse - origin
        end

        if moving then
            UI.opt_x:set(math.floor(origin.x))
            UI.opt_y:set(math.floor(origin.y))
        end
    end

    mouse_was_down = held
end)

events.shutdown:set(function()
    poll_generation = poll_generation + 1
    if clantag_shown ~= nil then pcall(common.set_clan_tag, "") end
    pcall(stop_listener)
    pcall(save)
end)

if is_connected() then
    log("connected ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â enable the player in the menu")
else
    log("not connected ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â press 'Connect Spotify'")
end






