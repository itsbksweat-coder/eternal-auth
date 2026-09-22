
function clientHardeningLua() {
  return `
local function __ea_client_envs()
    local out,seen={},{}
    local function add(v)
        if type(v)=="table" and not seen[v] then seen[v]=true table.insert(out,v) end
    end
    add(_G)
    pcall(function() if getgenv then add(getgenv()) end end)
    pcall(function() if getrenv then add(getrenv()) end end)
    pcall(function() if getfenv then add(getfenv(0)) end end)
    return out
end

local function __ea_disable_clipboard()
    local names={
        "setclipboard","toclipboard","writeclipboard","set_clipboard","write_clipboard",
        "setrbxclipboard","copyclipboard","clipboardset","setclip",
        "getclipboard","readclipboard","get_clipboard","read_clipboard","clipboardget","getclip"
    }
    local childNames={
        "set","write","copy","setclipboard","toclipboard","writeclipboard","set_clipboard","write_clipboard",
        "get","read","getclipboard","readclipboard","get_clipboard","read_clipboard","copyclipboard","setclip"
    }
    local disabled={}
    local function replace(tbl,name)
        pcall(function()
            local old=tbl[name]
            if type(old)~="function" then return end
            local noop=disabled[old]
            if not noop then
                noop=function(...) return nil end
                disabled[old]=noop
                disabled[noop]=noop
                if type(hookfunction)=="function" then pcall(hookfunction,old,noop) end
            end
            tbl[name]=noop
        end)
    end
    for _,env in ipairs(__ea_client_envs()) do
        for _,name in ipairs(names) do replace(env,name) end
        for _,tableName in ipairs({"clipboard","Clipboard","syn"}) do
            local t=env[tableName]
            if type(t)=="table" then
                for _,name in ipairs(childNames) do replace(t,name) end
            end
        end
    end
end

local __ea_blocked_logger_files={
    ["testestzen.txt"]=true,
    ["sabcom_hub.lua"]=true
}
local function __ea_blocked_path(path)
    local p=string.lower(tostring(path or "")):gsub("\\\\","/")
    local base=p:match("([^/]+)$") or p
    return __ea_blocked_logger_files[base]==true
end
local __ea_known_logger_file=false
local function __ea_guard_logger_files()
    for _,env in ipairs(__ea_client_envs()) do
        pcall(function()
            local rawIs=env.isfile
            if type(rawIs)=="function" then
                for name in pairs(__ea_blocked_logger_files) do
                    local ok,exists=pcall(rawIs,name)
                    if ok and exists then __ea_known_logger_file=true end
                end
            end
        end)
        for _,name in ipairs({"writefile","appendfile","readfile","isfile"}) do
            pcall(function()
                local old=env[name]
                if type(old)~="function" then return end
                if name=="isfile" then
                    env[name]=function(path,...)
                        if __ea_blocked_path(path) then return false end
                        return old(path,...)
                    end
                elseif name=="readfile" then
                    env[name]=function(path,...)
                        if __ea_blocked_path(path) then return "" end
                        return old(path,...)
                    end
                else
                    env[name]=function(path,...)
                        if __ea_blocked_path(path) then return nil end
                        return old(path,...)
                    end
                end
            end)
        end
    end
end

local function __ea_obviously_hooked(fn)
    if type(fn)~="function" then return false end
    local ok,result=pcall(function()
        if type(islclosure)=="function" and islclosure(fn) then return true end
        if type(iscclosure)=="function" then return not iscclosure(fn) end
        return false
    end)
    return ok and result==true
end

local function __ea_http_hook_score()
    local score=0
    local seen={}
    local function check(fn)
        if type(fn)=="function" and not seen[fn] then
            seen[fn]=true
            if __ea_obviously_hooked(fn) then score=score+1 end
        end
    end
    for _,env in ipairs(__ea_client_envs()) do
        check(env.request)
        check(env.http_request)
        check(env.httprequest)
        if type(env.syn)=="table" then check(env.syn.request) end
        if type(env.http)=="table" then check(env.http.request) end
    end
    return math.min(score,2)
end

local function __ea_websocket_hook_score()
    local score=0
    local seen={}
    local function checkTable(t)
        if type(t)~="table" or seen[t] then return end
        seen[t]=true
        for _,name in ipairs({"connect","Connect","new","New","Create"}) do
            local fn=t[name]
            if type(fn)=="function" and __ea_obviously_hooked(fn) then
                score=1
                return
            end
        end
    end
    for _,env in ipairs(__ea_client_envs()) do
        checkTable(env.WebSocket)
        checkTable(env.websocket)
        checkTable(env.Websocket)
        if type(env.syn)=="table" then
            checkTable(env.syn.websocket)
            checkTable(env.syn.WebSocket)
        end
    end
    return score
end

local __ea_spy_signatures={
    "http spy","http logger","httpspy","http_spy","httplogger",
    "websocket spy","websocket logger","ws spy","ws logger",
    "network logger","packet logger","source viewer","script viewer",
    "source dumper","script dumper","decompiler","hook spy","hookspy"
}
local function __ea_spy_env_detected()
    for _,env in ipairs(__ea_client_envs()) do
        local ok,found=pcall(function()
            for name,value in pairs(env) do
                local lowered=string.lower(tostring(name))
                for _,sig in ipairs(__ea_spy_signatures) do
                    if string.find(lowered,sig,1,true) and (type(value)=="function" or type(value)=="table") then
                        return true
                    end
                end
            end
            return false
        end)
        if ok and found then return true end
    end
    return false
end

local function __ea_hwid_spoofed()
    for _,env in ipairs(__ea_client_envs()) do
        for _,name in ipairs({"RbxGetIdentity","__Identify"}) do
            local ok,fn=pcall(function() return env[name] end)
            if ok and type(fn)=="function" then
                if __ea_obviously_hooked(fn) then return true end
                local okValue,value=pcall(fn)
                if okValue and type(value)=="string" and #value>=32 and value:match("^[a-fA-F0-9]+$") then
                    return true
                end
            end
        end
    end
    return false
end

__ea_guard_logger_files()
__ea_disable_clipboard()
`;
}

export function authenticatedLauncher(url, key = null) {
  return `${key === null ? '-- Set script_key to your license key before running.' : 'script_key=' + JSON.stringify(key)}
local e=(getgenv and getgenv()) or _G
local k=script_key or e.script_key
local function stop(msg)
    pcall(function()
        game:GetService("Players").LocalPlayer:Kick(tostring(msg or "Authentication failed."))
    end)
end
if not k or tostring(k)=="" or tostring(k)=="KEY" then stop("Missing script key") return end
local h=game:GetService("HttpService")
local legacyDevice
pcall(function()
    if type(gethwid)=="function" then
        local value=gethwid()
        if value and tostring(value)~="" then legacyDevice=tostring(value) end
    end
end)

-- Prefer Eternal Auth's own persisted device id. Some mobile executors expose
-- a gethwid() value that changes between launches.
local d
if readfile and writefile then
    local ok,v=pcall(readfile,"eternal_auth_device.txt")
    if ok and v and tostring(v)~="" then
        d=tostring(v)
    else
        d=h:GenerateGUID(false)
        pcall(writefile,"eternal_auth_device.txt",d)
    end
end
if not d or tostring(d)=="" then d=legacyDevice end
if not d or tostring(d)=="" then stop("Missing HWID") return end
local req=request or http_request or (syn and syn.request) or (http and http.request)
if type(req)~="function" then stop("HTTP request unavailable") return end
e.script_key=k
local ok,r=pcall(req,{
    Url=${JSON.stringify(url)},
    Method="GET",
    Headers={
        Authorization="Bearer "..tostring(k),
        ["X-Eternal-Device"]=tostring(d),
        ["X-Eternal-Legacy-Device"]=legacyDevice and tostring(legacyDevice) or "",
        ["X-Eternal-Execute"]="1"
    }
})
if not ok or not r then stop("Eternal Auth connection failed") return end
local code=tonumber(r.StatusCode or r.status_code or 0)
local body=r.Body or r.body or ""
if code~=200 then
    if string.find(tostring(body),"Blacklisted",1,true) then
        stop("Blacklisted")
    else
        local reason=tostring(body or "")
        if reason=="" then reason="HTTP "..tostring(code) end
        stop("Eternal Auth: "..reason)
    end
    return
end
if type(loadstring)~="function" then stop("loadstring unavailable") return end
local fn,err=loadstring(body)
pcall(function() r.Body="" r.body="" end)
body=nil
if type(fn)~="function" then error("Eternal Auth loader compile error: "..tostring(err),0) end
fn()`;
}
export function ffaLauncher(url) {
  return `-- Eternal Auth FFA loader (no key required)
local h=game:GetService("HttpService")
local function stop(msg)
    pcall(function()
        game:GetService("Players").LocalPlayer:Kick(tostring(msg or "Authentication failed."))
    end)
end
local d
if readfile and writefile then
    local ok,v=pcall(readfile,"eternal_auth_device.txt")
    if ok and v and tostring(v)~="" then
        d=tostring(v)
    else
        d=h:GenerateGUID(false)
        pcall(writefile,"eternal_auth_device.txt",d)
    end
end
if not d or tostring(d)=="" then
    pcall(function()
        if type(gethwid)=="function" then d=gethwid() end
    end)
end
if not d or tostring(d)=="" then stop("Missing HWID") return end
local req=request or http_request or (syn and syn.request) or (http and http.request)
if type(req)~="function" then stop("HTTP request unavailable") return end
local ok,r=pcall(req,{
    Url=${JSON.stringify(url)},
    Method="GET",
    Headers={
        ["X-Eternal-Device"]=tostring(d),
        ["X-Eternal-Execute"]="1"
    }
})
if not ok or not r then stop("Eternal Auth connection failed") return end
local code=tonumber(r.StatusCode or r.status_code or 0)
local body=r.Body or r.body or ""
if code~=200 then
    stop(string.find(body,"Blacklisted",1,true) and "Blacklisted" or ("Eternal Auth denied access ("..tostring(code)..")"))
    return
end
if type(loadstring)~="function" then stop("loadstring unavailable") return end
local fn,err=loadstring(body)
pcall(function() r.Body="" r.body="" end)
body=nil
if type(fn)~="function" then error("Eternal Auth loader compile error: "..tostring(err),0) end
fn()`;
}

