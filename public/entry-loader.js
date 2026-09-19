
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

local function __ea_obviously_hooked(fn)
    if type(fn)~="function" then return false end
    local ok,result=pcall(function()
        if type(islclosure)=="function" and islclosure(fn) then return true end
        if type(iscclosure)=="function" then return not iscclosure(fn) end
        return false
    end)
    return ok and result==true
end

__ea_disable_clipboard()
`;
}

export function authenticatedLauncher(url, key = null) {
  return `${key === null ? '-- Set script_key to your license key before running.' : 'script_key=' + JSON.stringify(key)}
local e=(getgenv and getgenv()) or _G
local k=script_key or e.script_key
local function stop() pcall(function() game:GetService("Players").LocalPlayer:Kick("Blacklisted") end) end
if not k or tostring(k)=="" or tostring(k)=="KEY" then stop() return end
local h=game:GetService("HttpService")
local d
pcall(function() if type(gethwid)=="function" then d=gethwid() end end)
if not d or tostring(d)=="" then
    if readfile and writefile then
        local ok,v=pcall(readfile,"eternal_auth_device.txt")
        if ok and v and v~="" then d=v else d=h:GenerateGUID(false) pcall(writefile,"eternal_auth_device.txt",d) end
    end
end
if not d or tostring(d)=="" then stop() return end
local req=request or http_request or (syn and syn.request) or (http and http.request)
if not req then stop() return end
${clientHardeningLua()}
if __ea_obviously_hooked(loadstring) or __ea_obviously_hooked(req) then stop() return end
e.script_key=k
local ok,r=pcall(req,{Url=${JSON.stringify(url)},Method="GET",Headers={Authorization="Bearer "..tostring(k),["X-Eternal-Device"]=tostring(d),["X-Eternal-Execute"]="1"}})
if not ok or not r or tonumber(r.StatusCode or r.status_code)~=200 then stop() return end
local f=loadstring(r.Body or r.body or "")
if not f then stop() return end
f()`;
}

export function ffaLauncher(url) {
  return `-- Eternal Auth FFA loader (no key required)
local e=(getgenv and getgenv()) or _G
local h=game:GetService("HttpService")
local function stop() pcall(function() game:GetService("Players").LocalPlayer:Kick("Blacklisted") end) end
local d
pcall(function() if type(gethwid)=="function" then d=gethwid() end end)
if not d or tostring(d)=="" then
    if readfile and writefile then
        local ok,v=pcall(readfile,"eternal_auth_device.txt")
        if ok and v and v~="" then d=v else d=h:GenerateGUID(false) pcall(writefile,"eternal_auth_device.txt",d) end
    end
end
if not d or tostring(d)=="" then stop() return end
local req=request or http_request or (syn and syn.request) or (http and http.request)
if not req then stop() return end
${clientHardeningLua()}
if __ea_obviously_hooked(loadstring) or __ea_obviously_hooked(req) then stop() return end
local ok,r=pcall(req,{Url=${JSON.stringify(url)},Method="GET",Headers={["X-Eternal-Device"]=tostring(d),["X-Eternal-Execute"]="1"}})
if not ok or not r or tonumber(r.StatusCode or r.status_code)~=200 then stop() return end
local f=loadstring(r.Body or r.body or "")
if not f then stop() return end
f()`;
}
