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
e.script_key=k
local ok,r=pcall(req,{Url=${JSON.stringify(url)},Method="GET",Headers={Authorization="Bearer "..tostring(k),["X-Eternal-Device"]=tostring(d)}})
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
local ok,r=pcall(req,{Url=${JSON.stringify(url)},Method="GET",Headers={["X-Eternal-Device"]=tostring(d)}})
if not ok or not r or tonumber(r.StatusCode or r.status_code)~=200 then stop() return end
local f=loadstring(r.Body or r.body or "")
if not f then stop() return end
f()`;
}
