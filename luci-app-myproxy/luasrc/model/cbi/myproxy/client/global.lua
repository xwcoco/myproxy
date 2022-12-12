local api = require "luci.model.cbi.myproxy.api.api"
local appname = api.appname
local uci = api.uci
local datatypes = api.datatypes
local has_singbox = api.is_finded("singbox")



m = Map(appname)

local nodes_table = {}
for k, e in ipairs(api.get_valid_nodes()) do
    nodes_table[#nodes_table + 1] = e
end


local socks_table = {}
uci:foreach(appname, "socks", function(s)
    if s.enabled == "1" and s.node then
        local id, remarks
        for k, n in pairs(nodes_table) do
            if (s.node == n.id) then
                remarks = n["remark"]; break
            end
        end
        id = "127.0.0.1" .. ":" .. s.port
        socks_table[#socks_table + 1] = {
            id = id,
            remarks = id .. " - " .. (remarks or translate("Misconfigured"))
        }
    end
end)


m:append(Template(appname .. "/global/status"))

s = m:section(TypedSection, "global")
s.anonymous = true
s.addremove = false

s:tab("Main", translate("Main"))

-- [[ Global Settings ]]--
o = s:taboption("Main", Flag, "enabled", translate("Main switch"))
o.rmempty = false


-- 分流
local shuntConfigName="singbox_shunt"
local singboxNodeId = api.uci_get_singbox_shunt_id();
if (has_singbox) and #nodes_table > 0 then

        uci:foreach(appname, "shunt_rules", function(e)
            local id = e[".name"]
            -- log.print("shunt_rules_id = "..id)
            if id and e.remarks then
                o = s:taboption("Main", ListValue, shuntConfigName .. "." .. id .. "_node", string.format('* <a href="%s" target="_blank">%s</a>', api.url("shunt_rules", id), e.remarks))
                -- o:depends("node", v.id)
                o:value("nil", translate("Close"))
                o:value("_default", translate("Default"))
                o:value("_direct", translate("Direct Connection"))
                o:value("_blackhole", translate("Blackhole"))
                for k1, v1 in pairs(nodes_table) do
                    o:value(v1.id, v1["remark"])
                end
                o.cfgvalue = function(self, section)
                    return m:get(singboxNodeId, id) or "nil"
                end
                o.write = function(self, section, value)
                    m:set(singboxNodeId, id, value)
                end
            end
        end)

        local id = "default_node"
        o = s:taboption("Main", ListValue, shuntConfigName .. "." .. id, string.format('* <a style="color:red">%s</a>', translate("Default")))
        -- o:depends("node", v.id)
        o:value("_direct", translate("Direct Connection"))
        o:value("_blackhole", translate("Blackhole"))
        for k1, v1 in pairs(nodes_table) do
            o:value(v1.id, v1["remark"])
        end
        o.cfgvalue = function(self, section)
            return m:get(singboxNodeId, id) or "nil"
        end
        o.write = function(self, section, value)
            m:set(singboxNodeId, id, value)
        end
        

    -- end
end

o = s:taboption("Main", Flag, "localhost_proxy", translate("Localhost Proxy"), translate("When selected, localhost can transparent proxy."))
o.default = "1"
o.rmempty = false

s:tab("tun",translate("Mode"))

proxy_mode = s:taboption("tun",ListValue,"proxy_mode",translate("Proxy Mode"))
proxy_mode:value("tun")
proxy_mode:value("tproxy")
proxy_mode:value("redirect")
proxy_mode.default = "tun"

tun_mtu = s:taboption("tun",Value,"tun_mtu",translate("Mtu"))
tun_mtu.description = translate("The maximum transmission unit.")
tun_mtu.default = 9000
tun_mtu:depends("proxy_mode","tun")

tun_strict_route = s:taboption("tun",Flag,"tun_strict_route",translate("Strict Route"))
tun_strict_route.description= translate("Enforce strict routing rules when auto_route is enabled")
tun_strict_route.default = true
tun_strict_route:depends("proxy_mode","tun")

tun_stack = s:taboption("tun",ListValue,"tun_stack",translate("TCP/IP Stack"))
tun_stack:value("system")
tun_stack:value("gvisor")
tun_stack.default = "system"
tun_stack.description = translate("system - Sometimes better performance,gVisor -Better compatibility, based on google/gvisor")
tun_stack:depends("proxy_mode","tun")

s:tab("log", translate("Log"))
o = s:taboption("log", Flag, "close_log", translate("Close Node Log"))
o.rmempty = false

loglevel = s:taboption("log", ListValue, "loglevel", string.format('* <a href="%s?id=global" target="_blank">%s</a>', api.url("get_redir_log"), translate("Log Level")) )
loglevel.default = "warning"
loglevel:value("debug")
loglevel:value("info")
loglevel:value("warning")
loglevel:value("error")

s:tab("faq", "FAQ")

o = s:taboption("faq", DummyValue, "")
o.template = appname .. "/global/faq"

-- [[ Socks Server ]]--
o = s:taboption("Main", Flag, "socks_enabled", "Socks " .. translate("Main switch"))
o.rmempty = false

s = m:section(TypedSection, "socks", translate("Socks Config"))
s.anonymous = true
s.addremove = true
s.template = "cbi/tblsection"
function s.create(e, t)
    TypedSection.create(e, api.gen_uuid())
end

o = s:option(DummyValue, "status", translate("Status"))
o.rawhtml = true
o.cfgvalue = function(t, n)
    return string.format('<div class="_status" socks_id="%s"></div>', n)
end

---- Enable
o = s:option(Flag, "enabled", translate("Enable"))
o.default = 1
o.rmempty = false

socks_node = s:option(ListValue, "node", translate("Socks Node"))

local n = 0
uci:foreach(appname, "socks", function(s)
    if s[".name"] == section then
        return false
    end
    n = n + 1
end)

o = s:option(Value, "port", "Socks " .. translate("Listen Port"))
o.default = n + 1080
o.datatype = "port"
o.rmempty = false


o = s:option(Value, "http_port", "HTTP " .. translate("Listen Port") .. " " .. translate("0 is not use"))
o.default = 0
o.datatype = "port"

for k, v in pairs(nodes_table) do
    socks_node:value(v.id, v["remark"])
end

m:append(Template(appname .. "/global/footer"))

return m
