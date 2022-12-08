local api = require "luci.model.cbi.myproxy.api.api"
local appname = api.appname
local uci = api.uci
local datatypes = api.datatypes
local has_singbox = api.is_finded("singbox")
local log = require "luci.log"


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

-- local doh_validate = function(self, value, t)
--     if value ~= "" then
--         local flag = 0
--         local util = require "luci.util"
--         local val = util.split(value, ",")
--         local url = val[1]
--         val[1] = nil
--         for i = 1, #val do
--             local v = val[i]
--             if v then
--                 if not datatypes.ipmask4(v) then
--                     flag = 1
--                 end
--             end
--         end
--         if flag == 0 then
--             return value
--         end
--     end
--     return nil, translate("DoH request address") .. " " .. translate("Format must be:") .. " URL,IP"
-- end

m:append(Template(appname .. "/global/status"))

s = m:section(TypedSection, "global")
s.anonymous = true
s.addremove = false

s:tab("Main", translate("Main"))

-- [[ Global Settings ]]--
o = s:taboption("Main", Flag, "enabled", translate("Main switch"))
o.rmempty = false

---- Node
-- node = s:taboption("Main", ListValue, "node", "<a style='color: red'>" .. translate("Node") .. "</a>")
-- node.description = ""
-- local current_node = luci.sys.exec(string.format("[ -f '/tmp/etc/%s/id/TCP' ] && echo -n $(cat /tmp/etc/%s/id/TCP)", appname, appname))
-- if current_node and current_node ~= "" and current_node ~= "nil" then
--     local n = uci:get_all(appname, current_node)
--     if n then
--         if tonumber(m:get("@auto_switch[0]", "enable") or 0) == 1 then
--             local remarks = api.get_full_node_remarks(n)
--             local url = api.url("node_config", current_node)
--             node.description = node.description .. translatef("Current node: %s", string.format('<a href="%s">%s</a>', url, remarks)) .. "<br />"
--         end
--     end
-- end
-- node:value("nil", translate("Close"))

-- 分流
local shuntConfigName="singbox_shunt"
local singboxNodeId = api.uci_get_singbox_shunt_id();
if (has_singbox) and #nodes_table > 0 then
    -- local normal_list = {}
    -- local shunt_list = {}
    -- for k, v in pairs(nodes_table) do
    --     if v.node_type == "normal" then
    --         normal_list[#normal_list + 1] = v
    --     end
    --     if v.protocol and v.protocol == "_shunt" then
    --         shunt_list[#shunt_list + 1] = v
    --     end
    -- end
    -- for k, v in pairs(shunt_list) do

        uci:foreach(appname, "shunt_rules", function(e)
            local id = e[".name"]
            log.print("shunt_rules_id = "..id)
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
        
        local id = "main_node"
        o = s:taboption("Main", ListValue, shuntConfigName .. "." .. id, string.format('* <a style="color:red">%s</a>', translate("Default Preproxy")), translate("When using, localhost will connect this node first and then use this node to connect the default node."))
        -- o:depends("node", v.id)
        o:value("nil", translate("Close"))
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



s:tab("log", translate("Log"))
o = s:taboption("log", Flag, "close_log", translate("Close Node Log"))
o.rmempty = false

loglevel = s:taboption("log", ListValue, "loglevel", translate("Log Level"))
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

-- if has_v2ray or has_xray then
--     o = s:option(Value, "http_port", "HTTP " .. translate("Listen Port") .. " " .. translate("0 is not use"))
--     o.default = 0
--     o.datatype = "port"
-- end

-- for k, v in pairs(nodes_table) do
--     node:value(v.id, v["remark"])
--     if v.type == "Socks" then
--         if has_v2ray or has_xray then
--             socks_node:value(v.id, v["remark"])
--         end
--     else
--         socks_node:value(v.id, v["remark"])
--     end
-- end

m:append(Template(appname .. "/global/footer"))

return m
