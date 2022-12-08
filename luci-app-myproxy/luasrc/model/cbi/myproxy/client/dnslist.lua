local api = require "luci.model.cbi.myproxy.api.api"
local appname = api.appname
local sys = api.sys
local datatypes = api.datatypes
local uci = api.uci
local sys = api.sys

m = Map(appname)

-- [[ Other Settings ]]--
s = m:section(TypedSection, "global_dnslist")
s.anonymous = true


-- [[ Node List ]]--
s = m:section(TypedSection, "dnslist",translate("DNS List"))
s.anonymous = true
s.addremove = true
s.sortable = true
s.template = "cbi/tblsection"

function s.create(e, t)
    t = TypedSection.create(e, t)
end

dns_enable = s:option(Flag,"enable",translate("Enable"))
dns_enable.default = 1

proxy_rule = s:option(ListValue,"rule",translate("Rule"))

proxy_rule:value(nil,translate("-"))

uci:foreach(appname, "shunt_rules", function(e)
    if e[".name"] and e.remarks then
        proxy_rule:value(e[".name"],e.remarks)
        
    end
end)

proxy_rule.default="NONE"

dns_remarks = s:option(Value,"remarks",translate("remarks"))
dns_remarks.placeholder = "服务器名称，唯一"


o = s:option(ListValue,"protocol",translate("Protocol"))
o:value("System",translate("System"))
o:value("udp",translate("UDP"))
o:value("tcp",translate("TCP"))
o:value("https",translate("DOH"))
o:value("tls",translate("tls"))
o:value("QUIC",translate("QUIC"))
o:value("HTTP3",translate("HTTP3"))
o:value("RCode",translate("RCode"))
o.default = "udp"

o = s:option(Value,"addr",translate("address"))
o.placeholder = "202.102.224.68"

o = s:option(Value,"port",translate("Port"))
o.default = "53"
o.placeholder = "53"


detour = s:option(ListValue,"detour",translate("detour"))
detour:value("default",translate("default"))
detour:value("direct",translate("direct"))

local nodes_table = {}
for k, e in ipairs(api.get_valid_nodes()) do
    if e.node_type == "normal" then
        nodes_table[#nodes_table + 1] = {
            id = e[".name"],
            remarks = e["remark"]
        }
    end
end

if #nodes_table > 0 then
            for k, v in pairs(nodes_table) do
                detour:value(v.id, v.remarks)
            end
        end

return m