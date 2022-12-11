local api = require "luci.model.cbi.myproxy.api.api"
local appname = api.appname
local datatypes = api.datatypes

m = Map(appname, "Singbox " .. translate("Shunt Rule"))
m.redirect = api.url()

s = m:section(NamedSection, arg[1], "shunt_rules", "")
s.addremove = false
s.dynamic = false

remarks = s:option(Value, "remarks", translate("Remarks"))
remarks.default = arg[1]
remarks.rmempty = false

protocol = s:option(MultiValue, "protocol", translate("Protocol"))
protocol:value("tls")
protocol:value("http")
protocol:value("quic")

network = s:option(ListValue, "network", translate("Network"))
network:value("", "TCP UDP")
network:value("tcp", "TCP")
network:value("udp", "UDP")

source_geoip = s:option(DynamicList,"source_geoip",translate("Source GeoIP"))
source_geoip.description = "<ul><li>" .. translate("Example:")
.. "</li><li>" .. translate("GeoIP") .. ": private"
.. "</li></ul>"


source = s:option(DynamicList, "source", translate("Source"))
source.description = "<ul><li>" .. translate("Example:")
.. "</li><li>" .. translate("IP") .. ": 192.168.1.100"
.. "</li><li>" .. translate("IP CIDR") .. ": 192.168.1.0/24"
.. "</li></ul>"


sourcePort = s:option(DynamicList, "sourcePort", translate("Source port"))

source_port_range = s:option(DynamicList,"sourcePortRange",translate("Source Port Range"))
source_port_range.description = "<ul><li>" .. translate("Example:")
.. "</li><li> 1000:2000"
.. "</li><li> :3000"
.. "</li><li> 4000:"
.. "</li></ul>"



domain_list = s:option(DynamicList, "domain", translate("Domain"))
domain_list.description = translate("Match full domain,Example test.com")

domain_suffix = s:option(DynamicList,"domain_suffix",translate("Domain Suffix"))
domain_suffix.description = translate("Match domain suffix. Examples : .cn")

domain_keyword = s:option(DynamicList,"domain_keyword",translate("Domain Keyword"))
domain_keyword.description = translate("Match domain using keyword. Examples: test ")

domain_regex = s:option(DynamicList,"domain_regex",translate("Domain Regex"))
domain_regex.description = translate("Match domain using regular expression. Examples: \\.goo.*\\.com$' matches 'www.google.com' and 'fonts.googleapis.com', but not 'google.com")

geosite = s:option(DynamicList,"geosite",translate("Geosite"))
geosite.description = "Match geosite.such as google or cn"

geoip = s:option(DynamicList,"geoip",translate("Geoip"))
geoip.description = "<ul><li>" .. translate("Example:")
.. "</li><li>" .. translate("GeoIP") .. ": private"
.. "</li></ul>"

ip_list = s:option(DynamicList, "ip_cidr", "IP")
ip_list.description = "<ul><li>" .. translate("Example:")
.. "</li><li>" .. translate("IP") .. ": 192.168.1.100"
.. "</li><li>" .. translate("IP CIDR") .. ": 192.168.1.0/24"
.. "</li></ul>"

port = s:option(DynamicList, "port", translate("port"))
port.description = "Match port"

port_range = s:option(DynamicList,"port_range",translate("Port Range"))
port_range.description = "<ul><li> " .. translate("Match port range. Example:")
.. "</li><li> 1000:2000"
.. "</li><li> :3000"
.. "</li><li> 4000:"
.. "</li></ul>"


-- domain_list.validate = function(self, value)
--     local hosts= {}
--     string.gsub(value, '[^' .. "\r\n" .. ']+', function(w) table.insert(hosts, w) end)
--     for index, host in ipairs(hosts) do
--         local flag = 1
--         local tmp_host = host
--         if host:find("regexp:") and host:find("regexp:") == 1 then
--             flag = 0
--         elseif host:find("domain:.") and host:find("domain:.") == 1 then
--             tmp_host = host:gsub("domain:", "")
--         elseif host:find("full:.") and host:find("full:.") == 1 then
--             tmp_host = host:gsub("full:", "")
--         elseif host:find("geosite:") and host:find("geosite:") == 1 then
--             flag = 0
--         elseif host:find("ext:") and host:find("ext:") == 1 then
--             flag = 0
--         end
--         if flag == 1 then
--             if not datatypes.hostname(tmp_host) then
--                 return nil, tmp_host .. " " .. translate("Not valid domain name, please re-enter!")
--             end
--         end
--     end
--     return value
-- end
-- domain_list.description = "<br /><ul><li>" .. translate("Plaintext: If this string matches any part of the targeting domain, this rule takes effet. Example: rule 'sina.com' matches targeting domain 'sina.com', 'sina.com.cn' and 'www.sina.com', but not 'sina.cn'.")
-- .. "</li><li>" .. translate("Regular expression: Begining with 'regexp:', the rest is a regular expression. When the regexp matches targeting domain, this rule takes effect. Example: rule 'regexp:\\.goo.*\\.com$' matches 'www.google.com' and 'fonts.googleapis.com', but not 'google.com'.")
-- .. "</li><li>" .. translate("Subdomain (recommended): Begining with 'domain:' and the rest is a domain. When the targeting domain is exactly the value, or is a subdomain of the value, this rule takes effect. Example: rule 'domain:v2ray.com' matches 'www.v2ray.com', 'v2ray.com', but not 'xv2ray.com'.")
-- .. "</li><li>" .. translate("Full domain: Begining with 'full:' and the rest is a domain. When the targeting domain is exactly the value, the rule takes effect. Example: rule 'domain:v2ray.com' matches 'v2ray.com', but not 'www.v2ray.com'.")
-- .. "</li><li>" .. translate("Pre-defined domain list: Begining with 'geosite:' and the rest is a name, such as geosite:google or geosite:cn.")
-- .. "</li><li>" .. translate("Domains from file: Such as 'ext:file:tag'. The value must begin with ext: (lowercase), and followed by filename and tag. The file is placed in resource directory, and has the same format of geosite.dat. The tag must exist in the file.")
-- .. "</li></ul>"
-- ip_list = s:option(TextValue, "ip_list", "IP")
-- ip_list.rows = 10
-- ip_list.wrap = "off"
-- ip_list.validate = function(self, value)
--     local ipmasks= {}
--     string.gsub(value, '[^' .. "\r\n" .. ']+', function(w) table.insert(ipmasks, w) end)
--     for index, ipmask in ipairs(ipmasks) do
--         if ipmask:find("geoip:") and ipmask:find("geoip:") == 1 then
--         elseif ipmask:find("ext:") and ipmask:find("ext:") == 1 then
--         else
--             if not (datatypes.ipmask4(ipmask) or datatypes.ipmask6(ipmask)) then
--                 return nil, ipmask .. " " .. translate("Not valid IP format, please re-enter!")
--             end
--         end
--     end
--     return value
-- end
-- ip_list.description = "<br /><ul><li>" .. translate("IP: such as '127.0.0.1'.")
-- .. "</li><li>" .. translate("CIDR: such as '127.0.0.0/8'.")
-- .. "</li><li>" .. translate("GeoIP: such as 'geoip:cn'. It begins with geoip: (lower case) and followed by two letter of country code.")
-- .. "</li><li>" .. translate("IPs from file: Such as 'ext:file:tag'. The value must begin with ext: (lowercase), and followed by filename and tag. The file is placed in resource directory, and has the same format of geoip.dat. The tag must exist in the file.")
-- .. "</li></ul>"

return m
