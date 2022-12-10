local api = require "luci.model.cbi.myproxy.api.api"
local appname = api.appname
local uci = api.uci

if not arg[1] or not uci:get(appname, arg[1]) then
    luci.http.redirect(api.url("node_list"))
end

local ss_encrypt_method_list = {
    "rc4-md5", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-ctr",
    "aes-192-ctr", "aes-256-ctr", "bf-cfb", "salsa20", "chacha20", "chacha20-ietf",
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305"
}

local ss_rust_encrypt_method_list = {
    "plain", "none",
    "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha8-poly1305", "2022-blake3-chacha20-poly1305"
}

local ssr_encrypt_method_list = {
    "none", "table", "rc2-cfb", "rc4", "rc4-md5", "rc4-md5-6", "aes-128-cfb",
    "aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "bf-cfb", "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb",
    "cast5-cfb", "des-cfb", "idea-cfb", "seed-cfb", "salsa20", "chacha20",
    "chacha20-ietf"
}

local ssr_protocol_list = {
    "origin", "verify_simple", "verify_deflate", "verify_sha1", "auth_simple",
    "auth_sha1", "auth_sha1_v2", "auth_sha1_v4", "auth_aes128_md5",
    "auth_aes128_sha1", "auth_chain_a", "auth_chain_b", "auth_chain_c",
    "auth_chain_d", "auth_chain_e", "auth_chain_f"
}
local ssr_obfs_list = {
    "plain", "http_simple", "http_post", "random_head", "tls_simple",
    "tls1.0_session_auth", "tls1.2_ticket_auth"
}

local v_ss_encrypt_method_list = {
    "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305"
}

local x_ss_encrypt_method_list = {
    "aes-128-gcm", "aes-192-gcm","aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"
}

local security_list = {"none", "auto", "aes-128-gcm", "chacha20-poly1305", "zero"}

local header_type_list = {
    "none", "srtp", "utp", "wechat-video", "dtls", "wireguard"
}
local encrypt_methods_ss_aead = {
	"chacha20-ietf-poly1305",
	"aes-128-gcm",
	"aes-256-gcm",
}

m = Map(appname, translate("Node Config"))
m.redirect = api.url()

s = m:section(NamedSection, arg[1], "nodes", "")
s.addremove = false
s.dynamic = false

share = s:option(DummyValue, "myproxy", " ")
share.rawhtml  = true
share.template = "myproxy/node_list/link_share_man"
share.value = arg[1]

remarks = s:option(Value, "remarks", translate("Node Remarks"))
remarks.default = translate("Remarks")
remarks.rmempty = false


protocol = s:option(ListValue, "protocol", translate("Protocol"))
protocol:value("shadowsocks", translate("Shadowsocks"))
protocol:value("vmess", translate("Vmess"))
protocol:value("trojan", translate("Trojan"))
protocol:value("wireguard", translate("wireguard"))
protocol:value("hysteria", translate("hysteria"))
protocol:value("shadowtls", translate("shadowtls"))
protocol:value("shadowsocksr", translate("shadowsocksr"))
protocol:value("vless", translate("VLESS"))
protocol:value("tor", translate("tor"))
protocol:value("http", translate("HTTP"))
protocol:value("socks", translate("Socks"))
protocol:value("ssh", translate("ssh"))


local nodes_table = {}
for k, e in ipairs(api.get_valid_nodes()) do
    if e.node_type == "normal" then
        nodes_table[#nodes_table + 1] = {
            id = e[".name"],
            remarks = e["remark"]
        }
    end
end


address = s:option(Value, "address", translate("Address (Support Domain Name)"))
address.rmempty = false

port = s:option(Value, "port", translate("Port"))
port.datatype = "port"
port.rmempty = false
port:depends("protocol", "shadowsocks")
port:depends("protocol", "vmess")
port:depends("protocol", "trojan")
port:depends("protocol", "wireguard")
port:depends("protocol", "hysteria")
port:depends("protocol", "shadowtls")
port:depends("protocol", "shadowsocksr")
port:depends("protocol", "vless")
port:depends("protocol", "http")
port:depends("protocol", "socks")
port:depends("protocol", "ssh")

username = s:option(Value, "username", translate("Username"))
username:depends("protocol", "http")
username:depends("protocol", "socks")
username:depends("protocol", "ssh")
-- username:depends("protocol", "trojan")

password = s:option(Value, "password", translate("Password"))
password.password = true
password:depends("protocol", "http")
password:depends("protocol", "socks")
password:depends("protocol", "shadowsocks")
password:depends("protocol", "trojan")
password:depends("protocol", "shadowtls")
password:depends("protocol", "shadowsocksr")
password:depends("protocol", "ssh")


hysteria_obfs = s:option(Value, "hysteria_obfs", translate("Obfs Password"))
hysteria_obfs:depends("protocol", "hysteria")

hysteria_auth_type = s:option(ListValue, "hysteria_auth_type", translate("Auth Type"))
hysteria_auth_type:value("disable", translate("Disable"))
hysteria_auth_type:value("string", translate("STRING"))
hysteria_auth_type:value("base64", translate("BASE64"))
hysteria_auth_type:depends("protocol", "hysteria")

hysteria_auth_password = s:option(Value, "hysteria_auth_password", translate("Auth Password"))
hysteria_auth_password.password = true
hysteria_auth_password:depends("hysteria_auth_type", "string")
hysteria_auth_password:depends("hysteria_auth_type", "base64")

hysteria_up_mbps = s:option(Value, "hysteria_up_mbps", translate("Max upload Mbps"))
hysteria_up_mbps.default = "10"
hysteria_up_mbps:depends("protocol", "hysteria")

hysteria_down_mbps = s:option(Value, "hysteria_down_mbps", translate("Max download Mbps"))
hysteria_down_mbps.default = "50"
hysteria_down_mbps:depends("protocol", "hysteria")


hysteria_recv_window_conn = s:option(Value, "hysteria_recv_window_conn", translate("QUIC stream receive window"))
hysteria_recv_window_conn:depends("protocol", "hysteria")

hysteria_recv_window = s:option(Value, "hysteria_recv_window", translate("QUIC connection receive window"))
hysteria_recv_window:depends("protocol", "hysteria")

hysteria_disable_mtu_discovery = s:option(Flag, "hysteria_disable_mtu_discovery", translate("Disable MTU detection"))
hysteria_disable_mtu_discovery:depends("protocol", "hysteria")

x_ss_encrypt_method = s:option(ListValue, "x_ss_encrypt_method", translate("Encrypt Method"))
for a, t in ipairs(x_ss_encrypt_method_list) do x_ss_encrypt_method:value(t) end
x_ss_encrypt_method:depends("protocol", "shadowsocks" )
function x_ss_encrypt_method.cfgvalue(self, section)
	return m:get(section, "method")
end
function x_ss_encrypt_method.write(self, section, value)
	m:set(section, "method", value)
end

uot = s:option(Flag, "uot", translate("UDP over TCP"))
uot:depends("protocol","shadowsocks" )

-- TLS

tls = s:option(Flag, "tls", translate("TLS"))
tls.default = 0
tls:depends({ protocol = "vmess" })
tls:depends({ protocol = "vless" })
tls:depends({ protocol = "socks" })
tls:depends({ protocol = "trojan" })
tls:depends({ protocol = "hysteria" })

tls_serverName = s:option(Value, "tls_serverName", translate("Domain"))
tls_serverName:depends("tls", true)

tls_allowInsecure = s:option(Flag, "tls_allowInsecure", translate("allowInsecure"), translate("Whether unsafe connections are allowed. When checked, Certificate validation will be skipped."))
tls_allowInsecure.default = "0"
tls_allowInsecure:depends("tls", true)

alpn = s:option(ListValue, "alpn", translate("alpn"))
alpn.default = "default"
alpn:value("default", translate("Default"))
alpn:value("h2,http/1.1")
alpn:value("h2")
alpn:value("http/1.1")
alpn:depends({ tls = true })


ech = s:option(Flag,"ech",translate("Encrypted Client Hello"))
ech.default = 0
ech:depends({tls = true})

utls = s:option(Flag,"utls",translate("uTLS"))
utls.default = 0
utls:depends({tls = true})

fingerprint = s:option(ListValue,"fingerprint",translate("Finger Print"))
fingerprint:depends({utls = true})
fingerprint:value("chrome")
fingerprint:value("firefox")
fingerprint:value("edge")
fingerprint:value("safari")
fingerprint:value("360")
fingerprint:value("qq")
fingerprint:value("ios")
fingerprint:value("android")
fingerprint:value("random")

transport = s:option(ListValue, "transport", translate("Transport"))
transport:value("http", "HTTP")
transport:value("ws", "WebSocket")
transport:value("quic", "QUIC")
transport:value("grpc", "gRPC")
transport:depends({ protocol = "vmess" })
transport:depends({ protocol = "vless" })
transport:depends({ protocol = "trojan" })
-- transport:depends({ protocol = "vless" })
-- transport:depends({ protocol = "socks" })
-- transport:depends({ protocol = "shadowsocks" })
-- transport:depends({ protocol = "trojan" })

transport_host = s:option(Value, "transport_host", translate("Host"))
transport_host:depends("transport", "http")

transport_path = s:option(Value,"transport_path",translate("Transport Path"))
transport_path:depends("transport", "http")
transport_path:depends("transport", "ws")

transport_method = s:option(ListValue,"transport_method",translate("Http Method"))
transport_method:depends("transport", "http")
transport_method:value("get")
transport_method:value("post")

ws_maxEarlyData = s:option(Value, "ws_maxEarlyData", translate("Early data length"))
ws_maxEarlyData.placeholder = "1024"
ws_maxEarlyData:depends("transport", "ws")

grpc_serviceName = s:option(Value, "grpc_serviceName", "ServiceName")
grpc_serviceName:depends("transport", "grpc")


-- [[ Mux ]]--
mux = s:option(Flag, "mux", translate("Mux"))
mux:depends("protocol","vmess")
mux:depends({protocol = "vless", xtls = false })
mux:depends("protocol","shadowsocks")
mux:depends("protocol","trojan")


mux_protocol = s:option(ListValue,"mux_protocol",translate("mux protocol"))
mux_protocol:value("smux")
mux_protocol:value("yamux")
mux_protocol.default = "smux"
mux_protocol:depends({mux = true})

mux_max_connections = s:option(Value,"mux_max_connections",translate("mux max connections"))
mux_max_connections.default = "4"
mux_max_connections:depends({mux = true})

mux_min_streams = s:option(Value,"mux_min_streams",translate("mux min streams"))
mux_min_streams.default = "4"
mux_min_streams:depends({mux = true})

mux_max_streams = s:option(Value,"mux_max_streams",translate("mux max streams"),translate("Maximum multiplexed streams in a connection before opening a new connection.Conflict with max_connections and min_streams "))
mux_max_streams.default = "0"
mux_max_streams:depends({mux = true})


-- Dial Fields

-- dial_field_enable = s:option(Flag,"dial_enable",translate("Dial Eanble"))
-- dial_field_enable:depends("protocol","shadowsocks")

dial_detour = s:option(Value,"dial_detour",translate("detour"),translate("detour - The tag of the upstream outbound"))
-- dial_detour:depends("protocol","shadowsocks")
-- detour:depends({dial_field_enable = true})

dial_bind_interface = s:option(Value,"dial_bind_interface",translate("bind_interface"),translate("The network interface to bind to."))
-- dial_bind_interface:depends("protocol","shadowsocks")
dial_bind_interface.placeholder = "en0"

dial_inet4_bind_address = s:option(Value,"dial_inet4_bind_address",translate("inet4 bind address"))
-- dial_inet4_bind_address:depends("protocol","shadowsocks")
dial_inet4_bind_address.datatype="ip4addr"
dial_inet4_bind_address.placeholder = "0.0.0.0"

dial_connect_timeout = s:option(Value,"dial_connect_timeout",translate("connect timeout"))
-- dial_connect_timeout:depends("protocol","shadowsocks")
dial_connect_timeout.placeholder = "5s"

dial_tcp_fast_open = s:option(Flag,"dial_tcp_fast_open",translate("tcp fast open"))
-- dial_tcp_fast_open:depends("protocol","shadowsocks")

dial_udp_fragment = s:option(Flag,"dial_udp_fragment",translate("udp_fragment"))
-- dial_udp_fragment:depends("protocol","shadowsocks")

uuid = s:option(Value, "uuid", translate("ID"))
uuid.password = true
uuid:depends({  protocol = "vmess" })
uuid:depends({  protocol = "vless" })

security = s:option(ListValue, "security", translate("Encrypt Method"))
for a, t in ipairs(security_list) do security:value(t) end
security:depends({ protocol = "vmess" })

return m
