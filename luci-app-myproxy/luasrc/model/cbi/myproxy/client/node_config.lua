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

password = s:option(Value, "password", translate("Password"))
password.password = true
password:depends("protocol", "http")
password:depends("protocol", "socks")
password:depends("protocol", "shadowsocks")
password:depends("protocol", "trojan")
password:depends("protocol", "shadowtls")
password:depends("protocol", "shadowsocksr")
password:depends("protocol", "ssh")


-- hysteria_protocol = s:option(ListValue, "hysteria_protocol", translate("Protocol"))
-- hysteria_protocol:value("udp", "UDP")
-- hysteria_protocol:value("faketcp", "faketcp")
-- hysteria_protocol:value("wechat-video", "wechat-video")
-- hysteria_protocol:depends("type", "Hysteria")
-- function hysteria_protocol.cfgvalue(self, section)
-- 	return m:get(section, "protocol")
-- end
-- function hysteria_protocol.write(self, section, value)
-- 	m:set(section, "protocol", value)
-- end

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


-- ss_encrypt_method = s:option(Value, "ss_encrypt_method", translate("Encrypt Method"))
-- for a, t in ipairs(ss_encrypt_method_list) do ss_encrypt_method:value(t) end
-- ss_encrypt_method:depends("type", "SS")
-- function ss_encrypt_method.cfgvalue(self, section)
-- 	return m:get(section, "method")
-- end
-- function ss_encrypt_method.write(self, section, value)
-- 	m:set(section, "method", value)
-- end

-- ss_rust_encrypt_method = s:option(Value, "ss_rust_encrypt_method", translate("Encrypt Method"))
-- for a, t in ipairs(ss_rust_encrypt_method_list) do ss_rust_encrypt_method:value(t) end
-- ss_rust_encrypt_method:depends("type", "SS-Rust")
-- function ss_rust_encrypt_method.cfgvalue(self, section)
-- 	return m:get(section, "method")
-- end
-- function ss_rust_encrypt_method.write(self, section, value)
-- 	m:set(section, "method", value)
-- end

-- ssr_encrypt_method = s:option(Value, "ssr_encrypt_method", translate("Encrypt Method"))
-- for a, t in ipairs(ssr_encrypt_method_list) do ssr_encrypt_method:value(t) end
-- ssr_encrypt_method:depends("type", "SSR")
-- function ssr_encrypt_method.cfgvalue(self, section)
-- 	return m:get(section, "method")
-- end
-- function ssr_encrypt_method.write(self, section, value)
-- 	m:set(section, "method", value)
-- end



-- encryption = s:option(Value, "encryption", translate("Encrypt Method"))
-- encryption.default = "none"
-- encryption:value("none")
-- encryption:depends({ type = "V2ray", protocol = "vless" })
-- encryption:depends({ type = "Xray", protocol = "vless" })


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
dial_detour:depends("protocol","shadowsocks")
-- detour:depends({dial_field_enable = true})

dial_bind_interface = s:option(Value,"dial_bind_interface",translate("bind_interface"),translate("The network interface to bind to."))
dial_bind_interface:depends("protocol","shadowsocks")
dial_bind_interface.placeholder = "en0"

dial_inet4_bind_address = s:option(Value,"dial_inet4_bind_address",translate("inet4 bind address"))
dial_inet4_bind_address:depends("protocol","shadowsocks")
dial_inet4_bind_address.datatype="ip4addr"
dial_inet4_bind_address.placeholder = "0.0.0.0"

dial_connect_timeout = s:option(Value,"dial_connect_timeout",translate("connect timeout"))
dial_connect_timeout:depends("protocol","shadowsocks")
dial_connect_timeout.placeholder = "5s"

dial_tcp_fast_open = s:option(Flag,"dial_tcp_fast_open",translate("tcp fast open"))
dial_tcp_fast_open:depends("protocol","shadowsocks")

dial_udp_fragment = s:option(Flag,"dial_udp_fragment",translate("udp_fragment"))
dial_udp_fragment:depends("protocol","shadowsocks")

uuid = s:option(Value, "uuid", translate("ID"))
uuid.password = true
uuid:depends({  protocol = "vmess" })
uuid:depends({  protocol = "vless" })

security = s:option(ListValue, "security", translate("Encrypt Method"))
for a, t in ipairs(security_list) do security:value(t) end
security:depends({ protocol = "vmess" })



-- ssr_protocol = s:option(Value, "ssr_protocol", translate("Protocol"))
-- for a, t in ipairs(ssr_protocol_list) do ssr_protocol:value(t) end
-- ssr_protocol:depends("type", "SSR")
-- function ssr_protocol.cfgvalue(self, section)
-- 	return m:get(section, "protocol")
-- end
-- function ssr_protocol.write(self, section, value)
-- 	m:set(section, "protocol", value)
-- end

-- protocol_param = s:option(Value, "protocol_param", translate("Protocol_param"))
-- protocol_param:depends("type", "SSR")

-- obfs = s:option(Value, "obfs", translate("Obfs"))
-- for a, t in ipairs(ssr_obfs_list) do obfs:value(t) end
-- obfs:depends("type", "SSR")

-- obfs_param = s:option(Value, "obfs_param", translate("Obfs_param"))
-- obfs_param:depends("type", "SSR")

-- timeout = s:option(Value, "timeout", translate("Connection Timeout"))
-- timeout.datatype = "uinteger"
-- timeout.default = 300
-- timeout:depends("type", "SS")
-- timeout:depends("type", "SS-Rust")
-- timeout:depends("type", "SSR")

-- tcp_fast_open = s:option(ListValue, "tcp_fast_open", translate("TCP Fast Open"), translate("Need node support required"))
-- tcp_fast_open:value("false")
-- tcp_fast_open:value("true")
-- tcp_fast_open:depends("type", "SS")
-- tcp_fast_open:depends("type", "SS-Rust")
-- tcp_fast_open:depends("type", "SSR")

-- ss_plugin = s:option(ListValue, "ss_plugin", translate("plugin"))
-- ss_plugin:value("none", translate("none"))
-- if api.is_finded("xray-plugin") then ss_plugin:value("xray-plugin") end
-- if api.is_finded("v2ray-plugin") then ss_plugin:value("v2ray-plugin") end
-- if api.is_finded("obfs-local") then ss_plugin:value("obfs-local") end
-- ss_plugin:depends("type", "SS")
-- ss_plugin:depends("type", "SS-Rust")
-- function ss_plugin.cfgvalue(self, section)
-- 	return m:get(section, "plugin")
-- end
-- function ss_plugin.write(self, section, value)
-- 	m:set(section, "plugin", value)
-- end

-- ss_plugin_opts = s:option(Value, "ss_plugin_opts", translate("opts"))
-- ss_plugin_opts:depends("ss_plugin", "xray-plugin")
-- ss_plugin_opts:depends("ss_plugin", "v2ray-plugin")
-- ss_plugin_opts:depends("ss_plugin", "obfs-local")
-- function ss_plugin_opts.cfgvalue(self, section)
-- 	return m:get(section, "plugin_opts")
-- end
-- function ss_plugin_opts.write(self, section, value)
-- 	m:set(section, "plugin_opts", value)
-- end





-- xtls = s:option(Flag, "xtls", translate("XTLS"))
-- xtls.default = 0
-- xtls:depends({ type = "Xray", protocol = "vless", tls = true })
-- xtls:depends({ type = "Xray", protocol = "trojan", tls = true })

-- tlsflow = s:option(Value, "tlsflow", translate("flow"))
-- tlsflow.default = ""
-- tlsflow:value("", translate("Disable"))
-- tlsflow:value("xtls-rprx-vision")
-- tlsflow:value("xtls-rprx-vision-udp443")
-- tlsflow:depends({ type = "Xray", protocol = "vless", tls = true , xtls = false })

-- flow = s:option(Value, "flow", translate("flow"))
-- flow.default = "xtls-rprx-direct"
-- flow:value("xtls-rprx-origin")
-- flow:value("xtls-rprx-origin-udp443")
-- flow:value("xtls-rprx-direct")
-- flow:value("xtls-rprx-direct-udp443")
-- flow:value("xtls-rprx-splice")
-- flow:value("xtls-rprx-splice-udp443")
-- flow:depends("xtls", true)







-- xray_fingerprint = s:option(ListValue, "xray_fingerprint", translate("Finger Print"))
-- xray_fingerprint:value("disable", translate("Disable"))
-- xray_fingerprint:value("chrome")
-- xray_fingerprint:value("firefox")
-- xray_fingerprint:value("safari")
-- xray_fingerprint:value("randomized")
-- xray_fingerprint.default = "disable"
-- xray_fingerprint:depends({ type = "Xray", tls = true, xtls = false })
-- xray_fingerprint:depends({ type = "Xray", tls = true, xtls = true })
-- function xray_fingerprint.cfgvalue(self, section)
-- 	return m:get(section, "fingerprint")
-- end
-- function xray_fingerprint.write(self, section, value)
-- 	m:set(section, "fingerprint", value)
-- end



-- --[[
-- ss_transport = s:option(ListValue, "ss_transport", translate("Transport"))
-- ss_transport:value("ws", "WebSocket")
-- ss_transport:value("h2", "HTTP/2")
-- ss_transport:value("h2+ws", "HTTP/2 & WebSocket")
-- ss_transport:depends({ type = "V2ray", protocol = "shadowsocks" })
-- ss_transport:depends({ type = "Xray", protocol = "shadowsocks" })
-- ]]--

-- -- [[ TCP部分 ]]--

-- -- TCP伪装
-- tcp_guise = s:option(ListValue, "tcp_guise", translate("Camouflage Type"))
-- tcp_guise:value("none", "none")
-- tcp_guise:value("http", "http")
-- tcp_guise:depends("transport", "tcp")

-- -- HTTP域名
-- tcp_guise_http_host = s:option(DynamicList, "tcp_guise_http_host", translate("HTTP Host"))
-- tcp_guise_http_host:depends("tcp_guise", "http")

-- -- HTTP路径
-- tcp_guise_http_path = s:option(DynamicList, "tcp_guise_http_path", translate("HTTP Path"))
-- tcp_guise_http_path:depends("tcp_guise", "http")

-- -- [[ mKCP部分 ]]--

-- mkcp_guise = s:option(ListValue, "mkcp_guise", translate("Camouflage Type"), translate('<br />none: default, no masquerade, data sent is packets with no characteristics.<br />srtp: disguised as an SRTP packet, it will be recognized as video call data (such as FaceTime).<br />utp: packets disguised as uTP will be recognized as bittorrent downloaded data.<br />wechat-video: packets disguised as WeChat video calls.<br />dtls: disguised as DTLS 1.2 packet.<br />wireguard: disguised as a WireGuard packet. (not really WireGuard protocol)'))
-- for a, t in ipairs(header_type_list) do mkcp_guise:value(t) end
-- mkcp_guise:depends("transport", "mkcp")

-- mkcp_mtu = s:option(Value, "mkcp_mtu", translate("KCP MTU"))
-- mkcp_mtu.default = "1350"
-- mkcp_mtu:depends("transport", "mkcp")

-- mkcp_tti = s:option(Value, "mkcp_tti", translate("KCP TTI"))
-- mkcp_tti.default = "20"
-- mkcp_tti:depends("transport", "mkcp")

-- mkcp_uplinkCapacity = s:option(Value, "mkcp_uplinkCapacity", translate("KCP uplinkCapacity"))
-- mkcp_uplinkCapacity.default = "5"
-- mkcp_uplinkCapacity:depends("transport", "mkcp")

-- mkcp_downlinkCapacity = s:option(Value, "mkcp_downlinkCapacity", translate("KCP downlinkCapacity"))
-- mkcp_downlinkCapacity.default = "20"
-- mkcp_downlinkCapacity:depends("transport", "mkcp")

-- mkcp_congestion = s:option(Flag, "mkcp_congestion", translate("KCP Congestion"))
-- mkcp_congestion:depends("transport", "mkcp")

-- mkcp_readBufferSize = s:option(Value, "mkcp_readBufferSize", translate("KCP readBufferSize"))
-- mkcp_readBufferSize.default = "1"
-- mkcp_readBufferSize:depends("transport", "mkcp")

-- mkcp_writeBufferSize = s:option(Value, "mkcp_writeBufferSize", translate("KCP writeBufferSize"))
-- mkcp_writeBufferSize.default = "1"
-- mkcp_writeBufferSize:depends("transport", "mkcp")

-- mkcp_seed = s:option(Value, "mkcp_seed", translate("KCP Seed"))
-- mkcp_seed:depends("transport", "mkcp")

-- -- [[ WebSocket部分 ]]--
-- ws_host = s:option(Value, "ws_host", translate("WebSocket Host"))
-- ws_host:depends("transport", "ws")
-- ws_host:depends("ss_transport", "ws")

-- ws_path = s:option(Value, "ws_path", translate("WebSocket Path"))
-- ws_path:depends("transport", "ws")
-- ws_path:depends("ss_transport", "ws")
-- ws_path:depends({ type = "Brook", brook_protocol = "wsclient" })

-- ws_enableEarlyData = s:option(Flag, "ws_enableEarlyData", translate("Enable early data"))
-- ws_enableEarlyData:depends({ type = "V2ray", transport = "ws" })

-- ws_maxEarlyData = s:option(Value, "ws_maxEarlyData", translate("Early data length"))
-- ws_maxEarlyData.default = "1024"
-- ws_maxEarlyData:depends("ws_enableEarlyData", true)

-- ws_earlyDataHeaderName = s:option(Value, "ws_earlyDataHeaderName", translate("Early data header name"), translate("Recommended value: Sec-WebSocket-Protocol"))
-- ws_earlyDataHeaderName:depends("ws_enableEarlyData", true)

-- -- [[ HTTP/2部分 ]]--
-- h2_host = s:option(Value, "h2_host", translate("HTTP/2 Host"))
-- h2_host:depends("transport", "h2")
-- h2_host:depends("ss_transport", "h2")

-- h2_path = s:option(Value, "h2_path", translate("HTTP/2 Path"))
-- h2_path:depends("transport", "h2")
-- h2_path:depends("ss_transport", "h2")

-- h2_health_check = s:option(Flag, "h2_health_check", translate("Health check"))
-- h2_health_check:depends({ type = "Xray", transport = "h2"})

-- h2_read_idle_timeout = s:option(Value, "h2_read_idle_timeout", translate("Idle timeout"))
-- h2_read_idle_timeout.default = "10"
-- h2_read_idle_timeout:depends("h2_health_check", true)

-- h2_health_check_timeout = s:option(Value, "h2_health_check_timeout", translate("Health check timeout"))
-- h2_health_check_timeout.default = "15"
-- h2_health_check_timeout:depends("h2_health_check", true)

-- -- [[ DomainSocket部分 ]]--
-- ds_path = s:option(Value, "ds_path", "Path", translate("A legal file path. This file must not exist before running."))
-- ds_path:depends("transport", "ds")

-- -- [[ QUIC部分 ]]--
-- quic_security = s:option(ListValue, "quic_security", translate("Encrypt Method"))
-- quic_security:value("none")
-- quic_security:value("aes-128-gcm")
-- quic_security:value("chacha20-poly1305")
-- quic_security:depends("transport", "quic")

-- quic_key = s:option(Value, "quic_key", translate("Encrypt Method") .. translate("Key"))
-- quic_key:depends("transport", "quic")

-- quic_guise = s:option(ListValue, "quic_guise", translate("Camouflage Type"))
-- for a, t in ipairs(header_type_list) do quic_guise:value(t) end
-- quic_guise:depends("transport", "quic")

-- -- [[ gRPC部分 ]]--
-- grpc_serviceName = s:option(Value, "grpc_serviceName", "ServiceName")
-- grpc_serviceName:depends("transport", "grpc")

-- grpc_mode = s:option(ListValue, "grpc_mode", "gRPC " .. translate("Transfer mode"))
-- grpc_mode:value("gun")
-- grpc_mode:value("multi")
-- grpc_mode:depends({ type = "Xray", transport = "grpc"})

-- grpc_health_check = s:option(Flag, "grpc_health_check", translate("Health check"))
-- grpc_health_check:depends({ type = "Xray", transport = "grpc"})

-- grpc_idle_timeout = s:option(Value, "grpc_idle_timeout", translate("Idle timeout"))
-- grpc_idle_timeout.default = "10"
-- grpc_idle_timeout:depends("grpc_health_check", true)

-- grpc_health_check_timeout = s:option(Value, "grpc_health_check_timeout", translate("Health check timeout"))
-- grpc_health_check_timeout.default = "20"
-- grpc_health_check_timeout:depends("grpc_health_check", true)

-- grpc_permit_without_stream = s:option(Flag, "grpc_permit_without_stream", translate("Permit without stream"))
-- grpc_permit_without_stream.default = "0"
-- grpc_permit_without_stream:depends("grpc_health_check", true)

-- grpc_initial_windows_size = s:option(Value, "grpc_initial_windows_size", translate("Initial Windows Size"))
-- grpc_initial_windows_size.default = "0"
-- grpc_initial_windows_size:depends({ type = "Xray", transport = "grpc"})



-- mux_concurrency = s:option(Value, "mux_concurrency", translate("Mux concurrency"))
-- mux_concurrency.default = 8
-- mux_concurrency:depends("mux", true)
-- mux_concurrency:depends("smux", true)

-- smux_idle_timeout = s:option(Value, "smux_idle_timeout", translate("Mux idle timeout"))
-- smux_idle_timeout.default = 60
-- smux_idle_timeout:depends("smux", true)

-- hysteria_up_mbps = s:option(Value, "hysteria_up_mbps", translate("Max upload Mbps"))
-- hysteria_up_mbps.default = "10"
-- hysteria_up_mbps:depends("type", "Hysteria")

-- hysteria_down_mbps = s:option(Value, "hysteria_down_mbps", translate("Max download Mbps"))
-- hysteria_down_mbps.default = "50"
-- hysteria_down_mbps:depends("type", "Hysteria")

-- hysteria_recv_window_conn = s:option(Value, "hysteria_recv_window_conn", translate("QUIC stream receive window"))
-- hysteria_recv_window_conn:depends("type", "Hysteria")

-- hysteria_recv_window = s:option(Value, "hysteria_recv_window", translate("QUIC connection receive window"))
-- hysteria_recv_window:depends("type", "Hysteria")

-- hysteria_disable_mtu_discovery = s:option(Flag, "hysteria_disable_mtu_discovery", translate("Disable MTU detection"))
-- hysteria_disable_mtu_discovery:depends("type", "Hysteria")

-- protocol.validate = function(self, value)
--     if value == "_shunt" or value == "_balancing" then
--         address.rmempty = true
--         port.rmempty = true
--     end
--     return value
-- end

return m
