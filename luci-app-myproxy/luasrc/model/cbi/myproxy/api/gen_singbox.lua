module("luci.model.cbi.myproxy.api.gen_singbox", package.seeall)
local api = require "luci.model.cbi.myproxy.api.api"

local var = api.get_args(arg)
local flag = var["-flag"]
local node_id = var["-node"]
local tcp_proxy_way = var["-tcp_proxy_way"]
local redir_port = var["-redir_port"]
local sniffing = var["-sniffing"]
local route_only = var["-route_only"]
local buffer_size = var["-buffer_size"]
local local_socks_address = var["-local_socks_address"] or "0.0.0.0"
local local_socks_port = var["-local_socks_port"]
local local_socks_username = var["-local_socks_username"]
local local_socks_password = var["-local_socks_password"]
local local_http_address = var["-local_http_address"] or "0.0.0.0"
local local_http_port = var["-local_http_port"]
local local_http_username = var["-local_http_username"]
local local_http_password = var["-local_http_password"]
local loglevel = var["-loglevel"] or "warning"
local new_port
--++
local uci = api.uci
local sys = api.sys
local jsonc = api.jsonc
local appname = api.appname
local fs = api.fs
local dns = nil
local fakedns = nil
local inbounds = {}
local outbounds = {}
local routing = nil
local finalOutboundTag = nil

local dns_shunt_rules_list = {}
local dns_detour_node_list = {}

local usedNode = {}

local function get_new_port()
    if new_port then
        new_port = tonumber(sys.exec(string.format("echo -n $(/usr/share/%s/app.sh get_new_port %s tcp)", appname, new_port + 1)))
    else
        new_port = tonumber(sys.exec(string.format("echo -n $(/usr/share/%s/app.sh get_new_port auto tcp)", appname)))
    end
    return new_port
end

-- local function get_domain_excluded()
--     local path = string.format("/usr/share/%s/domains_excluded", appname)
--     local content = fs.readfile(path)
--     if not content then return nil end
--     local hosts = {}
--     string.gsub(content, '[^' .. "\n" .. ']+', function(w)
--         local s = w:gsub("^%s*(.-)%s*$", "%1") -- Trim
--         if s == "" then return end
--         if s:find("#") and s:find("#") == 1 then return end
--         if not s:find("#") or s:find("#") ~= 1 then table.insert(hosts, s) end
--     end)
--     if #hosts == 0 then hosts = nil end
--     return hosts
-- end

-- function gen_outbound(node, tag, proxy_table)
--     local proxy = 0
--     local proxy_tag = "nil"
--     if proxy_table ~= nil and type(proxy_table) == "table" then
--         proxy = proxy_table.proxy or 0
--         proxy_tag = proxy_table.tag or "nil"
--     end
--     local result = nil
--     if node and node ~= "nil" then
--         local node_id = node[".name"]
--         if tag == nil then
--             tag = node_id
--         end

--         if node.type == "V2ray" or node.type == "Xray" then
--             proxy = 0
--             if proxy_tag ~= "nil" then
--                 node.proxySettings = {
--                     tag = proxy_tag,
--                     transportLayer = true
--                 }
--             end
--         end

--         if node.type ~= "V2ray" and node.type ~= "Xray" and node.type ~= "sing-box" then
--             local relay_port = node.port
--             new_port = get_new_port()
--             sys.call(string.format('/usr/share/%s/app.sh run_socks "%s"> /dev/null',
--                 appname,
--                 string.format("flag=%s node=%s bind=%s socks_port=%s config_file=%s relay_port=%s",
--                     new_port, --flag
--                     node_id, --node
--                     "127.0.0.1", --bind
--                     new_port, --socks port
--                     string.format("%s_%s_%s_%s.json", flag, tag, node_id, new_port), --config file
--                     (proxy == 1 and proxy_tag ~= "nil" and relay_port) and tostring(relay_port) or "" --relay port
--                     )
--                 )
--             )
--             node = {}
--             node.protocol = "socks"
--             node.transport = "tcp"
--             node.address = "127.0.0.1"
--             node.port = new_port
--             node.stream_security = "none"
--         else
--             if node.tls and node.tls == "1" then
--                 node.stream_security = "tls"
--                 if node.type == "Xray" and node.xtls and node.xtls == "1" then
--                     node.stream_security = "xtls"
--                 end
--             end
--         end

--         result = {
--             -- _flag_tag = node_id,
--             -- _flag_proxy = proxy,
--             -- _flag_proxy_tag = proxy_tag,
--             tag = tag,
--             proxySettings = node.proxySettings or nil,
--             type = node.protocol,

--         }
--         if (node.protocol == "shadowsocks") then
--             result["server"] =  node.address or nil
--             result["server_port"] = tonumber(node.port) or nil
--             result["method"] = node.method or nil
--             result["password"] =  node.password or ""

--         end

--         -- result = {
--         --     _flag_tag = node_id,
--         --     _flag_proxy = proxy,
--         --     _flag_proxy_tag = proxy_tag,
--         --     tag = tag,
--         --     proxySettings = node.proxySettings or nil,
--         --     protocol = node.protocol,
--         --     mux = (node.stream_security ~= "xtls") and {
--         --         enabled = (node.mux == "1") and true or false,
--         --         concurrency = (node.mux_concurrency) and tonumber(node.mux_concurrency) or 8
--         --     } or nil,
--         --     -- 底层传输配置
--         --     streamSettings = (node.protocol == "vmess" or node.protocol == "vless" or node.protocol == "socks" or node.protocol == "shadowsocks" or node.protocol == "trojan") and {
--         --         network = node.transport,
--         --         security = node.stream_security,
--         --         xtlsSettings = (node.stream_security == "xtls") and {
--         --             serverName = node.tls_serverName,
--         --             allowInsecure = (node.tls_allowInsecure == "1") and true or false
--         --         } or nil,
--         --         tlsSettings = (node.stream_security == "tls") and {
--         --             serverName = node.tls_serverName,
--         --             allowInsecure = (node.tls_allowInsecure == "1") and true or false,
--         --             fingerprint = (node.type == "Xray" and node.fingerprint and node.fingerprint ~= "disable") and node.fingerprint or nil
--         --         } or nil,
--         --         tcpSettings = (node.transport == "tcp" and node.protocol ~= "socks") and {
--         --             header = {
--         --                 type = node.tcp_guise or "none",
--         --                 request = (node.tcp_guise == "http") and {
--         --                     path = node.tcp_guise_http_path or {"/"},
--         --                     headers = {
--         --                         Host = node.tcp_guise_http_host or {}
--         --                     }
--         --                 } or nil
--         --             }
--         --         } or nil,
--         --         kcpSettings = (node.transport == "mkcp") and {
--         --             mtu = tonumber(node.mkcp_mtu),
--         --             tti = tonumber(node.mkcp_tti),
--         --             uplinkCapacity = tonumber(node.mkcp_uplinkCapacity),
--         --             downlinkCapacity = tonumber(node.mkcp_downlinkCapacity),
--         --             congestion = (node.mkcp_congestion == "1") and true or false,
--         --             readBufferSize = tonumber(node.mkcp_readBufferSize),
--         --             writeBufferSize = tonumber(node.mkcp_writeBufferSize),
--         --             seed = (node.mkcp_seed and node.mkcp_seed ~= "") and node.mkcp_seed or nil,
--         --             header = {type = node.mkcp_guise}
--         --         } or nil,
--         --         wsSettings = (node.transport == "ws") and {
--         --             path = node.ws_path or "",
--         --             headers = (node.ws_host ~= nil) and
--         --                 {Host = node.ws_host} or nil,
--         --             maxEarlyData = tonumber(node.ws_maxEarlyData) or nil,
--         --             earlyDataHeaderName = (node.ws_earlyDataHeaderName) and node.ws_earlyDataHeaderName or nil
--         --         } or nil,
--         --         httpSettings = (node.transport == "h2") and {
--         --             path = node.h2_path,
--         --             host = node.h2_host,
--         --             read_idle_timeout = tonumber(node.h2_read_idle_timeout) or nil,
--         --             health_check_timeout = tonumber(node.h2_health_check_timeout) or nil
--         --         } or nil,
--         --         dsSettings = (node.transport == "ds") and
--         --             {path = node.ds_path} or nil,
--         --         quicSettings = (node.transport == "quic") and {
--         --             security = node.quic_security,
--         --             key = node.quic_key,
--         --             header = {type = node.quic_guise}
--         --         } or nil,
--         --         grpcSettings = (node.transport == "grpc") and {
--         --             serviceName = node.grpc_serviceName,
--         --             multiMode = (node.grpc_mode == "multi") and true or nil,
--         --             idle_timeout = tonumber(node.grpc_idle_timeout) or nil,
--         --             health_check_timeout = tonumber(node.grpc_health_check_timeout) or nil,
--         --             permit_without_stream = (node.grpc_permit_without_stream == "1") and true or nil,
--         --             initial_windows_size = tonumber(node.grpc_initial_windows_size) or nil
--         --         } or nil
--         --     } or nil,
--         --     settings = {
--         --         vnext = (node.protocol == "vmess" or node.protocol == "vless") and {
--         --             {
--         --                 address = node.address,
--         --                 port = tonumber(node.port),
--         --                 users = {
--         --                     {
--         --                         id = node.uuid,
--         --                         level = 0,
--         --                         security = (node.protocol == "vmess") and node.security or nil,
--         --                         encryption = node.encryption or "none",
--         --                         flow = node.flow or nil
--         --                     }
--         --                 }
--         --             }
--         --         } or nil,
--         --         servers = (node.protocol == "socks" or node.protocol == "http" or node.protocol == "shadowsocks" or node.protocol == "trojan") and {
--         --             {
--         --                 address = node.address,
--         --                 port = tonumber(node.port),
--         --                 method = node.method or nil,
--         --                 flow = node.flow or nil,
--         --                 ivCheck = (node.protocol == "shadowsocks") and node.iv_check == "1" or nil,
--         --                 uot = (node.protocol == "shadowsocks") and node.uot == "1" or nil,
--         --                 password = node.password or "",
--         --                 users = (node.username and node.password) and {
--         --                     {
--         --                         user = node.username,
--         --                         pass = node.password
--         --                     }
--         --                 } or nil
--         --             }
--         --         } or nil
--         --     }
--         -- }
--         local alpn = {}
--         if node.alpn and node.alpn ~= "default" then
--             string.gsub(node.alpn, '[^' .. "," .. ']+', function(w)
--                 table.insert(alpn, w)
--             end)
--         end
--         if alpn and #alpn > 0 then
--             if result.streamSettings.tlsSettings then
--                 result.streamSettings.tlsSettings.alpn = alpn
--             end
--             if result.streamSettings.xtlsSettings then
--                 result.streamSettings.xtlsSettings.alpn = alpn
--             end
--         end
--     end
--     return result
-- end


function getDNSDetour(id)
    local _node = uci:get_all(appname, id)
    if _node then
        if checkNodeIsOutbounded(_node["remarks"]) then
            return _node["remarks"]
        end
        local _outbound = genOutBound(_node)
        if _outbound then
            table.insert(outbounds,_outbound)
            addNodeToUsedNode(_node)
            return _node["remarks"]
        end
    end

    return nil
end

function getDNSShuntRule(name)
    return dns_shunt_rules_list[name]
end

function getMultiplexSetting(node) 
    if node.mux then
        local ret = {
            enabled = true,
            protocol = node.mux_protocol or "smux",
            max_connections = tonumber(node.mux_max_connections or "4"),
            min_streams = tonumber(node.mux_min_streams or "4"),
            max_streams = tonumber(node.mux_max_streams or "0")
        }
        return ret
    end
    return nil
end

function getTLSSetting(node)
    if node.tls then 
        local tmpalpn = {}
        if node.alpn == "default" then
            tmpalpn= nil
        elseif node.alpn == "h2,http/1.1" then
            tmpalpn[#template+1] = "h2"
            tmpalpn[#template+1] = "http/1.1"
        elseif node.alpn == "h2" then
            tmpalpn[#template+1] = "h2"
        else 
            tmpalpn[#template+1] = "http/1.1"
        end

        local utls = nil
        if node.utls ~= nil and node.utls == 1 then
            utls = {
                enabled = true,
                fingerprint = node.fingerprint or "chrome"
            }
        end

        local ret = {
            enabled = true,
            server_name = node.tls_serverName or "",
            insecure = tls_allowInsecure == 1 or nil,
            alpn = tmpalpn,
            utls = utls
        }
        -- if node.tls_allowInsecure then
        --     ret["insecure"] = true
        -- end
        return ret
    end
    return nil
end

function getV2rayTransport(node)
    local result = {
        type = node.transport
    }
    if node.transport == "http" then
        result["host"] = node.transport_path or ""
        result["path"] = node.transport_path or ""
        result["method"] = node.transport_method or ""
    elseif node.transport == "ws" then
        result["path"] = node.transport_path or ""
        result["max_early_data"] = tonumber(node.ws_maxEarlyData or "0")
    elseif node.transport == "grpc" then
        result["service_name"] = node.grpc_serviceName or ""
    end 
    return result
end


function genOutBound(node,tag) 
    local result = nil
    if node and node ~= "nil" then
        local node_id = node[".name"]
        if tag == nil then
            tag = node["remarks"]
        end
        result = {
            tag = tag,
            type = node.protocol,
            server =  node.address or nil,
            server_port = tonumber(node.port) or nil,
            
            detour = node.dial_detour or nil,
            bind_interface = node.dial_bind_interface or nil,
            inet4_bind_address = node.dial_inet4_bind_address or nil,
            connect_timeout = node.dial_connect_timeout or nil,
            tcp_fast_open = node.dial_tcp_fast_open == 1 or nil,
            udp_fragment = node.dial_udp_fragment == 1 or nil,
        }
        if (node.protocol == "shadowsocks") then
            result["method"] = node.method or nil
            result["password"] =  node.password or ""
            result["multiplex"] = getMultiplexSetting(node)

        elseif node.protocol == "vmess" or node.protocol == "vless" then
            result["uuid"] = node.uuid
            result["multiplex"] = getMultiplexSetting(node)

            if node.protocol == "vmess" then
                result["security"] = node.security
            end
            
            result["tls"] = getTLSSetting(node)
            result["transport"] = getV2rayTransport(node)
        elseif node.protocol == "trojan" then
            result["password"] = node.password or ""
            result["tls"] = getTLSSetting(node)
            result["transport"] = getV2rayTransport(node)
            result["multiplex"] = getMultiplexSetting(node)
        elseif node.protocol == "hysteria" then
            result["up_mbps"] = tonumber(node.hysteria_up_mbps or "0")
            result["down_mbps"] = tonumber(node.hysteria_down_mbps or "0")
            result["obfs"] = node.hysteria_obfs or nil
            if node["hysteria_auth_type"] == "string" then
                result["auth_str"] = node.hysteria_auth_password or ""
            elseif node.hysteria_auth_type == "base64" then
                result["auth"] = node.hysteria_auth_password or ""
            end
            result["recv_window_conn"] = tonumber(node.hysteria_recv_window_conn) or nil
            result["recv_window"] = tonumber(node.hysteria_recv_window) or nil
            result["disable_mtu_discovery"] = node.hysteria_disable_mtu_discovery == 1 or nil
            result["tls"] = getTLSSetting(node)
        end        
    end
    return result
end

function genRouteRule(node,outboundTag,isDnsRule)
    local result = {}

    if node["protocol"] then
        result.protocol = api.clone(node["protocol"])
    end

    if node["network"] then
        result.network = node["network"]
    end

    if node["source_geoip"] then
        result.source_geoip = api.clone(node["souce_geoip"])
    end

    if node["source"] then
        result.source_ip_cidr = api.clone(node["source"])
    end

    if node["sourcePort"] then
        result.source_port = api.clone(node["sourcePort"]) 
    end

    if node["sourcePortRange"] then
        result.source_port_range = api.clone(node["sourcePortRange"])
    end

    if node["domain"] then
        result.domain = api.clone(node["domain"])
    end

    if node["domain_suffix"] then
        result.domain_suffix = api.clone(node["domain_suffix"])
    end

    if node["domain_keyword"] then
        result.domain_keyword = api.clone(node["domain_keyword"])
    end

    if node["domain_regex"] then
        result.domain_regex = api.clone(node["domain_regex"])
    end


    if node["geosite"] then
        local tmp = node["geosite"]
       
        result.geosite =  api.clone(tmp)
    end

    if isDnsRule == false then

        if node["geoip"] then
            local tmp = node["geoip"]
            result.geoip = api.clone(tmp)
        end

        if node["ip_cidr"] then
            result.ip_cidr = api.clone(node["ip_cidr"])
        end        
    end



    if node["port"] then
        result.port = node["port"]
    end

    if node["port_range"] then
        result.port_range = api.clone(node["port_range"])
    end

    if outboundTag then
        result.outbound = outboundTag
    end
    return result
end

function checkNodeIsOutbounded(name) 
    for k,v in pairs(usedNode) do 
        -- log.print("checkNodeIsOutbounded remakrs" .. v["remarks"] .. " name = " .. name)
        if v["remarks"] == name then
            return true
        end
    end
    return false
end

function addNodeToUsedNode(node) 
    usedNode[#usedNode+1] = node
end

if true then
    if local_socks_port then
        local inbound = {
            listen = local_socks_address,
            listen_port = tonumber(local_socks_port),
            type = "socks",
            sniff = true,
            tag = "socks_in"
        }
        if local_socks_username and local_socks_password and local_socks_username ~= "" and local_socks_password ~= "" then
            inbound.users = {
                {
                    username = local_socks_username,
                    password = local_socks_password
                }
            }
        end
        table.insert(inbounds, inbound)
    end
    if local_http_port then
        local inbound = {
            listen = local_http_address,
            plisten_portort = tonumber(local_http_port),
            type = "http"
        }
        if local_http_username and local_http_password and local_http_username ~= "" and local_http_password ~= "" then
            inbound.users = {
                {
                    username = local_http_username,
                    password = local_http_password
                }
            }
        end
        table.insert(inbounds, inbound)
    end

    if redir_port then
        -- log.print("tcp_proxy_way = " .. tcp_proxy_way)
        local inbound = {
            listen_port = tonumber(redir_port),
            listen = "::",
            type = tcp_proxy_way,
            -- sniff = sniffing and true,
            -- sniff_override_destination = true
        }
        if tcp_proxy_way == "tun" then
            local mtu = uci:get_first(appname,"global","tun_mtu","9000")
            local tun_strict_route = uci:get_first(appname,"global","tun_strict_route","1")
            local tun_stack = uci:get_first(appname,"global","tun_stack","system")

            inbound = {
                type =  "tun",
                tag = "tun-in",
                inet4_address =  "172.19.0.1/30",
                interface_name = "utun",
                auto_route = true,
                sniff =  true,
                sniff_override_destination = false,
                mtu = tonumber(mtu),
                strict_route = tun_strict_route == 1 ,
                stack = tun_stack or "system"
            }
        end

        table.insert(inbounds,inbound)

    end

    local nodes = {}
    local allnodes = {}
    local singboxNode = nil

    -- 只有一个Node
    if node_id ~= nil and node_id ~= "singbox_shunt" then
        local node = uci:get_all(appname, node_id)
        local rules = {}
        if node then
            local _outbound = genOutBound(node)
            if _outbound then
                table.insert(outbounds,_outbound)
                local _rule = {
                    inbound = "socks_in",
                    outbound = _outbound.tag
                }
                table.insert(rules,_rule)
            end
        end
        routing = {
            rules = rules
        }
    else
        -- allnodes = api.get_valid_nodes()
        local singboxNodeId = uci:get_first(appname,api.singboxShuntNodeName)
        if singboxNodeId == nil then
            return
        end
        singboxNode = uci:get_all(appname,singboxNodeId)
        
        local node = singboxNode
        local rules = {}
        local default_node_id = node.default_node or "_direct"

        if default_node_id == "_direct" then
            table.insert(outbounds,{
                type =  "direct",
                tag = "default"
            })
            
        elseif default_node_id == "_blackhole" then
            table.insert(outbounds,{
                type = "block",
                tag = "default"
            })
        else 
            local _node = uci:get_all(appname, default_node_id)
            local _outbound = genOutBound(_node,"default")
            if _outbound then
                table.insert(outbounds,_outbound)
            end
        end

        uci:foreach(appname, "shunt_rules", function(e)
            local name = e[".name"]
            dns_shunt_rules_list[name] = e
            local _node_id = singboxNode[name] or "nil"
            local outboundTag
            if _node_id == "_direct" then
                outboundTag = "direct"
            elseif _node_id == "_blackhole" then
                outboundTag = "blackhole"
            elseif _node_id == "_default" then
                outboundTag = "default"
            else
                if _node_id ~= "nil" then
                    local _node = uci:get_all(appname, _node_id)

                    if checkNodeIsOutbounded(_node["remarks"]) == false then 
                        local _outbound = genOutBound(_node)
                        if _outbound then
                            table.insert(outbounds,_outbound)
                            outboundTag = _outbound.tag

                            addNodeToUsedNode(_node)
                        end
                    else
                        outboundTag = _node["remarks"]
                    end

                end
            end
            if outboundTag then
                local _rule = genRouteRule(e,outboundTag,false)
                if _rule then
                    table.insert(rules,_rule)
                end
            end

        end)

        routing = {
            rules = rules,
            final = "default"
        }

        -- if tcp_proxy_way ~= "tun" then
            routing.default_mark = 255
        -- end


    end
end


if flag == "global" then
    local rules = {}
    local servers = {}
    
    uci:foreach(appname, "dnslist", function(e)
        if (e["enable"] == "1") then
            local addr = ""
            if e.protocol == "System" then
                addr = "local"
            elseif e.protocol == "udp" then
                addr = "udp://" .. e.addr .. ":" .. e.port
            elseif e.protocol == "tcp" then
                addr = "tcp://" .. e.addr .. ":" .. e.port
            elseif e.protocol == "https" then
                addr = e.addr
            elseif e.protocol == "tls" then
                addr = "tls://" .. e.addr
            elseif e.protocol == "QUIC" then
                addr = "quic://" .. e.addr .. ":" .. e.port
            elseif e.protocol == "HTTP3" then
                addr = "h3://" .. e.addr 
            else 
                addr = "rcode://" .. e.addr 
            end

            local detour = e.detour
            if detour ~= "direct" and detour ~= "default" then
                -- log.print("dns detour " .. detour)
                detour = getDNSDetour(detour)
                -- log.print("dns detour " .. detour)
            end

            if detour == "default" then
                detour = nil
            end

            local address_resolver = e.address_resolver




            local server = {
                tag = e.remarks,
                address = addr,
                strategy = "ipv4_only",
                address_resolver = address_resolver or nil,
                detour = detour
            }
            table.insert(servers,server)

            if e.rule ~= "nil" then
                local node = getDNSShuntRule(e.rule)
                if node then
                    local nodeRules = genRouteRule(node,nil,true)
                    if (nodeRules) then
                        nodeRules.server = server.tag
                        table.insert(rules,nodeRules)
                    end
                end
            end
        end
    end)

    dns = {
        servers = servers,
        rules = rules
    }

    table.insert(routing.rules, 1, {
        protocol = "dns",
        outbound = "dns-out"
    })

    table.insert(outbounds, {
        type = "dns",
        tag = "dns-out"
    })

    table.insert(inbounds,{
        type = "direct",
        listen = "::",
        listen_port = 53,
        tag = "dns-in"
    })
    
    table.insert(routing.rules,{
        inbound = "dns-in",
        outbound = "dns-out"
    })
end


local v2ray_asset_location = uci:get_first(name, 'global_rules', "singbox_location_asset", "/etc/singbox/")

local tmpgeip = {
    path = v2ray_asset_location .. "geoip.db"
}
routing.geoip = tmpgeip

local tmpgeosite = {
    path = v2ray_asset_location .. "geosite.db"
}

routing.geosite = tmpgeosite

routing.auto_detect_interface = true


if inbounds or outbounds then
    local config = {
        log = {
            --access = string.format("/tmp/etc/%s/%s_access.log", appname, "global"),
            --error = string.format("/tmp/etc/%s/%s_error.log", appname, "global"),
            --dnsLog = true,
            level = loglevel
        },
        -- DNS
        dns = dns,
        -- 传入连接
        inbounds = inbounds,
        -- 传出连接
        outbounds = outbounds,
        -- 路由
        route = routing,
        -- 本地策略
        
    }
    table.insert(outbounds, {
        type = "direct",
        tag = "direct"
    })


    table.insert(outbounds, {
        type = "block",
        tag = "blackhole"
    })
    print(jsonc.stringify(config, 1))
end