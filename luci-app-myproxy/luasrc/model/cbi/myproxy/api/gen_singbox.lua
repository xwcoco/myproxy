module("luci.model.cbi.myproxy.api.gen_singbox", package.seeall)
local api = require "luci.model.cbi.myproxy.api.api"
local log = require "luci.log"

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

local function get_domain_excluded()
    local path = string.format("/usr/share/%s/domains_excluded", appname)
    local content = fs.readfile(path)
    if not content then return nil end
    local hosts = {}
    string.gsub(content, '[^' .. "\n" .. ']+', function(w)
        local s = w:gsub("^%s*(.-)%s*$", "%1") -- Trim
        if s == "" then return end
        if s:find("#") and s:find("#") == 1 then return end
        if not s:find("#") or s:find("#") ~= 1 then table.insert(hosts, s) end
    end)
    if #hosts == 0 then hosts = nil end
    return hosts
end

function gen_outbound(node, tag, proxy_table)
    local proxy = 0
    local proxy_tag = "nil"
    if proxy_table ~= nil and type(proxy_table) == "table" then
        proxy = proxy_table.proxy or 0
        proxy_tag = proxy_table.tag or "nil"
    end
    local result = nil
    if node and node ~= "nil" then
        local node_id = node[".name"]
        if tag == nil then
            tag = node_id
        end

        if node.type == "V2ray" or node.type == "Xray" then
            proxy = 0
            if proxy_tag ~= "nil" then
                node.proxySettings = {
                    tag = proxy_tag,
                    transportLayer = true
                }
            end
        end

        if node.type ~= "V2ray" and node.type ~= "Xray" and node.type ~= "sing-box" then
            local relay_port = node.port
            new_port = get_new_port()
            sys.call(string.format('/usr/share/%s/app.sh run_socks "%s"> /dev/null',
                appname,
                string.format("flag=%s node=%s bind=%s socks_port=%s config_file=%s relay_port=%s",
                    new_port, --flag
                    node_id, --node
                    "127.0.0.1", --bind
                    new_port, --socks port
                    string.format("%s_%s_%s_%s.json", flag, tag, node_id, new_port), --config file
                    (proxy == 1 and proxy_tag ~= "nil" and relay_port) and tostring(relay_port) or "" --relay port
                    )
                )
            )
            node = {}
            node.protocol = "socks"
            node.transport = "tcp"
            node.address = "127.0.0.1"
            node.port = new_port
            node.stream_security = "none"
        else
            if node.tls and node.tls == "1" then
                node.stream_security = "tls"
                if node.type == "Xray" and node.xtls and node.xtls == "1" then
                    node.stream_security = "xtls"
                end
            end
        end

        result = {
            -- _flag_tag = node_id,
            -- _flag_proxy = proxy,
            -- _flag_proxy_tag = proxy_tag,
            tag = tag,
            proxySettings = node.proxySettings or nil,
            type = node.protocol,

        }
        if (node.protocol == "shadowsocks") then
            result["server"] =  node.address or nil
            result["server_port"] = tonumber(node.port) or nil
            result["method"] = node.method or nil
            result["password"] =  node.password or ""

        end

        -- result = {
        --     _flag_tag = node_id,
        --     _flag_proxy = proxy,
        --     _flag_proxy_tag = proxy_tag,
        --     tag = tag,
        --     proxySettings = node.proxySettings or nil,
        --     protocol = node.protocol,
        --     mux = (node.stream_security ~= "xtls") and {
        --         enabled = (node.mux == "1") and true or false,
        --         concurrency = (node.mux_concurrency) and tonumber(node.mux_concurrency) or 8
        --     } or nil,
        --     -- 底层传输配置
        --     streamSettings = (node.protocol == "vmess" or node.protocol == "vless" or node.protocol == "socks" or node.protocol == "shadowsocks" or node.protocol == "trojan") and {
        --         network = node.transport,
        --         security = node.stream_security,
        --         xtlsSettings = (node.stream_security == "xtls") and {
        --             serverName = node.tls_serverName,
        --             allowInsecure = (node.tls_allowInsecure == "1") and true or false
        --         } or nil,
        --         tlsSettings = (node.stream_security == "tls") and {
        --             serverName = node.tls_serverName,
        --             allowInsecure = (node.tls_allowInsecure == "1") and true or false,
        --             fingerprint = (node.type == "Xray" and node.fingerprint and node.fingerprint ~= "disable") and node.fingerprint or nil
        --         } or nil,
        --         tcpSettings = (node.transport == "tcp" and node.protocol ~= "socks") and {
        --             header = {
        --                 type = node.tcp_guise or "none",
        --                 request = (node.tcp_guise == "http") and {
        --                     path = node.tcp_guise_http_path or {"/"},
        --                     headers = {
        --                         Host = node.tcp_guise_http_host or {}
        --                     }
        --                 } or nil
        --             }
        --         } or nil,
        --         kcpSettings = (node.transport == "mkcp") and {
        --             mtu = tonumber(node.mkcp_mtu),
        --             tti = tonumber(node.mkcp_tti),
        --             uplinkCapacity = tonumber(node.mkcp_uplinkCapacity),
        --             downlinkCapacity = tonumber(node.mkcp_downlinkCapacity),
        --             congestion = (node.mkcp_congestion == "1") and true or false,
        --             readBufferSize = tonumber(node.mkcp_readBufferSize),
        --             writeBufferSize = tonumber(node.mkcp_writeBufferSize),
        --             seed = (node.mkcp_seed and node.mkcp_seed ~= "") and node.mkcp_seed or nil,
        --             header = {type = node.mkcp_guise}
        --         } or nil,
        --         wsSettings = (node.transport == "ws") and {
        --             path = node.ws_path or "",
        --             headers = (node.ws_host ~= nil) and
        --                 {Host = node.ws_host} or nil,
        --             maxEarlyData = tonumber(node.ws_maxEarlyData) or nil,
        --             earlyDataHeaderName = (node.ws_earlyDataHeaderName) and node.ws_earlyDataHeaderName or nil
        --         } or nil,
        --         httpSettings = (node.transport == "h2") and {
        --             path = node.h2_path,
        --             host = node.h2_host,
        --             read_idle_timeout = tonumber(node.h2_read_idle_timeout) or nil,
        --             health_check_timeout = tonumber(node.h2_health_check_timeout) or nil
        --         } or nil,
        --         dsSettings = (node.transport == "ds") and
        --             {path = node.ds_path} or nil,
        --         quicSettings = (node.transport == "quic") and {
        --             security = node.quic_security,
        --             key = node.quic_key,
        --             header = {type = node.quic_guise}
        --         } or nil,
        --         grpcSettings = (node.transport == "grpc") and {
        --             serviceName = node.grpc_serviceName,
        --             multiMode = (node.grpc_mode == "multi") and true or nil,
        --             idle_timeout = tonumber(node.grpc_idle_timeout) or nil,
        --             health_check_timeout = tonumber(node.grpc_health_check_timeout) or nil,
        --             permit_without_stream = (node.grpc_permit_without_stream == "1") and true or nil,
        --             initial_windows_size = tonumber(node.grpc_initial_windows_size) or nil
        --         } or nil
        --     } or nil,
        --     settings = {
        --         vnext = (node.protocol == "vmess" or node.protocol == "vless") and {
        --             {
        --                 address = node.address,
        --                 port = tonumber(node.port),
        --                 users = {
        --                     {
        --                         id = node.uuid,
        --                         level = 0,
        --                         security = (node.protocol == "vmess") and node.security or nil,
        --                         encryption = node.encryption or "none",
        --                         flow = node.flow or nil
        --                     }
        --                 }
        --             }
        --         } or nil,
        --         servers = (node.protocol == "socks" or node.protocol == "http" or node.protocol == "shadowsocks" or node.protocol == "trojan") and {
        --             {
        --                 address = node.address,
        --                 port = tonumber(node.port),
        --                 method = node.method or nil,
        --                 flow = node.flow or nil,
        --                 ivCheck = (node.protocol == "shadowsocks") and node.iv_check == "1" or nil,
        --                 uot = (node.protocol == "shadowsocks") and node.uot == "1" or nil,
        --                 password = node.password or "",
        --                 users = (node.username and node.password) and {
        --                     {
        --                         user = node.username,
        --                         pass = node.password
        --                     }
        --                 } or nil
        --             }
        --         } or nil
        --     }
        -- }
        local alpn = {}
        if node.alpn and node.alpn ~= "default" then
            string.gsub(node.alpn, '[^' .. "," .. ']+', function(w)
                table.insert(alpn, w)
            end)
        end
        if alpn and #alpn > 0 then
            if result.streamSettings.tlsSettings then
                result.streamSettings.tlsSettings.alpn = alpn
            end
            if result.streamSettings.xtlsSettings then
                result.streamSettings.xtlsSettings.alpn = alpn
            end
        end
    end
    return result
end


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
        }
        if (node.protocol == "shadowsocks") then
            result["server"] =  node.address or nil
            result["server_port"] = tonumber(node.port) or nil
            result["method"] = node.method or nil
            result["password"] =  node.password or ""

        end        
    end
    return result
end

function genRouteRule(node,outboundTag)
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

    if node["geoip"] then
        local tmp = node["geoip"]
        result.geoip = api.clone(tmp)
    end

    if node["ip_cidr"] then
        result.ip_cidr = api.clone(node["ip_cidr"])
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
        log.print("checkNodeIsOutbounded remakrs" .. v["remarks"] .. " name = " .. name)
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
            port = tonumber(local_socks_port),
            protocol = "socks",
            settings = {auth = "noauth", udp = true},
            sniffing = {enabled = true, destOverride = {"http", "tls"}}
        }
        if local_socks_username and local_socks_password and local_socks_username ~= "" and local_socks_password ~= "" then
            inbound.settings.auth = "password"
            inbound.settings.accounts = {
                {
                    user = local_socks_username,
                    pass = local_socks_password
                }
            }
        end
        table.insert(inbounds, inbound)
    end
    if local_http_port then
        local inbound = {
            listen = local_http_address,
            port = tonumber(local_http_port),
            protocol = "http",
            settings = {allowTransparent = false}
        }
        if local_http_username and local_http_password and local_http_username ~= "" and local_http_password ~= "" then
            inbound.settings.accounts = {
                {
                    user = local_http_username,
                    pass = local_http_password
                }
            }
        end
        table.insert(inbounds, inbound)
    end

    if redir_port then
        log.print("tcp_proxy_way = " .. tcp_proxy_way)
        local inbound = {
            listen_port = tonumber(redir_port),
            listen = "::",
            type = tcp_proxy_way,
            -- sniff = sniffing and true,
            -- sniff_override_destination = true
        }
        if tcp_proxy_way == "tun" then
            inbound = {
                type =  "tun",
                tag = "tun-in",
                inet4_address =  "172.19.0.1/30",
                auto_route = true,
                sniff =  true,
                sniff_override_destination = false
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
        if node then
            nodes[node_id] = node
        end
    else
        -- allnodes = api.get_valid_nodes()
        local singboxNodeId = uci:get_first(appname,api.singboxShuntNodeName)
        if singboxNodeId == nil then
            log.print("NO Singlebox!")
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
                local _rule = genRouteRule(e,outboundTag)
                if _rule then
                    table.insert(rules,_rule)
                end
            end

        end)

        routing = {
            rules = rules
        }


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
                log.print("dns detour " .. detour)
                detour = getDNSDetour(detour)
                log.print("dns detour " .. detour)
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
                    local nodeRules = genRouteRule(node)
                    if (nodeRules) then
                        nodeRules.server = server.tag
                        table.insert(rules,nodeRules)
                    end
                end
            end
        end
    end)

    table.insert(servers,{
        address = "local",
        tag = "local"
    })

    dns = {
        servers = servers,
        rules = rules
    }

    table.insert(routing.rules, 1, {
        inbound = {
            "dns-in"
        },
        outbound = "dns-out"
    })

    table.insert(outbounds, {
        type = "dns",
        tag = "dns-out"
    })    
end


local tmpgeip = {
    path = "/usr/share/singbox/geoip.db"
}
routing.geoip = tmpgeip

local tmpgeosite = {
    path = "/usr/share/singbox/geosite.db"
}

routing.geosite = tmpgeosite

routing.auto_detect_interface = true


-- if dns_listen_port then
--     table.insert(inbounds, {
--         listen = "127.0.0.1",
--         listen_port = tonumber(dns_listen_port),
--         type = "direct",
--         tag = "dns-in",
--         network = "udp"
    
--     })

--     table.insert(outbounds, {
--         tag = "dns-out",
--         type = "dns",
--     })


-- end

-- if remote_dns_server or remote_dns_doh_url or remote_dns_fake then
--     local rules = {}
--     local _remote_dns_proto

--     if not routing then
--         routing = {
--             domainStrategy = "IPOnDemand",
--             rules = {}
--         }
--     end

--     dns = {
--         tag = "dns-in1",
--         hosts = {},
--         disableCache = (dns_cache and dns_cache == "0") and true or false,
--         disableFallback = true,
--         disableFallbackIfMatch = true,
--         servers = {},
--         clientIp = (remote_dns_client_ip and remote_dns_client_ip ~= "") and remote_dns_client_ip or nil,
--         queryStrategy = (dns_query_strategy and dns_query_strategy ~= "") and dns_query_strategy or "UseIPv4"
--     }

--     local dns_host = ""
--     if flag == "global" then
--         dns_host = uci:get(appname, "@global[0]", "dns_hosts") or ""
--     else
--         flag = flag:gsub("acl_", "")
--         local dns_hosts_mode = uci:get(appname, flag, "dns_hosts_mode") or "default"
--         if dns_hosts_mode == "default" then
--             dns_host = uci:get(appname, "@global[0]", "dns_hosts") or ""
--         elseif dns_hosts_mode == "disable" then
--             dns_host = ""
--         elseif dns_hosts_mode == "custom" then
--             dns_host = uci:get(appname, flag, "dns_hosts") or ""
--         end
--     end
--     if #dns_host > 0 then
--         string.gsub(dns_host, '[^' .. "\r\n" .. ']+', function(w)
--             local host = sys.exec(string.format("echo -n $(echo %s | awk -F ' ' '{print $1}')", w))
--             local key = sys.exec(string.format("echo -n $(echo %s | awk -F ' ' '{print $2}')", w))
--             if host ~= "" and key ~= "" then
--                 dns.hosts[host] = key
--             end
--         end)
--     end

--     if true then
--         local _remote_dns = {
--             _flag = "remote",
--             domains = #dns_remote_domains > 0 and dns_remote_domains or nil
--             --expectIPs = #dns_remote_expectIPs > 0 and dns_remote_expectIPs or nil
--         }

--         if remote_dns_udp_server then
--             _remote_dns.address = remote_dns_udp_server
--             _remote_dns.port = tonumber(remote_dns_port) or 53
--             _remote_dns_proto = "udp"
--         end

--         if remote_dns_tcp_server then
--             _remote_dns.address = remote_dns_tcp_server
--             _remote_dns.port = tonumber(remote_dns_port) or 53
--             _remote_dns_proto = "tcp"
--         end

--         if remote_dns_doh_url and remote_dns_doh_host then
--             if remote_dns_server and remote_dns_doh_host ~= remote_dns_server and not api.is_ip(remote_dns_doh_host) then
--                 dns.hosts[remote_dns_doh_host] = remote_dns_server
--             end
--             _remote_dns.address = remote_dns_doh_url
--             _remote_dns.port = tonumber(remote_dns_port) or 443
--             _remote_dns_proto = "tcp"
--         end

--         if remote_dns_fake then
--             remote_dns_server = "1.1.1.1"
--             fakedns = {}
--             fakedns[#fakedns + 1] = {
--                 ipPool = "198.18.0.0/16",
--                 poolSize = 65535
--             }
--             if dns_query_strategy == "UseIP" then
--                 fakedns[#fakedns + 1] = {
--                     ipPool = "fc00::/18",
--                     poolSize = 65535
--                 }
--             end
--             _remote_dns.address = "fakedns"
--         end

--         table.insert(dns.servers, _remote_dns)
--     end

--     if true then
--         local nodes_domain_text = sys.exec('uci show passwall2 | grep ".address=" | cut -d "\'" -f 2 | grep "[a-zA-Z]$" | sort -u')
--         string.gsub(nodes_domain_text, '[^' .. "\r\n" .. ']+', function(w)
--             table.insert(dns_direct_domains, "full:" .. w)
--         end)

--         local _direct_dns = {
--             _flag = "direct",
--             domains = #dns_direct_domains > 0 and dns_direct_domains or nil
--             --expectIPs = #dns_direct_expectIPs > 0 and dns_direct_expectIPs or nil
--         }

--         if direct_dns_udp_server then
--             _direct_dns.address = direct_dns_udp_server
--             _direct_dns.port = tonumber(direct_dns_port) or 53
--             table.insert(routing.rules, 1, {
--                 type = "field",
--                 ip = {
--                     direct_dns_udp_server
--                 },
--                 port = tonumber(direct_dns_port) or 53,
--                 network = "udp",
--                 outboundTag = "direct"
--             })
--         end

--         if direct_dns_tcp_server then
--             _direct_dns.address = direct_dns_tcp_server:gsub("tcp://", "tcp+local://")
--             _direct_dns.port = tonumber(direct_dns_port) or 53
--         end

--         if direct_dns_doh_url and direct_dns_doh_host then
--             if direct_dns_server and direct_dns_doh_host ~= direct_dns_server and not api.is_ip(direct_dns_doh_host) then
--                 dns.hosts[direct_dns_doh_host] = direct_dns_server
--             end
--             _direct_dns.address = direct_dns_doh_url:gsub("https://", "https+local://")
--             _direct_dns.port = tonumber(direct_dns_port) or 443
--         end

--         table.insert(dns.servers, _direct_dns)
--     end

--     if dns_listen_port then
--         table.insert(inbounds, {
--             listen = "127.0.0.1",
--             port = tonumber(dns_listen_port),
--             protocol = "dokodemo-door",
--             tag = "dns-in",
--             settings = {
--                 address = remote_dns_server or "1.1.1.1",
--                 port = 53,
--                 network = "tcp,udp"
--             }
--         })

--         table.insert(outbounds, {
--             tag = "dns-out",
--             protocol = "dns",
--             settings = {
--                 address = remote_dns_server or "1.1.1.1",
--                 port = tonumber(remote_dns_port) or 53,
--                 network = _remote_dns_proto or "tcp",
--             }
--         })

--         table.insert(routing.rules, 1, {
--             type = "field",
--             inboundTag = {
--                 "dns-in"
--             },
--             outboundTag = "dns-out"
--         })
--     end

--     local default_dns_flag = "remote"
--     if node_id and redir_port then
--         local node = uci:get_all(appname, node_id)
--         if node.protocol == "_shunt" then
--             if node.default_node == "_direct" then
--                 default_dns_flag = "direct"
--             end
--         end
--     end

--     if dns.servers and #dns.servers > 0 then
--         local dns_servers = nil
--         for index, value in ipairs(dns.servers) do
--             if not dns_servers and value["_flag"] == default_dns_flag then
--                 dns_servers = {
--                     _flag = "default",
--                     address = value.address,
--                     port = value.port
--                 }
--                 break
--             end
--         end
--         if dns_servers then
--             table.insert(dns.servers, 1, dns_servers)
--         end
--     end

--     local default_rule_index = #routing.rules > 0 and #routing.rules or 1
--     for index, value in ipairs(routing.rules) do
--         if value["_flag"] == "default" then
--             default_rule_index = index
--             break
--         end
--     end
--     for index, value in ipairs(rules) do
--         local t = rules[#rules + 1 - index]
--         table.insert(routing.rules, default_rule_index, t)
--     end

--     local dns_hosts_len = 0
--     for key, value in pairs(dns.hosts) do
--         dns_hosts_len = dns_hosts_len + 1
--     end

--     if dns_hosts_len == 0 then
--         dns.hosts = nil
--     end
-- end

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
        fakedns = fakedns,
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
        tag = "block"
    })
    print(jsonc.stringify(config, 1))
end