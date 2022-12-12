#!/usr/bin/lua

require 'nixio'
require 'luci.sys'
local luci = luci
local ucic = luci.model.uci.cursor()
local jsonc = require "luci.jsonc"
local name = 'myproxy'
local arg1 = arg[1]

local reboot = 0
local geoip_update = 0
local geosite_update = 0
local v2ray_asset_location = ucic:get_first(name, 'global_rules', "singbox_location_asset", "/usr/share/singbox/")

-- Custom geo file
-- local geoip_api = ucic:get_first(name, 'global_rules', "geoip_url", "https://github.com/SagerNet/sing-geoip/releases/latest")
local geoip_api = "https://api.github.com/repos/SagerNet/sing-geoip/releases/latest"
-- local geosite_api = ucic:get_first(name, 'global_rules', "geosite_url", "https://github.com/SagerNet/sing-geosite/releases/latest")
local geosite_api = "https://api.github.com/repos/SagerNet/sing-geosite/releases/latest" 
--

local log = function(...)
    if arg1 then
        local result = os.date("%Y-%m-%d %H:%M:%S: ") .. table.concat({...}, " ")
        if arg1 == "log" then
            local f, err = io.open("/tmp/log/myproxy.log", "a")
            if f and err == nil then
                f:write(result .. "\n")
                f:close()
            end
        elseif arg1 == "print" then
            print(result)
        end
    end
end

-- trim
local function trim(text)
    if not text or text == "" then return "" end
    return (string.gsub(text, "^%s*(.-)%s*$", "%1"))
end

-- curl
local function curl(url, file)
	local cmd = "curl -skL -w %{http_code} --retry 3 --connect-timeout 3 '" .. url .. "'"
	if file then
		cmd = cmd .. " -o " .. file
	end
	local stdout = luci.sys.exec(cmd)

	if file then
		return tonumber(trim(stdout))
	else
		return trim(stdout)
	end
end

--获取geoip
local function fetch_geoip()
	--请求geoip
	xpcall(function()
		local json_str = curl(geoip_api)
		-- log(json_str)
		local json = jsonc.parse(json_str)
		if json.tag_name and json.assets then
			for _, v in ipairs(json.assets) do
				if v.name and v.name == "geoip.db.sha256sum" then
					local sret = curl(v.browser_download_url, "/tmp/geoip.db.sha256sum")
					if sret == 200 then
						local f = io.open("/tmp/geoip.db.sha256sum", "r")
						local content = f:read()
						f:close()
						f = io.open("/tmp/geoip.db.sha256sum", "w")
						f:write(content:gsub("geoip.db", "/tmp/geoip.db"), "")
						f:close()

						if nixio.fs.access(v2ray_asset_location .. "geoip.db") then
							luci.sys.call(string.format("cp -f %s %s", v2ray_asset_location .. "geoip.db", "/tmp/geoip.db"))
							if luci.sys.call('sha256sum -c /tmp/geoip.db.sha256sum > /dev/null 2>&1') == 0 then
								log("geoip 版本一致，无需更新。")
								return 1
							end
						end
						for _2, v2 in ipairs(json.assets) do
							if v2.name and v2.name == "geoip.db" then
								sret = curl(v2.browser_download_url, "/tmp/geoip.db")
								if luci.sys.call('sha256sum -c /tmp/geoip.db.sha256sum > /dev/null 2>&1') == 0 then
									luci.sys.call(string.format("mkdir -p %s && cp -f %s %s", v2ray_asset_location, "/tmp/geoip.db", v2ray_asset_location .. "geoip.db"))
									luci.sys.call(string.format("echo %s > /etc/singbox/geo_ip_version",json.tag_name))
									reboot = 1
									log("geoip 更新成功。")
									return 1
								else
									log("geoip 更新失败，请稍后再试。")
								end
								break
							end
						end
					end
					break
				end
			end
		end
	end,
	function(e)
	end)

	return 0
end

--获取geosite
local function fetch_geosite()
	--请求geosite
	xpcall(function()
		local json_str = curl(geosite_api)
		local json = jsonc.parse(json_str)
		if json.tag_name and json.assets then
			for _, v in ipairs(json.assets) do
				if v.name and v.name == "geosite.db.sha256sum" then
					local sret = curl(v.browser_download_url, "/tmp/geosite.db.sha256sum")
					if sret == 200 then
						local f = io.open("/tmp/geosite.db.sha256sum", "r")
						local content = f:read()
						f:close()
						f = io.open("/tmp/geosite.db.sha256sum", "w")
						f:write(content:gsub("geosite.db", "/tmp/geosite.db"), "")
						f:close()

						if nixio.fs.access(v2ray_asset_location .. "geosite.db") then
							luci.sys.call(string.format("cp -f %s %s", v2ray_asset_location .. "geosite.db", "/tmp/geosite.db"))
							if luci.sys.call('sha256sum -c /tmp/geosite.db.sha256sum > /dev/null 2>&1') == 0 then
								log("geosite 版本一致，无需更新。")
								return 1
							end
						end
						for _2, v2 in ipairs(json.assets) do
							if v2.name and v2.name == "geosite.db" then
								sret = curl(v2.browser_download_url, "/tmp/geosite.db")
								if luci.sys.call('sha256sum -c /tmp/geosite.db.sha256sum > /dev/null 2>&1') == 0 then
									luci.sys.call(string.format("mkdir -p %s && cp -f %s %s", v2ray_asset_location, "/tmp/geosite.db", v2ray_asset_location .. "geosite.db"))
									luci.sys.call(string.format("echo %s > /etc/singbox/geo_site_version",json.tag_name))
									reboot = 1
									log("geosite 更新成功。")
									return 1
								else
									log("geosite 更新失败，请稍后再试。")
								end
								break
							end
						end
					end
					break
				end
			end
		end
	end,
	function(e)
	end)

	return 0
end

if arg[2] then
	if arg[2]:find("geoip") then
		geoip_update = 1
	end
	if arg[2]:find("geosite") then
		geosite_update = 1
	end
else
	geoip_update = ucic:get_first(name, 'global_rules', "geoip_update", 1)
	geosite_update = ucic:get_first(name, 'global_rules', "geosite_update", 1)
end
if geoip_update == 0 and geosite_update == 0 then
	os.exit(0)
end

log("开始更新规则...")

if tonumber(geoip_update) == 1 then
	log("geoip 开始更新...")
	local status = fetch_geoip()
	os.remove("/tmp/geoip.db")
	os.remove("/tmp/geoip.db.sha256sum")
end

if tonumber(geosite_update) == 1 then
	log("geosite 开始更新...")
	local status = fetch_geosite()
	os.remove("/tmp/geosite.db")
	os.remove("/tmp/geosite.db.sha256sum")
end

ucic:set(name, ucic:get_first(name, 'global_rules'), "geoip_update", geoip_update)
ucic:set(name, ucic:get_first(name, 'global_rules'), "geosite_update", geosite_update)
ucic:save(name)
luci.sys.call("uci commit " .. name)

if reboot == 1 then
	log("重启服务，应用新的规则。")
	-- luci.sys.call("/usr/share/" .. name .. "/iptables.sh flush_ipset > /dev/null 2>&1 &")
end
log("规则更新完毕...")
