module("luci.model.cbi.myproxy.api.geofile", package.seeall)
local api = require "luci.model.cbi.myproxy.api.api"

function to_check() 
    
    local geoip_api = "https://api.github.com/repos/SagerNet/sing-geoip/releases/latest"
    local geosite_api = "https://api.github.com/repos/SagerNet/sing-geosite/releases/latest" 

    local geoip_local_version = api.get_local_geoip_version()
    local ip = api.common_to_check(geoip_api,geoip_local_version,"geoip.db")
    local geosite_local_version = api.get_local_geosite_version()
    local site = api.common_to_check(geosite_api,geosite_local_version,"geosite.db")
    return {
        geoip = ip,
        geosite = site
    }

end