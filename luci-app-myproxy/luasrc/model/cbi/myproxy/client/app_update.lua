local api = require "luci.model.cbi.myproxy.api.api"
local appname = api.appname

m = Map(appname)

-- [[ App Settings ]]--
s = m:section(TypedSection, "global_app", translate("App Update"),
              "<font color='red'>" ..
                  translate("Please confirm that your firmware supports FPU.") ..
                  "</font>")
s.anonymous = true
s:append(Template(appname .. "/app_update/v2ray_version"))
-- s:append(Template(appname .. "/app_update/xray_version"))
-- s:append(Template(appname .. "/app_update/brook_version"))
-- s:append(Template(appname .. "/app_update/hysteria_version"))

o = s:option(Value, "singbox_file", translatef("%s App Path", "Sing-box"))
o.default = "/usr/bin/sing-box"
o.rmempty = false



o = s:option(DummyValue, "tips", " ")
o.rawhtml = true
o.cfgvalue = function(t, n)
    return string.format('<font color="red">%s</font>', translate("if you want to run from memory, change the path, /tmp beginning then save the application and update it manually."))
end

return m
