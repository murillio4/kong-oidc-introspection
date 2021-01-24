local BasePlugin = require("kong.plugins.base_plugin")
local Access = require("kong.plugins.openidc.access")

local kong = kong
local ngx = ngx

local log = ngx.log
local DEBUG = ngx.DEBUG
local ERROR = ngx.ERR
local WARN = ngx.WARN

local OpenidcHandler = BasePlugin:extend()

OpenidcHandler.PRIORITY = 1001
OpenidcHandler.VERSION = "0.1.0"

function OpenidcHandler:new()
  OpenidcHandler.super.new(self, "kong-openidc")
end


function OpenidcHandler:init_worker()
  OpenidcHandler.super.init_worker(self)
end

function OpenidcHandler:access(conf)
  OpenidcHandler.super.access(self)

  return Access:start(conf)
end

return OpenidcHandler;