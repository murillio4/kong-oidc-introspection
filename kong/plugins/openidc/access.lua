local openidc = require "resty.openidc"

local kong = kong
local log = kong.log

local Access = {}

local function exit_401(err)
    return kong.response.exit(401, err or "not authenticated")
end

function Access:start(config)
    log.debug("[access.lua] : Starting bearer jwt token validation")

    local res, err = openidc.bearer_jwt_verify(config)
    if err then
        return exit_401(err)
    end
end

return Access