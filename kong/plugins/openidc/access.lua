local openidc = require "resty.openidc"

local kong = kong
local log = kong.log

local Access = {}

local function exit_40x(code, err)
    return kong.response.exit(code, err)
end

function Access:start(config)
    log.debug("[access.lua] : Starting bearer jwt token validation")
    local res, err = openidc.bearer_jwt_verify(config)

    if err or not res then
        return exit_40x(401, "Unauthenticated")
    end

    if config.audience and res.aud ~= config.audience then
        return exit_40x(403, "Unauthorized")
    end
end

return Access