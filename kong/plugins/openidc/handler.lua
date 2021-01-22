local b64 = ngx.encode_base64
local unb64 = ngx.decode_base64
local kong = kong
local ngx = ngx

local log = ngx.log
local DEBUG = ngx.DEBUG
local ERROR = ngx.ERR
local WARN = ngx.WARN

local OpenidcHandler = {
  PRIORITY = 1003,
  VERSION = "0.1.0",
}

-- local function openidc_cache_get(type, key)
--   local dict = ngx.shared[type]
--   local value
--   if dict then
--     value = dict:get(key)
--     if value then log(DEBUG, "cache hit: type=", type, " key=", key) end
--   end
--   return value
-- end

-- -- set value in server-wide cache if available
-- local function openidc_cache_set(type, key, value, exp)
--   local dict = ngx.shared[type]
--   if dict and (exp > 0) then
--     local success, err, forcible = dict:set(key, value, exp)
--     log(DEBUG, "cache set: success=", success, " err=", err, " forcible=", forcible)
--   end
-- end

-- -- perform base64url decoding
-- local function openidc_base64_url_decode(input)
--   local reminder = #input % 4
--   if reminder > 0 then
--     local padlen = 4 - reminder
--     input = input .. string.rep('=', padlen)
--   end
--   input = input:gsub('%-', '+'):gsub('_', '/')
--   return unb64(input)
-- end

-- -- is the JWT signing algorithm one that has been expected?
-- local function is_algorithm_expected(jwt_header, expected_algs)
--   if expected_algs == nil or not jwt_header or not jwt_header.alg then
--     return true
--   end
--   if type(expected_algs) == 'string' then
--     expected_algs = { expected_algs }
--   end
--   for _, alg in ipairs(expected_algs) do
--     if alg == jwt_header.alg then
--       return true
--     end
--   end
--   return false
-- end

-- local function openidc_load_jwt_none_alg(enc_hdr, enc_payload)
--   local header = cjson_s.decode(openidc_base64_url_decode(enc_hdr))
--   local payload = cjson_s.decode(openidc_base64_url_decode(enc_payload))
--   if header and payload and header.alg == "none" then
--     return {
--       raw_header = enc_hdr,
--       raw_payload = enc_payload,
--       header = header,
--       payload = payload,
--       signature = ''
--     }
--   end
--   return nil
-- end

-- -- does lua-resty-jwt and/or we know how to handle the algorithm of the JWT?
-- local function is_algorithm_supported(jwt_header)
--   return jwt_header and jwt_header.alg and (jwt_header.alg == "none"
--       or string.sub(jwt_header.alg, 1, 2) == "RS"
--       or string.sub(jwt_header.alg, 1, 2) == "HS")
-- end

-- local function openidc_configure_timeouts(httpc, timeout)
--   if timeout then
--     if type(timeout) == "table" then
--       local r, e = httpc:set_timeouts(timeout.connect or 0, timeout.send or 0, timeout.read or 0)
--     else
--       local r, e = httpc:set_timeout(timeout)
--     end
--   end
-- end

-- -- Set outgoing proxy options
-- local function openidc_configure_proxy(httpc, proxy_opts)
--   if httpc and proxy_opts and type(proxy_opts) == "table" then
--     log(DEBUG, "openidc_configure_proxy : use http proxy")
--     httpc:set_proxy_options(proxy_opts)
--   else
--     log(DEBUG, "openidc_configure_proxy : don't use http proxy")
--   end
-- end

-- local function decorate_request(http_request_decorator, req)
--   return http_request_decorator and http_request_decorator(req) or req
-- end

-- local function openidc_parse_json_response(response, ignore_body_on_success)
--   local ignore_body_on_success = ignore_body_on_success or false

--   local err
--   local res

--   -- check the response from the OP
--   if response.status ~= 200 then
--     err = "response indicates failure, status=" .. response.status .. ", body=" .. response.body
--   else
--     if ignore_body_on_success then
--       return nil, nil
--     end

--     -- decode the response and extract the JSON object
--     res = cjson_s.decode(response.body)

--     if not res then
--       err = "JSON decoding failed"
--     end
--   end

--   return res, err
-- end

-- -- get the Discovery metadata from the specified URL
-- local function openidc_discover(url, ssl_verify, keepalive, timeout, exptime, proxy_opts, http_request_decorator)
--   log(DEBUG, "openidc_discover: URL is: " .. url)

--   local json, err
--   local v = openidc_cache_get("discovery", url)
--   if not v then

--     log(DEBUG, "discovery data not in cache, making call to discovery endpoint")
--     -- make the call to the discovery endpoint
--     local httpc = http.new()
--     openidc_configure_timeouts(httpc, timeout)
--     openidc_configure_proxy(httpc, proxy_opts)
--     local res, error = httpc:request_uri(url, decorate_request(http_request_decorator, {
--       ssl_verify = (ssl_verify ~= "no"),
--       keepalive = (keepalive ~= "no")
--     }))
--     if not res then
--       err = "accessing discovery url (" .. url .. ") failed: " .. error
--       log(ERROR, err)
--     else
--       log(DEBUG, "response data: " .. res.body)
--       json, err = openidc_parse_json_response(res)
--       if json then
--         openidc_cache_set("discovery", url, cjson.encode(json), exptime or 24 * 60 * 60)
--       else
--         err = "could not decode JSON from Discovery data" .. (err and (": " .. err) or '')
--         log(ERROR, err)
--       end
--     end

--   else
--     json = cjson.decode(v)
--   end

--   return json, err
-- end

-- -- turn a discovery url set in the opts dictionary into the discovered information
-- local function openidc_ensure_discovered_data(opts)
--   local err
--   if type(opts.discovery) == "string" then
--     local discovery
--     discovery, err = openidc_discover(opts.discovery, opts.ssl_verify, opts.keepalive, opts.timeout, opts.jwk_expires_in, opts.proxy_opts,
--                                       opts.http_request_decorator)
--     if not err then
--       opts.discovery = discovery
--     end
--   end
--   return err
-- end

-- -- is the JWT signing algorithm an asymmetric one whose key might be
-- -- obtained from the discovery endpoint?
-- local function uses_asymmetric_algorithm(jwt_header)
--   return string.sub(jwt_header.alg, 1, 2) == "RS"
-- end

-- local function openidc_jwks(url, force, ssl_verify, keepalive, timeout, exptime, proxy_opts, http_request_decorator)
--   log(DEBUG, "openidc_jwks: URL is: " .. url .. " (force=" .. force .. ") (decorator=" .. (http_request_decorator and type(http_request_decorator) or "nil"))

--   local json, err, v

--   if force == 0 then
--     v = openidc_cache_get("jwks", url)
--   end

--   if not v then

--     log(DEBUG, "cannot use cached JWKS data; making call to jwks endpoint")
--     -- make the call to the jwks endpoint
--     local httpc = http.new()
--     openidc_configure_timeouts(httpc, timeout)
--     openidc_configure_proxy(httpc, proxy_opts)
--     local res, error = httpc:request_uri(url, decorate_request(http_request_decorator, {
--       ssl_verify = (ssl_verify ~= "no"),
--       keepalive = (keepalive ~= "no")
--     }))
--     if not res then
--       err = "accessing jwks url (" .. url .. ") failed: " .. error
--       log(ERROR, err)
--     else
--       log(DEBUG, "response data: " .. res.body)
--       json, err = openidc_parse_json_response(res)
--       if json then
--         openidc_cache_set("jwks", url, cjson.encode(json), exptime or 24 * 60 * 60)
--       end
--     end

--   else
--     json = cjson.decode(v)
--   end

--   return json, err
-- end

-- local function get_jwk(keys, kid)

--   local rsa_keys = {}
--   for _, value in pairs(keys) do
--     if value.kty == "RSA" and (not value.use or value.use == "sig") then
--       table.insert(rsa_keys, value)
--     end
--   end

--   if kid == nil then
--     if #rsa_keys == 1 then
--       log(DEBUG, "returning only RSA key of JWKS for keyid-less JWT")
--       return rsa_keys[1], nil
--     else
--       return nil, "JWT doesn't specify kid but the keystore contains multiple RSA keys"
--     end
--   end
--   for _, value in pairs(rsa_keys) do
--     if value.kid == kid then
--       return value, nil
--     end
--   end

--   return nil, "RSA key with id " .. kid .. " not found"
-- end

-- local function split_by_chunk(text, chunkSize)
--   local s = {}
--   for i = 1, #text, chunkSize do
--     s[#s + 1] = text:sub(i, i + chunkSize - 1)
--   end
--   return s
-- end

-- local function openidc_pem_from_x5c(x5c)
--   -- TODO check x5c length
--   log(DEBUG, "Found x5c, getting PEM public key from x5c entry of json public key")
--   local chunks = split_by_chunk(b64(openidc_base64_url_decode(x5c[1])), 64)
--   local pem = "-----BEGIN CERTIFICATE-----\n" ..
--       table.concat(chunks, "\n") ..
--       "\n-----END CERTIFICATE-----"
--   log(DEBUG, "Generated PEM key from x5c:", pem)
--   return pem
-- end

-- local function encode_length(length)
--   if length < 0x80 then
--     return string.char(length)
--   elseif length < 0x100 then
--     return string.char(0x81, length)
--   elseif length < 0x10000 then
--     return string.char(0x82, math.floor(length / 0x100), length % 0x100)
--   end
--   error("Can't encode lengths over 65535")
-- end

-- local function encode_sequence(array, of)
--   local encoded_array = array
--   if of then
--     encoded_array = {}
--     for i = 1, #array do
--       encoded_array[i] = of(array[i])
--     end
--   end
--   encoded_array = table.concat(encoded_array)

--   return string.char(0x30) .. encode_length(#encoded_array) .. encoded_array
-- end

-- local function encode_binary_integer(bytes)
--   if bytes:byte(1) > 127 then
--     -- We currenly only use this for unsigned integers,
--     -- however since the high bit is set here, it would look
--     -- like a negative signed int, so prefix with zeroes
--     bytes = "\0" .. bytes
--   end
--   return "\2" .. encode_length(#bytes) .. bytes
-- end

-- local function encode_sequence_of_integer(array)
--   return encode_sequence(array, encode_binary_integer)
-- end

-- local wrap = ('.'):rep(64)
-- local envelope = "-----BEGIN %s-----\n%s\n-----END %s-----\n"

-- local function der2pem(data, typ)
--   typ = typ:upper() or "CERTIFICATE"
--   data = b64(data)
--   return string.format(envelope, typ, data:gsub(wrap, '%0\n', (#data - 1) / 64), typ)
-- end

-- local function encode_bit_string(array)
--   local s = "\0" .. array -- first octet holds the number of unused bits
--   return "\3" .. encode_length(#s) .. s
-- end

-- local function openidc_pem_from_rsa_n_and_e(n, e)
--   log(DEBUG, "getting PEM public key from n and e parameters of json public key")

--   local der_key = {
--     openidc_base64_url_decode(n), openidc_base64_url_decode(e)
--   }
--   local encoded_key = encode_sequence_of_integer(der_key)
--   local pem = der2pem(encode_sequence({
--     encode_sequence({
--       "\6\9\42\134\72\134\247\13\1\1\1" -- OID :rsaEncryption
--           .. "\5\0" -- ASN.1 NULL of length 0
--     }),
--     encode_bit_string(encoded_key)
--   }), "PUBLIC KEY")
--   log(DEBUG, "Generated pem key from n and e: ", pem)
--   return pem
-- end

-- local function openidc_pem_from_jwk(opts, kid)
--   local err = openidc_ensure_discovered_data(opts)
--   if err then
--     return nil, err
--   end

--   if not opts.discovery.jwks_uri or not (type(opts.discovery.jwks_uri) == "string") or (opts.discovery.jwks_uri == "") then
--     return nil, "opts.discovery.jwks_uri is not present or not a string"
--   end

--   local cache_id = opts.discovery.jwks_uri .. '#' .. (kid or '')
--   local v = openidc_cache_get("jwks", cache_id)

--   if v then
--     return v
--   end

--   local jwk, jwks

--   for force = 0, 1 do
--     jwks, err = openidc_jwks(opts.discovery.jwks_uri, force, opts.ssl_verify, opts.keepalive, opts.timeout, opts.jwk_expires_in, opts.proxy_opts,
--                              opts.http_request_decorator)
--     if err then
--       return nil, err
--     end

--     jwk, err = get_jwk(jwks.keys, kid)

--     if jwk and not err then
--       break
--     end
--   end

--   if err then
--     return nil, err
--   end

--   local pem
--   -- TODO check x5c length
--   if jwk.x5c then
--     pem = openidc_pem_from_x5c(jwk.x5c)
--   elseif jwk.kty == "RSA" and jwk.n and jwk.e then
--     pem = openidc_pem_from_rsa_n_and_e(jwk.n, jwk.e)
--   else
--     return nil, "don't know how to create RSA key/cert for " .. cjson.encode(jwk)
--   end

--   openidc_cache_set("jwks", cache_id, pem, opts.jwk_expires_in or 24 * 60 * 60)
--   return pem
-- end

-- -- parse a JWT and verify its signature (if present)
-- local function openidc_load_jwt_and_verify_crypto(opts, jwt_string, asymmetric_secret,
--   symmetric_secret, expected_algs, ...)
--     local r_jwt = require("resty.jwt")
--     local enc_hdr, enc_payload, enc_sign = string.match(jwt_string, '^(.+)%.(.+)%.(.*)$')
--     if enc_payload and (not enc_sign or enc_sign == "") then
--       local jwt = openidc_load_jwt_none_alg(enc_hdr, enc_payload)
--       if jwt then
--         if opts.accept_none_alg then
--           log(DEBUG, "accept JWT with alg \"none\" and no signature")
--           return jwt
--         else
--           return jwt, "token uses \"none\" alg but accept_none_alg is not enabled"
--         end
--       end -- otherwise the JWT is invalid and load_jwt produces an error
--     end
  
--     local jwt_obj = r_jwt:load_jwt(jwt_string, nil)
--     if not jwt_obj.valid then
--       local reason = "invalid jwt"
--       if jwt_obj.reason then
--         reason = reason .. ": " .. jwt_obj.reason
--       end
--       return nil, reason
--     end
  
--     if not is_algorithm_expected(jwt_obj.header, expected_algs) then
--       local alg = jwt_obj.header and jwt_obj.header.alg or "no algorithm at all"
--       return nil, "token is signed by unexpected algorithm \"" .. alg .. "\""
--     end
  
--     local secret
--     if is_algorithm_supported(jwt_obj.header) then
--       if uses_asymmetric_algorithm(jwt_obj.header) then
--         if opts.secret then
--           log(WARN, "using deprecated option `opts.secret` for asymmetric key; switch to `opts.public_key` instead")
--         end
--         secret = asymmetric_secret or opts.secret
--         if not secret and opts.discovery then
--           log(DEBUG, "using discovery to find key")
--           local err
--           secret, err = openidc_pem_from_jwk(opts, jwt_obj.header.kid)
  
--           if secret == nil then
--             log(ERROR, err)
--             return nil, err
--           end
--         end
--       else
--         if opts.secret then
--           log(WARN, "using deprecated option `opts.secret` for symmetric key; switch to `opts.symmetric_key` instead")
--         end
--         secret = symmetric_secret or opts.secret
--       end
--     end
  
--     if #{ ... } == 0 then
--       -- an empty list of claim specs makes lua-resty-jwt add default
--       -- validators for the exp and nbf claims if they are
--       -- present. These validators need to know the configured slack
--       -- value
--       local jwt_validators = require("resty.jwt-validators")
--       jwt_validators.set_system_leeway(opts.iat_slack and opts.iat_slack or 120)
--     end
  
--     jwt_obj = r_jwt:verify_jwt_obj(secret, jwt_obj, ...)
--     if jwt_obj then
--       log(DEBUG, "jwt: ", cjson.encode(jwt_obj), " ,valid: ", jwt_obj.valid, ", verified: ", jwt_obj.verified)
--     end
--     if not jwt_obj.verified then
--       local reason = "jwt signature verification failed"
--       if jwt_obj.reason then
--         reason = reason .. ": " .. jwt_obj.reason
--       end
--       return jwt_obj, reason
--     end
--     return jwt_obj
--   end

-- -- main routine for OAuth 2.0 JWT token validation
-- -- optional args are claim specs, see jwt-validators in resty.jwt
-- local function jwt_verify(access_token, opts, ...)
--   local err
--   local json

--   local slack = opts.iat_slack and opts.iat_slack or 120
--   -- see if we've previously cached the validation result for this access token
--   local v = openidc_cache_get("introspection", access_token)
--   if not v then
--     local jwt_obj
--     jwt_obj, err = openidc_load_jwt_and_verify_crypto(opts, access_token, opts.public_key, opts.symmetric_key,
--       opts.token_signing_alg_values_expected, ...)
--     if not err then
--       json = jwt_obj.payload
--       log(DEBUG, "jwt: ", cjson.encode(json))

--       local ttl = json.exp and json.exp - ngx.time() or 120
--       openidc_cache_set("introspection", access_token, cjson.encode(json), ttl)
--     end

--   else
--     -- decode from the cache
--     json = cjson.decode(v)
--   end

--   -- check the token expiry
--   if json then
--     if json.exp and json.exp + slack < ngx.time() then
--       log(ERROR, "token expired: json.exp=", json.exp, ", ngx.time()=", ngx.time())
--       err = "JWT expired"
--     end
--   end

--   return json, err
-- end

-- local function get_first(table_or_string)
--   local res = table_or_string
--   if table_or_string and type(table_or_string) == 'table' then
--     res = table_or_string[1]
--   end
--   return res
-- end

-- -- get an OAuth 2.0 bearer access token from the HTTP request
-- local function openidc_get_bearer_access_token(opts)

--   local err

--   local accept_token_as = opts.auth_accept_token_as or "header"

--   -- get the access token from the Authorization header
--   local headers = ngx.req.get_headers()
--   local header_name = opts.auth_accept_token_as_header_name or "Authorization"
--   local header = get_first(headers[header_name])

--   if header == nil or header:find(" ") == nil then
--     err = "no Authorization header found"
--     log(ERROR, err)
--     return nil, err
--   end

--   local divider = header:find(' ')
--   if string.lower(header:sub(0, divider - 1)) ~= string.lower("Bearer") then
--     err = "no Bearer authorization header value found"
--     log(ERROR, err)
--     return nil, err
--   end

--   local access_token = header:sub(divider + 1)
--   if access_token == nil then
--     err = "no Bearer access token value found"
--     log(ERROR, err)
--     return nil, err
--   end

--   return access_token, err
-- end

-- local function bearer_jwt_verify(opts, ...)
--   local json

--   -- get the access token from the request
--   local access_token, err = openidc_get_bearer_access_token(opts)
--   if access_token == nil then
--     return nil, err
--   end

--   log(DEBUG, "access_token: ", access_token)

--   json, err = jwt_verify(access_token, opts, ...)
--   return json, err, access_token
-- end

function OpenidcHandler:access(conf)
  if not conf.run_on_preflight and kong.request.get_method() == "OPTIONS" then
    return
  end

  local res, err = require("resty.openidc"):bearer_jwt_verify(conf)
  
  if err then
    log(ERROR, err)
    return kong.response.exit(401, {message = err })
  end
end

return OpenidcHandler;