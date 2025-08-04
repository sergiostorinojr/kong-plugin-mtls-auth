-- utils
local set_header = kong.service.request.set_header

local function is_empty(s)
    return s == nil or s == ''
end

local function extract_and_add_rdn (t, dn, startPos, endPos)
    local delimiterPos, _ = string.find(dn, "=", startPos)
    if delimiterPos then
        local k = string.sub(dn, startPos, delimiterPos-1)
        local v = string.sub(dn, delimiterPos+1, endPos)
        t[k] = v
    end
end

local function parse_dn (dn)
    local t = {}
    local nextRdn = 1
    while (nextRdn <= #dn) do
        local endOfRdnPos, _ = string.find(dn, "[^\\],", nextRdn)
        if (endOfRdnPos == nil) then
            endOfRdnPos = #dn
        end
        extract_and_add_rdn(t, dn, nextRdn, endOfRdnPos)
        nextRdn = endOfRdnPos + 2
    end
    return t
end

-- Plugin definition for Kong 3.x+
local MtlsAuth = {
    PRIORITY = 975,
    VERSION = "1.0.0",
}

function MtlsAuth:access(conf)
    if ngx.var.ssl_client_verify ~= "SUCCESS" then
        return kong.response.exit(conf.error_response_code, [[{"error":"invalid_request", "error_description": "mTLS client not provided or invalid"}]], {
            ["Content-Type"] = "application/json"
        })
    end

    local cert_dn = parse_dn(ngx.var.ssl_client_s_dn)

    if not is_empty(conf.upstream_cert_header) then
        set_header(conf.upstream_cert_header, ngx.var.ssl_client_escaped_cert)
    end

    if not is_empty(conf.upstream_cert_fingerprint_header) then
        set_header(conf.upstream_cert_fingerprint_header, ngx.var.ssl_client_fingerprint)
    end

    if not is_empty(conf.upstream_cert_serial_header) then
        set_header(conf.upstream_cert_serial_header, ngx.var.ssl_client_serial)
    end

    if not is_empty(conf.upstream_cert_i_dn_header) then
        set_header(conf.upstream_cert_i_dn_header, ngx.var.ssl_client_i_dn)
    end

    if not is_empty(conf.upstream_cert_s_dn_header) then
        set_header(conf.upstream_cert_s_dn_header, ngx.var.ssl_client_s_dn)
    end

    if not is_empty(conf.upstream_cert_cn_header) then
        set_header(conf.upstream_cert_cn_header, cert_dn["CN"])
    end

    if not is_empty(conf.upstream_cert_org_header) then
        set_header(conf.upstream_cert_org_header, cert_dn["O"])
    end
end

return MtlsAuth
