// 共享内存字典（需在 Nginx 配置中定义 zone=vs_ip）
const whiteList = ngx.shared.vs_ip;

// 基础配置（毫秒）
const DEFAULT_TTL_MS = 120 * 60 * 1000; // 2 小时
const TTL_REFRESH_THRESHOLD_MS = 60 * 60 * 1000; // 剩余 1 小时内刷新

function isPositiveInteger(n) {
    return Number.isInteger(n) && n > 0;
}

/**
 * 解析并规范化 TTL（毫秒）。
 * @param {string|number|undefined} rawTtl 原始 TTL
 * @returns {number} 正整数毫秒值，非法时回退默认值
 */
function parseTtlMs(rawTtl) {
    // njs shared dict 的 ttl 参数单位是毫秒；非法值回退默认值。
    const parsed = Number(rawTtl);
    return isPositiveInteger(parsed) ? parsed : DEFAULT_TTL_MS;
}

/**
 * 检查 shared dict 是否已在 Nginx 中完成配置。
 * @returns {boolean}
 */
function ensureStore() {
    return !!whiteList;
}

/**
 * 写入或刷新白名单 IP。
 * @param {string} ip 客户端 IP
 * @param {number|string|undefined} ttlMs 过期时长（毫秒）
 */
function storeIP(ip, ttlMs) {
    const now = Date.now();
    const safeTtlMs = parseTtlMs(ttlMs);
    // value 存绝对过期时间戳，ttl 交给 shared dict 做兜底清理。
    whiteList.set(ip, now + safeTtlMs, safeTtlMs);
}

/**
 * 判断 IP 是否允许访问，并在接近过期时自动续期。
 * @param {string} ip 客户端 IP
 * @returns {boolean}
 */
function isAllowed(ip) {
    if (!ip || !ensureStore()) {
        return false;
    }

    const expireAtRaw = whiteList.get(ip);
    if (expireAtRaw === undefined || expireAtRaw === null) {
        return false;
    }

    const expireAt = Number(expireAtRaw);
    if (Number.isNaN(expireAt)) {
        whiteList.delete(ip);
        return false;
    }

    const now = Date.now();
    if (expireAt <= now) {
        whiteList.delete(ip);
        return false;
    }

    // 剩余时间过短时续期，减少每次请求都写 shared dict 的开销。
    if ((expireAt - now) <= TTL_REFRESH_THRESHOLD_MS) {
        storeIP(ip, DEFAULT_TTL_MS);
    }
    return true;
}

/**
 * HTTP 场景鉴权入口（如 auth_request / js_content）。
 * @param {NginxHTTPRequest} r njs HTTP 请求对象
 */
function http_verify(r) {
    if (!ensureStore()) {
        r.error("vs_ip shared dict is not configured");
        r.return(500, "VShield storage is not configured");
        return;
    }

    const clientIP = r.remoteAddress;
    if (isAllowed(clientIP)) {
        r.log(`http_verify allowed IP address: ${clientIP}`);
        // js_content/auth_request 场景需显式返回状态码。
        r.return(200, "OK");
        return;
    }

    r.error(`http_verify denied IP address: ${clientIP}`);
    r.return(403, "Forbidden");
}

/**
 * Stream 场景鉴权入口。
 * @param {NginxStreamSession} s njs Stream 会话对象
 */
function stream_verify(s) {
    if (!ensureStore()) {
        s.error("vs_ip shared dict is not configured");
        s.deny();
        return;
    }

    const clientIP = s.remoteAddress;
    if (isAllowed(clientIP)) {
        s.log(`stream_verify allowed IP address: ${clientIP}`);
        // stream 子系统通过 allow/deny 决策连接，不使用 HTTP return。
        s.allow();
        return;
    }

    s.error(`stream_verify denied IP address: ${clientIP}`);
    s.deny();
}

/**
 * 将当前请求来源 IP 注册进白名单。
 * @param {NginxHTTPRequest} r njs HTTP 请求对象
 */
function register(r) {
    if (!ensureStore()) {
        r.return(500, "VShield storage is not configured");
        return;
    }

    const clientIP = r.remoteAddress;
    if (!clientIP) {
        r.return(400, "Missing client IP");
        return;
    }

    storeIP(clientIP, DEFAULT_TTL_MS);
    r.return(200, `${clientIP} is registered`);
}

/**
 * 将当前请求来源 IP 从白名单移除。
 * @param {NginxHTTPRequest} r njs HTTP 请求对象
 */
function cancel(r) {
    if (!ensureStore()) {
        r.return(500, "VShield storage is not configured");
        return;
    }

    const clientIP = r.remoteAddress;
    if (!clientIP) {
        r.return(400, "Missing client IP");
        return;
    }

    whiteList.delete(clientIP);
    r.return(200, `${clientIP} is unregistered`);
}

/**
 * 管理接口：列出所有白名单条目。
 * @param {NginxHTTPRequest} r njs HTTP 请求对象
 */
function adminWhiteList(r) {
    if (!ensureStore()) {
        r.return(500, "VShield storage is not configured");
        return;
    }

    const result = [];
    for (const ip of whiteList.keys()) {
        const expireAt = Number(whiteList.get(ip));
        if (Number.isNaN(expireAt)) {
            continue;
        }
        result.push({
            ip: ip,
            // 使用 ISO 字符串，避免时区导致的管理端展示歧义。
            expireAt: new Date(expireAt).toISOString()
        });
    }

    r.headersOut["Content-Type"] = "application/json; charset=utf-8";
    r.return(200, JSON.stringify(result));
}

/**
 * 管理接口：注册指定 IP，可选 timeout（毫秒）。
 * @param {NginxHTTPRequest} r njs HTTP 请求对象
 */
function adminRegister(r) {
    if (!ensureStore()) {
        r.return(500, "VShield storage is not configured");
        return;
    }

    const clientIP = r.args.ip;
    if (!clientIP) {
        r.return(400, "Missing query parameter: ip");
        return;
    }

    const ttlMs = parseTtlMs(r.args.timeout);
    storeIP(clientIP, ttlMs);
    r.return(200, `${clientIP} is registered`);
}

/**
 * 管理接口：取消指定 IP 注册。
 * @param {NginxHTTPRequest} r njs HTTP 请求对象
 */
function adminCancel(r) {
    if (!ensureStore()) {
        r.return(500, "VShield storage is not configured");
        return;
    }

    const clientIP = r.args.ip;
    if (!clientIP) {
        r.return(400, "Missing query parameter: ip");
        return;
    }

    whiteList.delete(clientIP);
    r.return(200, `${clientIP} is unregistered`);
}


export default {
    http_verify,
    stream_verify,
    register,
    cancel,
    adminWhiteList,
    adminRegister,
    adminCancel
}
