# VShield

VShield 是一个基于 Nginx njs 的 IP 白名单访问控制脚本，用于在 HTTP 或 Stream 场景快速实现“仅允许登记 IP 访问”。

## 功能概览

- 基于 `ngx.shared` 的白名单存储（共享内存）
- 支持 HTTP 鉴权：`http_verify`
- 支持 Stream 鉴权：`stream_verify`
- 支持自助注册/取消：`register`、`cancel`
- 支持管理端接口：查询、注册指定 IP、取消指定 IP
- 支持独立页面（静态资源）：管理员管理页、用户自助注册页、拦截提示页
- 白名单自动过期，临近过期时自动续期（减少频繁写入）
- 支持审计日志：记录“哪个用户对哪个 IP 做了什么操作”

## 环境要求

- Nginx（启用 `http`/`stream`）
- [njs 模块](https://nginx.org/en/docs/njs/)
- 在 Nginx 中声明共享字典：`js_shared_dict_zone zone=vs_ip:...`

## 快速开始（HTTP）

将 `VShield.js` 放在 Nginx 可访问目录（例如 `/etc/nginx/njs/`），并配置：

```nginx
http {
    js_path "/etc/nginx/njs/";
    js_import VShield from VShield.js;

    # 必需：脚本中固定使用 zone=vs_ip
    js_shared_dict_zone zone=vs_ip:1M timeout=2h;

    upstream backend {
        server 127.0.0.1:8081;
    }

    server {
        listen 80;
        server_name _;

        # 业务入口：先鉴权再转发
        location /secure/ {
            auth_request /validate;
            proxy_pass http://backend;
        }

        # 鉴权子请求
        location = /validate {
            internal;
            js_content VShield.http_verify;
        }

        # 当前来源 IP 自助加入白名单
        location = /register {
            js_content VShield.register;
        }

        # 当前来源 IP 自助移出白名单
        location = /cancel {
            js_content VShield.cancel;
        }

        # 管理接口：列出白名单（建议加鉴权）
        location = /admin/whitelist {
            js_content VShield.adminWhiteList;
        }

        # 管理接口：注册指定 IP，支持 timeout(毫秒)
        # 示例: /admin/register?ip=1.2.3.4&timeout=600000
        location = /admin/register {
            js_content VShield.adminRegister;
        }

        # 管理接口：移除指定 IP
        # 示例: /admin/cancel?ip=1.2.3.4
        location = /admin/cancel {
            js_content VShield.adminCancel;
        }
    }
}
```

## Stream 场景示例

```nginx
stream {
    js_path "/etc/nginx/njs/";
    js_import VShield from VShield.js;
    js_shared_dict_zone zone=vs_ip:1M timeout=2h;

    server {
        listen 3306;
        js_access VShield.stream_verify;
        proxy_pass 127.0.0.1:3307;
    }
}
```

## 认证模式（OAuth2-Proxy + Basic Auth 同时支持）

对于 `/register` 和 `/admin/*`，推荐同时开启两种认证并使用 `satisfy any`：

- 浏览器用户：通过 `auth_request` 对接 `oauth2-proxy`
- CLI 用户：通过 `auth_basic`（用户名/密码）
- 任意一种认证通过即可访问

完整示例见：`examples/nginx.dual-auth.conf`

关键配置模式如下：

```nginx
location = /admin/register {
    satisfy any;
    auth_request /oauth2/auth;
    auth_basic "VShield Admin";
    auth_basic_user_file /etc/nginx/vshield.htpasswd;
    js_content VShield.adminRegister;
}
```

CLI 示例：

```bash
# Basic Auth 方式（适合脚本/终端）
curl -u admin:password \
  "http://127.0.0.1/admin/register?ip=1.2.3.4&timeout=600000"
```

说明：

- OAuth2 的交互式登录天然更适合浏览器用户。
- CLI 场景可优先使用 Basic Auth，避免浏览器跳转流程。
- 若你希望 CLI 也走 Bearer Token，可在 oauth2-proxy 侧配置对应 token 校验能力，再继续复用 `auth_request`。

## 页面化体验（管理员 + 普通用户）

页面与 API 已分离，`VShield.js` 仅负责鉴权与数据接口，页面由 Nginx 托管静态文件。

仓库内静态页面目录：`ui/`

- `ui/portal.html`：用户自助注册页
- `ui/admin.html`：管理员控制台
- `ui/deny.html`：拦截提示页

部署示例（将静态页面复制到 Nginx）：

```bash
mkdir -p /etc/nginx/vshield-ui
cp -r ./ui/* /etc/nginx/vshield-ui/
```

推荐在业务入口使用如下模式，让拦截后用户看到明确提示并可一键前往注册页：

```nginx
error_page 403 = /ui/deny.html;

location /ui/ {
    alias /etc/nginx/vshield-ui/;
    try_files $uri =404;
}

location = /ui/portal.html {
    satisfy any;
    auth_request /oauth2/auth;
    auth_request_set $vshield_user $upstream_http_x_auth_request_user;
    auth_basic "VShield Register";
    auth_basic_user_file /etc/nginx/vshield.htpasswd;
    alias /etc/nginx/vshield-ui/portal.html;
}

location = /ui/admin.html {
    satisfy any;
    auth_request /oauth2/auth;
    auth_request_set $vshield_user $upstream_http_x_auth_request_user;
    auth_basic "VShield Admin";
    auth_basic_user_file /etc/nginx/vshield.htpasswd;
    alias /etc/nginx/vshield-ui/admin.html;
}

location /secure/ {
    auth_request /validate;
    proxy_pass http://app_backend;
}
```

管理员审计日志（记录到 Nginx 日志）依赖 `auth_request_set` 透传用户：

```nginx
location = /admin/register {
    satisfy any;
    auth_request /oauth2/auth;
    auth_request_set $vshield_user $upstream_http_x_auth_request_user;
    auth_basic "VShield Admin";
    auth_basic_user_file /etc/nginx/vshield.htpasswd;
    js_content VShield.adminRegister;
}
```

## 接口说明

| 方法 | 入口函数 | 说明 |
| --- | --- | --- |
| HTTP | `http_verify` | 检查 `remoteAddress` 是否在白名单，允许返回 `200`，拒绝返回 `403` |
| Stream | `stream_verify` | 检查并执行 `allow()` / `deny()` |
| HTTP | `register` | 将当前来源 IP 加入白名单 |
| HTTP | `cancel` | 将当前来源 IP 从白名单移除 |
| HTTP | `adminWhiteList` | 返回白名单 JSON 列表 |
| HTTP | `adminRegister` | 通过 `ip`、`timeout`(毫秒) 注册指定 IP |
| HTTP | `adminCancel` | 通过 `ip` 取消指定 IP |

## TTL 与续期机制

- 默认 TTL：`120 * 60 * 1000`（2 小时）
- `timeout` 参数单位：毫秒
- 当剩余有效期小于等于 1 小时时，访问命中会自动续期为默认 2 小时

## 调用示例

```bash
# 自助注册当前 IP
curl -i http://127.0.0.1/register

# 访问受保护资源
curl -i http://127.0.0.1/secure/demo

# 管理端注册指定 IP（10 分钟）
curl -i "http://127.0.0.1/admin/register?ip=1.2.3.4&timeout=600000"

# 查询白名单
curl -i http://127.0.0.1/admin/whitelist

# 管理端移除指定 IP
curl -i "http://127.0.0.1/admin/cancel?ip=1.2.3.4"
```

## 测试

项目提供 `node:test` 单元测试，覆盖鉴权、注册/取消、管理接口、TTL 续期与审计日志。

```bash
node --test test/VShield.test.mjs
```

## 注意事项

- `vs_ip` 是脚本中固定共享字典名，Nginx 配置必须一致。
- 生产环境请为 `/admin/*`、`/register`、`/cancel` 增加访问控制（内网、Basic Auth、JWT、IP 限制等）。
- 若部署在反向代理后，请确认 `remoteAddress` 是否为真实客户端 IP（必要时结合 Nginx realip 配置）。
- 如果同时启用 `auth_request` 与 `auth_basic`，请使用 `satisfy any`，避免把 CLI 场景强制变成浏览器 OAuth 跳转。
- 审计日志通过 njs `r.log` 输出，关键字段为：`actor`、`source_ip`、`target_ip`、`action`、`status`。
- OAuth2 场景建议用 `auth_request_set $vshield_user $upstream_http_x_auth_request_user;`，这样日志可以记录真实登录用户。

## 易用性改进建议

- 增加 `make` 或脚本命令封装常见操作（注册、取消、查询白名单）。
- 将 `admin` 与 `register` 的入口分组到独立前缀（例如 `/vshield/*`），降低与业务路由冲突概率。
- 为 `/admin/*` 增加访问审计日志字段（操作者、来源 IP、目标 IP、超时时间）。
- 增加速率限制（`limit_req`）保护管理接口，防止暴力尝试。
- 增加一份最小生产配置模板（TLS、realip、双认证、限流），减少集成成本。

## 许可证

[Apache-2.0](./LICENSE)
