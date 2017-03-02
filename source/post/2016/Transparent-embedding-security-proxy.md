```toml
title = "安全认证代理的透明接入"
slug = "Transparent-embedding-security-proxy"
desc = "Transparent-embedding-security-proxy"
date = "2016-07-13 13:29:12"
update_date = "2016-07-13 13:29:12"
author = ""
thumb = ""
tags = ["安全认证代理的透明接入"]
```

## 背景
之前在sina做一个移动办公应用的安全对外发布代理（新浪口袋）时，是在openresty中的location中专门提供了认证的接口，app需要认证时将认证信息全部发给代理，在代理层进行动态口令与静态口令的认证。

认证通过后，再由代理在header中附加了认证信息给后端。现在又接到了类似项目，就改为了透明接入的方式，现有的客户端与服务器端只需做很少的改动就能接入。

不方便多说，只简单提一下：

1. 安全代理层与后端共有2重的身份认证，访问后端服务器时，如果代理层的身份认证没通过则返回一个特定的json串，客户端app就知道该发起登录认证的请求了。
1. 认证的接口是在白名单中放行的，不做访问控制，但是代理会劫持请求的响应信息，通过后端服务器的返回结果，代理便可判断用户是否登录成功，是否颁发有实效的token。

<!--more-->

[![secProxy](/media/sec_proxy.png)]

## openresty中的配置

openresty的配置大致如下：

```ini

upstream proxy_app.xsec.io {
        server 1.1.1.1:443;
    }

 server {
        listen       443;
        server_name  app.xsec.io;
        client_max_body_size 100m;
        charset utf-8;
        access_log      /var/log/nginx/app.xsec.io-access.log Merpproxy;
        error_log       /var/log/nginx/app.xsec.io-debug.log debug;

        location ~* ^/(login/CheckPhone|login/checkCode|APP) {
                proxy_connect_timeout 360s;
                proxy_read_timeout 5400s;
                proxy_send_timeout 5400s;
                proxy_pass_header Server;
                proxy_set_header Host $http_host;
                proxy_redirect off;
                proxy_set_header X-Real-IP $remote_addr;
                proxy_set_header X-Scheme $scheme;
                proxy_pass http://proxy_app.xsec.io;
        }

        location ~* ^/login/CheckLdap {

            content_by_lua '
            helper.get_post_info()
            ';

            header_filter_by_lua '
            local result, username, device_info = helper.chk_login()
            local timestamp = ngx.time()
            local secure_key = config.access_key.key
            local sign = access_key.make_sign(secure_key, timestamp)

            if result then
                local resp = access_key.create_key(username, device_info, key, sign, timestamp, 0)
                -- ngx.log(ngx.DEBUG, string.format("resp:%s, resp.text:%s, type:%s", resp, resp.text, type(resp.text)))
                -- helper.make_resp(resp)
                ngx.ctx.resp = resp or {}
                helper.make_cookies(resp)
            end
            ';

            body_filter_by_lua '
                local body = helper.get_resp_body()
                ngx.log(ngx.DEBUG, string.format("body:%s, type of body:%s", body, type(body)))
                local resp = ngx.ctx.resp or {}
                ngx.log(ngx.DEBUG, string.format("resp:%s, resp.text:%s, type:%s", resp, resp.text, type(resp.text)))
                helper.make_resp(body, resp)
            ';

            proxy_set_header authorization xsec_security;
            proxy_pass_header Server;
            # proxy_set_header Host $http_host;
            proxy_set_header Host proxy_app.xsec.io;
            proxy_redirect off;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Scheme $scheme;
            proxy_pass $scheme://proxy_app.xsec.io;
            }
            error_page  404              /index.html;
            error_page   500 502 503 504  /index.html;
    }

# http protocol
server {
        listen       80;
        ssl off;
        server_name  app.xsec.io;
        rewrite ^(.*) https://proxy_app.xsec.io/$1 permanent;
    }

```

### 代码解读
- location ~* ^/(login/CheckPhone|login/checkCode|APP)是设备激活阶段需要的短信验证码获取及输入阶段，不做拦截
- location ~* ^/login/CheckLdap是输入加密的ldap密码阶段，我们在透明接入就实现在这部分：
    - content_by_lua阶段中获取了用户的登录信息，比如用户名、设备信息等
    - header_filter_by_lua阶段判断了用户是否登录成功（成功的话服务器会set-cookie，否则不会set-cookie），也可以放在body_filter_by_lua阶段，根据服务器返回的json判断
        1. 登录成功的话，代理服务器会生成与账户、设备唯一绑定的认证key，并设备cookies
        1. 将认证key保存到ctx中，方便在body_filter_by_lua阶段中使用
    - body_filter_by_lua阶段中拦截了服务器返回的json，反序列化后将代理的认证信息插入后再以json的方式发给客户端
        
- 客户端激活成功后，不再使用ldap（ldap一旦泄漏，所有内网的系统都可以登录了），只使用代理维护的key与totp进行双因素认证。