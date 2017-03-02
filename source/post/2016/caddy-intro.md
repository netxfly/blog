```toml
title = "用caddy替换nginx实现全站自动https"
slug = "caddy-intro"
desc = "caddy-intro"
date = "2016-07-27 10:23:05"
update_date = "2016-07-27 10:23:05"
author = ""
thumb = ""
tags = ["caddy", "自动免费全站https"]
```

## caddy简介

[Caddy](https://caddyserver.com) 是用 Go 语言实现的一款 Web 服务器，部分特点如下：

- 使用、部署非常方便（比nginx的配置还要简单）
- 自动化https（内置了Let’s Encrypt 服务，自动申请，自动续期）
- 支持fastcgi，跑个php只需要要一句配置指令

```ini
fastcgi /blog/ 127.0.0.1:9000 php
```

- 支持众多插件，可以轻易地扩展功能

我blog中N个站点分分钟就从nginx迁移到caddy中，还直接变成了免费的全站https，计划抽空的时候给caddy开发一个waf插件。
<!--more-->

以下为我的caddy文件的配置，供大家参考：

```ini
root@vultr:/data/caddy# cat caddy.conf 
x.xsec.io {
        proxy / 127.0.0.1:9001
}

xsec.io, www.xsec.io www.secdevops.cn, secdevops.cn {
    proxy / 127.0.0.1:8080 127.0.0.1:8081 127.0.0.1:8082 127.0.0.1:8083 127.0.0.1:8084 127.0.0.1:8085 127.0.0.1:8086 127.0.0.1:8087 127.0.0.1:8088 127.0.0.1:8089
}

docs.xsec.io, books.xsec.io {
    root /data/books/
    browse
}

git.xsec.io {
    proxy / 127.0.0.1:3000
}

g.xsec.io {
    proxy / 127.0.0.1:10000
}

```

## 参考资料
1. [Caddy 部署实践](https://wuwen.org/2015/11/13/caddy-in-action.html)
1. [Caddy，一个用Go实现的Web Server](http://tonybai.com/2015/06/04/caddy-a-web-server-in-go/)