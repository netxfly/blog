```toml
title = "DNS代理服务器，可以记录log到数据库中"
slug = "dns-proxy-server"
desc = "dns-proxy-server"
date = "2017-08-15 13:28:01"
update_date = "2017-08-15 13:28:01"
author = ""
thumb = ""
tags = ["信息安全"]
```

## xsec-dns-server

xsec dns proxy server为一个DNS代理服务器，可以将DNS请求代理到后端的DNS服务器中，在代理的过程中会将dns log写入到数据库中。

### 主要特性如下：

1. 代理DNS请求并记录请求数据
1. 后端支持 sqlite、postgres、mysql和mongodb四种数据库

### 使用说明：

```shell
$ ./xsec-dns-server 
[xorm] [info]  2017/08/15 11:01:24.497380 PING DATABASE mysql
NAME:
   xsec dns proxy server - xsec dns proxy server

USAGE:
   xsec-dns-server [global options] command [command options] [arguments...]
   
VERSION:
   0.1
   
COMMANDS:
     serve    dns proxy Server
     web      web server
     help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h     show help
   --version, -v  print the version

```

- serve参数表示启动一个dns代理服务器
- web 参数表示启动一个简单WEB服务器，用来查看dns日志。

### 运行截图

![](https://docs.xsec.io/images/serve.png)

![](https://docs.xsec.io/images/web.png)

项目地址：https://github.com/netxfly/xsec-ip-database

## 更新记录

### 2017/9/28

- 恶意域名的种子中新增了360 netlab提供的DGA，使得域名记录直接上到了百万级。

！[](https://docs.xsec.io/images/evil_ips/netlab_360.png)

- 因为data.netlab.360.com在国内，而且体积在70M以上，所以从vps中的拉取速度很慢，建议下载到本地，将`feeds/netlab360.go`中的URL改为本地地址。

```go
url := "http://data.netlab.360.com/feeds/dga/dga.txt"
	// url := "http://127.0.0.1:8000/dga.txt"
```
- 如果vps内存不足，会在将恶意IP和域名导出到文件中时报错，解决方案为增加swap分区。
![](https://docs.xsec.io/images/evil_ips/swap.png)