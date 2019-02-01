```toml
title = "Exchange邮箱安全代理系统开发"
slug = "mail-sec-proxy-golang"
desc = "mail-sec-proxy-golang"
date = "2019-01-03 12:06:44"
update_date = "2019-01-03 12:06:44"
author = ""
thumb = ""
draft = false
tags = ["tag"]
```

## 概述

邮箱是企业的基础设施，大量的沟通是通过邮件完成的，邮件内容里面承载了非常多的商业敏感信息与机密，员工邮箱账户因社工库、撞库、弱口令、github等途径泄露出去的后果不言而喻。

许多企业的安全工程师可能会从邮箱的账户策略和ACL来保护员工邮箱账户的安全，如强制要求设置强壮的密码、定期修改密码、邮箱服务器仅对内网开放，外网访问需要拨入VPN等。

但这些手段存在以下弊端：

1. 什么样的口令算安全的，如果正好是被社工库收录的复杂口令，是完全符合密码策略的
1. 定期修改口令，可能会改回一个已经泄露的复杂的口令
1. 强壮的口令也可能会通过github、网盘等途径泄露出去
1. 邮箱放在内网，外网只能通过VPN访问，虽然杜绝了来自外网的攻击，但是员工在外出办公时非常不便

本文要开发的邮件安全代理系统可以兼顾安全性与用户体验。

项目地址：[https://github.com/MiSecurity/exchange_proxy](https://github.com/MiSecurity/exchange_proxy)

## 邮箱安全代理架构与功能说明

本次开发的邮件安全代理只适用于Exchange邮件服务器，架构如下：

![](http://docs.xsec.io/images/mail_proxy/mail_proxy01.png)

通过邮件安全代理将内网的邮件服务器集群的443端口发布到外网，Exchange支持OWA、EWS、ActiveSync、RPC协议，是支持通过WEB端、手机端与电脑客户端连接的。
但这样仅是将邮箱服务器的https服务代理出去了，对于账户泄露还是没有任何的防御措施，接下来我们需要给加上二次确认机制。

- 对于WEB端访问，要求用户除了用户名与密码外，还得输入OTP动态口令
- 对于手机端，新设备第一次访问时，需要通过短信发送的URL进行设备绑定，只有用户激活过的设备才可以收发邮件，如果收到陌生的设备的激活短信说明账户泄露了
- 对于电脑端，每次在外网连接时，需要用户通过短信确认自己的出口IP与客户端类型，只有授权后才可以收发邮件

我们线上的承载了2W多人的安全代理是用lua技术栈（openresty + orange框架）开发的，逻辑架构如下所示：

![](http://docs.xsec.io/images/mail_proxy/mail_proxy02.png)

目前的线上的系统做了许多定制化的工作，是通过haproxy、Keepalived和openresty跑起来的，代码量较大，安装、部署与运维相对比较繁琐，光运维文档就可以写一篇文章了，笔者暂时不打算开源这一套系统，本次我们再用go语言实现一套轻量级的。

对EWS协议的支持需要兼容数个不同的邮件客户端，需要踩的坑也比较多，如Mac mail app、windows下的outlook与mac下的outlook都需要定制化兼容，本次为了节省时间，就先不兼容EWS了，有通过电脑收发邮件的需求时可以安装BlueMail与邮箱邮箱大师。这2个PC客户端走的是active sync协议，装在电脑中是可以使用的。

## 具体实现
我们的安全代理使用了一个[https://github.com/vulcand/oxy](https://github.com/vulcand/oxy)中间件，我们只要实现了`http.Handler`就可以开发自己的插件，关于中间件的相关知识可以看看[开源图书《Go语言高级编程》的相关章节](https://github.com/chai2010/advanced-go-programming-book/blob/master/ch5-web/ch5-03-middleware.md)。

接下为分别讲OWA与activeSync协议的插件的开发。

### OWA插件的开发

实现一个只有普通owa代理功能的代码如下：

![](http://docs.xsec.io/images/mail_proxy/code001.png)

`vars.MailConfig.Host`是我们在配置文件中配置的域名列表，支持多域名，`vars.MailConfig.Backend`是后端的邮件服务器地址。

现在只是完成的基本的代理功能，接下来我们添加上OTP动态口令检测的功能：

- 对于GET请求，修改response的内容，在返回的表单中添加一个输入动态口令的输入框
- 对于POST请求，先获取到用户名与oto动态口令，先去OTP接口中验证一下otp口令是否合法，合法的话将用户请求传到后端，否则直接在代理层面就阻断请求

详细的代码如下：

![](http://docs.xsec.io/images/mail_proxy/code002.png)

`util.CheckToken`为验证token工具函数，可以在github中查看，我们在main函数中写入以下内容，就实现了一个支持OTP二次验证的WEB端的安全代理了。

![](http://docs.xsec.io/images/mail_proxy/code003.png)

`listen80Port`的目的是监听80端口，将用户请求跳转到443端口，防止用户不会直接输入https，导致404后以为邮件服务器不可用的问题。

效果如下图所示，只有输入正确的账户密码与OTP口令才可以登录。

![](http://docs.xsec.io/images/mail_proxy/mail_proxy03.png)

### ActiveSync插件开发

同样一个普通的代理activeSync请求的实现代码如下：

![](http://docs.xsec.io/images/mail_proxy/code004.png)

我们需要加上安全过滤功能，封装为一个`http.HandlerFunc`，详细的功能逻辑如下：

1. 设备访问时，获取用户名、设备ID、设备类型，指令，如果是第一次访问则新建一条设备信息并保存到redis中，并装设备的状态标识设置为未激活
2. 用户输入密码的过程中，手机端会通过wbxml协议传递手机端的信息，如设备型号、Imei、当前设备的手机号码、ISP提供商等信息，把这些信息解析出来存入redis
3. 根据用户名与设备ID，判断当前设备的状态，如果为未激活则进入激活流程，如果已经激活就直接放行，对于已经阻止的设备会直接block
4. 设备未激活前，也允许用户连接服务器，但会对一些关键的指令做了过滤，保证用户体验的同时也确保了信息安全

在未激活前，过滤的指令列表如下：

![](http://docs.xsec.io/images/mail_proxy/code005.png)

代码中有详细的注释，就不细说了，ActiveSync插件的完整代码如下所示：
![](http://docs.xsec.io/images/mail_proxy/code006.png)

进入激活流程后需要检测激活的频率，我们定为1分钟只允许激活一次，然后生成激活码和短信并发送给用户。短信的发送频率限定为每10小时一次，防止频繁发送对用户造成骚扰，以下为激活流程相关的代码：
![](http://docs.xsec.io/images/mail_proxy/code007.png)

最后在main函数中再加入一条以下的路由，手机端的安全代理功能就生效了：

```go
mux.HandleFunc("/Microsoft-Server-ActiveSync", active_sync.ActiveSyncHandler(active_sync.SyncRedirect))
```

将手机配置为咱们的代理后，立即会收到一条验证确认短信，如下图所示：

![](http://docs.xsec.io/images/mail_proxy/mail_proxy04.png)

### 禁止PC端的请求

代理默认会将非路由中的请求透传到后端，目前PC端也是可以访问的，我们需要显式屏蔽一下，防止手机端与WEB端做了安全策略了，却被攻击者通过PC端绕过。

![](http://docs.xsec.io/images/mail_proxy/code008.png)

### 设备激活功能
现在能发出手机端的激活短信了，但还无法激活，为保证用户正常使用，接下来我们需要开发下设备激活的接口，这些接口的路由如下：

![](http://docs.xsec.io/images/mail_proxy/code009.png)

- `/static/`是提供静态资源的路由，如css、js、图片等
- `/a/`是显示激活页面的路由
- `/a/activedevice`是设备激活的接口，由前端激活页面的JS调用
- `/a/ignoredevice`是设备忽略的接口，也由前端激活页面的JS调用

完整的激活接口代码请查看github，效果如下图所示：

- 启动代理服务器
![](http://docs.xsec.io/images/mail_proxy/mail_proxy041.png)

- 激活页面
![](http://docs.xsec.io/images/mail_proxy/mail_proxy05.png)

- 显示激活状态
![](http://docs.xsec.io/images/mail_proxy/mail_proxy06.png)

## 后记

该套系统依赖企业的一些基础设备，如OTP系统、HR的通过用户名查找手机的接口、短信接口等。所以不能拿来直接使用，需要根据实际情况对接下相关的接口，然后在配置文件写入正确的配置：

![](http://docs.xsec.io/images/mail_proxy/code010.png)

正式上线之前，最好提供相应的管理后台并与内网的管理系统对接，邮件代理管理后台提供以下功能：

- 管理员可查看、修改每个用户的账户与设备状态
- 管理员可查看每个设备的激活进程，方便故障排查
- 用户也可自行管理自己的设备

设备数据保存在redis中，用go/python/php等语言都可以实现，我就不单独提供了。

代理系统的进程可以托管在supervisor或god中，部署了该系统后，可以解决邮件服务器手机端与WEB端的安全，目前的开源版本没有电脑端的安全代理功能，建议在PC端收发邮件时拨入VPN，或者在电脑中用BlueMail客户端收发邮件。
