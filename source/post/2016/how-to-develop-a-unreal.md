```toml
title = "自制攻击欺骗防御系统"
slug = "how-to-develop-a-unreal"
desc = "how-to-develop-a-unreal"
date = "2016-11-02 17:00:21"
update_date = "2016-11-02 17:00:21"
author = ""
thumb = ""
tags = ["镜花水月"]
```

部门每周三例行的技术分享投稿文章，首发在[小米安全中心的公众号](http://mp.weixin.qq.com/s?__biz=MzI2NzI2OTExNA==&mid=2247483994&idx=1&sn=64fcc83146fb6c5ec9943e64f10306c7&chksm=ea8024cfddf7add9acb9f42110e43a31722f9e60881542de6e14957edce7e36e35524ce41a96#rd)

# 自制攻击欺骗防御系统

## 概述

峥嵘栋梁，一旦而摧；水月镜像，无心来去。                                                       

本次自制的欺骗防御系统名字叫镜花水月，镜花水月是《死神》中蓝染惣右介的斩魄刀（幻觉系最强斩魄刀）的名字，能力是完全支配对手的五感。

这个名字非常适合攻击欺骗防御类系统：把攻击者的流量从正常的请求中区分、剥离出来，并无缝地转移到伪造了正常业务和服务的沙盒中，让攻击者去沙盒环境中玩耍并会记录其详细的行为。

与传统的蜜罐相比，镜花水月的优点为：

1. 零误报（只对内部或外部的攻击行为进行报警）；
1. 保护业务系统（第一时间会将攻击者从正常的服务中转移到沙箱环境中，攻击者却浑然不知）；
1. 方便取证及定位攻击者（沙盒中会记录攻击者的来源及详细的攻击行为）。 

## 技术架构

![](/media/image/unreal/unreal.png)

镜花水月由4个模块组成：

1. Agent，部署于服务器中的Agent，用于实时获取用户的访问日志并传递到检测端Server中，如果是恶意攻击，则会将流量重定向到沙盒中。目前支持的服务有：
    1. WEB
    1. FTP
    1. SSH
    1. Rsync
    1. Mysql
    1. Redis
    1. Mongodb
1. Server，攻击检测服务器，实时检测Agent传递过来的日志并判断是否为攻击者，并为Agent动态、实时地维护了一份攻击者的来源IP策略；
1. Manager，策略管理服务器，有为Agent和server提供策略、攻击log统计、查看的功能
1. 沙盒由以下3部分构成：
    1. 安装了FTP、SSH、Rsync、Mysql、Redis和Mongodb的虚拟机或Docker，可实时将这些服务的访问log发送到远程的Rsyslog中
    1. 克隆的WEB站点
    1. 日志服务器，将沙盒通过Rsyslog发送过来的数据解析出来并入库，供Manager查询、分析

为了方便部署以及高性能的要求，镜花水月的各组件中除了WEB攻击检测模块是用lua开发的外，其余的全是用go语言开发的（WEB攻击检测模块是基于openresty+lua开发的）。

<!--more-->

## Agent的实现

### agent的架构

Agent支持以蜜罐、镜花水月、攻击反弹和防火墙4种模式运行。

```bash
$ ./client -h
Usage of ./client:
  -c string
    	command, such as start or stop policy (default "start")
  -m string
    	running mode, honeypot, unreal, back or firewall mode (default "honeypot")

```

这四种模式的区别及功能分别如下：

1. 启动时会应用不同的策略：
    1. 蜜罐会将除了白名单IP和端口外的所有流量直接转向沙盒中；
    1. 镜花水月只将被Server判定为恶意攻击者转向沙盒，不影响正常的请求（攻击欺骗防御模式）；
    1. 反弹模式是将攻击者的流量全部原封不动的返回，类似于金庸小说《天龙八部》中的斗转星移；
    1. 防火墙模式是将识别出来的攻击者的IP Block掉。
1. 以镜花水月、攻击反弹和防火墙模式启动时，除了会应用从manager获取到的策略外，还会在Agent中启动4个服务监控的goroutine，这些goroutine会将收集到的Vsftpd、Rsync、mysql和Redis服务的日志实时发到Server端。

Agent的整体工作流如下：

1. 判断启动模式，如果启动参数为unreal，则以镜花水月模式启动，默认以蜜罐模式启动；
1. 从配置文件conf/app.ini读取配置参数，如果是蜜罐模式，按配置文件中指定的时间间隔，定期从Manager获取策略并应用，如果是镜花水月模式，则每10秒更新一次策略，并启动Vsftpd、Rsync、mysql和Redis的监控goroutine

关于蜜罐的详细实现，可以参考笔者之前的文章[自制蜜罐之前端部分，https://xsec.io/2016/7/8/how-to-develop-a-honeypot.html](https://xsec.io/2016/7/8/how-to-develop-a-honeypot.html)，本文只贴一些关键的部分代码。

项目的代码结构如下图所示：

![](/media/image/unreal/client.png)

### Agent的日志配置

Agent是通过rsyslog向server实时汇报采集到的非WEB应用程序的数据的（web的攻击检测会在后面说明），在部署agent前需要做以下3步的配置：

1. 配置服务器中运行的应用的日志参数，将能写syslog的写入到syslog中，不能写syslog的写入到指定的文件中
1. 将写入文件中的log读取出来，转换成syslog格式再转存到本地的syslog中
1. 配置rsyslog的规则，将我们需要分析的log转发到后端server中，rsyslog的转发策略如下图所示：

![](/media/image/unreal/rsyslog_config.png)

ssh和mongodb的日志可以写入到syslog中，直接配置rsyslog的转发策略即可。

redis的操作内容不支持写入syslog，需要先连接redis，然后利用monitor命令监控redis指令的执行，经测试无法监控到config指令，而且启用monitor后，性能会降低一半。
所以redis的指令监控服务不适合部署在对性能要求很高的服务器中。

Vsftpd、Rsync和Mysql服务需要配置应用对日志的支持，以下为关键的配置项：
```bash
// VsftpdLog的配置
xferlog_enable=YES
xferlog_file=/var/log/xferlog
xferlog_std_format=YES
dual_log_enable=YES
syslog_enable=YES
log_ftp_protocol=YES

// Rsync的配置
$ cat /etc/rsyncd.conf 
log file = /var/log/rsyncd.log

// mysql的配置
[mysqld]
bind-address = 127.0.0.1
general-log-file = /var/log/mysqld.log                                                                                           
general_log = 1
```

把Vsftpd、Rsync和mysql的日志转存为syslog方法一样，都是不断地Tail文件，并把新增的日志发送到syslog中，代码如下：

```go
// "/var/log/vsftpd.log"
func MonitorVsftpd(logName string) {
	t, err := tail.TailFile(logName, tail.Config{Follow: true})
	if err == nil {
		for line := range t.Lines {
			l3, err := syslog.New(syslog.LOG_ERR, "vsftpd-server")
			defer l3.Close()
			if err != nil {
				log.Fatal("error")
			}
			l3.Info(line.Text)
			fmt.Println(line.Text)
		}
	}
}
```

以下为将redis的monitor指令的结果转存为syslog的代码：

```go
func MonitorRedis(host, port, password string) {
	flag.Parse()
	conn, err := net.Dial("tcp", host+":"+port)
	if err == nil {
		conn.Write([]byte(fmt.Sprintf("auth %v\r\n", password)))
		conn.Write([]byte("monitor \r\n"))
		defer conn.Close()

		ch := make(chan []byte)
		eCh := make(chan error)

		l3, err := syslog.New(syslog.LOG_ERR, "redis-server")
		defer l3.Close()
		if err != nil {
			log.Fatal("error")
		}

		go func(ch chan []byte, eCh chan error) {
			for {
				// try to read the data
				data := make([]byte, 512)
				_, err := conn.Read(data)
				if err != nil {
					eCh <- err
					return
				}
				ch <- data
			}
		}(ch, eCh)

		ticker := time.Tick(time.Second)
		for {
			select {
			case data := <-ch:
				n := bytes.IndexByte(data, 0)
				s := string(data[:n])
				d := strings.Replace(s, "\r\n", "", -1)
				l3.Warning(d)
			case err := <-eCh:
				fmt.Println(err)
				break
			case <-ticker:
			}
		}
	}
}
```

### Agent的编码实现

启动模式的处理部分代码如下：

```go

// start honeypot
func StartHoneypot(mode string) {
	for {
		p, err := GetPolicy()
		log.Println(p, err)
		if err == nil {
			run(p, mode)
		}
		if strings.ToLower(mode) == "honeypot" {
			time.Sleep(time.Second * time.Duration(setting.Interval))
		} else {
			time.Sleep(time.Second * 10)
		}
	}
}

// start agent
func Start(mode string) {

	if strings.ToLower(mode) != "honeypot" {
		go util.MonitorVsftpd(setting.VsftpdLog)
		go util.MonitorRsync(setting.RsyncLog)
		go util.MonitorMysql(setting.MysqlLog)
		go util.MonitorRedis(setting.RedisHost, setting.RedisPort, setting.RedisPass)

	}

	StartHoneypot(mode)
}
```

不同模式会应用不同的iptables的策略，部分代码如下：
```go

// set iptables
func SetIptables(policy Policy, mode string) {
	if strings.ToLower(mode) == "honeypot" {
		whiteIpPolicy := policy.WhiteIp
		// set white policy
		for _, whiteIp := range whiteIpPolicy {
			fmt.Println("/sbin/iptables", "-t", "filter", "-A", "WHITELIST", "-i", setting.Interface, "-s", whiteIp, "-j", "DROP")
			exec.Command("/sbin/iptables", "-t", "filter", "-A", "WHITELIST", "-i", setting.Interface, "-s", whiteIp, "-j", "DROP").Output()
		}

		fmt.Println("/sbin/iptables", "-t", "nat", "-A", "HONEYPOT", "-i", setting.Interface, "-p", "tcp", "-m", "multiport", "!", "--dports", strings.Join(policy.WhitePort, ","), "-j", "DNAT", "--to-destination", policy.Backend)
		ret, err := exec.Command("/sbin/iptables", "-t", "nat", "-A", "HONEYPOT", "-i", setting.Interface, "-p", "tcp", "-m", "multiport", "!", "--dports", strings.Join(policy.WhitePort, ","), "-j", "DNAT", "--to-destination", policy.Backend).Output()
		fmt.Println(ret, err)
	} else if strings.ToLower(mode) == "unreal" {
		blackIps := policy.BlackIp
		for _, blackIp := range blackIps {
			if strings.TrimSpace(blackIp) != "127.0.0.1" {
				fmt.Println("/sbin/iptables", "-t", "nat", "-A", "HONEYPOT", "-i", setting.Interface, "-p", "tcp", "-m", "multiport", "!", "--dports", strings.Join(policy.WhitePort, ","), "-s", blackIp, "-j", "DNAT", "--to-destination", policy.Backend)
				ret, err := exec.Command("/sbin/iptables", "-t", "nat", "-A", "HONEYPOT", "-i", setting.Interface, "-p", "tcp", "-m", "multiport", "!", "--dports", strings.Join(policy.WhitePort, ","), "-s", blackIp, "-j", "DNAT", "--to-destination", policy.Backend).Output()
				fmt.Println(ret, err)
			}

		}
	} else if strings.ToLower(mode) == "back" {
		blackIps := policy.BlackIp
		for _, blackIp := range blackIps {
			if strings.TrimSpace(blackIp) != "127.0.0.1" {
				fmt.Println("/sbin/iptables", "-t", "nat", "-A", "HONEYPOT", "-i", setting.Interface, "-p", "tcp", "-m", "multiport", "!", "--dports", strings.Join(policy.WhitePort, ","), "-s", blackIp, "-j", "DNAT", "--to-destination", blackIp)
				ret, err := exec.Command("/sbin/iptables", "-t", "nat", "-A", "HONEYPOT", "-i", setting.Interface, "-p", "tcp", "-m", "multiport", "!", "--dports", strings.Join(policy.WhitePort, ","), "-s", blackIp, "-j", "DNAT", "--to-destination", blackIp).Output()
				fmt.Println(ret, err)
			}

		}
	} else if strings.ToLower(mode) == "firewall" {
		blackIps := policy.BlackIp
		for _, blackIp := range blackIps {
			fmt.Println("/sbin/iptables", "-t", "filter", "-A", "WHITELIST", "-i", setting.Interface, "-s", blackIp, "-j", "DROP")
			exec.Command("/sbin/iptables", "-t", "filter", "-A", "WHITELIST", "-i", setting.Interface, "-s", blackIp, "-j", "DROP").Output()
		}
	}
	exec.Command("/sbin/iptables", "-t", "nat", "-A", "POSTROUTING", "-o", setting.Interface, "-j", "MASQUERADE").Output()
}
```

### WEB服务的攻击检测

WEB服务器的攻击检测是利用反向代理型的waf实现的，关于waf的自制，可以参考笔者之前的文章[《中小企业如何自建免费的云waf》，https://xsec.io/2016/8/23/how-to-develop-a-free-cloud-waf.html](https://xsec.io/2016/8/23/how-to-develop-a-free-cloud-waf.html)

WAF在检测到攻击后有3种处理模式：
1. 跳转到指定的URL
1. 输出自定义的HTML内容
1. 镜花水月模式，攻击者的请求不再反代到正常的后端，而是反代到克隆的WEB业务后端，克隆的WEB站点可以伪造得和真实站点相同，并打开了详细的log，如access log、Debug log和orm log等，连接的是脱敏的测试数据库。

waf检测到攻击后，开启镜花水月模式的处理代码如下：
```javascript
-- WAF response
function _M.waf_output()
    if config.config_waf_model == "redirect" then
        ngx.redirect(config.config_waf_redirect_url, 301)
    elseif config.config_waf_model == "jinghuashuiyue" then
        local bad_guy_ip = _M.get_client_ip()
        _M.set_bad_guys(bad_guy_ip, config.config_expire_time)
    else
        ngx.header.content_type = "text/html"
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say(string.format(config.config_output_html, _M.get_client_ip()))
        ngx.exit(ngx.status)
    end
end

-- set bad guys ip to ngx.shared dict
function _M.set_bad_guys(bad_guy_ip, expire_time)
    local badGuys = ngx.shared.badGuys
    local req, _ = badGuys:get(bad_guy_ip)
    if req then
        badGuys:incr(bad_guy_ip, 1)
    else
        badGuys:set(bad_guy_ip, 1, expire_time)
    end
end 
```

在利用waf-admin添加需要保护的后端站点时，需要增加2种后端的地址：

1. 正常的后端地址
1. 克隆业务的后端地址

如下图所示（请不要在意安全后端工程师做的UI）：
![](/media/image/unreal/waf-admin.png)

waf管理后台在生成新站点的配置文件时后，会在每个请求中都会调用waf.start_jingshuishuiyue()函数，waf.start_jingshuishuiyue()会判断用户的类型是好人或坏蛋，如果是坏蛋的话，直接转到克隆的后端中去。

以下为waf.start_jingshuishuiyue()的代码：
```javascript
function _M.start_jingshuishuiyue()
    local host = util.get_server_host()
    ngx.var.target = "proxy_"
    if host and _M.bad_guy_check() then
        ngx.var.target = "unreal_"
    end
end
```

以下为waf管理端在录入新的网站并为其生成配置文件时的模板文件内容：
```html
upstream proxy_{{.site.SiteName}} { {{range .site.BackendAddr}}
        server {{.}} max_fails=3  fail_timeout=20s;
        {{end}} }

upstream unreal_{{.site.SiteName}} { {{range .site.UnrealAddr}}
        server {{.}} max_fails=3  fail_timeout=20s;
        {{end}} }

server  {
        listen       {{.site.Port}};
        ssl          {{.site.Ssl}};
        server_name  {{.site.SiteName}};
        client_max_body_size 100m;
        charset utf-8;
        access_log      /var/log/nginx/{{.site.SiteName}}-access.log;
        error_log       /var/log/nginx/{{.site.SiteName}}-debug.log {{.site.DebugLevel}};
        
        location ~* ^/ {
            access_by_lua 'waf.start_jingshuishuiyue()';
            proxy_pass_header Server;
            proxy_set_header Host $http_host;
            proxy_redirect off;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Scheme $scheme;
            proxy_pass $scheme://${target}{{.site.SiteName}};
            }

            error_page  404              /index.html;
            error_page   500 502 503 504  /index.html;
        }
```

## Server的实现

### Server的架构

server的主要功能是在TCP和UDP的514端口上启动Rsyslog服务，接收各个Agent发来的Rsyslog数据并判断Agent的启动类型、各服务是否被攻击。

1. 如果收到的是蜜罐模式传过来的数据，则会根据规则进行报警；
1. 如果收到的是镜花水月模式传递过来的数据，则会检测是否为攻击，攻击了几次，是否需要对该攻击者发动镜花水月，如果需要发动的话，则会实时修改manager中的策略，Agent会在几秒后拿到新策略，将攻击者转移到沙盒中。

Server端支持水平扩展，只要能连接到邮件服务器，后端的mongodb与Redis即可，关于蜜罐的实现部分请参考笔者之前的文章，本文只写攻击检测部分。

server端的项目结构如图所示：
![](/media/image/unreal/server.png)

如上图所示，如果不是蜜罐的日志，则会判断应用日志的类型，并调用相应的威胁检测模块，检测的方法都是通过正则匹配中攻击的特征，比如暴破密码、rsync列目录、上传、下载文件等。然后将攻击者的IP，攻击次数记录到manger的Redis中。

以下为VSFTP密码暴力破解的检测示例：

```go
package check

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"gopkg.in/redis.v3"

	"xsec-honeypot/server/setting"
)

func CheckvsFTP(sysLog map[string]interface{}, redisClient *redis.Client) {
	content, _ := sysLog["content"].(string)
	client, _ := sysLog["client"].(string)
	hostname, _ := sysLog["hostname"].(string)
	re, _ := regexp.Compile(`.* \[pid .*] \[(.+?)\] FTP response: Client "(.+?)", "530 .*"`)
	ret := re.FindStringSubmatch(content)
	if len(ret) > 0 {
		src := ret[2]
		slice_dst := strings.Split(client, ":")
		dst := client
		if len(slice_dst) > 0 {
			dst = slice_dst[0]
		}
		fmt.Printf("Src:%v, User:%v, Client:%v, NodeName:%v\n", src, ret[1], client, hostname)
		k := fmt.Sprintf("app-%v-%v-%v", src, dst, dst)
		bRet, _ := redisClient.Exists(k).Result()
		if bRet {
			redisClient.HIncrBy(k, "times", 1)
		} else {
			redisClient.HSet(k, "times", "1")
			redisClient.Expire(k, time.Duration(setting.AlarmRecoveryTime)*time.Minute)
		}
	}
}
```

## Manager的实现

### Manager的架构

Manager是整套系统的管理后台，支持的功能有：

1. 用户管理
1. Agent资产管理
1. 蜜罐策略管理
1. 攻击日志、报警日志展示
1. 为Agent和server提供策略拉取服务

Manager的代码结构如下：
![](/media/image/unreal/manager.png)

### Manager的代码实现

从manager获取策略时，需要进行认证，防止攻击者无意间获取到蜜罐或镜花水月的所有策略后，进行针对性的避开去攻击其他系统。

获取策略的api接口只支持post方法：
```go
m.Group("/api/", func() {
		m.Post("/policy/", routers.PolicyJSON)
	}) 
```

Agent和Server配置文件中的key必须与manager中的一致，否则会因认证失败无法获取到策略，如下代码所示：

```go
func PolicyJSON(ctx *macaron.Context) {
	ctx.Req.ParseForm()
	timestamp := ctx.Req.Form.Get("timestamp")
	secureKey := ctx.Req.Form.Get("secureKey")
	log.Println(timestamp, secureKey)
	mySecureKey := util.MakeMd5(fmt.Sprintf("%v%v", timestamp, setting.AppKey))
	ret := models.APIData{}
	if mySecureKey == secureKey {
		policy, _ := models.ListPolicy()
		ret = models.APIData{Code: 0, Data: map[string]interface{}{"message": "Get policy successful",
			"value": policy}}
	} else {
		ret = models.APIData{Code: 1, Data: map[string]interface{}{"message": "Api signature verification failed",
			"value": make([]string, 0)}}

	}

	ctx.JSON(200, ret)

}
```
每次获取策略的接口时，Manager会从redis中查出所有满足策略的攻击者的IP，然后返回给Agent，Agent便可以对这些攻击者的IP发动镜花水月模式了。

```go

func ListPolicy() (policy []Policy, err error) {
	err = collPolicy.Find(nil).All(&policy)
	blackIp, err1 := ListRealTimePolicy()
	fmt.Println(blackIp, err1)
	if err == nil && err1 == nil {
		if len(policy) > 0 {
			policy[0].BlackIp = blackIp
		}
	}

	return policy, err
}

func ListRealTimePolicy() (blackIp []string, err error) {
	ret, err := RedisClient.Keys("app-*-*-*").Result()
	// fmt.Printf("%v,%v", ret, ret)
	for _, item := range ret {
		v := strings.Split(item, "-")
		fmt.Println(v, len(v))
		if len(v) > 0 {
			attacker := Attacker{}
			attacker.Src = v[1]
			attacker.Dst = v[2]
			attacker.Client = v[3]
			strTimes, _ := RedisClient.HGet(item, "times").Result()
			times, _ := strconv.Atoi(strTimes)
			if times > AuthFailuresTimes {
				blackIp = append(blackIp, attacker.Src)
			}
		}
	}
	return blackIp, err
}
```

以上代码中，`ListRealTimePolicy()`表示从redis中筛选出攻击者的IP，并由`ListPolicy()`方法一起返回蜜罐的策略。

## 沙盒的实现

沙盒可以装在虚拟机中或者封装到docker中，沙盒产生的数据的记录方式有以下2种：

1. 利用tcpdump在宿主机中抓出相应协议的包，然后利用dpkt解析pcap文件，然后存入manager的DB中
1. 在沙盒中部署类似Agent中的日志分析脚本，并将结果发送到rsyslog中，然后再由rsyslog转发到我们的server中，server收到后再存入manager中的DB中