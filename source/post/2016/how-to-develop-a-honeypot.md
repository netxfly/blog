```toml
title = "自制蜜罐之前端部分"
slug = "how-to-develop-a-honeypot"
desc = "how-to-develop-a-honeypot"
date = "2016-07-08 16:04:12"
update_date = "2016-07-08 16:04:12"
author = ""
thumb = ""
tags = ["自制蜜罐"]
```

## 自制蜜罐
### 背景
生产系统的内网部署蜜罐后可以监控到黑客对内网的探测及攻击行为，方便安全工程师第一时间发现被入侵并及时止损，防止出现公司重要数据被窃取却浑然不然的情况。
所以我们有必要在重要业务的内网机房部署蜜罐。

### 需求
1. 第一时间发现攻击者
1. 攻击行为及指纹记录、识别
1. 覆盖到全部的协议及端口

目前市面上已经有许多商业或开源的蜜罐系统，如[awesome-honeypots](https://github.com/paralax/awesome-honeypots)中收集了大量的开源的蜜罐系统，
但是这些开源的蜜罐系统存在以下问题：

1. 安装、部署比较复杂、繁琐，学习成本高
1. 自定义或扩展功能的成本高
1. 覆盖不到全部的协议及端口
1. 开发进度滞后，没有覆盖到最新的redis、elastic、stuct2等漏洞的利用的监控

所以我们有必要自己开发一套易于部署、覆盖全端口全协议及最新漏洞的蜜罐系统。
<!--more-->

## 蜜罐架构图
![架构图](/media/images_honeypot/topology.png)

1. Agent
    1. 记录攻击log并发送到server中
    1. 按照策略将攻击流量转到后端server
    1. 定期更新policy
1. Server:
    1. 接收来自各agent的攻击log
    1. 通过策略判断是否需要报警
    1. 攻击log及报警log保存、备份
1. Backend
    1. 利用docker构建常见的各服务
    1. 攻击行为记录、指纹识别
1. Policy server
    1. Agent和server的策略管理

## Agent的实现

Agent利用iptables记录了对Agent所有端口的tcp及udp协议的访问log，并用iptables将请求按policy指定的规则转到了后端的攻击行为识别服务器中。

### iptables基础

netfilter/iptables（简称为iptables）组成Linux平台下的包过滤防火墙，与大多数的Linux软件一样，这个包过滤防火墙是免费的，它可以代替昂贵的商业防火墙解决方案，完成封包过滤、封包重定向和网络地址转换（NAT）等功能。
Netfilter是Linux操作系统核心层内部的一个数据包处理模块，它具有如下功能：

1. 网络地址转换(Network Address Translate)
1. 数据包内容修改
1. 包过滤的防火墙功能

真正实现防火墙功能的是处于内核级的netfilter，iptables是应用层的netfilter的管理工具，netfilter与iptables在linux操作系统中的位置及角色如下图所示：

![iptables1](/media/images_honeypot/iptables1.png)

Netfilter提供了数据包的5个Hook Point，当有数据通过这些位置时，钩子就会触发，从而可以调用我们自定义的函数，这5个挂载点分别为：

- NF_IP_PRE_ROUTING
- NF_IP_LOCAL_IN
- NF_IP_FORWARD
- NF_IP_LOCAL_OUT
- NF_IP_POST_ROUTING

Netfilter所设置的规则是存放在内核内存中的，而 iptables 是一个应用层的应用程序，它通过 Netfilter 放出的接口来对存放在内核内存中的 XXtables（Netfilter的配置表）进行修改。

这个XXtables由表tables、链chains、规则rules组成，iptables在应用层负责修改这个规则文件。

iptables内置了4个表，即Filter表、Nat表、Mangle表和Raw表，分别用于实现包过滤、网络地址转换、包重构(修改)和数据跟踪处理。

这几个表的优先顺序为Raw -> Mangle -> Nat -> Filter。
iptables表和链的结构如下图所示：

![iptables2](/media/images_honeypot/iptables2.png)

#### iptables中的规则表（table）

1. Raw表有两个链：OUTPUT、PREROUTING，作用为决定数据包是否被状态跟踪机制处理
1. Mangle表有五个链：PREROUTING、POSTROUTING、INPUT、OUTPUT、FORWARD，作用为修改数据包的服务类型、TTL、并且可以配置路由实现QOS
1. Nat表有三个链：PREROUTING、POSTROUTING、OUTPUT，作用为用于网络地址转换
1. Filter表有三个链：INPUT、FORWARD、OUTPUT，作用为数据包过滤

#### iptables中的规则链接（chain）

1. INPUT——进来的数据包应用此规则链中的策略。
1. OUTPUT——外出的数据包应用此规则链中的策略。
1. FORWARD——转发数据包时应用此规则链中的策略。
1. PREROUTING——对数据包作路由选择前应用此链中的规则，所有的数据包进来的时侯都先由这个链处理。
1. POSTROUTING——对数据包作路由选择后应用此链中的规则，所有的数据包出来的时侯都先由这个链处理。

#### iptales中的数据流

![iptables3](/media/images_honeypot/iptables3.png)

iptables中的数据流可以总结为以下3句话：

1. 发往本地的包，数据流向为：PREROUTING -> INPUT
1. 发往其他地址的包，数据流向为：PREROUTING -> FORWARD -> POSTROUTING
1. 从本地发出的包的数据流向为： OUTPUT -> POSTROUTING

#### iptables规则管理

![iptables4](/media/images_honeypot/iptables4.png)

![iptables5](/media/images_honeypot/iptables5.png)

#### iptables命令参数
```bash
[-t 表名]：该规则所操作的哪个表，可以使用filter、nat等，如果没有指定则默认为filter
-A：新增一条规则，到该规则链列表的最后一行
-I：插入一条规则，原本该位置上的规则会往后顺序移动，没有指定编号则为1
-D：从规则链中删除一条规则，要么输入完整的规则，或者指定规则编号加以删除
-R：替换某条规则，规则替换不会改变顺序，而且必须指定编号。
-P：设置某条规则链的默认动作
-nL：-L、-n，查看当前运行的防火墙规则列表
chain名：指定规则表的哪个链，如INPUT、OUPUT、FORWARD、PREROUTING等
[规则编号]：插入、删除、替换规则时用，--line-numbers显示号码
[-i|o 网卡名称]：i是指定数据包从哪块网卡进入，o是指定数据包从哪块网卡输出
[-p 协议类型]：可以指定规则应用的协议，包含tcp、udp和icmp等
[-s 源IP地址]：源主机的IP地址或子网地址
[--sport 源端口号]：数据包的IP的源端口号
[-d目标IP地址]：目标主机的IP地址或子网地址
[--dport目标端口号]：数据包的IP的目标端口号
-m：extend matches，这个选项用于提供更多的匹配参数，如：

-m state --state ESTABLISHED,RELATED
-m tcp --dport 22
-m multiport --dports 80,8080
-m icmp --icmp-type 8
<-j 动作>：处理数据包的动作，包括ACCEPT、DROP、REJECT等
```

### 利用shell实现一个demo

```bash
#!/bin/bash
:<<BLOCK
Copyright (c) 2016 www.xsec.io

 - User: netxfly<x@xsec.io>
 - Date: 2016/6/20

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
BLOCK

WHITELIST_IPs=(1.1.1.1.1 111.111.111.111 222.222.222.222)
WHITELIST_PORTS="88,96,99,55522"
BACKEND="10.10.10.10"
ATTACK_IP="9.9.9.9.9"

ATTACK_IP1="9.9.9.9.0/24"
UNREAL_TARGET="220.181.112.244:80"

# set ip_forward
function set_ip_forward()
{
    /sbin/sysctl -w net.ipv4.ip_forward=1
    sysctl -p
}

# delete custom iptables chain
function delete_policy()
{
    /sbin/iptables -t nat -F 
    /sbin/iptables -t nat -X HONEYPOT
    /sbin/iptables -t nat -X FIREWALL_IN
    /sbin/iptables -t nat -X FIREWALL_OUT

    /sbin/iptables -t filter -F 
    /sbin/iptables -t filter -X WHITELIST
}

# init iptables chain
function init_policy()
{
    /sbin/iptables -t nat -N HONEYPOT
    /sbin/iptables -t nat -A PREROUTING -j HONEYPOT

    /sbin/iptables -t filter -N WHITELIST
    /sbin/iptables -t filter -A INPUT -j WHITELIST

    /sbin/iptables -t nat -N FIREWALL_IN
    /sbin/iptables -t nat -A PREROUTING -j FIREWALL_IN
    /sbin/iptables -t nat -N FIREWALL_OUT
    /sbin/iptables -t nat -A POSTROUTING -j FIREWALL_OUT

    /sbin/iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

    /sbin/iptables -t nat -A HONEYPOT -i eth0 -p tcp -m state --state NEW,ESTABLISHED,RELATED -j LOG --log-prefix "iptables:"

}

# set white policy(ip white)
function set_white_policy()
{
    for ip in $WHITELIST_IPs
    do
        /sbin/iptables -t filter -A WHITELIST -s $ip -j DROP
    done
}

# set honeypot policy(ports white)
function set_honeypot_policy()
{
    /sbin/iptables -A HONEYPOT -t nat -i eth0 -p tcp -m multiport ! --dport $WHITELIST_PORTS -j DNAT --to-destination $BACKEND
    /sbin/iptables -A HONEYPOT -t nat -i eth0 -p udp -m multiport ! --dport $WHITELIST_PORTS -j DNAT --to-destination $BACKEND
    # /sbin/iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
}

# start honeypot
function StartHoneypot()
{
    set_ip_forward
    init_policy
    set_white_policy
    set_honeypot_policy
}

# stop honeypot
function StopHoneypot()
{
    delete_policy
}

function showHelp()
{
    echo "Usage: [sudo] ./honeypot.sh  [OPTIONS]"
    echo "Options:"
    echo -e "\t-h | --help\t\t show this help"
    echo -e "\t-start   \t\t start honeypot"
    echo -e "\t-stop    \t\t stop honeypot"
}

# Check if user is root
[ $(id -u) != "0" ] && { echo "Must run as root, exit1111..." >&2; exit 1; }

while true ; do
    case "$1" in

        -h|--help)
            showHelp;
            echo ""
            exit 0
            ;;

        -start|--start)
        echo "start honeypot";
        StartHoneypot;
        exit 0
        ;;

        -stop|--stop)
        echo "stop honeypot";
        StopHoneypot;
        exit 0
        ;;

        *)
            # echo "invalid option. $1"
            showHelp;
            exit 1
            ;;
    esac
done

function policy_reset()
{
    /sbin/iptables -t nat -F FIREWALL_IN
    /sbin/iptables -t nat -F FIREWALL_OUT
    iptables -t nat -A FIREWALL_OUT -o eth0 -j MASQUERADE
}

# # douzhuanxingyi
function douzhuanxingyi()
{
    iptables -t nat -A FIREWALL_IN  -s $ATTACK_IP -j DNAT --to-destination $ATTACK_IP
    
}

function jinghuashuiyue()
{
    /sbin/iptables -t nat -A FIREWALL_IN -i eth0 -p tcp -m tcp --dport 1:65535 -s $ATTACK_IP1 -j DNAT --to-destination $UNREAL_TARGET
}
```
#### demo代码解读

1. set_ip_forward函数将net.ipv4.ip_forward设为了1，这样才能开启linux的数据转发功能。
1. init_policy中利用-N指令新建了不同的chain，目的是为了在将同类的操作放到同一个链中，防止在操作规则的过程中影响到其他的iptables规则。
1. set_white_policy为设置白名单，来自白名单的请求直接drop掉，不会转到后端服务器；
1. set_honeypot_policy为设置蜜罐的转发规则，除了服务器管理、监控外的其他端口外的其他请求全部转到后端
1. douzhuanxingyi使用了金庸武侠小说《天龙八部》中武功名，指将攻击者的攻击全部反弹回去
1. jinghuashuiyue是使用了动画片《死神》中蓝染的斩魄刀的名字：(幻觉系最强斩魄刀），指将攻击者的所有请求转到一个伪造的地址中，误导攻击者。
1. 在使用了DNAT后，需要在POSTROUTING链中设置SNAT，每条规则都需要设置，操作麻烦且容易出错，用`-j MASQUERADE`可以自动完成这些操作

### golang实现最终的agent
相比python来说，golang写的程序无任何依赖，直接编译为一个二进制文件就能执行，所以我们选择了golang。
agent的功能为：

1. 支持配置，配置文件中为策略的URL，转发数据的网卡名
1. 定期从策略服务器中拉取最新的策略并应用
1. 将syslog发送到后端的server中

发送syslog到后端服务器的功能无需开发，centos 6默认全部为rsyslog，只需配置下rsyslog便可将日志发送到后端server，
配置完需重启rsyslog服务/etc/init.d/rsyslog restart，配置参数如下：

```bash
[root@honeypot_agent01 agent]# cat /etc/rsyslog.d/iptables.conf 
:msg,contains,"iptables"  @@111.111.111.111:514
```

111.111.111.111 为蜜罐的server，514为端口，@@表示以TCP发送log，@表示以UDP发送数据
建议全部使用TCP，个别网络的ACL导致tcp不通时可以使用udp。

agent的定期运行配置在cronta中，每1分钟更新一次策略

```bash
[root@honeypot_agent01 agent]# crontab -e
*/1 * * * *  /data/honeypot/agent/honeypot_agent
```

Agent的部分代码如下：

```go

// Get forward policy && white list
func GetPolicy() (p Policys, err error) {

	resp, err := http.Get(Url)
	if err != nil {
		log.Fatal(err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	json.Unmarshal(body, &p)
	resp.Body.Close()
	return p, err
}

// set iptables
func SetIptables(policy Policys) {
	// InitPolicy()

	white_ip_policy := policy.Whiteip
	// set white policy
	for _, white_ip := range white_ip_policy {
		fmt.Println("/sbin/iptables", "-t", "filter", "-A", "WHITELIST", "-i", interfaceName, "-s", white_ip, "-j", "DROP")
		exec.Command("/sbin/iptables", "-t", "filter", "-A", "WHITELIST", "-i", interfaceName, "-s", white_ip, "-j", "DROP").Output()
	}

	fmt.Println("/sbin/iptables", "-t", "nat", "-A", "HONEYPOT", "-i", interfaceName, "-p", "tcp", "-m", "multiport", "!", "--dports", strings.Join(policy.Whiteport, ","), "-j", "DNAT", "--to-destination", policy.Backend)
	ret, err := exec.Command("/sbin/iptables", "-t", "nat", "-A", "HONEYPOT", "-i", interfaceName, "-p", "tcp", "-m", "multiport", "!", "--dports", strings.Join(policy.Whiteport, ","), "-j", "DNAT", "--to-destination", policy.Backend).Output()
	fmt.Println(ret, err)
	exec.Command("/sbin/iptables", "-t", "nat", "-A", "POSTROUTING", "-o", interfaceName, "-j", "MASQUERADE").Output()
}

// set ipv4.ip_forward
func SetIp_forward() {
	cmd := exec.Command("/sbin/sysctl", "-w", "net.ipv4.ip_forward=1")
	cmd.Run()
	cmd = exec.Command("/sbin/sysctl", "-p")
	cmd.Run()
}

// Init iptables policy
func InitPolicy() {
	// set honeypot chain in nat table
	exec.Command("/sbin/iptables", "-t", "nat", "-N", "HONEYPOT").Run()
	exec.Command("/sbin/iptables", "-t", "nat", "-F", "HONEYPOT").Run()
	exec.Command("/sbin/iptables", "-t", "nat", "-A", "PREROUTING", "-j", "HONEYPOT").Run()
	exec.Command("/sbin/iptables", "-t", "nat", "-A", "HONEYPOT", "-i", interfaceName, "-p", "tcp", "-m", "state", "--state", "NEW,ESTABLISHED,RELATED", "-j", "LOG", "--log-prefix", "iptables ").Run()
	// set white list chain in filter table
	exec.Command("/sbin/iptables", "-t", "filter", "-N", "WHITELIST").Run()
	exec.Command("/sbin/iptables", "-t", "filter", "-F", "WHITELIST").Run()
	exec.Command("/sbin/iptables", "-t", "filter", "-A", "INPUT", "-j", "WHITELIST").Run()
}

// Delete Policy
func DeletePolicy() {
	// Flush rule
	exec.Command("/sbin/iptables", "-t", "nat", "-F").Run()
	exec.Command("/sbin/iptables", "-t", "filter", "-F").Run()
	// delete chain
	exec.Command("/sbin/iptables", "-t", "nat", "-X", "HONEYPOT").Run()
	exec.Command("/sbin/iptables", "-t", "filter", "-X", "WHITELIST").Run()
}

// Start Agent
func Start(p Policys) {
	Stop()
	// set ip forward
	SetIp_forward()
	// create iptables chain
	InitPolicy()
	// set iptables rule
	SetIptables(p)
}

// Stop Agent
func Stop() {
	// clean iptables rule and chain
	DeletePolicy()
}

```
## Server的实现
蜜罐server使用`gopkg.in/mcuadros/go-syslog.v2`包实现了一个rsyslog server，将每条收到的rsyslog进行格式化，然后判断是否在白名单中，如果不在白名单中，然后对攻击数据进行计数（超过一定的时间后再开始从0开始计数），
如果在规定的时间内超过配置的报警的次数后就不会再报了，防止短时间内产生大量的垃圾邮件。

比如可以把策略设为：同一个来源的攻击者，3分钟内只发1封报警邮件，报警策略的代码如下：

```go
// check if send alarm mail
func AlarmPolicy(redisConfig RedisConfig, sysLog map[string]interface{}) (isAlarm bool) {
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", redisConfig.Host, redisConfig.Port),
		Password: redisConfig.Password, //  password set
		DB:       redisConfig.Db,       // use default DB
	})

	src, ok := sysLog["src"].(string)
	if ok {
		bRet, _ := client.Exists(src).Result()
		if bRet {
			client.HIncrBy(src, "times", 1)
			// client.Expire(src, time.Duration(redisConfig.Duration)*time.Minute)

		} else {
			client.HSet(src, "times", "1")
			client.Expire(src, time.Duration(redisConfig.Duration)*time.Minute)
		}

		strRet, _ := client.HGet(src, "times").Result()
		ret, _ := strconv.Atoi(strRet)
		fmt.Printf("strRet:%v, ret:%v, AlarmOffTime:%v\n", strRet, ret, redisConfig.AlarmOffTime)
		if ret <= redisConfig.AlarmOffTime {
			isAlarm = true
		}
	}
	return isAlarm
}

// send alarm mail
func Alarm(redisConfig RedisConfig, sysLog map[string]interface{}, subject string, body string, mail_config MailConfig, alarmInfo AlarmInfo) {
	if AlarmPolicy(redisConfig, sysLog) {
		go SendMail(subject, body, mail_config)
		go InsertElastic(*alarmInfo.Client, alarmInfo.EsIndex, alarmInfo.EsDocument, alarmInfo.Id, alarmInfo.LogParts)
	}
}

```

以下为server处理rsyslog的核心代码：

```go
func main() {
	Loadconfig()

	channel := make(syslog.LogPartsChannel)
	handler := syslog.NewChannelHandler(channel)

	server := syslog.NewServer()
	server.SetFormat(syslog.Automatic)
	server.SetHandler(handler)
	server.ListenUDP("0.0.0.0:514")
	server.ListenTCP("0.0.0.0:514")

	server.Boot()

	go func(channel syslog.LogPartsChannel) {
		client, err := helper.ConnectElastic(es_info)
		log.Println(client, err, syslogConfig.Backup)
		for logParts := range channel {
			// fmt.Printf("%V,%v\n", logParts, logParts)
			value, ok := logParts["content"].(string)
			if ok {
				// backup syslog to localhost
				if syslogConfig.Backup == 1 {
					go helper.BackupSyslog(syslogConfig.Tag, value)
				}
				ret := helper.ParseLogContent(value)
				// logParts["content"] = ret
				// fmt.Println(ret)
				delete(logParts, "content")
				for k, v := range ret {
					logParts[k] = v
				}
				// fmt.Println("logParts: ", logParts)
				p, _ := helper.GetPolicy(Url)
				white_list := helper.GetWhiteList(p)
				white_ports := helper.GetWhitePort(p)
				src := ret["src"]
				id := ret["id"]
				dpt := ret["dpt"]

				// for mail content template
				var mailContent helper.MailContent
				Timestamp, _ := logParts["timestamp"].(time.Time)
				mailContent.Timestamp = Timestamp.Format("2006-01-02 15:04:05")
				mailContent.SrcIp, _ = logParts["src"].(string)
				mailContent.SrcHostname, _ = helper.GetHostNameByIp(mailContent.SrcIp)
				mailContent.SrcPort, _ = logParts["spt"].(string)
				mailContent.Proto, _ = logParts["proto"].(string)
				mailContent.DestIp, _ = logParts["dst"].(string)
				mailContent.DestPort, _ = logParts["dpt"].(string)
				mailContent.Hostname, _ = logParts["hostname"].(string)
				mailContent.Color = helper.GetColor()

				log.Println(white_list, src, white_ports, dpt, mailContent)
				if !white_list[src] && !white_ports[dpt] {
					subject := fmt.Sprintf("[蜜罐报警]%v, 截获来自%v:%v对%v:%v的攻击(%v)", mailContent.Timestamp, src, ret["spt"], ret["dst"], ret["dpt"], ret["proto"])
					// body, _ := json.MarshalIndent(logParts, "", "\t")
					t, _ := template.New("mail").Parse(helper.HtmlMail)
					var body bytes.Buffer
					t.Execute(&body, mailContent)

					// Alarm info, save to es too
					var alarmInfo helper.AlarmInfo
					alarmInfo.Client = client
					alarmInfo.EsIndex = es_info.Index
					alarmInfo.EsDocument = es_info.DocumentAlarm
					alarmInfo.Id = id
					alarmInfo.LogParts = logParts

					go helper.Alarm(redisConfig, logParts, subject, fmt.Sprintf("%s", body.String()), mail_config, alarmInfo)
					
					go helper.InsertElastic(*client, es_info.Index, es_info.Document, id, logParts)
				}
			}
			// log.Println(strings.Repeat("-", 70))
		}
	}(channel)

	server.Wait()
}

```

蜜罐的测试效果：
![honeypot](/media/images_honeypot/honeypot.png)


## 扩展功能
以上的Agent放在重要系统的内网网段为一个支持所有协议和端口的蜜罐，其实也可以改为一个适用于小网站的防火墙放在外网。
做成防火墙需要做的改动如下：

1. 去掉数据转发到后端的功能
1. 设计防火墙策略（以下仅为举例，正式使用的话，需要根据对不同的端口的攻击设置不同的频率）例如：
    1. 如果1分钟内同一个IP的请求超过100，可以将攻击者的所有请求转到一个欺骗的地址（镜花水月）
    1. 如果1分钟内同一个IP的请求超过300，可以将攻击者的所有请求原封不动的反弹回去（斗转星移）
    1. 如果1分钟内同一个IP的请求超过600，直接将攻击者的IP Block掉，禁止访问。

## 参考资料

1. [How Does It Work: IPTables](https://n0where.net/how-does-it-work-iptables/)
1. [Linux下iptables防火墙原理及使用](http://txgcwm.github.io/blog/2013/07/25/linuxxia-iptablesfang-huo-qiang-yuan-li-ji-shi-yong/)
1. [iptables防火墙原理详解](https://segmentfault.com/a/1190000002540601)