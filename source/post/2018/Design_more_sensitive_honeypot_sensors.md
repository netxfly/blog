```toml
title = "设计灵敏的蜜罐传感器"
slug = "Design_more_sensitive_honeypot_sensors"
desc = "Design_more_sensitive_honeypot_sensors"
date = "2018-01-04 11:11:07"
update_date = "2018-01-04 11:11:07"
author = ""
thumb = ""
draft = false
tags = ["tag"]
```

### 设计灵敏的蜜罐传感器

以前我写过一篇蜜罐设计的文章[自制蜜罐之前端部分，https://xsec.io/2016/7/8/how-to-develop-a-honeypot.html](https://xsec.io/2016/7/8/how-to-develop-a-honeypot.html)，这个蜜罐的传感器实现的原理是设置iptables的LOG指令，将`NEW,ESTABLISHED,RELATED`三种状态的连接信息记录到syslog中，然后再通过rsyslog的转发机制发送到蜜罐server中进行检测：

```go
exec.Command("/sbin/iptables", "-t", "nat", "-A", "HONEYPOT", "-p", "tcp", "-m", "state",
		"--state", "NEW,ESTABLISHED,RELATED", "-j", "LOG", "--log-prefix", "iptables_honeypot").Run()
```

tips：iptables的几种状态
```bash
ESTABLISHED：表示包是完全有效的，而且属于一个已建立的连接，这个连接的两端都已经有数据发送。
NEW：表示包将要或已经开始建立一个新的连接，或者是这个包和一个还没有在两端都有数据发送的连接有关。
RELATED：表示包正在建立一个新的连接，这个连接是和一个已建立的连接相关的。比如，FTP data transfer，ICMP error 和一个TCP或UDP连接相关
INVALID：表示这个包没有已知的流或连接与之关联，也可能是它包含的数据或包头有问题
```

这个蜜罐的弊端是只能检测到有状态的扫描尝试，比如对Server端支持的服务的攻击尝试，对于server端没有监听的端口的扫描尝试，传感器是检测不到的。于是笔者打算把数据捕获模块更换一下，用sniff本地网卡的方式替换掉以前的iptables的LOG指令。

### 实现原理

利用libpcap库监听本地指定网卡的数据，先过一次白名单，将白名单中的数据忽略，将不在白名单中的的IP 五元组信息通过http的方式发到server端进行检测、报警。

使用libpcap抓包的前置条件是安装并设置数据转发
```bash
# centos
yum install -y libpcap-devel
# Debian/Ubuntu
sudo apt-get install -y libpcap-dev
# OSX
brew install libpcap

# OSX
sudo sysctl net.inet.ip.forwarding=1
# FreeBSD
sudo sysctl -w net.inet.ip.forwarding=1
# Linux
sudo sysctl -w net.ipv4.ip_forward=1
```
<!--more-->
### 具体实现

本项目暂不会开源，本文只写原理及截取部分关键代码。
packets/packets.go的作用为捕获本地网卡所有的数据包后，发给`processPacket`函数处理。

```go
package packets

import (
	"github.com/patrickmn/go-cache"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"xsec-honeypot/client/logger"
	"xsec-honeypot/client/setting"
	"xsec-honeypot/client/vars"

	"time"
	"strings"
	"net/url"
)

var (
	device      string
	snapshotLen int32 = 1024
	promiscuous bool  = true
	err         error
	timeout     time.Duration = pcap.BlockForever
	handle      *pcap.Handle

	filter = ""

	ApiUrl    string
	SecureKey string

	Ips []string

	ApiIp    string
	SensorIp string
)

func init() {
	device = setting.Interface
	ApiUrl = setting.SERVER_URL
	SecureKey = setting.KEY

	Ips, err = GetIpList(device)

	urlParsed, err := url.Parse(ApiUrl)
	if err == nil {
		apiHost := urlParsed.Host
		ApiIp, _ = Host2Ip(strings.Split(apiHost, ":")[0])
		SensorIp = Ips[0]
	}

	vars.CACHE = cache.New(5*time.Minute, cache.DefaultExpiration)
}

func Start() {
	// Open device
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		logger.Log.Fatal(err)
	}
	defer handle.Close()
	handle.SetBPFFilter(filter)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		processPacket(packet)
	}
}

```

以下为`processPacket`及其辅助函数的代码，稍后会逐步解释几个关键点：

```go

package packets

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"xsec-honeypot/client/models"
	"xsec-honeypot/client/logger"
	"xsec-honeypot/client/util"
	"xsec-honeypot/client/setting"
	"xsec-honeypot/client/util/syslog"

	"encoding/json"
	"time"
	"net/url"
	"net/http"
	"fmt"
	"xsec-honeypot/client/vars"
	"strings"
)

func processPacket(packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, ok := ipLayer.(*layers.IPv4)
		if ok {
			switch ip.Protocol {
			case layers.IPProtocolTCP:
				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				if tcpLayer != nil {
					tcp, _ := tcpLayer.(*layers.TCP)

					srcPort := SplitPortService(tcp.SrcPort.String())
					dstPort := SplitPortService(tcp.DstPort.String())

					connInfo := models.NewConnectionInfo("tcp", ip.SrcIP.String(), srcPort, ip.DstIP.String(), dstPort)

					go func(info *models.ConnectionInfo) {
						if !CheckSelfPacker(info) && !IsInWhite(info) && !CheckCache(info) {
							logger.Log.Debugf("[TCP] %v:%v -> %v:%v", ip.SrcIP, tcp.SrcPort.String(), ip.DstIP, tcp.DstPort.String())
							SendPacker(info)
						}
					}(connInfo)

				}

			case layers.IPProtocolUDP:
				udpLayer := packet.Layer(layers.LayerTypeUDP)
				if udpLayer != nil {
					udp, _ := udpLayer.(*layers.UDP)

					srcPort := SplitPortService(udp.SrcPort.String())
					dstPort := SplitPortService(udp.DstPort.String())
					connInfo := models.NewConnectionInfo("tcp", ip.SrcIP.String(), srcPort, ip.DstIP.String(), dstPort)

					go func(info *models.ConnectionInfo) {
						if !CheckSelfPacker(info) && !IsInWhite(info) && !CheckCache(info) {
							logger.Log.Debugf("[UDP] %v:%v -> %v:%v", ip.SrcIP, udp.SrcPort.String(), ip.DstIP, udp.DstPort.String())
							SendPacker(info)
						}
					}(connInfo)

				}

			}
		}
	}

}

func SendPackerAPI(connInfo *models.ConnectionInfo) (err error) {
	infoJson, err := json.Marshal(connInfo)
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	urlApi := fmt.Sprintf("%v%v", ApiUrl, "/api/packet/")
	secureKey := util.MakeSign(timestamp, SecureKey)

	http.PostForm(urlApi, url.Values{"timestamp": {timestamp}, "secureKey": {secureKey}, "data": {string(infoJson)}})
	return err
}

func SendPacker(connInfo *models.ConnectionInfo) (err error) {
	if setting.TRANSMISSION_MODE == "http" {
		SendPackerAPI(connInfo)
	} else {
		js, err := connInfo.String()
		if err == nil {
			syslog.SyslogObject.Write(js)
		}
	}
	return err
}

func CheckSelfPacker(p *models.ConnectionInfo) (ret bool) {
	if p.SrcIp == SensorIp ||
		p.SrcIp == SensorIp && p.DstIp == ApiIp ||
		p.SrcIp == ApiIp && p.DstIp == SensorIp {
		ret = true
	}
	return ret
}

func IsExistCache(p *models.ConnectionInfo) (ret bool) {
	k := fmt.Sprintf("%v:%v-%v:%v", p.SrcIp, p.SrcPort, p.DstIp, p.DstPort)
	_, ret = vars.CACHE.Get(k)
	return ret
}

func CachePacket(p *models.ConnectionInfo) {
	k := fmt.Sprintf("%v:%v-%v:%v", p.SrcIp, p.SrcPort, p.DstIp, p.DstPort)
	vars.CACHE.Set(k, true, 5*time.Minute)
}

func CheckCache(p *models.ConnectionInfo) (ret bool) {
	if IsExistCache(p) {
		ret = true
	} else {
		CachePacket(p)
	}
	return ret
}

func SplitPortService(portService string) (port string) {
	t := strings.Split(portService, "(")
	if len(t) > 0 {
		port = t[0]
	}
	return port
}

```

关键点说明：

- 在传感器启动时，会实例化一块内存`vars.CACHE = cache.New(5*time.Minute, cache.DefaultExpiration)`用来存放IP五元组信息，因为每一个连接，我们都会抓到大量的包，如果全部传递到服务器端会造成很大的压力，也会造成大量的重复报警。现在采用Cache的机制，保证5分钟内，同一个连接只向服务器上报一次。

IP五元组的定义在`models/packet.go`中，如下：
```go
type ConnectionInfo struct {
	Protocol string `json:"protocol"`
	SrcIp    string `json:"src_ip"`
	SrcPort  string `json:"src_port"`
	DstIp    string `json:"dst_ip"`
	DstPort  string `json:"dst_port"`
}
```
- `!CheckSelfPacker(info) && !IsInWhite(info) && !CheckCache(info)`的作用是排除蜜罐的传感器与服务器端、管理端的通信连接、排除白名单、排除是否已经上报过，然后通过`SendPacker` 调用http接口向服务器端传递`models.ConnectionInfo`数据。

### 写在最后

当然我们不是完全把iptables舍弃了，只是把传感器的数据捕获模块更新了，改得更加灵敏了。根据策略将攻击者重定向到蜜罐后端的沙盒服务的功能还是依赖iptables做的。

遇到跨机房与跨多个公有云的处理也离不开iptables的配合，这个时候可以在传感器中集成一个vpn client，传感器启动时直接拨入到server端和沙盒服务所在的网段中，然后利用iptables将相应的攻击通过vpn链路转发到相应的沙盒中。
