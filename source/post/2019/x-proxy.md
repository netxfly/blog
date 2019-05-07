```toml
title = "代理蜜罐的开发与应用实战"
slug = "x-proxy"
desc = "x-proxy"
date = "2019-04-12 10:36:04"
update_date = "2019-04-12 10:36:04"
author = ""
thumb = ""
draft = false
tags = ["代理蜜罐的开发与应用实战"]
```

## 代理蜜罐概述
### 蜜罐与代理蜜罐
#### 蜜罐的概念

蜜罐是一种对攻击者进行欺骗的技术，吸引恶意攻击者的任何对象，包括系统、各种服务等，可以及时发现攻击者，并对攻击者的行为进行分析。蜜罐可以分为低交互、高交互、蜜表等种类。

- 低交互式蜜罐只允许简单的交互连接，一般部署在内网，只要有人触碰就会向安全团队报警
- 高交互式蜜罐允许攻击者入侵成功并取得系统权限，可以记录攻击者的一举一动，但可能会带来额外的风险，被攻击者作为跳板进一步攻击其他重要系统
- 蜜表是一种伪造的敏感数据，如数据库表、登录密码文件等，普通用户无法获取到，攻击者在获取时会引发报警

#### 代理蜜罐的概念

- 代理蜜罐本身是一种代理，但是这个代理添加了使用者信息记录的功能，比如来源IP，访问的URL，请求参数与响应数据等。
- 代理蜜罐可以是sock代理，也可以是http代理，部署在外网，供黑产、黄牛、爬虫党扫描到并加入到他们的代理池中使用的

#### VPN蜜罐

可以记录用户的数据vpn就是vpn蜜罐，可以参考以下文章：

[Is NordVPN a Honeypot?](http://vpnscam.com/is-nordvpn-a-honeypot/)

```
数据是新时代的石油，如何采集大量网民的上网数据？做一个 VPN 软件，然后让很多人用，从此开启上帝视角。
本文扒皮了NordVPN，一个月内花 $50 万投放电视广告，背后大金主是一家数据分析公司，数据分析结果会卖给出价最高的公司。
```

我们的代理蜜罐也可以与iptables结合改为VPN蜜罐，具体方法可以参考我之前写过的文章，[基于vpn和透明代理的web漏洞扫描器的实现思路及demo](https://github.com/netxfly/Transparent-Proxy-Scanner)，但向黑产推行我们的VPN蜜罐时成本和难度比较高，本文暂时不讨论。

## 代理蜜罐架构

![](http://docs.xsec.io/images/x-proxy//proxy_honeypot.png)

- 代理蜜罐Agent，提供代理服务，收集http请求与响应数据并发送到server集群
- 代理蜜罐Server（支持水平扩展），接收Agent传来的数据，对数据简单判断后入库
- 后端数据库（mongodb），存储代理蜜罐的数据
- 数据分析程序，对存数的数据进行加工处理，方便管理端展示
- 管理端，查看收集到的数据与数据分析结果

### Agent实现
#### goproxy包介绍

我们的代理蜜罐是基于[goproxy](https://github.com/elazarl/goproxy)包开发的，goproxy包的介绍如下：

1. 是一个可自定义的http代理库，支持普通的http、HTTPS代理，也支持中间人劫持方式的https代理
1. 代理本身是一个`net/http handler`

`net/http handler`怎么理解呢？以下的例子为一个最简单的http代理：
```go
package main

import (
    "github.com/elazarl/goproxy"
    "log"
    "net/http"
)

func main() {
    proxy := goproxy.NewProxyHttpServer()
    proxy.Verbose = true
    log.Fatal(http.ListenAndServe(":8080", proxy))
}
```

我们创建了一个`ProxyHttpServer`，然后把这个对象传给了`http.ListenAndServe`函数，`Handler`的定义与`ListenAndServe`的原型为如下：

```go 
type Handler interface {
    ServeHTTP(ResponseWriter, *Request)
}
func ListenAndServe(addr string, handler Handler) error
```

`ProxyHttpServer`实现了`ServeHTTP`方法，如下所示：
```go
func (proxy *ProxyHttpServer) ServeHTTP(w http.ResponseWriter, r *http.Request)
```

我们再看看`net/http`实现一个简单的http server的代码如下：

```go
package main

import (
	"net/http"
)
func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("老弟，来了呀"))
	})
	http.ListenAndServe(":8080", mux)
}
```

上述代码片段中，`proxy`与`mux`都是`ListenAndServe`的第2个参数，都是一个`net/http handler`。

#### 支持MITM的代理实现

```go
package main

import (
	"github.com/elazarl/goproxy"
	"log"
	"flag"
	"net/http"
)

func main() {
	verbose := flag.Bool("v", false, "should every proxy request be logged to stdout")
	addr := flag.String("addr", ":8080", "proxy listen address")
	flag.Parse()
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = *verbose
    // 显示指定CONNECT请求的处理方式为AlwaysMitm
    proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	log.Fatal(http.ListenAndServe(*addr, proxy))
}
```

上面的代码实现了一个简单的http/https代理，并显式指定了对Connect的请求为总是进行Mitm攻击，这样我们才可以操作与记录用户的请求与响应数据。

- TIPS

```
MITM是指中间人攻击，Man-in-the-MiddleAttack，简称“MITM攻击”，通过拦截正常的网络通信数据，并进行数据篡改和嗅探，而通信的双方却毫不知情。
```

#### 记录请求数据

proxy对象的`OnRequest`方法会返回一个`ReqProxyConds`对象，`ReqProxyConds`对象的`DoFunc`函数支持对请求进行处理，函数原型如下所示：
```go
// ProxyHttpServer.OnRequest Will return a temporary ReqProxyConds struct, aggregating the given condtions.
// You will use the ReqProxyConds struct to register a ReqHandler, that would filter
// the request, only if all the given ReqCondition matched.
// Typical usage:
//	proxy.OnRequest(UrlIs("example.com/foo"),UrlMatches(regexp.MustParse(`.*\.exampl.\com\./.*`)).Do(...)
func (proxy *ProxyHttpServer) OnRequest(conds ...ReqCondition) *ReqProxyConds {
	return &ReqProxyConds{proxy, conds}
}

// DoFunc is equivalent to proxy.OnRequest().Do(FuncReqHandler(f))
func (pcond *ReqProxyConds) DoFunc(f func(req *http.Request, ctx *ProxyCtx) (*http.Request, *http.Response)) {
	pcond.Do(FuncReqHandler(f))
}
```
所以，我们在需要记录request请求时，只需要在proxy的代码中加入以下代码即可：

```go
proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
proxy.OnRequest().DoFunc(modules.ReqHandlerFunc)
log.Fatal(http.ListenAndServe(*addr, proxy))
```

`modules.ReqHandlerFunc`是传递给`DoFunc`处理用请求的函数，详细代码如下：
```go
func ReqHandlerFunc(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	return req, nil
}
```
笔者最初以为`http.Request`会保存到`goproxy.ProxyCtx`中，这个函数不用做任何处理，直接在`proxy.OnResponse().DoFunc`的`RespHandlerFunc`中记录请求与响应数据就可以了，但实际测试下来，在OnResponse中的ProxyCtx中有时候会拿不到request的请求参数，
所以在`OnRequest().DoFunc`的`ReqHandlerFunc`中专门加了请求参数获取的功能，并放到一个并发的map中，key为session_id，值为客户端的请求参数，如下所示：

```go
func ReqHandlerFunc(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	vars.Cmap.Set(fmt.Sprintf("sess_%v", ctx.Session), req)
	if req != nil {
		buf, _ := ioutil.ReadAll(req.Body)
        reqTmp1 := ioutil.NopCloser(bytes.NewBuffer(buf))
        // 恢复reg.body
        req.Body = reqTmp1
        // 使用reg.body
		_ = req.ParseForm()
        params := req.Form
        
        reqTmp := ioutil.NopCloser(bytes.NewBuffer(buf))
        // 再次恢复reg.body
		req.Body = reqTmp
		vars.Cmap.Set(fmt.Sprintf("sess_%v", ctx.Session), params)
	}
	return req, nil
}
```

需要注意的地方是`reg.body`是个`io.ReadCloser`，使用完后值会变成空，后续再次使用的时候会报错，我们用完之后需要再用`ioutil.NopCloser`将其恢复。

#### 记录响应数据
与记录请求数据的方式类似，我们在proxy中加入一句代码即可记录响应数据，如下所示：
```go
proxy.OnResponse().DoFunc(modules.RespHandlerFunc)
```
`RespHandlerFunc`的代码如下所示，作用是把请求与响应数据通过HTTP POST的方式传递给Server端，由server端处理与存储。

```go
func RespHandlerFunc(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	if resp != nil {
		t, ok := vars.Cmap.Get(fmt.Sprintf("sess_%v", ctx.Session))
		defer vars.Cmap.Remove(fmt.Sprintf("sess_%v", ctx.Session))
		if ok {
			params, _ := t.(url.Values)
			//log.Logger.Errorf("params: %v, ok: %v", params, ok)

			meta := NewMeta(ctx, params, time.Now())
			meta.readBody()
			r := meta.Parse()
			r.print()
			data, err := r.Json()
			if err == nil {
				go func() {
					_ = api.Post(string(data))
				}()
			}
		}

	}
	return resp
}

```
传递给服务器端数据为以下struct的json字符串：
```go
type(
    HttpRecord struct {
		Id            int64       `json:"id"`
		Session       int64       `json:"session"`
		Method        string      `json:"method"`
		RemoteAddr    string      `json:"remote_addr"`
		StatusCode    int         `json:"status"`
		ContentLength int64       `json:"content_length"`
		Host          string      `json:"host"`
		Port          string      `json:"port"`
		Url           string      `json:"url"`
		Scheme        string      `json:"scheme"`
		Path          string      `json:"path"`
		ReqHeader     http.Header `json:"req_header"`
		RespHeader    http.Header `json:"resp_header"`
		RequestParam  url.Values  `json:"request_param"`
		RequestBody   []byte      `json:"request_body"`
		ResponseBody  []byte      `json:"response_body"`
		VisitTime     time.Time   `json:"visit_time"`
	}
)
```

默认会记录所有的响应数据，比如图片、音、视频文件的内容，对我们的代理蜜罐来说，这些数据是不需要的，记录下来的话，会增加我们的计算、传输与存储成本。

goproxy的`github.com/elazarl/goproxy/ext/html`扩展包提供了以下几个函数，允许我们给reponse对象设置条件，如下所示：
```go
var IsHtml goproxy.RespCondition = goproxy.ContentTypeIs("text/html")
var IsCss goproxy.RespCondition = goproxy.ContentTypeIs("text/css")
var IsJavaScript goproxy.RespCondition = goproxy.ContentTypeIs("text/javascript",
	"application/javascript")
var IsJson goproxy.RespCondition = goproxy.ContentTypeIs("text/json")
var IsXml goproxy.RespCondition = goproxy.ContentTypeIs("text/xml")
var IsWebRelatedText goproxy.RespCondition = goproxy.ContentTypeIs("text/html",
	"text/css",
	"text/javascript", "application/javascript",
	"text/xml",
	"text/json")
```
我们把OnResponse的条件设为`goproxy_html.IsWebRelatedText`就可以过滤掉不需要的图片、音、视频文件了，如下所示：

```go
proxy.OnResponse(goproxy_html.IsWebRelatedText).DoFunc(modules.RespHandlerFunc)
```

#### 自定义http证书

默认的证书签名为goproxy，有经验的灰、黑产人员可能会做简单的筛选，识别出来我们的代理蜜罐，所以我们需要把https证书也自定义一下。
笔者在Agent的certs目录下，提供了一个相应的sh脚本与模板，可以自动生成适合代理使用的证书，如下图所示：
![](http://docs.xsec.io/images/x-proxy//cert_gen.png)

使用自定义https证书的方式为读取到证书的内容，然后指定`goproxy.GoproxyCa`为我们自定义的证书内容，如下所示：
```go
func setCA(caCert, caKey []byte) error {
	goproxyCa, err := tls.X509KeyPair(caCert, caKey)
	if err != nil {
		return err
	}
	if goproxyCa.Leaf, err = x509.ParseCertificate(goproxyCa.Certificate[0]); err != nil {
		return err
	}
	goproxy.GoproxyCa = goproxyCa
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	return nil
}

func SetCA() (err error) {
	caCert, errCert := ReadFile(vars.CaCert)
	caKey, errKey := ReadFile(vars.CaKey)
	if errCert == nil && errKey == nil {
		err = setCA(caCert, caKey)
	}
	return err
}
```

#### Agent的使用实战

最终完成的Agent支持通过默认配置与命令行参数启动，配置文件的选项如下：

```ini
[proxy]
HOST = 
PORT = 1080
DEBUG = false

[server]
MODE = http
SECRET = api_secret_key
API_URL = http://x_proxy_server:80/api/send
```
- HOST为agent绑定的地址，默认为0.0.0.0
- PORT为agent绑定的端口
- DEBUG为debug模式

- MODE为向server端发送数据的模式，目前只支持http方式
- API_URL为server端接收数据的API接口
- SECRET为api签名key

启动参数如下：
```ini
$ ./agent                                                                                                                                                                                                                                                      
NAME:
   agent - x-proxy agent

USAGE:
   agent [global options] command [command options] [arguments...]
   
VERSION:
   0.1
   
COMMANDS:
     serve    start x-proxy agent
     help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --debug, -d             debug mode
   --port value, -p value  proxy port (default: 1080)
   --help, -h              show help
   --version, -v           print the version
```

用./agent serve指令可直接启动，图中的红色ERROR是笔者为显眼输出的调试LOG，并不是程度真的报错，可以看到有黑产正在撞库。

![](http://docs.xsec.io/images/x-proxy//agent.png)

#### 代理蜜罐发布

我们的代理蜜罐部署之后，就需要等别人使用了，可以被动等待黑产、代理代理商扫描到我们，也可以主动去代理服务商们那里提交我们的代理IP。

比如以下代理服务商有个代理测试（空手套代理）的功能，我们将计就计提交之后，马上就发现有数据进来了。

![](http://docs.xsec.io/images/x-proxy//proxy_release.png)

### server端的实现

Server端的功能比较简单，只是接收客户端传来的数据，反序列化后入库，后端数据库支持`mysql`与`mongodb`，可以在配置文件中配置数据库信息。
主程序为一个用`macron`实现的http server，只实现了一个api接口，如下所示：

```go
func Start() {
	m := macaron.Classic()
	m.Use(macaron.Renderer())

	m.Get("/", routers.Index)
	m.Post("/api/send", routers.RecvData)
	log.Logger.Infof("start web server at: %v", settings.HttpPort)
	log.Logger.Debug(http.ListenAndServe(fmt.Sprintf("0.0.0.0:%v", settings.HttpPort), m))
}
```

路由`routers.RecvData`的作用是接收来自客户端的数据，返序列化后并入库，支持通过nginx作为负载均衡水平扩展，完整代码如下所示：
```go
func RecvData(ctx *macaron.Context) {
	_ = ctx.Req.ParseForm()
	timestamp := ctx.Req.Form.Get("timestamp")
	secureKey := ctx.Req.Form.Get("secureKey")
	data := ctx.Req.Form.Get("data")
	agentHost := ctx.Req.Form.Get("hostname")

	headers := ctx.Req.Header

	// get remote ips
	realIp := headers["X-Forwarded-For"]
	ips := make([]string, 0)
	if len(realIp) > 0 {
		t := strings.Split(realIp[0], ",")
		for _, ip := range t {
			sliceIp := strings.Split(ip, ".")
			if len(sliceIp) == 4 {
				ips = append(ips, strings.TrimSpace(ip))
			}

		}
	} else {
		ips = append(ips, ctx.Req.RemoteAddr)
	}

	mySecretKey := util.MakeSign(timestamp, settings.SECRET)
	if secureKey == mySecretKey {
		var h models.HttpRecord
		err := json.Unmarshal([]byte(data), &h)
		// log.Logger.Info(resp, err)
		agentIp := util.Address2Ip(ctx.Req.RemoteAddr)
		if err == nil {
			if len(ips) > 0 {
				agentIp = ips[0]
			}
			record := models.NewRecord(agentIp, agentHost, h)
			err = record.Insert()
			log.Logger.Infof("record: %v, err: %v", record, err)
		}
	} else {
		_, _ = ctx.Write([]byte("error"))
	}
}
```

Server端需要通过supervisor跑在后台，运行情况如下图所示：

![](http://docs.xsec.io/images/x-proxy//proxy_server.png)

通过输出的debug日志可以看到，一个棒子的网站正在被用代理访问中，具体在做啥不可描述的事，已经入库了。

### 管理端的开发

管理端的功能查看Server端保存的数据，是个对数据库进行增改查删的WEB程序，笔者还是用go的`macron`框架写的，目前实现的路由如下所示：
![](http://docs.xsec.io/images/x-proxy//proxy_manager.png)

WEB开发大同小异，笔者不详细贴代码了，伴随这个文章的github中有完整的项目代码。

第一次启动时会添加一个默认账户，用户名与密码分别为：`xproxy`与`x@xsec.io`，需要登录到后台中修改初始口令。

后台展示的`站点列表`与`密码列表`需要用对数据分析后写到新的collection中，笔者暂不提供了，给大家留个作业吧，对照数据结构，可以用python从`record`集合中分析出来写入`password`集合中。

管理端的截图：

- http record请求与响应记录：

![](http://docs.xsec.io/images/x-proxy//proxy_manager1.png)

- 检测到黑产正在撞网易的库
![](http://docs.xsec.io/images/x-proxy//163.png)

- 检测到黑产正在撞微博的库
![](http://docs.xsec.io/images/x-proxy//weibo.png)

## 代理蜜罐的应用场景
### 被动扫描器

- [代理式的被动扫描器](https://github.com/netxfly/passive_scan)
- [VPN式的被动扫描器]((https://github.com/netxfly/Transparent-Proxy-Scanner))

### 威胁情报

- 甲方用来检测自己的业务是否被黑产、黄牛党利用、抓取撞库的账户信息等，甲方厂商们也可共享情报，各SRC除了在逢时过节用互相送礼物的方式维系关系外，共享抓到的威胁情报也是个不错的选择
- 乙方厂商可以用来作为情报的输入源之一
- 白帽子可以拿到撞库等情报向SRC提情报换取奖励

### 其他用途

- 使用了别人的代理，别人就可以操纵你的流量，记录、篡改不在话下，如果代理提供商还有其他附加业务，可以做的事情你懂的

## 后记

- 该套系统的代码及思路为双刃剑，仅供用于正途，请勿用于非法用途，否则产生的一切后果请自行承担；
- 撞库截图中涉及到的厂商看到后请赶紧联系我索取详情（证明身份后我会告之详情），因为黑产的撞库行为还在继续日夜进行中；
- 本人任职于美团信息安全部，有想一起共事的小伙伴请加我微信详谈（工种不限）；
- 邮箱：x@sec.lu，微信：netxfly
- 项目地址：[https://github.com/netxfly/x-proxy](https://github.com/netxfly/x-proxy)

## 附录

### 参考资料
- [Is NordVPN a Honeypot?](http://vpnscam.com/is-nordvpn-a-honeypot/)
- [基于vpn和透明代理的web漏洞扫描器的实现思路及demo](https://github.com/netxfly/Transparent-Proxy-Scanner)

### 学习GO语言的资料

- [在2019成为一名Go开发者的路线图](https://github.com/Quorafind/golang-developer-roadmap-cn)
- [Go 入门指南](https://github.com/Unknwon/the-way-to-go_ZH_CN)
- [build-web-application-with-golang](https://github.com/astaxie/build-web-application-with-golang)
- [Go语言高级编程](https://github.com/chai2010/advanced-go-programming-book)
- [Go 语言学习资料与社区索引](https://github.com/Unknwon/go-study-index)

### 用到的库与框架

- [goproxy](https://github.com/elazarl/goproxy)
- [cli](github.com/urfave/cli)
- [logrus](github.com/sirupsen/logrus)
- [macaron](https://github.com/go-macaron/macaron)
- [xorm](github.com/go-xorm/xorm)
- [upper.io](upper.io/db.v3)
- [mgo](gopkg.in/mgo.v2)
