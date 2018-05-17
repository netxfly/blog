```toml
title = "「技术随笔」iptables报too many ports specified的解决"
slug = "iptables-too-many-ports-specified-solution"
desc = "iptables-too-many-ports-specified-solution"
date = "2018-05-17 13:09:14"
update_date = "2018-05-17 13:09:14"
author = ""
thumb = ""
draft = false
tags = ["tag"]
```

## 背景

笔者写的蜜罐的agent底层依赖iptables，在设置高交互蜜罐的端口转发规则时会用到iptables的`multiport --dports`指令，但是超过`--dports`超过15个的话，会报`too many ports specified`错误：
```bash
iptables -A INPUT -p tcp -m multiport --dports 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
iptables -A INPUT -p tcp -m multiport --dports 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16
iptables v1.4.21: too many ports specified
Try `iptables -h' or 'iptables --help' for more information.
```

关于蜜罐与攻击欺骗防御系统的设计与实现，可以参考笔者之前写过的文章。

1. [设计灵敏的蜜罐传感器](https://xsec.io/2018/1/4/Design_more_sensitive_honeypot_sensors.html)
1. [自制攻击欺骗防御系统](https://zhuanlan.zhihu.com/p/23535920)
1. [自制蜜罐之前端部分](https://www.xsec.io/2016/7/8/how-to-develop-a-honeypot.html)

## 解决方案
### 投石问路
蜜罐的规则在运营过程是肯定会超过15个，不可能为了规避iptables的这个特性就缩小规则列表。
IPTABLES报这个错误的根本原因是iptables的源码中`include/linux/netfilter/xt_multiport.h`的宏`XT_MULTI_PORTS`指定了参数个数为15个，如下所示：
```c
#ifndef _XT_MULTIPORT_H
#define _XT_MULTIPORT_H

#include <linux/types.h>c

enum xt_multiport_flags {
	XT_MULTIPORT_SOURCE,
	XT_MULTIPORT_DESTINATION,
	XT_MULTIPORT_EITHER
};

#define XT_MULTI_PORTS	15
```
很傻很天真的我最初认为把这个将XT_MULTI_PORTS的值改大重新编译iptables就可以了，事实证明我还是太年青了。等编译完后一执行又报错了，提示让看dmesg，发现如下错误：
```bash
[ 1379.325905] x_tables: ip_tables: multiport.1 match: invalid size 48 (kernel) != (user) 456
[ 1650.126296] x_tables: ip_tables: multiport.1 match: invalid size 48 (kernel) != (user) 304
```
以上2条LOG分别是将`XT_MULTI_PORTS`改为150和100产生的。为什么捏？

通过观察`include/linux/netfilter/xt_multiport.h`的代码片断，确定为正好是以下struct中`XT_MULTI_PORTS`分别为150和100的size。
```c
struct xt_multiport_v1 {
	__u8 flags;				/* Type of comparison */
	__u8 count;				/* Number of ports */
	__u16 ports[XT_MULTI_PORTS];	/* Ports */
	__u8 pflags[XT_MULTI_PORTS];	/* Port flags */
	__u8 invert;			/* Invert flag */
};
```

这个时候我才恍然大悟，本来iptables就是netfilter的用户接口，最终的操作结果是传到内核级模块netfilter中的，还需要修内核中netfilter模块相对应的代码部分，经确定在以下文件中`include/uapi/linux/netfilter/xt_multiport.h`，修改完还要重新编译内核。这个方案比较麻烦，先PASS了，还是在agent中实现吧。

### 柳暗花明

如果一条策略中的端口超过了15个，那我们将策略分成多条即可。先写一个端口数量分割的工具函数：
```go
func SplitWhitePorts(ports []string) (map[int][]string) {
	result := make(map[int][]string)
	total := len(ports)
	batch := 0
	if total%15 == 0 {
		batch = total / 15
		for i := 0; i < batch; i++ {
			result[i] = ports[i*15 : (i+1)*15]
		}
	} else {
		batch = total / 15
		for i := 0; i < batch; i++ {
			result[i] = ports[i*15 : (i+1)*15]
		}
		result[batch] = ports[batch*15 : total]
	}

	return result
}
```
测试结果满足预期：
```bash
[ `go run csrf.go` | done: 561.973248ms ]
	map[0:[1 2 3 4 5 6]]
	map[0:[1 2 3 4 5 6 7 8 9 10 11 12 13 14 15]]
	map[0:[1 2 3 4 5 6 7 8 9 10 11 12 13 14 15] 1:[16 17 18 19 20]]
```
然后在刷新策略部分应用之：
```go
if strings.ToLower(mode) == "honeypot" {
		whiteIpPolicy := vars.HoneypotPolicy.WhiteIp
		// set white policy
		for _, whiteIp := range whiteIpPolicy {
			logger.Log.Println("/sbin/iptables", "-t", "filter", "-A", "WHITELIST", "-i", setting.Interface, "-s", whiteIp, "-j", "DROP")
			exec.Command("/sbin/iptables", "-t", "filter", "-A", "WHITELIST", "-i", setting.Interface, "-s",
				whiteIp, "-j", "DROP").Output()
		}

		for _, ports := range util.SplitWhitePorts(vars.HoneypotPolicy.WhitePort) {
			logger.Log.Println("/sbin/iptables", "-t", "nat", "-A", "HONEYPOT", "-i", setting.Interface,
				"-p", "tcp", "-m", "multiport", "!", "--dports", strings.Join(ports, ","),
				"-j", "DNAT", "--to-destination", vars.HoneypotPolicy.Backend)

			ret, err := exec.Command("/sbin/iptables", "-t", "nat", "-A", "HONEYPOT", "-i", setting.Interface,
				"-p", "tcp", "-m", "multiport", "!", "--dports", strings.Join(ports, ","), "-j",
				"DNAT", "--to-destination", vars.HoneypotPolicy.Backend).Output()
			logger.Log.Println(ret, err)
		}
	} 
```
