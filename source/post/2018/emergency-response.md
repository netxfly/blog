```toml
title = "应急响应浅谈"
slug = "emergency-response"
desc = "emergency-response"
date = "2018-08-31 12:11:58"
update_date = "2018-08-31 12:11:58"
author = ""
thumb = ""
draft = false
tags = ["信息安全"]
```

#应急响应浅谈
## 应急响应及应急响应中心
应急响应是安全从业者最常见的工作之一（系统被黑后紧急救火，PDR模型-防护、检测、响应中的三大模块之一）。很多人可能认为应急响应就是发现服务器被黑之后，登录上去查后门的那段过程。
其实应急响应的完整定义为：`组织为了应对突发/重大信息安全事件的发生所做的准备，以及在事件发生后所采取的措施`。

通俗地讲，应急响应不应该只包括救火，还应包括救火前的一系列准备。如果在工作中忽略了准备部分，可能会出现以下几种情况：

1. 不具备基本的入侵检测能力，平时检测不到入侵事件，更谈不上应急响应了。有可能被入侵成功很久了却浑然不知，攻击者可能早就在达成目标后悄然离去了；
1. 能检测到入侵事件，但没有专门的应急响应小组，资产管理系统也不完善，安全工程师花了很长时间才找到对应的负责人，因进入响应时间太晚，攻击者可能在达到目标并擦除痕迹后全身而退了，或者进一步把其他关联的系统一并拿下了；
1. 平时无应急响应技能及入侵检测工具包的积累，接到事件的工程师登录到服务器上绞尽脑汁敲了几行命令后，最后得出『经排查安全的结论』给部门Leader与业务部门了，但真实情况是真被入侵并植入后门了。

现在各大厂商都成立了相应的安全应急响应中心（SRC），用来接收外部白帽子的提交的漏洞与威胁情报，虽然叫应急响应中心，但是这里提交过来的漏洞与情报不需要每次都启动应急响应，需要根据漏洞的类型、危害级别判断。

安全应急响应中心是对自己安全团队所做的安全保障工作的补充，如果SRC发现的漏洞与入侵事件比例很高，安全团队就该好好反思下安全工作为啥只治标不治本、频繁地被动救火了。

## 指导原则及方法论

应急响应是既紧急又重要的工作，对工程师的技术与意识都有一定的要求，比如很多安全工程师接到业务系统被黑的情报后，可能会联系业务负责人要到服务器账户，然后登录到服务器中检查被渗透的痕迹与后门。这段时间非常宝贵，反映太慢可能会使一些本来可以快速平息的安全小事件发酵成造成重大的损失安全事故。

- 对于应急响应，首先要了解应急响应的指导原则与方法论，只关注技术的话，可能会本末倒置。

    因信息安全事件的种类和严重程度各有不同，应急响应的处理方式也各不相同，比如DDOS、业务系统被入侵、钓鱼邮件的应急响应方式与过程肯定是不同的，被业内广为接受的应急响应模型与方法论有`PDCERF`模型与ITIL中的`事件管理`与`问题管理`模块。

- 其次要求应急人员有较高的入侵检测能力，否则在排查被入侵的系统时，上去查了半天啥也发现不了，最后给出的结论是安全的。

    笔者在第一份工作时，部门老大要求在进行代码审计与应急响应等依赖人员技术和经验的工作时，必须采用双人Check机制，最后汇总对比结果，防止遗漏。
    入侵检测需要检测的项目很多，最好能整理出相应的自动化检测工具自动给出报告，这样不但可以提高工作效率，还可以弱化对应急响应人员技术水平的依赖。

### PDCERF模型

![](http://docs.xsec.io/images/response/PDCERF.png)

<!--more-->

#### 准备阶段

有条件的话，自上而下达成应急响应共识，建立应急响应流程与应急响应小组，由应急小组全权负责对紧急安全事件的处理、资源协调工作，应急小组的成员除了技术负责人外，还要有公关负责人，方便在必要的时候，根据安全团队的建议对外进行公关。

对于没有条件建立应急响应流程的安全部门来说，最基本的要做好以下准备：

- 至少要有入侵检测的能力（入侵检测系统或SRC接收的高危漏漏洞或情报等）及具备相应技能的应急响应人员，否则登录上去也查不出啥，甚至给出错误的结论，最好能准备一套有效的入侵检测工具；
- 维护一份各业务系统的资产列表，应急联系人列表，否则出事了后，安全工程师自下而上找一圈也找不到相应的负责人配合处理，会错过最佳处理时机。


#### 检测阶段

检测的目的是确认入侵事件是否发生，如真发生了入侵事件，评估造成的危害、范围以及发展的速度，事件会不会进一步升级。然后根据评估结果通知相关的人员进入救火的流程。

#### 遏制阶段

遏制的目的是控制事件影响的范围、损失与破坏的进一步扩大，避免事件的进一步升级。

比如是感染蠕虫事件，需要先在网络层面封掉其传播的端口，否则安全人员在本台机器中杀毒的时候，蠕虫又把其他一批服务器感染了；
对于被黑客攻陷的服务，可以选择第一时间利用ACL或防火墙将攻击者隔离出去、关闭服务、拔掉网线或关闭服务器等方式。如果应急人员第一时间只想到了查后门和入侵痕迹，在这个时间段内，攻击者可能早从这台机器转移到其他服务器中了。

具体的遏制方式需要应急响应人员根据对业务的影响以及遏制效果综合考虑，判断的标准是对业务的影响最小、遏制效果最佳。

#### 根除阶段

根除是找到系统的漏洞并修复，清除掉攻击者的后门、webshell等，对于被装了rootkits的机器需要重装操作系统，防止查杀不彻底被黑客再度进入。

#### 恢复阶段

恢复阶段是根除攻击源、修复系统后将其恢复上线，也叫恢复业务的连续性。然后去掉遏制阶段添加的一些临时策略。

#### 跟踪总结阶段

在业务系统恢复后，需要整理一份详细的事件总结报告，包括事件发生及各部门介入处理的时间线，事件可能造成的损失。
复盘安全事件产生的根本原因，根据经验教训进一步优化安全策略。优化安全策略时，要从技术、人员、管理、工程等多个维度考虑，因为安全本身不是一个纯技术问题，光靠技术手段只能解决部分安全问题。

### 事件管理与问题管理

事件管理与问题管理是ITIL中的2大核心模块，对于应急响应同样也有重要的参考意义。

- 事件管理的核心思想是快速解决问题，尽快恢复业务系统的可用性，毕竟关键业务系统中断的每一分钟都会给公司带来损失；
- 问题管理的核心思想是从通过对一个或一类事件的处理，总结成其性，解出彻底的解决办法，从根本上杜绝该类事件的发生；
- 事件管理与问题管理总是成对出现的，事件管理的输出可以作为问题管理的输入。