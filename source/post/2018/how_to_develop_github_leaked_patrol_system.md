```toml
title = "github泄露巡航系统开发"
slug = "how_to_develop_github_leaked_patrol_system"
desc = "how_to_develop_github_leaked_patrol_system"
date = "2018-01-31 19:40:32"
update_date = "2018-01-31 19:40:32"
author = ""
thumb = ""
draft = false
tags = ["tag"]
```

## 概述

github敏感信息泄露一直是企业信息泄露和知识产权泄露的重灾区，安全意识薄弱的同事经常会将公司的代码、各种服务的账户等极度敏感的信息『开源』到github中，github也是黑、白帽子、安全工程师的必争之地，作为甲方的安全工程师，我们需要一套可以定期自动扫描特定的关键字系统，以期第一时间发现猪队友同事泄露出去的敏感信息。

积极响应开源号召的同学请开自己业余的项目，公司的产品代码、各系统账户属于公司的资产，擅自对外界公布属于侵犯公司的知识产权的行为，是违法的，造成后果严重者，不仅会被公司开除，还需承担相应的法律责任。

接下来我们一起来看看如何写一款github泄露扫描系统。

### 功能需求

虽然写代码可以一把梭，但一把梭之前需要先把要写的功能清单列一下，我们的github扫描系统会实现以下功能：

1. 双引擎搜索，github code接口搜索全局github以及本地搜索例行监控的repos
1. 支持对指定的用户、仓库、组织进行监控
1. 提供WEB管理界面，支持规则管理（github搜索规则及本地repos搜索规则）
1. 支持github token管理和用户管理
1. 扫描结果审核

已经完成的项目的地址为：[https://github.com/xiaomisec/x-patrol](https://github.com/xiaomisec/x-patrol)
<!--more-->

## 实现过程
### 引擎1 - github code搜索模块的实现

github对API调用的速率限制如下：

1. 对未验证的请求，每小时的限速为60次，使用token认证后，可以把速率提升为每小时5000次。
1. 对于搜索API，未验证的请求的速率限制为10次每分钟，认证后，可以提高到30次每分钟。

所以在使用github的sdk前，我们需要先准备好token管理模块，方便我们随机获取到额度没用完的token建立client去请求数据，github token的数据结构如下：

![](http://docs.xsec.io/images/github/paper/github_token.png)

每个token初始化时，默认额度为最大值5000，然后在使用的过程中根据返回值动态实时更新remaining的值：

![](http://docs.xsec.io/images/github/paper/github_newtoken.png)

我们在使用github client前，从数据库中先拉取当前额度还大于50的token
![](http://docs.xsec.io/images/github/paper/valid_tokens.png)

然后用这些当前额度够用的Token创建一个map[string]*Client，每次使用时随机获取一个github client，代码如下所示：
![](http://docs.xsec.io/images/github/paper/github_client.png)

在github client建立好后，我们就可以使用关键字进行全局代码搜索了，暂定只取前500条记录，相关的代码片断如下：

![](http://docs.xsec.io/images/github/paper/search_code.png)

在实际使用中，我们的系统中会存在大量的规则需要github code 搜索引擎执行，以下为相应的任务管理代码：

1. `ScheduleTasks(duration time.Duration)`函数是定时任务管理，duration指定了多久进行一次github code 搜索
1. `GenerateSearchCodeTask() (map[int][]models.Rules, error)`函数为任务分割函数，因为github search api的速率限制为每分钟30次，我们将其按25个分发几批
1. ` RunSearchTask(mapRules map[int][]models.Rules, err error)`函数会按批次执行搜索任务，每次执行完都会查看用时，如果小于1分钟就等待到1分钟，以便我们永远不会超出search api的速率限制
1. `Search(rules []models.Rules) ()`函数的作用是以并发的方式进行github code搜索，并将搜索结果保存到数据库中。

![](http://docs.xsec.io/images/github/paper/github_search.png)

### 引擎2 - 本地repos高速搜索模块

我们在使用password等通用的敏感关键字进行github code搜索时，往往会搜索到大量与要监控的目标无关的结果，从里面排查出我们想监控的目标的敏感信息如同大海捞针一般。为了避免这个问题，我们的解决方案是：

1. 只关注与目标相关的用户、组织与仓库，比如搜集小米公司员工的用户名，组织，然后通过github sdk查出这些组织与用户所有的仓库，定期拉到本地用更详细的关键字进行深入扫描；
1. 利用与目标相关的关键字进行github code搜索，将搜索结果中的库放到引擎2中定期地进行本地深入扫描。

引擎2的高速搜索算法来自一个开源项目[https://github.com/etsy/hound](https://github.com/etsy/hound)，该算法最初来自google的大神Russ Cox 的一篇文章[Regular Expression Matching with a Trigram Index or How Google Code Search Worked](https://swtch.com/~rsc/regexp/regexp4.html)，有兴趣了解算法的同学可以仔细阅读一下，我直接将该算法封装为了一个SearchRepos函数，传递一条规则和一批仓库进去，会返回该规则的搜索结果。

![](http://docs.xsec.io/images/github/paper/search_repos.png)

以下为引擎2的任务调度核心代码：

![](http://docs.xsec.io/images/github/paper/search_task.png)

代码解读：

- `SegmentationTask(reposConfig []models.RepoConfig) (map[int][]models.RepoConfig)`的作用是将需要扫描的仓库按配置的MAX_Concurrency_REPOS的数量分成批次
- `DistributionTask(tasksMap map[int][]models.RepoConfig, rules []models.Rules)`会将任务按批次分别传给`Run(reposConfig []models.RepoConfig, rule models.Rules)`执行
- `Run(reposConfig []models.RepoConfig, rule models.Rules)`的本意是并发执行代码搜索任务，比如有10000个仓库，每次并发100，100次就查完了。想想这个速率就美滋滋。
- `SaveSearchResult(responses map[string]*index.SearchResponse, rule models.Rules, err error)`函数的作用是将搜索结果去重保存到数据库中
- `ScheduleTasks(duration time.Duration)`为定时任务的调度函数，每隔指定的时间后重新获取最新的仓库及规则并进行本地代码搜索。

### 规则管理

前面我们已经实现了github code搜索与本地repos的深入扫描功能，接下来需要提供一个规则管理模块了，利用规则对引擎1和引擎2进行调度。
为了兼容`gitrob`的规则文件，我们把规则的数据结果定义如下，并提供增、改、删、查、禁用、启用等功能

![](http://docs.xsec.io/images/github/paper/rule.png)

程序启动时，如果发现规则表为空，则会默认插入当前目录中`conf/gitrob.json`中规则，代码如下：

![](http://docs.xsec.io/images/github/paper/init_rule.png)

我们再提供一个自定义规则管理的WEB界面，以下为规则相关的路由信息，详细实现请直接参考github仓库。

![](http://docs.xsec.io/images/github/paper/rule_web.png)

最后的效果图如下，需要注意的是在为github code搜索填写规则时，因为我代码中为了兼容正则，没有直接加精确搜索，需要在配置规则时手工加上双引号表示精确搜索。

![](http://docs.xsec.io/images/github/rules.png)

### 资产管理及仓库管理

对于github泄露检测来说，资产就是我们需要监控的用户、组织与仓库，这些信息会最终转化为仓库列表中，供本地检测模块使用。

以下代码为将录入资产列表中的用户、组织的仓库全部查询出来并插入到仓库表中。

![](http://docs.xsec.io/images/github/paper/assets.png)

仓库管理表中的信息为引擎2的扫描目标，允许修改禁用、启用状态，在结果审核时，忽略的仓库的状态会设为禁用状态，下次扫描时将会忽略。token管理、用户管理、仓库管理、结果审核展示界面的WEB实现的占用篇幅较大就不细说了，详细请参考github中完整的代码，最终的效果如下：

仓库管理：
![](http://docs.xsec.io/images/github/repos.png)

## 命令行

到目前为止，我们的github泄露巡航系统的核心功能及WEB管理功能已经一把梭完了，接下来用`github.com/urfave/cli`库再给这些功能加上命令行外壳，把WEB启动功能与扫描功能分开。

![](http://docs.xsec.io/images/github/paper/cmd.png)

最终我们的程序的命令行如下:
![](http://docs.xsec.io/images/github/paper/usage.png)

1. web指令表示启动web管理端
1. scan指令表示只启动github搜索
1. scan -m local，表示只启动本地代码搜索功能
1. scan -m all，表示同时启动github代码搜索与本地Repos搜索功能

### 使用说明

- 配置好conf/app.ini中的参数后启动WEB。
默认会监听到本地的8000端口，默认的管理员账户和密码分别为：`xsec`和`x@xsec.io`。
![](http://docs.xsec.io/images/github/web.png)

- 然后在WEB中录入github token、规则。
![](http://docs.xsec.io/images/github/rules.png)

- 启动搜索功能：
    1. scan指令表示只启动github搜索
    1. scan -m local，表示只启动本地代码搜索功能
    1. scan -m all，表示同时启动github代码搜索与本地Repos搜索功能

![](http://docs.xsec.io/images/github/search.png)

- 审核结果
github code搜索结果审核：
![](http://docs.xsec.io/images/github/report1.png)

本地repos详细搜索结果审核：
![](http://docs.xsec.io/images/github/report2.png)


## 第3种选择

[sourcegraph](https://about.sourcegraph.com/)是非常专业的代码搜索服务商，他们提供的Sourcegraph Server是免费的代码搜索服务器，通过docker的方式部署，支持无限扩展，支持对GitHub, BitBucket, GitLab等仓库的代码搜索。搜索内容包括仓库代码、diff、commit。

Sourcegraph Server还提供了GraphQL API，可直接通过API提交代码搜索请求。利用Sourcegraph Server代替引擎2的功能应该会有不错的效果，有兴趣的同学可以尝试一下。