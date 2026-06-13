# CLink Codegraph 维护与人工验收指南

## 打开方式

直接用浏览器打开 `.codegraph/index.html` 即可查看 CLink 静态数据流图。

该页面是纯静态文件：无 npm、无 build、无本地服务、无 CDN、无网络依赖。浏览器只读取仓库内的 `index.html`、`assets/graph-data.js`、`assets/app.js`、`assets/styles.css`。

## 默认首页

默认首页展示完整运行时数据传输流程图：

`User/script -> clink CLI -> IPC -> local clinkd daemon -> SOCKS/process injection/VIF/BufferPool/TCP/TLS -> remote clinkd daemon`

首页用于把 control plane、data plane、进程集成、虚拟网卡、传输层、远端转发和观测链路放在同一张图里，便于 review 时确认数据如何跨越进程边界、网络边界和权限边界。

## 专题视图

左侧导航包含以下专题视图：

- CLI 控制端
- IPC 控制面
- daemon 生命周期
- TCP/TLS 与 IPv4/IPv6
- SOCKS 转发
- 进程注入链路
- 虚拟网卡/VIF
- 零拷贝转发
- 观测与调试
- 风险边界总览
- 源码索引

## 交互说明

- 左侧导航：切换总览和各专题视图。
- 点击节点：右侧展示该节点的职责、输入、输出、源码位置、测试位置、风险标签和调试信号。
- 点击边：右侧展示数据类型、源端、目标端、地址族、源码位置和边界说明。
- 右侧 tabs：在概览、深度理解、源码、风险、调试之间切换详情。
- 搜索：按节点、边、源码路径、说明文字检索，结果可直接定位到图中元素。
- toggles：按 control、data、risk、source、IPv4、IPv6 维度筛选图中元素。

## 维护说明

### graph-data.js 数据格式

`assets/graph-data.js` 必须保持 JSON-compatible 单 assignment 形式：

```js
window.CLINK_GRAPH = {
  "meta": {},
  "views": [],
  "nodes": {},
  "edges": {},
  "groups": {},
  "legends": {},
  "glossary": {}
};
```

维护规则：

- 文件中只保留一个 `window.CLINK_GRAPH = ...` assignment，可带结尾分号。
- 对象、数组、字符串、数字、布尔值和 null 按 JSON-compatible 写法维护。
- 不使用函数、注释、变量引用、计算字段或运行时代码生成数据。
- `meta.defaultViewId` 保持为 `home`，并指向已有 view。

### 新增 node

新增节点时同步检查：

- `nodes` 中新增唯一 `id`，对象内 `id` 与 key 完全一致。
- 填写 `label`、`kind`、`layer`、`position`、`summary`、`inputs`、`outputs`、`sourceFiles`、`tests`、`addressFamilies`、`risk`、`implementationStatus`、`details`。
- `details.basic` 包含 `role`、`receives`、`emits`、`whyItExists`。
- `details.deep` 包含 `codePath`、`dataFlow`、`runtimeBehavior`、`failureModes`、`debugSignals`、`ipv4Ipv6Notes`。
- 节点要加入至少一个相关 view；如属于新的视觉分组，也要更新 `groups`。

### 新增 edge

新增边时同步检查：

- `edges` 中新增唯一 `id`，对象内 `id` 与 key 完全一致。
- `from` 与 `to` 必须引用已有 node。
- 填写 `label`、`kind`、`dataType`、`addressFamilies`、`sourceFiles`、`notes`、`risk`、`implementationStatus`。
- 边要加入能解释该链路的相关 view；首页关键链路要保留在 `home.edges` 中。
- `notes` 只描述数据流、边界、观测点和 review point，不描述可被滥用的操作流程。

### 新增 view

新增视图时同步检查：

- `views` 中新增唯一 `id`，并填写 `title`、`description`、`nodes`、`edges`、`groups`。
- `nodes`、`edges`、`groups` 只能引用已经存在的对象。
- 视图名称使用中文为主，保留必要英文专有名词。
- 视图应聚焦一个 review 主题，避免把无关节点堆叠到同一页。

### risk tags 与 addressFamilies

- `risk` 只能使用验证脚本允许的标签，例如 `none`、`low`、`medium`、`high`、`auth`、`config`、`daemon-lifecycle`、`data-leak`、`dual-stack`、`injection`、`ipc`、`memory-pressure`、`observability`、`privilege`、`process-boundary`、`remote-access`、`routing`、`tls`。
- `addressFamilies` 只能使用验证脚本允许的标签，例如 `ipv4`、`ipv6`、`loopback`、`unix-domain-socket`、`windows-named-pipe`、`virtual-adapter`、`process`、`memory`、`not-applicable`。
- 涉及 IPv4/IPv6 的节点和边必须明确标注 `ipv4`、`ipv6` 或 `dual-stack` 风险语义；不涉及网络地址族的控制或内存对象使用 `not-applicable`、`process` 或 `memory`。
- 风险标签用于提示 review 关注点，不用于给出攻击步骤。

### 中文文案要求

- 页面文案以中文为主，保留 CLI、IPC、daemon、SOCKS、VIF、BufferPool、TCP、TLS、IPv4、IPv6、review point 等专有名词。
- 使用工程化、可审阅的描述，避免口语化称呼。
- 节点和边的说明要可追溯到源码路径或测试路径。
- 风险文案只说明数据流、边界、观测、review point，不写滥用步骤、绕过方法或可执行利用流程。

## 可选验证命令

在仓库根目录执行：

```bash
python3 .codegraph/tools/validate_graph_data.py
```

预期输出：

```text
PASS: codegraph shell and data are valid
```

## IPv4/IPv6 修复后复核清单

- TCP/TLS 与 IPv4/IPv6 视图同时覆盖本地监听、远端连接、TLS transport 和观测链路。
- 相关 node 的 `addressFamilies` 包含正确的 `ipv4`、`ipv6`、`loopback` 或 `not-applicable`。
- 相关 edge 的 `addressFamilies` 与实际数据通道一致。
- 双栈路径的 `risk` 包含 `dual-stack`，TLS 边界包含 `tls`。
- `details.deep.ipv4Ipv6Notes` 说明 IPv4 与 IPv6 在解析、监听、连接或路由上的差异。
- 首页链路仍能表达从本地到远端的完整 runtime flow。
- 搜索 `IPv4`、`IPv6`、`dual-stack` 能定位到对应节点或边。

## 防御性风险文案边界

风险区域只写以下内容：

- 数据从哪里进入、经过哪些边界、流向哪里。
- 哪些进程、权限、地址族、TLS 或路由边界需要 review。
- 哪些日志、指标、测试或源码路径可以辅助排查。
- 哪些配置需要人工确认。

风险区域不写以下内容：

- 可复制的滥用步骤。
- 绕过认证、绕过权限或规避监控的方法。
- 对特定目标执行未授权访问的流程。
- 可直接改造成攻击脚本的参数组合或命令序列。

## 人工验收清单

- 打开 `.codegraph/index.html`，页面无需网络即可加载样式、脚本和图数据。
- 默认进入总览视图，并展示 `User/script -> clink CLI -> IPC -> local clinkd daemon -> SOCKS/process injection/VIF/BufferPool/TCP/TLS -> remote clinkd daemon` 主链路。
- 左侧导航能切换所有专题视图。
- 点击任一节点后，右侧详情能展示概览、深度理解、源码、风险、调试信息。
- 点击任一边后，右侧详情能展示数据类型、地址族、源码位置和边界说明。
- 搜索 `IPC`、`TLS`、`IPv6`、`BufferPool` 能返回相关结果，并可定位到图中元素。
- toggles 能按 control、data、risk、source、IPv4、IPv6 筛选元素。
- 源码索引视图列出的路径与仓库当前结构一致。
- 风险边界总览只描述防御性 review 关注点。
- 执行 `python3 .codegraph/tools/validate_graph_data.py` 输出 PASS。
- 执行 `node --check .codegraph/assets/app.js` 与 `node --check .codegraph/assets/graph-data.js` 均无语法错误。
- 执行禁用词扫描时 `.codegraph` 下无匹配。
- 执行 `git diff --check` 无 whitespace error。
