# TunProxy

TunProxy 是一个面向 Linux 的透明代理控制器。它创建 TUN 接口，把本机 TCP 流量交给受控的 sing-box 内核，再通过用户指定的 SOCKS5 上游转发。

TunProxy 不管理代理节点、订阅或路由规则，也不修改 `HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY` 等 shell 环境变量。上游可以是本机、WSL2 宿主机、局域网计算机、路由器或其他标准 SOCKS5 服务。

## 特性

- C++17 实现，命令行操作。
- 无特权 CLI 通过本地 Unix Socket 调用受限的 root daemon，日常命令无需 `sudo`。
- 固定版本的 sing-box 私有内核，首次启用时按 manifest 下载。
- 下载、归档、二进制、版本、revision 和许可证完整校验。
- SOCKS5 上游，支持 IPv4、域名和括号形式的 IPv6 地址。
- TUN 全局透明代理和 DNS 劫持。
- 固定启用内网保护策略，绕过固定本地范围、实际 SOCKS5 上游和启用接口的自身地址。
- 强制绕过实际连接的 SOCKS5 上游地址，避免上游连接被 TUN 再次捕获。
- `auto_redirect` 失败时自动回退到普通 TUN 路由模式。
- 原子配置写入、文件锁、PID 启动时间校验和安全停止。
- 结果只写标准输出，日志只写标准错误，便于脚本处理。
- 只发布 Debian 包，仓库不包含 sing-box 二进制。

## 兼容性

| 平台 | 状态 |
| --- | --- |
| Ubuntu 22.04 amd64 | 正式支持 |
| Ubuntu 24.04 amd64 | 正式支持 |
| WSL2 Linux amd64 | 支持，前提是启用 systemd 且内核提供 TUN |
| ARM64 | 暂不支持 |
| Fedora、Arch、macOS、Windows 原生 | 未承诺兼容 |

`tunproxyd` 需要可用的 `/dev/net/tun` 和受限网络管理能力。控制 Socket 仅允许 root 和 `sudo` 组成员访问；Ubuntu 安装时创建的管理员默认已经属于该组。首次启用还需要访问 GitHub Releases，并依赖系统提供的 `curl`、CA 证书、`tar` 和 `sha256sum`。

## 安装

下载与系统架构匹配的 amd64 deb，并核对发布说明中给出的 SHA-256：

```bash
sha256sum ./tunproxy_0.3.1_amd64.deb
sudo apt install ./tunproxy_0.3.1_amd64.deb
```

推荐使用 `apt install` 安装本地包，以便同时处理依赖。文件名前的 `./` 不能省略；从其他目录安装时应使用 deb 的绝对路径。

确认安装版本和控制 Socket 状态：

```bash
tunproxy --version
systemctl is-active tunproxy.socket
tunproxy status
```

安装阶段不会联网下载 sing-box，也不会安装系统级 sing-box。安装程序只启用 `tunproxy.socket`，不会执行 `tunproxy on`、创建 TUN、启动 sing-box 或修改路由。首次执行 `tunproxy status` 可能按需启动后台服务，但代理仍保持 `OFF`；只有用户主动执行 `tunproxy on` 才会下载并验证固定内核并启用代理。

## 更新

无需卸载旧版本，也不要在更新前执行 `apt remove` 或 `apt purge`。下载新版本 deb、核对 SHA-256，然后直接覆盖安装：

```bash
sha256sum ./tunproxy_0.3.1_amd64.deb
sudo apt install ./tunproxy_0.3.1_amd64.deb
tunproxy --version
tunproxy status
```

示例中的文件名应替换为实际下载的新版本。该方式支持从 `0.1.x`、`0.2.x` 更新到 `0.3.x`，也用于后续版本之间的更新。

更新过程遵循以下规则：

1. 如果代理正在运行，先安全停止 sing-box、移除 TUN 和受管路由。
2. 替换 CLI、后台服务、systemd 单元、man page 和默认配置模板。
3. 保留 `/etc/tunproxy/config`、`/var/lib/tunproxy/cores/` 和 `/var/cache/tunproxy/`。
4. 清理不兼容的 PID、锁文件和临时运行配置，再启动新版控制 Socket。
5. 更新完成后保持 `OFF`，不会自动恢复更新前的 `ON` 状态。

需要恢复代理时由用户明确执行：

```bash
tunproxy on
```

更新期间网络代理会短暂中断。如果旧实例不能安全停止，包管理操作会失败并保留持久配置与核心，不会继续进行不完整替换。重复安装相同版本用于修复本地安装时，可以执行：

```bash
sudo apt install --reinstall ./tunproxy_0.3.1_amd64.deb
```

不支持通过直接安装较低版本进行配置降级。确需回退时，应先备份 `/etc/tunproxy/config`，并按目标版本的发布说明处理兼容性。

## 文件与目录

| 路径 | 来源 | 用途 |
| --- | --- | --- |
| `/usr/bin/tunproxy` | deb | CLI 可执行文件 |
| `/usr/lib/tunproxy/tunproxyd` | deb | 特权控制 daemon |
| `/lib/systemd/system/tunproxy.socket` | deb | 本地控制 Socket 单元 |
| `/lib/systemd/system/tunproxy.service` | deb | 按需启动的 daemon 单元 |
| `/usr/share/tunproxy/config.default` | deb | 首次安装时使用的默认配置 |
| `/usr/share/man/man8/tunproxy.8.gz` | deb | man page |
| `/usr/share/doc/tunproxy/` | deb | README、许可证和第三方许可信息 |
| `/etc/tunproxy/config` | `postinst` | 用户 SOCKS5 上游配置，升级时不会覆盖 |
| `/var/lib/tunproxy/cores/1.13.18/sing-box` | 首次 `on` | 固定并校验后的私有 sing-box 内核 |
| `/var/lib/tunproxy/cores/1.13.18/LICENSE` | 首次 `on` | 与私有内核对应的上游许可证 |
| `/var/cache/tunproxy/` | 运行时 | 内核下载临时文件，权限为 0700 |
| `/run/tunproxy/sing-box.json` | 运行时 | 动态生成的 sing-box 配置 |
| `/run/tunproxy/sing-box.log` | 运行时 | sing-box 日志 |
| `/run/tunproxy/state` | 运行时 | PID、启动时间、核心路径和运行阶段 |
| `/run/tunproxy/lock` | 运行时 | `on`、`off`、`setting` 操作锁 |
| `/run/tunproxy/control.sock` | systemd | CLI 与 daemon 的本地控制 Socket |

`/dev/net/tun` 是系统提供的设备节点，不属于 TunProxy 安装内容。`tunproxy0` 是运行时创建的网络接口，核心停止后应自动消失。

## 卸载

保留用户配置、已下载核心和缓存，仅移除 deb 管理的程序、man page 和 `/usr/share` 文件：

```bash
sudo apt remove tunproxy
```

移除程序以及全部 TunProxy 配置、下载核心、缓存、日志和运行状态：

```bash
sudo apt purge tunproxy
```

卸载或更新前，`prerm` 会先关闭代理。核心无法安全停止时，包管理操作会失败，不会继续删除状态文件。

`apt remove` 后保留：

```text
/etc/tunproxy/
/var/lib/tunproxy/
/var/cache/tunproxy/
/run/tunproxy/
```

`apt purge` 会删除上述四个目录及其中的全部内容。需要保留上游配置时，应在 purge 前备份 `/etc/tunproxy/config`。

## 使用

### 配置 SOCKS5 上游

直接设置 URI：

```bash
tunproxy setting socks5://127.0.0.1:10808
tunproxy setting socks5://172.28.32.1:10808
tunproxy setting socks5://192.168.1.20:7890
tunproxy setting socks5://[::1]:1080
```

不带参数时进入交互式设置：

```bash
tunproxy setting
```

当前配置文件格式为：

```ini
protocol=socks5
host=127.0.0.1
port=10808
```

当前版本不支持 SOCKS5 用户名密码认证、HTTP CONNECT、多上游和代理节点配置。

### 开启、关闭和查看状态

```bash
tunproxy on
tunproxy status
tunproxy bypass
tunproxy off
```

命令结果只写标准输出，每行一个 `键: 值`；日志、下载进度条和警告只写标准错误，脚本可以单独解析标准输出。内核已安装且校验通过时，`on` 不输出任何日志，直接给出结果块。

`on` 与 `status` 处于 `ON` 时的输出相同：

```text
Status: ON
Upstream: socks5://192.168.1.20:7890 (192.168.1.20)
Core: sing-box 1.13.18
PID: 1234
Routing: auto-redirect
Bypass: 13 CIDRs
```

括号内是本次实际选中并钉住的上游地址。`Routing` 为 `auto-redirect` 表示内核接受了 sing-box 的 auto_redirect 模式，为 `tun-route` 表示已回退到普通 TUN 路由。代理关闭时 `status` 输出：

```text
Status: OFF
Upstream: socks5://192.168.1.20:7890
Core: sing-box 1.13.18
```

内核尚未下载时 `Core` 一行显示 `not installed`。

首次启用会在标准错误输出下载进度和 `sing-box 1.13.18 installed`；内核校验失败、auto_redirect 回退、停止时需要 SIGKILL 等情况会输出以 `warning:` 开头的一行。连接上游失败、TUN 不可用或 sing-box 启动失败时，错误以 `error:` 开头立即输出。sing-box 自身运行日志位于：

```text
/run/tunproxy/sing-box.log
```

`on`、`off` 和配置修改由 daemon 串行执行；已有操作运行时，新的变更请求会立即报告正在进行的操作。`status` 仍可并发查询，并会验证 PID、进程启动时间和 `/proc/<pid>/exe`，不只依赖状态文件中的 PID。

### 内网绕过策略

内网绕过是固定的内部安全策略，不写入用户配置，也不提供关闭或恢复旧行为的开关。执行以下只读命令可以列出实际生效的 CIDR：

```bash
tunproxy bypass
```

代理处于 `ON` 时，首行为 `Bypass: active, N CIDRs`，随后一行 `Upstream:` 给出钉住的上游主机 CIDR，再逐行列出全部 CIDR。代理处于 `OFF` 时，首行为 `Bypass: preview, N CIDRs`，列表基于当前网络环境生成，上游地址会在下一次 `on` 完成解析和连通性校验后加入。

固定绕过范围：

```text
127.0.0.0/8
::1/128
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
100.64.0.0/10
169.254.0.0/16
fe80::/10
fc00::/7
224.0.0.0/4
ff00::/8
255.255.255.255/32
```

每次执行 `on` 还会通过 `getifaddrs()` 读取处于启用状态的接口地址。接口 IPv4 只会加入对应 `/32`，IPv6 只会加入对应 `/128`；未指定地址和 `tunproxy0` 会被忽略。CIDR 会被规范化、去重并写入本次运行状态，如果接口地址数量超过安全上限，启动会明确失败。TunProxy 不读取或绕过任意内核路由，因此分割默认路由、VPN 公网路由和自定义策略路由不会扩大绕过范围。SOCKS5 域名实际选中并成功连接的 IPv4 `/32` 或 IPv6 `/128` 地址始终优先直连。

规则顺序固定为：上游地址直连，固定范围和接口自身地址直连，其他 DNS 劫持，其他 UDP 拒绝，剩余 TCP 通过 SOCKS5。由此，局域网 DNS、mDNS、SSDP 和其他命中固定范围的 UDP 通信保持直连；发往公网且未命中绕过范围的非 DNS UDP 仍会被拒绝。

正常使用不需要 `sudo`。systemd 或控制 Socket 损坏时，管理员可以使用 root-only 恢复入口：

```bash
sudo tunproxy --direct status
sudo tunproxy --direct off
```

## 源码编译

构建环境建议使用 Ubuntu 22.04 或更高版本：

```bash
sudo apt update
sudo apt install build-essential cmake ninja-build curl ca-certificates \
    debhelper dpkg-dev lintian
```

编译并运行测试：

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

生成 Debian 包：

```bash
dpkg-buildpackage -b -us -uc
lintian --fail-on error ../tunproxy_0.3.1_amd64.deb
```

单元测试不联网，不需要 root，也不会创建 TUN 接口。真实内核的集成测试通过脚本按需运行，脚本会下载并校验固定版本的 sing-box 归档，然后用它验证生成的配置并演练 repair 流程：

```bash
tools/run-integration-tests.sh build
```

### 维护脚本

| 脚本 | 用途 |
| --- | --- |
| `tools/update-core-manifest.sh <version>` | 下载指定版本的官方归档，计算大小和 SHA-256，读取 revision，重写 `include/tunproxy/core_manifest.hpp`，并列出仍引用旧版本号的文档 |
| `tools/run-integration-tests.sh [build-dir]` | 下载并校验固定内核后运行全部测试，包括依赖真实内核的集成用例 |

版本号只在 `debian/changelog` 首行维护，CMake 从中生成 `version.hpp` 和 man page 头部。

### 发布前清单

正式发布使用 Ubuntu 22.04 构建 amd64 包。仓库不使用 GitHub Actions，构建与发布均在本地完成，发布前应完成：

1. `cmake --build` 零警告，`ctest` 全部通过。
2. `tools/run-integration-tests.sh` 通过。
3. `dpkg-buildpackage -b -us -uc` 与 `lintian --fail-on error` 通过。
4. 在 Ubuntu 22.04 和 24.04 上执行全新安装、覆盖更新、卸载。
5. 安装后在真实系统上执行 `tunproxy on`、TUN 往返访问、`tunproxy off`，确认 `tunproxy.service` 的 seccomp 过滤和其他加固项不影响 sing-box 运行。

## sing-box 内核

当前锁定版本：

```text
Version:  1.13.18
Revision: 45ca32dcb966f07f97fc888fe8586e359dbe8405
Asset:    sing-box-1.13.18-linux-amd64.tar.gz
```

官方下载地址：

```text
https://github.com/SagerNet/sing-box/releases/download/v1.13.18/sing-box-1.13.18-linux-amd64.tar.gz
```

固定校验值：

| 对象 | 大小 | SHA-256 |
| --- | ---: | --- |
| 归档 | 23922330 bytes | `d34d987ed6ae39ca3760269264fb502b867e5477db45518c829b07776245c495` |
| `sing-box` | 58102016 bytes | `8cb29c5b743fbda33502a2b6d49cf66ce13f5d1a41fcd0afc53fff17184ccf8e` |
| `LICENSE` | - | `650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c` |

下载和安装流程：

1. 仅允许 HTTPS，使用 `curl` 下载到受限缓存目录。
2. 校验归档大小和 SHA-256。
3. 使用 `tar` 只解出 manifest 指定的二进制和许可证成员。
4. 校验二进制大小、SHA-256、版本输出和 revision。
5. 校验上游许可证 SHA-256。
6. 通过临时 staging 目录和 `rename()` 原子替换已安装文件。

任何一步失败都不会执行未经校验的核心。已安装核心被删除、篡改或版本不匹配时，下一次 `tunproxy on` 会重新 repair。

## 运行时技术实现

TunProxy 由以下模块组成：

```text
ConfigManager       读取、校验和原子保存 SOCKS5 配置
BypassPolicy        规范化 CIDR，通过 getifaddrs 生成受限绕过策略
CommandController   统一执行本地恢复和 daemon 控制命令
CoreManager         下载、校验、修复和替换 sing-box
IPC                  分帧、限长的 Unix Socket 请求与事件流
ProxyManager        生成配置并管理 TUN/核心生命周期
RuntimeStateStore   保存 PID、启动时间、核心路径和运行阶段
Process             fork/exec、输出捕获和超时控制
Filesystem          原子文件写入、SHA-256 和安全目录创建
```

运行时生成 `/run/tunproxy/sing-box.json`，不会把 sing-box 原生 JSON 配置暴露给用户。当前配置包含：

- `tunproxy0` TUN 入站，自动路由和严格路由。
- TUN `route_exclude_address` 与 direct 规则共享同一份已锁定绕过 CIDR。
- SOCKS5 TCP 出站。
- direct 出站仅用于固定范围、启用接口的自身地址和实际 SOCKS5 上游地址。
- Cloudflare DNS-over-HTTPS，并通过 SOCKS5 detour 发送。
- DNS 请求使用 `hijack-dns` 规则。
- 未命中绕过策略的非 DNS UDP 流量明确拒绝，避免在不确定上游 UDP 能力时产生旁路流量。

进程启动采用已打开的核心文件描述符和 exec 握手。状态文件不仅保存 PID，还保存 `/proc/<pid>/stat` 的启动时间和可执行文件路径。停止时会重新验证这些身份信息，再发送 SIGTERM，超时后才发送 SIGKILL。

## 安全边界

- 不通过 shell 拼接和执行用户输入。
- 下载 URL、版本、revision 和校验值全部由程序固定。
- 配置和状态使用临时文件、`fsync()` 和 `rename()` 原子更新。
- 运行目录逐级检查并拒绝符号链接和路径遍历。
- 核心启动使用 `O_NOFOLLOW`、已打开文件描述符和 `fexecve()`。
- `/var/cache/tunproxy` 使用 0700，核心目录不加入用户 `PATH`。
- Socket 使用 `root:sudo 0660` 权限并通过 `SO_PEERCRED` 再次验证调用者。
- daemon 由 systemd 限制能力、设备、地址族、系统调用、命名空间和可写路径；下载及校验子进程会清除网络 capabilities。
- deb 安装阶段不联网，核心下载发生在显式 `tunproxy on` 操作中。

## 限制

- 当前目标是 amd64 Ubuntu，不提供 ARM64 和其他发行版的正式承诺。
- 只支持 SOCKS5，不支持代理认证、HTTP CONNECT 或节点协议管理。
- 当前重点是 TCP、DNS 和常见开发工具流量。
- 未命中内网绕过策略的非 DNS UDP 流量被拒绝，不适合作为公网游戏、VoIP 或完整 UDP 代理。
- 不提供 GUI、订阅管理和自动更新 TunProxy 自身。

## 目录结构

```text
include/tunproxy/   公共 C++ 接口、常量和数据结构
src/                核心实现、CLI 和 daemon 入口
tests/              按模块拆分的测试用例、测试框架和假内核
tools/              内核清单更新与集成测试脚本
debian/             Debian 控制文件和维护脚本
docs/               man page 模板
```

## 许可证

TunProxy 使用 MIT License，见 [LICENSE](LICENSE)。

TunProxy 下载的 sing-box 依据上游 GPLv3-or-later 及其许可证附加条款分发。固定版本、来源和第三方许可说明见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
