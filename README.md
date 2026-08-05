# VK DPI Bypass Proxy

本地 HTTPS 代理：对 VK 相关域名在 TLS 握手时做 **TLS Record Fragmentation**，用于绕过基于 SNI 的 DPI 封锁。可配合浏览器插件，只让 VK 走代理。

## 快速开始

### 方式 A：运行源码

需要 Python 3.9+（含 tkinter）。

```bash
python dpi_proxy.py
```

或双击 `启动代理.bat`（Windows），点「启动」。

### 方式 B：下载 Release 可执行文件

在本仓库 [Releases](https://github.com/secure-artifacts/vk-dpi-proxy/releases) 下载对应平台产物：

- Windows：`vk-dpi-proxy-windows.exe`
- macOS：`vk-dpi-proxy-macos.zip`（解压后打开 `.app`）
- Linux：`vk-dpi-proxy-linux.zip`

## 与浏览器插件配合（只代理 VK）

1. 本软件点「启动」
2. 加载旁边的插件仓库 / 本地文件夹 `vk-dpi-extension`，点「开启」
3. 打开 https://vk.com ；其它网站直连

不要开启 Windows「全部手动代理」，否则可能影响 YouTube 等网站。

## 如何发布新版本

本项目使用 GitHub Actions 自动构建和发布。每次发布新版本只需要创建一个 Git Tag 并推送即可。

### 发布步骤

#### 1. 确保代码已提交并推送

```bash
git status
git add .
git commit -m "你的改动说明"
git push origin main
```

#### 2. 创建版本 Tag

版本号格式为 `v主版本.次版本.修订版本`，例如 `v1.0.0`、`v1.1.0`。

```bash
git tag -a v1.0.1 -m "Release version 1.0.1"
```

#### 3. 推送 Tag 触发自动构建

```bash
git push origin v1.0.1
```

推送后，GitHub Actions 会自动：

1. 用 PyInstaller 构建 Windows / macOS / Linux 产物
2. 生成安全签名（Attestation）
3. 创建 Release 并上传构建产物

#### 4. 查看构建结果

- 构建进度：仓库 **Actions** 页面
- 发布结果：仓库 **Releases** 页面

### 版本号说明

| 版本号格式 | 什么时候用 | 示例 |
|-----------|-----------|------|
| `vX.0.0` | 重大更新、不兼容改动 | `v2.0.0` |
| `vX.Y.0` | 新增功能 | `v1.1.0` |
| `vX.Y.Z` | 修复 bug | `v1.0.1` |

### 如果构建失败怎么办

1. 打开 **Actions** 查看错误日志
2. 修复代码或 `.github/workflows/release.yml`
3. 删除失败的 tag 并重新创建：

```bash
git tag -d v1.0.1
git push origin :refs/tags/v1.0.1
git tag -a v1.0.1 -m "Release version 1.0.1"
git push origin v1.0.1
```

## 说明

- 仅处理 HTTPS `CONNECT`；请用 HTTPS 访问 VK
- 本工具针对 SNI/ClientHello 特征检测类封锁，不能替代完整 VPN
