# AITEST8.0 破解版（公益破解）

> **公益破解群：777410175** —— 免费分发，禁止倒卖。

AITEST8.0（AI 破甲工具箱）全模式收费版破解补丁成品。本机永久授权、全部功能解锁、**不联网、不要注册码**。

## 成品下载

| 文件 | 说明 |
|---|---|
| `AITEST8.0_破解版.exe` | **主程序，双击即用**，单文件，本机永久授权，全功能解锁 |
| `重打包补丁脚本.py` | 生成破解版的完整可复现脚本 |
| `使用说明.md` | 详细原理、指纹、验证记录 |

## 使用方法

1. 下载 `AITEST8.0_破解版.exe`
2. 双击运行（无需安装、无需注册码、无需联网）
3. 直接进入主界面，全部功能可用，永久授权

> 首次运行若被 SmartScreen 拦截，点「更多信息 → 仍要运行」。

## 文件指纹

| | 大小 | MD5 | SHA256 |
|---|---|---|---|
| 原版 | 70,092,309 | `135838befe5efb72c34c1f2a4e308271` | `2bbd7b8a20f1308169066c3fa5d06a3b55932fce32755e6950547aa5c706c7d7` |
| **破解版** | 70,090,768 | `8e8989191abf17a9141ceae75583d2e6` | `e58d01e3f470338344b55a0c746489b6f4bf8a8dfafed1d82f49b67d677b17c0` |

## 破解原理（三步）

程序是 PyInstaller onefile，`runtime/` 目录（542 条，81MB）以**明文 `.py` 源码**随包分发，运行期 `sys.path` 优先指向它，且由 `integrity_check.verify()` 做 Ed25519 清单校验（`runtime/integrity.json`，380 个文件 SHA256）。

1. `runtime/integrity_check.py` → `verify()` 恒返回 `True`，解除清单校验
2. `runtime/subscription.py` → 文末覆盖授权函数：`status()` 恒返回 `authorized: True / mode: lifetime`；`activate()`/`check_token()` 恒成功；`refresh()`/`start_background()` 空实现（**顺带彻底去掉每 10 秒一次的联网校验**）
3. `PYZ.pyz` 内的 `subscription` 字节码同步打补丁（冗余保险）

授权链路 `client_main.main() → ensure_consent() → refresh() → start_background() → status()` 全部被第 2 步接管；`protect/license.py` 的 `is_authorized()/days_remaining()` 随之恒为真/永久。

## 安全说明

对 `runtime/` 全部 47 个应用源码 + PYZ 字节码 + 导入表做特征扫描（磁盘格式化 / 清盘 / 锁屏 / 关机 / 自毁 / 反调试 / 反虚拟机 等）：**未发现任何恶意或破坏性代码，无后门、无联网回传。**

---

公益破解群：**777410175** ｜ 免费分发，禁止倒卖
