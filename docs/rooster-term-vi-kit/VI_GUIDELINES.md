# `rooster-term` 品牌视觉识别系统 (VI Kit)

本压缩包包含 **`rooster-term`** 的完整品牌视觉资产，可直接替换项目中的图标与主题色。

## 1. 目录结构

- `vi-board/`
  - `rooster-term-vi-system-board.jpg`：16:9 完整品牌视觉识别系统展示板（含标志网格、深浅色图标、色卡与终端界面样机）
  - `rooster-term-app-icon-master.jpg`：1:1 高清主图标母版渲染图
- `svg/`
  - `rooster-term-icon-dark.svg`：深色模式纯矢量应用图标
  - `rooster-term-icon-light.svg`：浅色模式纯矢量应用图标
  - `rooster-term-horizontal-lockup.svg`：横版品牌标志组合（Logo + `rooster-term` 标准字）
- `icons/`（可直接覆盖仓库 `packaging/icons/` 与 `crates/rooste-ssh/assets/`）
  - `icon-16.png`、`icon-32.png`、`icon-48.png`、`icon-64.png`、`icon-128.png`、`icon-256.png`、`icon-512.png`：已做透明圆角裁切的多尺寸 PNG 图标
  - `rooster.ico` / `rooste.ico`：Windows 多尺寸图标文件
  - `icon-64.rgba`：`64×64` 原始 RGBA 字节流（16,384 字节），可直接替换 `crates/rooste-ssh/assets/icon-64.rgba` 供 `eframe` 窗口图标加载
- `palette/`
  - `rooster-term-palette.json`：标准色板与字体 Token 定义

## 2. 标准色卡 (Color Tokens)

| 角色 | 名称 | Hex | RGB | 用途 |
| :--- | :--- | :--- | :--- | :--- |
| Primary BG | Midnight Slate | `#12161F` | `Rgb::new(18, 22, 31)` | 终端背景色、深色图标底板 |
| Panel BG | Roost Charcoal | `#1C2230` | `Rgb::new(28, 34, 48)` | 会话管理器、SFTP 面板、标签栏背景 |
| Brand Primary | Crest Amber | `#FF6B35` | `Rgb::new(255, 107, 53)` | 主按钮 (`primary_button`)、公鸡冠羽主色 |
| Brand Secondary | Dawn Gold | `#FFB800` | `Rgb::new(255, 184, 0)` | `tmux -CC` 网关标识、提示横幅、喙部高光 |
| Accent Cyan | Terminal Cyan | `#38BDF8` | `Rgb::new(56, 189, 248)` | 激活标签页顶部线条、终端光标、超链接 |
| Light Surface | Nordic Snow | `#F4F6F9` | `Rgb::new(244, 246, 249)` | Light 模式背景与 Dark 模式主文字 |

## 3. CLI / 欢迎页 ASCII 徽标

```text
      /\_/\
   > ( o.o )_   rooster-term
     /  ^  \    Fast, memory-safe SSH & tmux terminal
    /__/ \__\   >_
```
