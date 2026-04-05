# IDA Pro+ MCP

> **Enhanced IDA Pro MCP Server** — 基于上游 [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) 最新版，融合三大项目优势。

## 特性总览

| 来源 | 特性 | 说明 |
|:---|:---|:---|
| [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) | 80+ MCP 工具 | 反编译、反汇编、交叉引用、搜索、修改、调试、类型系统等 |
| [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) | Headless idalib | 无 GUI 批量分析（`--isolated-contexts`） |
| [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) | 多实例发现 | `list_instances` / `select_instance` / `open_file` |
| [enhancement](https://github.com/QiuChenly/ida-pro-mcp-enhancement) | **Broker 架构** | HTTP+SSE 中间层，IDA 主动注册，优雅管理多实例 |
| [IDA-NO-MCP](https://github.com/P4nda0s/IDA-NO-MCP) | **批量导出** | 一键导出全部函数/字符串/导入导出表/段信息到文件 |

```
Claude Code / Cursor ──MCP──► IDA Pro+ MCP Server
                                ├─ 标准模式: 直连 IDA RPC (默认)
                                └─ Broker 模式: HTTP+SSE 多实例管理 (--broker)
                                     ├─ IDA 实例 A (自动注册)
                                     ├─ IDA 实例 B (自动注册)
                                     └─ ...

新增批量导出工具:
  bulk_export      → 全函数反编译/反汇编导出
  export_strings   → 字符串表导出
  export_imports   → 导入/导出表
  export_segments  → 段信息 + 可选 hexdump
```

## 安装

### 前置条件

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (推荐) 或 pip
- IDA Pro 8.3+ (推荐 9.0+)

### 安装步骤

```bash
# 克隆
git clone https://github.com/YourUsername/ida-pro-mcp-plus.git
cd ida-pro-mcp-plus

# 安装（含 IDA 插件）
uv run ida-pro-mcp --install

# 或指定客户端
uv run ida-pro-mcp --install claude,cursor
```

### Claude Code 配置

```json
{
  "mcpServers": {
    "ida-pro-mcp-plus": {
      "type": "stdio",
      "command": "uv",
      "args": ["--directory", "/path/to/ida-pro-mcp-plus", "run", "ida-pro-mcp"],
      "env": {}
    }
  }
}
```

#### Broker 模式配置

```json
{
  "mcpServers": {
    "ida-pro-mcp-plus": {
      "type": "stdio",
      "command": "uv",
      "args": ["--directory", "/path/to/ida-pro-mcp-plus", "run", "ida-pro-mcp", "--broker"],
      "env": {}
    }
  }
}
```

## 使用

### 标准模式（默认）

与上游 ida-pro-mcp 完全兼容。IDA 中按 `Ctrl+Alt+M` (Windows/Linux) 或 `Ctrl+Option+M` (macOS) 启动插件。

```bash
# 运行 MCP 服务
uv run ida-pro-mcp

# 指定 IDA 实例
uv run ida-pro-mcp --ida-rpc http://127.0.0.1:13337

# 启用危险操作（调试器等）
uv run ida-pro-mcp --unsafe
```

### Broker 模式（多实例管理）

适合同时打开多个 IDA 窗口的场景。

```bash
# 启动 Broker（默认端口 13337）
uv run ida-pro-mcp --broker

# 指定端口
uv run ida-pro-mcp --broker --broker-port 13338
```

IDA 实例通过插件自动注册到 Broker。使用 MCP 工具切换：

```
list_instances    → 查看所有已连接的 IDA 实例
select_instance   → 切换当前活动实例
```

### 批量导出（新增）

```
bulk_export       → 导出所有函数到 .c/.asm 文件
export_strings    → 导出字符串表
export_imports    → 导出导入/导出表
export_segments   → 导出段信息（可选 hexdump）
```

#### 示例：导出整个二进制供 AI 分析

通过 MCP 工具调用：

```
→ bulk_export(skip_library=true)

结果:
  output_dir: /path/to/binary_export/
  ├── decompile/         # 反编译成功的 .c 文件
  │   ├── 401000.c
  │   ├── 401050.c
  │   └── ...
  ├── disassembly/       # 反编译失败降级的 .asm 文件
  │   ├── 402000.asm
  │   └── ...
  └── function_index.txt # 函数索引

→ export_strings(min_length=6)
→ export_imports()
→ export_segments(include_hexdump=false)
```

每个导出的函数文件包含元数据头：

```c
/*
 * func-name: main
 * func-address: 0x401000
 * export-type: decompile
 * callers: 0x400e00
 * callees: 0x401100, 0x401200
 */
int __cdecl main(int argc, const char **argv, const char **envp)
{
    ...
}
```

### Headless 模式 (idalib)

```bash
# 无 GUI 分析二进制
uv run idalib-mcp /path/to/binary

# 多 agent 隔离上下文
uv run idalib-mcp --isolated-contexts /path/to/binary
```

## 工具列表

### 上游工具（80+）

| 类别 | 工具 |
|:---|:---|
| **核心** | `lookup_funcs`, `list_funcs`, `list_globals`, `imports`, `list_segments`, ... |
| **分析** | `decompile`, `disasm`, `xrefs_to`, `xrefs_to_field`, `callees`, `callgraph`, `find`, `find_regex`, `find_bytes`, `find_insns`, ... |
| **内存** | `get_bytes`, `get_int`, `get_string`, `get_global_value`, `patch`, `put_int`, ... |
| **类型** | `set_type`, `infer_types`, `declare_type`, `read_struct`, `search_structs`, ... |
| **修改** | `set_comments`, `rename`, `patch_asm`, `define_func`, `define_code`, `undefine`, ... |
| **栈帧** | `stack_frame`, `declare_stack`, `delete_stack` |
| **调试** | 20 个调试工具（需 `--unsafe`） |
| **Python** | `py_eval` |
| **实例** | `list_instances`, `select_instance`, `open_file` |

### 新增工具

| 工具 | 说明 |
|:---|:---|
| `bulk_export` | 全函数反编译/反汇编导出，支持断点续传、库函数过滤、内存清理 |
| `export_strings` | 字符串表导出，支持最小长度过滤 |
| `export_imports` | 导入表 + 导出表 |
| `export_segments` | 段信息 + 可选 hexdump |

## 架构

```
┌─────────────────────────────────────────────────────────┐
│                    MCP Clients                          │
│     (Claude Code / Cursor / VS Code / ...)              │
└────────────────┬────────────────────────────────────────┘
                 │ stdio / HTTP
┌────────────────▼────────────────────────────────────────┐
│              IDA Pro+ MCP Server                        │
│  ┌──────────┐  ┌──────────┐  ┌────────────────────┐    │
│  │ 标准模式  │  │ Broker   │  │ 批量导出工具        │    │
│  │ (直连RPC) │  │ (HTTP+   │  │ bulk_export        │    │
│  │          │  │  SSE)    │  │ export_strings     │    │
│  └────┬─────┘  └────┬─────┘  │ export_imports     │    │
│       │              │        │ export_segments    │    │
│       ▼              ▼        └────────────────────┘    │
│  ┌─────────┐  ┌──────────┐                              │
│  │ IDA RPC │  │IDA 注册表 │                              │
│  │ (1实例)  │  │ (N实例)  │                              │
│  └────┬────┘  └───┬──┬───┘                              │
└───────┼───────────┼──┼──────────────────────────────────┘
        │           │  │
        ▼           ▼  ▼
   ┌────────┐  ┌────────┐  ┌────────┐
   │ IDA #1 │  │ IDA #1 │  │ IDA #2 │
   └────────┘  └────────┘  └────────┘
```

## 致谢

- [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) — 上游基础，80+ 工具
- [QiuChenly/ida-pro-mcp-enhancement](https://github.com/QiuChenly/ida-pro-mcp-enhancement) — Broker 架构
- [P4nda0s/IDA-NO-MCP](https://github.com/P4nda0s/IDA-NO-MCP) — 批量导出思路

## License

MIT License — 与上游保持一致。
