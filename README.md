# 日志异常巡检官

重型日志异常巡检助手，把几十万行杂乱日志压成一页能看懂的巡检报告，配套主流日志格式速查、异常分级、错误模板归并方法与 20 类故障特征库，并内置纯标准库扫描器做多格式解析、堆栈合并、错误模板聚合、时段突刺定位与巡检报告生成

## 快速开始

见 [`SKILL.md`](./SKILL.md)。

## 目录说明

- `SKILL.md` — Skill 主文档
- `scripts/` — 纯标准库可执行脚本，开箱即用
- `references/` — 领域参考材料
- `hooks/` — 护栏规则
- `icon.png` — 技能图标

## 运行自检

```bash
python scripts/log_scan.py --selftest
```

## 关联资源

- 局内人·老K 系列 Skill：
  - [日志异常巡检官](https://github.com/muzhi-888/laoke-log-sentinel)（`laoke-log-sentinel`）
  - [正则表达式工程化助手](https://github.com/muzhi-888/laoke-regex-forge)（`laoke-regex-forge`）
- 落地页与更多工具：https://muzhi-888.github.io/ju-nei-ren-lao-k/

## 许可与免责

MIT 协议。本技能仅供合法的自有系统分析、开发与数据清洗使用，禁止用于未授权访问、隐私抓取或伪造凭证。
