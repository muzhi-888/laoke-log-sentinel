#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
log_scan.py —— 日志异常巡检器（纯标准库，零依赖）

能干什么
  1. 自动识别 7 种常见日志格式，逐行解析出时间 / 级别 / 正文
  2. 把 Java / Python / Go 的多行堆栈合并回它所属的那一条日志
  3. 把错误正文「占位化」后归并成错误模板，统计次数 / 首末出现时间 / 样例
  4. 按分钟或小时切桶做时间轴，用中位数 + MAD 找突刺（比均值+标准差抗污染）
  5. 用内置故障特征库给命中的错误打标签，给出方向性根因假设
  6. 输出文本巡检报告 / JSON（给下游程序消费）

只读不写：脚本从不修改被检查的日志文件。

用法速查
  python log_scan.py --input app.log
  python log_scan.py --input app.log --level ERROR,FATAL --top 15
  python log_scan.py --input app.log --bucket minute --spike-k 4
  python log_scan.py --input "logs/*.log" --since 2026-09-09T00:00 --until 2026-09-09T12:00
  python log_scan.py --input app.log --json > report.json
  python log_scan.py --input app.log --signature-only
  python log_scan.py --selftest
"""

import argparse
import glob
import io
import json
import os
import re
import sys
from collections import Counter, OrderedDict, defaultdict
from datetime import datetime

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

VERSION = "1.0.0"

# --------------------------------------------------------------------------
# 一、级别体系
# --------------------------------------------------------------------------

LEVEL_ALIASES = {
    "TRACE": "TRACE", "FINEST": "TRACE", "VERBOSE": "TRACE",
    "DEBUG": "DEBUG", "FINE": "DEBUG", "DBG": "DEBUG",
    "INFO": "INFO", "INFORMATION": "INFO", "NOTICE": "INFO", "I": "INFO",
    "WARN": "WARN", "WARNING": "WARN", "W": "WARN",
    "ERROR": "ERROR", "ERR": "ERROR", "SEVERE": "ERROR", "E": "ERROR",
    "FATAL": "FATAL", "CRIT": "FATAL", "CRITICAL": "FATAL",
    "PANIC": "FATAL", "EMERG": "FATAL", "ALERT": "FATAL",
}

LEVEL_ORDER = ["TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL", "UNKNOWN"]
BAD_LEVELS = ("WARN", "ERROR", "FATAL")


def norm_level(raw):
    if not raw:
        return "UNKNOWN"
    return LEVEL_ALIASES.get(raw.strip().upper(), "UNKNOWN")


# --------------------------------------------------------------------------
# 二、格式识别：每条规则 = (标识, 正则, 时间格式候选)
#     顺序有讲究：先试信息量大的，最后落到裸文本
# --------------------------------------------------------------------------

FORMATS = [
    # log4j / logback 默认：2026-09-09 07:32:50,123 ERROR [http-nio-8080-exec-3] c.x.OrderSvc - msg
    (
        "log4j",
        re.compile(
            r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?)\s+"
            r"(?P<level>[A-Z]{1,8})\s+"
            r"(?:\[(?P<thread>[^\]]{0,80})\]\s*)?"
            r"(?:(?P<logger>[\w$.]{1,120})\s*[-:]\s*)?"
            r"(?P<msg>.*)$"
        ),
    ),
    # 级别在前的变体：ERROR 2026-09-09 07:32:50 msg
    (
        "level_first",
        re.compile(
            r"^(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL|PANIC)\s+"
            r"(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?)\s+"
            r"(?P<msg>.*)$",
            re.I,
        ),
    ),
    # 方括号包裹：[2026-09-09 07:32:50] [error] msg  （nginx error_log 近似）
    (
        "bracket",
        re.compile(
            r"^\[?(?P<ts>\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?)\]?\s*"
            r"[\[\(]?(?P<level>[A-Za-z]{3,8})[\]\)]?\s*[:\-]?\s*"
            r"(?P<msg>.*)$"
        ),
    ),
    # 容器 / k8s：2026-09-09T07:32:50.123456789Z stdout F msg
    (
        "container",
        re.compile(
            r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z?)\s+"
            r"(?:stdout|stderr)\s+[FP]\s+(?P<msg>.*)$"
        ),
    ),
    # Go 标准库 / zap console：2026/09/09 07:32:50 msg
    (
        "go_std",
        re.compile(
            r"^(?P<ts>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?)\s+"
            r"(?:(?P<level>[A-Za-z]{4,8})\s+)?(?P<msg>.*)$"
        ),
    ),
    # syslog：Sep  9 07:32:50 host proc[123]: msg
    (
        "syslog",
        re.compile(
            r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
            r"(?P<host>\S+)\s+(?P<proc>[^:\[]+)(?:\[\d+\])?:\s*(?P<msg>.*)$"
        ),
    ),
    # nginx access：1.2.3.4 - - [09/Sep/2026:07:32:50 +0800] "GET /a HTTP/1.1" 500 123
    (
        "nginx_access",
        re.compile(
            r"^(?P<ip>[\d.:a-fA-F]+)\s+\S+\s+\S+\s+"
            r"\[(?P<ts>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}[^\]]*)\]\s+"
            r'"(?P<req>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)(?P<rest>.*)$'
        ),
    ),
]

TS_PATTERNS = [
    "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S,%f", "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S,%f", "%Y-%m-%dT%H:%M:%S",
    "%Y/%m/%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S",
    "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M", "%Y-%m-%d",
]


def parse_ts(raw):
    """尽力把时间串转成 datetime，失败返回 None（不抛异常，日志巡检不能因为一行怪时间挂掉）"""
    if not raw:
        return None
    s = raw.strip().rstrip("Z")
    # 时区后缀 +0800 / +08:00 先切掉，巡检只关心相对时序
    s = re.sub(r"\s*[+-]\d{2}:?\d{2}$", "", s)
    # 纳秒截成微秒，strptime 的 %f 只吃 1-6 位
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)
    for fmt in TS_PATTERNS:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    # syslog 没年份，补当前年份
    m = re.match(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$", s)
    if m:
        try:
            return datetime.strptime(
                "%d %s %s %s:%s:%s" % (datetime.now().year, m.group(1), m.group(2),
                                       m.group(3), m.group(4), m.group(5)),
                "%Y %b %d %H:%M:%S",
            )
        except ValueError:
            return None
    return None


# 堆栈续行特征：Java "\tat x.y.Z"、Caused by、Python "  File ..."、Go "\tgoroutine"
CONT_PATTERNS = [
    re.compile(r"^\s+at\s+[\w$.<>]+\("),
    re.compile(r"^\s*Caused by:\s"),
    # 异常类名独占一行 = 堆栈头，紧跟在上一条日志之后，如 java.sql.SQLException: xxx
    re.compile(r"^[\w$]+(?:\.[\w$]+){1,}(?:Exception|Error|Throwable)\b"),
    re.compile(r"^\s*Suppressed:\s"),
    re.compile(r"^\s*\.\.\.\s+\d+\s+more\s*$"),
    re.compile(r"^\s+File\s+\".+\",\s+line\s+\d+"),
    re.compile(r"^Traceback \(most recent call last\)"),
    re.compile(r"^\s+goroutine\s+\d+"),
    re.compile(r"^\s+0x[0-9a-f]{6,}"),
    re.compile(r"^\s{4,}\S"),
]


def is_continuation(line):
    if not line.strip():
        return False
    for p in CONT_PATTERNS:
        if p.match(line):
            return True
    return False


def detect_and_parse(line):
    """返回 dict(fmt, ts, level, msg, raw)；识别不出来就 fmt=plain"""
    for name, rx in FORMATS:
        m = rx.match(line)
        if not m:
            continue
        gd = m.groupdict()
        if name == "nginx_access":
            status = gd.get("status") or ""
            lvl = "ERROR" if status.startswith("5") else ("WARN" if status.startswith("4") else "INFO")
            msg = "%s -> %s" % ((gd.get("req") or "").strip(), status)
            return {"fmt": name, "ts": parse_ts(gd.get("ts")), "level": lvl,
                    "msg": msg, "raw": line, "status": status}
        lvl = norm_level(gd.get("level"))
        msg = (gd.get("msg") or "").strip()
        # bracket / go_std 容易把正文里的单词误当级别，级别认不出来就把它还原回正文
        if lvl == "UNKNOWN" and gd.get("level") and name in ("bracket", "go_std"):
            msg = ("%s %s" % (gd.get("level"), msg)).strip()
        if lvl == "UNKNOWN":
            lvl = guess_level_from_text(msg)
        return {"fmt": name, "ts": parse_ts(gd.get("ts")), "level": lvl,
                "msg": msg, "raw": line}
    # JSON 行日志
    s = line.strip()
    if s.startswith("{") and s.endswith("}"):
        try:
            obj = json.loads(s)
        except Exception:
            obj = None
        if isinstance(obj, dict):
            ts = None
            for k in ("time", "timestamp", "ts", "@timestamp", "eventTime", "datetime"):
                if k in obj:
                    ts = parse_ts(str(obj[k]))
                    if ts:
                        break
            lvl = "UNKNOWN"
            for k in ("level", "lvl", "severity", "levelname", "log.level"):
                if k in obj:
                    lvl = norm_level(str(obj[k]))
                    break
            msg = ""
            for k in ("message", "msg", "log", "event", "text"):
                if k in obj and isinstance(obj[k], (str, int, float)):
                    msg = str(obj[k])
                    break
            if not msg:
                msg = s[:400]
            if lvl == "UNKNOWN":
                lvl = guess_level_from_text(msg)
            return {"fmt": "json", "ts": ts, "level": lvl, "msg": msg.strip(), "raw": line}
    return {"fmt": "plain", "ts": None, "level": guess_level_from_text(s), "msg": s, "raw": line}


TEXT_LEVEL_HINTS = [
    (re.compile(r"\b(panic|fatal)\b", re.I), "FATAL"),
    (re.compile(r"(exception|error|failed|failure|refused|timeout|timed out|"
                r"异常|失败|错误|超时|拒绝)", re.I), "ERROR"),
    (re.compile(r"\b(warn|warning|retry|retrying|deprecated|slow)\b|(重试|告警|慢查询)", re.I), "WARN"),
]


def guess_level_from_text(msg):
    """
    没有级别字段时（syslog / 容器 stdout / 裸文本）反推级别。
    先看关键词，再用故障特征库兜底——内核级致命错误恰恰最爱出现在无级别日志里，
    像 "No space left on device"、"Too many open files" 一个 error 字样都没有，
    但它们比大部分 ERROR 都严重，绝不能被过滤掉。
    """
    text = msg or ""
    for rx, lvl in TEXT_LEVEL_HINTS:
        if rx.search(text):
            return lvl
    hits = match_signatures(text)
    if hits:
        sevs = {h[1] for h in hits}
        if "P0" in sevs or "P1" in sevs:
            return "ERROR"
        return "WARN"
    return "UNKNOWN"


# --------------------------------------------------------------------------
# 三、占位化：把变量抹掉，只留错误的「骨架」
#     顺序极其重要——长的、结构强的先替，否则会被短规则咬掉一半
# --------------------------------------------------------------------------

NORM_RULES = [
    (re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?"), "<TS>"),
    (re.compile(r"\d{4}/\d{2}/\d{2}\s\d{2}:\d{2}:\d{2}"), "<TS>"),
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<UUID>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b"), "<IP>"),
    # URL 必须排在 PATH 之前，否则 PATH 会把 http:// 后面的部分先咬掉，
    # 留下 "https:/<PATH>" 这种半截模板
    (re.compile(r"https?://[^\s'\"<>]+"), "<URL>"),
    (re.compile(r"\b[A-Za-z]:\\[^\s'\"]+"), "<PATH>"),
    (re.compile(r"(?<![\w.])/(?:[\w.\-]+/){1,}[\w.\-]*"), "<PATH>"),
    (re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b"), "<EMAIL>"),
    (re.compile(r"\b0x[0-9a-fA-F]{4,}\b"), "<HEX>"),
    (re.compile(r"\b[0-9a-fA-F]{16,}\b"), "<HASH>"),
    (re.compile(r"'[^']{0,200}'"), "'<STR>'"),
    (re.compile(r'"[^"]{0,200}"'), '"<STR>"'),
    (re.compile(r"\b\d+(?:\.\d+)?(?:ms|s|us|ns|KB|MB|GB|kb|mb|gb)\b"), "<SIZE>"),
    (re.compile(r"\b\d[\d,]{2,}\b"), "<NUM>"),
    (re.compile(r"\b\d+\b"), "<N>"),
    (re.compile(r"\s+"), " "),
]


def normalize(msg):
    s = msg or ""
    for rx, rep in NORM_RULES:
        s = rx.sub(rep, s)
    return s.strip()[:300]


# --------------------------------------------------------------------------
# 四、故障特征库：命中即给方向，不下死结论
# --------------------------------------------------------------------------

SIGNATURES = [
    ("连接池耗尽", r"(connection is not available|pool.{0,20}exhaust|HikariPool.{0,40}(timeout|request timed out)|"
                   r"Timeout waiting for idle object|too many connections|获取连接超时)",
     "P1", "连接没归还或慢 SQL 拖住连接。查慢查询 + 有没有裸用连接不 close + 池大小是否小于并发。"),
    ("内存溢出", r"(OutOfMemoryError|java heap space|GC overhead limit|Cannot allocate memory|"
                 r"MemoryError|fatal error: out of memory|OOMKilled|Killed process)",
     "P0", "看是堆内（对象堆积/缓存无上限）还是堆外（Direct/Netty），先抓 dump 再谈调参。"),
    ("GC 长停顿", r"(Full GC.{0,80}\d+\.\d+ secs|Pause Full|GC pause.{0,30}\d{3,}ms|allocation stall)",
     "P1", "先看 Full GC 频率而不是耗时，多数是老年代被撑满，配合内存溢出那条一起看。"),
    ("死锁", r"(Deadlock found when trying to get lock|deadlock detected|"
             r"Found one Java-level deadlock|fatal error: all goroutines are asleep)",
     "P1", "两个事务加锁顺序不一致。找出涉及的表和 SQL，统一加锁顺序，别指望重试兜住。"),
    ("请求超时", r"(SocketTimeoutException|Read timed out|connect timed out|"
                 r"context deadline exceeded|ETIMEDOUT|i/o timeout|upstream timed out)",
     "P1", "先分清是连接超时（对端没起/网络不通）还是读超时（对端慢）。前者查部署，后者查下游。"),
    ("连接被拒", r"(Connection refused|ECONNREFUSED|No route to host|"
                 r"Failed to connect to|connection reset by peer|ECONNRESET)",
     "P1", "对端端口没监听、被安全组挡了、或对端刚重启。先 telnet/nc 验证四层。"),
    ("文件句柄耗尽", r"(Too many open files|EMFILE|socket: too many open files)",
     "P0", "句柄泄漏为主（流/连接没 close），ulimit 只是止血。用 lsof 数一下句柄类型分布。"),
    ("磁盘写满", r"(No space left on device|ENOSPC|disk quota exceeded|磁盘空间不足)",
     "P0", "先查是不是日志自己写爆的，再查 inode 是否耗尽（df -i），别只看 df -h。"),
    ("线程池打满", r"(RejectedExecutionException|Task .{0,60} rejected from|"
                   r"queue capacity .{0,20}(full|exceeded)|worker pool exhausted)",
     "P1", "拒绝策略生效说明上游速率超过处理能力。看队列长度曲线，不要盲目加线程。"),
    ("限流熔断", r"(RateLimit|429 Too Many Requests|circuit breaker.{0,20}open|"
                 r"BlockException|FlowException|degrade)",
     "P2", "先确认是自家配置的阈值还是第三方给的。命中限流通常是重试风暴放大出来的。"),
    ("空指针类缺陷", r"(NullPointerException|TypeError.{0,40}NoneType|"
                     r"invalid memory address or nil pointer dereference|"
                     r"Cannot read propert(y|ies) of (undefined|null))",
     "P2", "代码缺陷，看堆栈第一行自家包名的那帧，别在框架帧里找。"),
    ("反序列化失败", r"(JsonParseException|JsonMappingException|Unrecognized field|"
                     r"JSONDecodeError|Unexpected token|unmarshal|cannot deserialize)",
     "P2", "上下游契约不一致，多数是对端悄悄改了字段。抓一条原始报文对比。"),
    ("SSL 证书问题", r"(SSLHandshakeException|certificate has expired|"
                     r"unable to find valid certification path|x509: certificate|CERT_HAS_EXPIRED)",
     "P1", "先看有效期再看信任链。证书到期这种事只会在最忙的那天发生。"),
    ("DNS 解析失败", r"(UnknownHostException|Name or service not known|"
                     r"EAI_AGAIN|no such host|Temporary failure in name resolution)",
     "P1", "容器里多数是 DNS 配置或 ndots 引起的，先在 Pod 里 nslookup 验一次。"),
    ("Redis 异常", r"(JedisConnectionException|READONLY You can't write|"
                   r"MISCONF|LOADING Redis is loading|redis: connection pool timeout|CROSSSLOT)",
     "P1", "READONLY 是切主后连到从库，MISCONF 是持久化失败，两者处理完全不同。"),
    ("数据库异常", r"(SQLException|Duplicate entry|Data too long for column|"
                   r"Lock wait timeout exceeded|Table .{0,40} doesn't exist|"
                   r"could not execute statement|max_allowed_packet)",
     "P1", "Lock wait timeout 看长事务，Duplicate entry 看幂等设计，别一律当 DB 抖动。"),
    ("鉴权失败", r"(401 Unauthorized|403 Forbidden|invalid.{0,15}token|"
                 r"signature.{0,15}(invalid|mismatch)|AccessDenied|权限不足|签名错误)",
     "P2", "先分清是凭证过期（可自愈）还是签名算法不一致（改代码）。看时间是否成片出现。"),
    ("重试风暴", r"(retry.{0,20}(attempt|times|\d+/\d+)|重试第\s*<?N?>?\s*次|"
                 r"giving up after .{0,20}attempts)",
     "P1", "重试自身会把下游打死。确认有没有指数退避 + 上限，以及是否多层同时重试。"),
    ("HTTP 5xx", r"(\b50[0234]\b.{0,40}(error|Internal Server|Bad Gateway|Service Unavailable)|"
                 r"-> 50[0234]$)",
     "P1", "502/504 多在网关与上游之间，500 在应用内部。先按状态码分开统计再定位。"),
    ("配置缺失", r"(Could not resolve placeholder|环境变量.{0,10}(未|没有)配置|"
                 r"missing required (config|env|property)|No such config)",
     "P1", "多环境配置漂移，发版当天最常见。对比一次目标环境与基线的配置差集。"),
]

COMPILED_SIGS = [(name, re.compile(pat, re.I), sev, hint) for name, pat, sev, hint in SIGNATURES]


def match_signatures(text):
    hits = []
    for name, rx, sev, hint in COMPILED_SIGS:
        if rx.search(text or ""):
            hits.append((name, sev, hint))
    return hits


# --------------------------------------------------------------------------
# 五、读取与解析
# --------------------------------------------------------------------------

def expand_inputs(patterns):
    files = []
    for p in patterns:
        hit = sorted(glob.glob(p))
        if hit:
            files.extend([f for f in hit if os.path.isfile(f)])
        elif os.path.isfile(p):
            files.append(p)
    seen, out = set(), []
    for f in files:
        rp = os.path.abspath(f)
        if rp not in seen:
            seen.add(rp)
            out.append(f)
    return out


def read_lines(path, encoding, max_lines):
    with io.open(path, "r", encoding=encoding, errors="replace") as fh:
        for i, line in enumerate(fh):
            if max_lines and i >= max_lines:
                break
            yield line.rstrip("\n").rstrip("\r")


def parse_stream(lines, merge_stack=True, max_stack=40):
    """把原始行流解析成条目流，多行堆栈合并进上一条"""
    entries = []
    for line in lines:
        if not line.strip():
            continue
        if merge_stack and entries and is_continuation(line):
            last = entries[-1]
            if last["stack_lines"] < max_stack:
                last["stack"].append(line.strip())
                last["stack_lines"] += 1
            continue
        e = detect_and_parse(line)
        e["stack"] = []
        e["stack_lines"] = 0
        entries.append(e)
    return entries


def full_text(e):
    if e["stack"]:
        return e["msg"] + " || " + " ".join(e["stack"][:6])
    return e["msg"]


# --------------------------------------------------------------------------
# 六、聚合分析
# --------------------------------------------------------------------------

def bucket_key(ts, mode):
    if ts is None:
        return None
    if mode == "minute":
        return ts.strftime("%Y-%m-%d %H:%M")
    if mode == "hour":
        return ts.strftime("%Y-%m-%d %H:00")
    if mode == "10min":
        return ts.strftime("%Y-%m-%d %H:") + "%02d0" % (ts.minute // 10)
    return ts.strftime("%Y-%m-%d")


def median(xs):
    if not xs:
        return 0.0
    s = sorted(xs)
    n = len(s)
    mid = n // 2
    return float(s[mid]) if n % 2 else (s[mid - 1] + s[mid]) / 2.0


def find_spikes(counter, k=3.0, min_count=5):
    """中位数 + MAD 找突刺。MAD 对少数极端值不敏感，比均值+标准差稳。"""
    if len(counter) < 4:
        return []
    keys = sorted(counter.keys())
    vals = [counter[x] for x in keys]
    med = median(vals)
    mad = median([abs(v - med) for v in vals])
    # MAD 为 0 说明大部分桶数值一样，退化成「明显高于中位数」判断
    thr = med + k * (mad * 1.4826) if mad > 0 else max(med * 2.0, med + 3)
    spikes = []
    for key in keys:
        v = counter[key]
        if v >= max(min_count, thr):
            ratio = (v / med) if med > 0 else float(v)
            spikes.append({"bucket": key, "count": v, "median": med,
                           "threshold": round(thr, 2), "ratio": round(ratio, 2)})
    spikes.sort(key=lambda x: -x["count"])
    return spikes


def analyze(entries, levels, top, bucket, spike_k, since, until):
    stat = {
        "total_lines": len(entries),
        "formats": Counter(),
        "levels": Counter(),
        "ts_ok": 0,
        "ts_range": [None, None],
    }
    focus = []
    for e in entries:
        stat["formats"][e["fmt"]] += 1
        stat["levels"][e["level"]] += 1
        ts = e["ts"]
        if ts:
            stat["ts_ok"] += 1
            lo, hi = stat["ts_range"]
            if lo is None or ts < lo:
                stat["ts_range"][0] = ts
            if hi is None or ts > hi:
                stat["ts_range"][1] = ts
        if since and ts and ts < since:
            continue
        if until and ts and ts > until:
            continue
        if e["level"] in levels:
            focus.append(e)

    templates = OrderedDict()
    for e in focus:
        tpl = normalize(e["msg"])
        if not tpl:
            tpl = "<空正文>"
        rec = templates.get(tpl)
        if rec is None:
            rec = {"template": tpl, "count": 0, "levels": Counter(),
                   "first": e["ts"], "last": e["ts"], "sample": e["msg"][:400],
                   "stack_head": e["stack"][0][:200] if e["stack"] else "",
                   "sigs": match_signatures(full_text(e)), "buckets": Counter()}
            templates[tpl] = rec
        rec["count"] += 1
        rec["levels"][e["level"]] += 1
        if e["ts"]:
            if rec["first"] is None or e["ts"] < rec["first"]:
                rec["first"] = e["ts"]
            if rec["last"] is None or e["ts"] > rec["last"]:
                rec["last"] = e["ts"]
            bk = bucket_key(e["ts"], bucket)
            if bk:
                rec["buckets"][bk] += 1
        if not rec["sigs"]:
            rec["sigs"] = match_signatures(full_text(e))

    ranked = sorted(templates.values(), key=lambda r: -r["count"])

    timeline = Counter()
    for e in focus:
        bk = bucket_key(e["ts"], bucket)
        if bk:
            timeline[bk] += 1
    spikes = find_spikes(timeline, k=spike_k)

    sig_summary = OrderedDict()
    for rec in ranked:
        for name, sev, hint in rec["sigs"]:
            s = sig_summary.setdefault(name, {"name": name, "severity": sev, "hint": hint,
                                              "count": 0, "templates": 0, "sample": rec["sample"][:200]})
            s["count"] += rec["count"]
            s["templates"] += 1
    sig_list = sorted(sig_summary.values(),
                      key=lambda s: (["P0", "P1", "P2"].index(s["severity"]), -s["count"]))

    return {
        "stat": stat,
        "focus_count": len(focus),
        "templates": ranked[:top],
        "template_total": len(ranked),
        "timeline": timeline,
        "spikes": spikes[:10],
        "signatures": sig_list,
    }


# --------------------------------------------------------------------------
# 七、报告输出
# --------------------------------------------------------------------------

def fmt_ts(ts):
    return ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "-"


def bar(n, mx, width=32):
    if mx <= 0:
        return ""
    filled = max(1, int(round(n * 1.0 / mx * width)))
    return "#" * filled


def print_report(res, files, bucket, top, show_timeline=True):
    st = res["stat"]
    print("=" * 72)
    print("日志巡检报告  log_scan v%s" % VERSION)
    print("=" * 72)
    print("文件      : %s" % (", ".join(files) if files else "(stdin)"))
    print("总条目    : %d 条（多行堆栈已合并计为 1 条）" % st["total_lines"])
    print("时间可解析: %d 条  范围 %s ~ %s"
          % (st["ts_ok"], fmt_ts(st["ts_range"][0]), fmt_ts(st["ts_range"][1])))
    print("格式分布  : %s" % ", ".join("%s=%d" % (k, v) for k, v in st["formats"].most_common()))
    lv = ", ".join("%s=%d" % (k, st["levels"][k]) for k in LEVEL_ORDER if st["levels"].get(k))
    print("级别分布  : %s" % (lv or "-"))
    print("纳入分析  : %d 条，归并出 %d 个错误模板" % (res["focus_count"], res["template_total"]))

    print("")
    print("-" * 72)
    print("一、错误模板 Top %d（按出现次数）" % min(top, len(res["templates"])))
    print("-" * 72)
    if not res["templates"]:
        print("没有命中任何目标级别的条目。要么真干净，要么级别过滤配窄了。")
    mx = res["templates"][0]["count"] if res["templates"] else 0
    for i, r in enumerate(res["templates"], 1):
        lvls = "/".join("%s:%d" % (k, v) for k, v in r["levels"].most_common())
        print("")
        print("[%02d] %d 次  %-22s %s" % (i, r["count"], lvls, bar(r["count"], mx, 24)))
        print("     模板: %s" % r["template"])
        print("     窗口: %s ~ %s" % (fmt_ts(r["first"]), fmt_ts(r["last"])))
        print("     样例: %s" % r["sample"][:180])
        if r["stack_head"]:
            print("     栈首: %s" % r["stack_head"])
        if r["sigs"]:
            print("     命中: %s" % ", ".join("%s(%s)" % (n, s) for n, s, _ in r["sigs"]))

    if show_timeline and res["timeline"]:
        print("")
        print("-" * 72)
        print("二、时间轴（按%s切桶，只显示有量的前 20 桶）"
              % {"minute": "分钟", "10min": "10分钟", "hour": "小时"}.get(bucket, "天"))
        print("-" * 72)
        items = sorted(res["timeline"].items())
        if len(items) > 20:
            items = sorted(res["timeline"].items(), key=lambda x: -x[1])[:20]
            items.sort()
        mxt = max(v for _, v in items)
        for k, v in items:
            print("  %-17s %6d  %s" % (k, v, bar(v, mxt, 34)))

    print("")
    print("-" * 72)
    print("三、突刺定位")
    print("-" * 72)
    if not res["spikes"]:
        print("  没有明显突刺，错误是均匀分布的——这种更像长期存在的老问题，不是新故障。")
    for s in res["spikes"]:
        print("  %s  %d 次（中位数 %.1f，阈值 %.1f，倍数 %.1fx）"
              % (s["bucket"], s["count"], s["median"], s["threshold"], s["ratio"]))
    if res["spikes"]:
        print("  → 拿最高的那个桶去比对发版记录、定时任务、上游流量，三者之一大概率对得上。")

    print("")
    print("-" * 72)
    print("四、故障特征命中与方向性假设")
    print("-" * 72)
    if not res["signatures"]:
        print("  未命中内置特征库。属于业务自定义错误，按模板 Top1 逐个看样例。")
    for s in res["signatures"]:
        print("")
        print("  [%s] %s  影响 %d 条 / %d 个模板" % (s["severity"], s["name"], s["count"], s["templates"]))
        print("       方向: %s" % s["hint"])

    print("")
    print("-" * 72)
    print("五、下一步建议")
    print("-" * 72)
    for line in next_steps(res):
        print("  - %s" % line)
    print("")
    print("提示：模板归并靠占位化，命中特征只代表方向，不等于根因。定论前请回原始日志看上下文。")


def next_steps(res):
    out = []
    p0 = [s for s in res["signatures"] if s["severity"] == "P0"]
    if p0:
        out.append("先处理 P0：%s。这类会直接把进程拖死，其他问题多半是它的连带反应。"
                   % "、".join(s["name"] for s in p0))
    if res["spikes"]:
        out.append("以 %s 这个桶为锚点，取前后各 5 分钟的完整原始日志，看第一条异常出现在哪里。"
                   % res["spikes"][0]["bucket"])
    else:
        out.append("错误分布均匀，建议改成按天切桶跑一次，看是不是在缓慢恶化。")
    if res["templates"]:
        t0 = res["templates"][0]
        if t0["count"] >= max(20, res["focus_count"] * 0.4):
            out.append("Top1 模板占了大头（%d 条），先把它压下去，报告会瞬间干净一半。" % t0["count"])
    names = {s["name"] for s in res["signatures"]}
    if "重试风暴" in names and len(names) > 1:
        out.append("同时出现重试与其他故障：先关掉或退避重试再定位，否则现象会被放大得看不清。")
    if "请求超时" in names and "连接池耗尽" in names:
        out.append("超时 + 连接池耗尽同时出现，典型的下游变慢连锁反应，从下游依赖查起。")
    out.append("修完之后拿同一条命令再跑一次，比对模板数量与突刺是否消失，这就是验证闭环。")
    return out


def to_json(res, files, bucket):
    st = res["stat"]
    return {
        "version": VERSION,
        "files": files,
        "bucket": bucket,
        "summary": {
            "total_entries": st["total_lines"],
            "ts_parsed": st["ts_ok"],
            "ts_from": fmt_ts(st["ts_range"][0]),
            "ts_to": fmt_ts(st["ts_range"][1]),
            "formats": dict(st["formats"]),
            "levels": {k: st["levels"][k] for k in LEVEL_ORDER if st["levels"].get(k)},
            "focus_entries": res["focus_count"],
            "template_total": res["template_total"],
        },
        "templates": [{
            "template": r["template"],
            "count": r["count"],
            "levels": dict(r["levels"]),
            "first": fmt_ts(r["first"]),
            "last": fmt_ts(r["last"]),
            "sample": r["sample"],
            "stack_head": r["stack_head"],
            "signatures": [{"name": n, "severity": s} for n, s, _ in r["sigs"]],
        } for r in res["templates"]],
        "timeline": dict(sorted(res["timeline"].items())),
        "spikes": res["spikes"],
        "signatures": res["signatures"],
        "next_steps": next_steps(res),
    }


# --------------------------------------------------------------------------
# 八、自检
# --------------------------------------------------------------------------

SELFTEST_LOG = """2026-09-09 07:30:01,101 INFO  [main] c.x.App - service started on port 8080
2026-09-09 07:30:12,220 INFO  [http-1] c.x.OrderSvc - create order id=100001 user=A1
2026-09-09 07:31:03,301 WARN  [http-2] c.x.OrderSvc - slow query cost=1200ms sql=select * from t_order
2026-09-09 07:32:00,010 ERROR [http-3] c.x.OrderSvc - HikariPool-1 - Connection is not available, request timed out after 30000ms
java.sql.SQLTransientConnectionException: HikariPool-1 - Connection is not available
\tat com.zaxxer.hikari.pool.HikariPool.createTimeoutException(HikariPool.java:696)
\tat com.x.OrderSvc.create(OrderSvc.java:88)
Caused by: java.net.SocketTimeoutException: Read timed out
2026-09-09 07:32:01,011 ERROR [http-4] c.x.OrderSvc - HikariPool-1 - Connection is not available, request timed out after 30000ms
2026-09-09 07:32:02,012 ERROR [http-5] c.x.OrderSvc - HikariPool-1 - Connection is not available, request timed out after 30000ms
2026-09-09 07:32:03,013 ERROR [http-6] c.x.OrderSvc - HikariPool-1 - Connection is not available, request timed out after 30000ms
2026-09-09 07:32:04,014 ERROR [http-7] c.x.PaySvc - call upstream pay-gateway/v2/pay failed, ip=10.2.3.4:8443
2026-09-09 07:32:05,015 ERROR [http-8] c.x.PaySvc - call upstream pay-gateway/v2/pay failed, ip=10.2.3.5:8443
2026-09-09 07:33:00,020 FATAL [gc] c.x.App - java.lang.OutOfMemoryError: Java heap space
{"time":"2026-09-09T07:34:00.500Z","level":"error","msg":"redis READONLY You can't write against a read only replica"}
2026-09-09T07:35:00.100Z stdout F Too many open files: /data/app/cache/seg-000123.idx
Sep  9 07:36:00 node-1 kernel[0]: No space left on device
1.2.3.4 - - [09/Sep/2026:07:37:00 +0800] "POST /api/pay HTTP/1.1" 500 233
2026-09-09 07:38:00,000 DEBUG [main] c.x.App - heartbeat ok
"""


def selftest():
    ok, fail = 0, 0

    def chk(name, cond, extra=""):
        nonlocal ok, fail
        if cond:
            ok += 1
            print("  [PASS] %s" % name)
        else:
            fail += 1
            print("  [FAIL] %s %s" % (name, extra))

    print("log_scan v%s 自检" % VERSION)
    print("-" * 60)

    # 1. 级别归一
    chk("级别归一 WARNING->WARN", norm_level("WARNING") == "WARN")
    chk("级别归一 severe->ERROR", norm_level("severe") == "ERROR")
    chk("级别归一 未知->UNKNOWN", norm_level("blabla") == "UNKNOWN")

    # 2. 时间解析
    chk("时间解析 log4j 逗号毫秒", parse_ts("2026-09-09 07:32:50,123") is not None)
    chk("时间解析 ISO 带 Z", parse_ts("2026-09-09T07:32:50.123456789Z") is not None)
    chk("时间解析 nginx 风格", parse_ts("09/Sep/2026:07:32:50 +0800") is not None)
    chk("时间解析 脏数据不抛异常", parse_ts("not-a-time") is None)

    # 3. 格式识别
    e = detect_and_parse("2026-09-09 07:32:50,123 ERROR [http-1] c.x.A - boom")
    chk("识别 log4j 格式", e["fmt"] == "log4j" and e["level"] == "ERROR" and e["msg"] == "boom",
        "got=%s" % e)
    e2 = detect_and_parse('{"time":"2026-09-09T07:34:00Z","level":"error","msg":"redis down"}')
    chk("识别 JSON 行", e2["fmt"] == "json" and e2["level"] == "ERROR" and "redis" in e2["msg"],
        "got=%s" % e2)
    e3 = detect_and_parse('1.2.3.4 - - [09/Sep/2026:07:37:00 +0800] "POST /api/pay HTTP/1.1" 500 233')
    chk("识别 nginx access 并按状态码定级", e3["fmt"] == "nginx_access" and e3["level"] == "ERROR",
        "got=%s" % e3)
    e4 = detect_and_parse("Sep  9 07:36:00 node-1 kernel[0]: No space left on device")
    chk("识别 syslog", e4["fmt"] == "syslog" and "No space" in e4["msg"], "got=%s" % e4)

    # 4. 堆栈续行
    chk("堆栈续行 at 帧", is_continuation("\tat com.x.A.b(A.java:1)"))
    chk("堆栈续行 Caused by", is_continuation("Caused by: java.io.IOException"))
    chk("正常日志不被当续行", not is_continuation("2026-09-09 07:32:50,123 ERROR x - y"))

    # 5. 占位化
    n1 = normalize("order id=100001 cost 1200ms from 10.2.3.4:8443 at 2026-09-09 07:32:50")
    chk("占位化抹掉 IP/时间/数字", "<IP>" in n1 and "<TS>" in n1 and "100001" not in n1, "got=%s" % n1)
    a = normalize("Connection is not available, request timed out after 30000ms")
    b = normalize("Connection is not available, request timed out after 45000ms")
    chk("同类错误归并成同一模板", a == b, "a=%s b=%s" % (a, b))
    c = normalize("failed to load /data/app/cache/seg-000123.idx")
    chk("占位化抹掉路径", "<PATH>" in c, "got=%s" % c)

    # 6. 特征库
    hits = match_signatures("HikariPool-1 - Connection is not available, request timed out")
    chk("特征命中 连接池耗尽", any(h[0] == "连接池耗尽" for h in hits), "got=%s" % hits)
    hits2 = match_signatures("java.lang.OutOfMemoryError: Java heap space")
    chk("特征命中 内存溢出且为 P0",
        any(h[0] == "内存溢出" and h[1] == "P0" for h in hits2), "got=%s" % hits2)
    chk("正常日志不误报", match_signatures("service started on port 8080") == [])

    # 7. 突刺
    cnt = Counter({"07:30": 1, "07:31": 1, "07:32": 30, "07:33": 1, "07:34": 2, "07:35": 1})
    sp = find_spikes(cnt, k=3.0)
    chk("突刺定位到 07:32", sp and sp[0]["bucket"] == "07:32", "got=%s" % sp)
    chk("样本太少不硬判", find_spikes(Counter({"a": 5, "b": 6}), k=3.0) == [])

    # 8. 端到端
    entries = parse_stream(SELFTEST_LOG.splitlines())
    chk("端到端 堆栈已合并（条目数少于原始行数）",
        len(entries) < len(SELFTEST_LOG.strip().splitlines()), "entries=%d" % len(entries))
    stacked = [e for e in entries if e["stack"]]
    chk("端到端 至少一条带堆栈", len(stacked) >= 1)
    res = analyze(entries, set(BAD_LEVELS), 10, "minute", 3.0, None, None)
    chk("端到端 归并出模板", res["template_total"] >= 5, "got=%d" % res["template_total"])
    top1 = res["templates"][0]
    chk("端到端 Top1 是连接池（4 次）", top1["count"] == 4, "got=%d / %s" % (top1["count"], top1["template"]))
    signames = {s["name"] for s in res["signatures"]}
    for want in ("连接池耗尽", "内存溢出", "文件句柄耗尽", "磁盘写满", "Redis 异常"):
        chk("端到端 命中特征 %s" % want, want in signames, "got=%s" % sorted(signames))
    chk("端到端 P0 排在最前", res["signatures"][0]["severity"] == "P0",
        "got=%s" % res["signatures"][0])
    chk("端到端 找到突刺", len(res["spikes"]) >= 1, "spikes=%s" % res["spikes"])
    chk("端到端 建议非空", len(next_steps(res)) >= 3)
    j = to_json(res, ["<selftest>"], "minute")
    chk("端到端 JSON 可序列化", isinstance(json.dumps(j, ensure_ascii=False), str))
    chk("端到端 时间范围已识别", j["summary"]["ts_parsed"] >= 15,
        "got=%s" % j["summary"]["ts_parsed"])

    print("-" * 60)
    print("PASS=%d  FAIL=%d" % (ok, fail))
    return 0 if fail == 0 else 1


# --------------------------------------------------------------------------
# 九、CLI
# --------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="log_scan.py",
        description="日志异常巡检器：归并错误模板、定位时间突刺、匹配故障特征",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  python log_scan.py --input app.log\n"
               "  python log_scan.py --input \"logs/*.log\" --bucket minute --top 15\n"
               "  python log_scan.py --input app.log --level ERROR,FATAL --json\n"
               "  python log_scan.py --selftest\n",
    )
    p.add_argument("--input", "-i", action="append", default=[],
                   help="日志文件路径，支持通配符，可重复传；不传则读标准输入")
    p.add_argument("--level", default="WARN,ERROR,FATAL",
                   help="纳入分析的级别，逗号分隔（默认 WARN,ERROR,FATAL）；ALL 表示全部")
    p.add_argument("--top", type=int, default=10, help="错误模板展示条数（默认 10）")
    p.add_argument("--bucket", default="minute", choices=["minute", "10min", "hour", "day"],
                   help="时间轴切桶粒度（默认 minute）")
    p.add_argument("--spike-k", type=float, default=3.0,
                   help="突刺灵敏度，越小越敏感（默认 3.0）")
    p.add_argument("--since", default=None, help="只看这个时间之后，如 2026-09-09T07:00")
    p.add_argument("--until", default=None, help="只看这个时间之前")
    p.add_argument("--max-lines", type=int, default=0, help="每个文件最多读多少行（0=不限）")
    p.add_argument("--encoding", default="utf-8", help="日志文件编码（默认 utf-8）")
    p.add_argument("--no-merge-stack", action="store_true", help="不合并多行堆栈")
    p.add_argument("--no-timeline", action="store_true", help="报告里不打印时间轴")
    p.add_argument("--signature-only", action="store_true", help="只输出故障特征命中部分")
    p.add_argument("--json", action="store_true", help="输出 JSON，便于下游程序消费")
    p.add_argument("--selftest", action="store_true", help="跑自检，全过 exit 0")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.selftest:
        return selftest()

    files = expand_inputs(args.input) if args.input else []
    if args.input and not files:
        sys.stderr.write("没找到任何匹配的日志文件：%s\n" % ", ".join(args.input))
        return 2

    lines = []
    if files:
        for f in files:
            try:
                lines.extend(read_lines(f, args.encoding, args.max_lines))
            except Exception as ex:
                sys.stderr.write("读取失败 %s: %s\n" % (f, ex))
    else:
        if sys.stdin.isatty():
            sys.stderr.write("没有 --input，也没有标准输入。用 --help 看用法。\n")
            return 2
        data = sys.stdin.read()
        lines = data.splitlines()

    if not lines:
        sys.stderr.write("日志是空的，没什么可分析。\n")
        return 2

    if args.level.strip().upper() == "ALL":
        levels = set(LEVEL_ORDER)
    else:
        levels = {norm_level(x) for x in args.level.split(",") if x.strip()}
        levels.discard("UNKNOWN")
        if not levels:
            levels = set(BAD_LEVELS)

    since = parse_ts(args.since) if args.since else None
    until = parse_ts(args.until) if args.until else None
    if args.since and since is None:
        sys.stderr.write("--since 时间格式认不出来：%s\n" % args.since)
        return 2
    if args.until and until is None:
        sys.stderr.write("--until 时间格式认不出来：%s\n" % args.until)
        return 2

    entries = parse_stream(lines, merge_stack=not args.no_merge_stack)
    res = analyze(entries, levels, max(1, args.top), args.bucket, args.spike_k, since, until)

    if args.json:
        print(json.dumps(to_json(res, files or ["<stdin>"], args.bucket),
                         ensure_ascii=False, indent=2))
        return 0

    if args.signature_only:
        if not res["signatures"]:
            print("未命中内置故障特征。")
        for s in res["signatures"]:
            print("[%s] %s  影响 %d 条 / %d 个模板" % (s["severity"], s["name"], s["count"], s["templates"]))
            print("     方向: %s" % s["hint"])
        return 0

    print_report(res, files or ["<stdin>"], args.bucket, args.top,
                 show_timeline=not args.no_timeline)
    return 0


if __name__ == "__main__":
    sys.exit(main())
