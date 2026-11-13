#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["pyyaml>=6.0.2,<7"]
#
# [tool.uv]
# exclude-newer = "2026-11-07T00:00:00Z"
# ///
"""ルールの YAML から、キットが使うファイルを作る（基本設計書 4.1、データ設計書 3.7）。

使い方（キットのリポジトリの一番上で）:
  uv run --locked build/build.py           検査してから生成する
  uv run --locked build/build.py --check   生成し直して差が出ないかを確かめる（CI 用）

生成するもの:
  plugins/security-kit/data/rules.json        フックが読むルールデータ
  plugins/security-kit/skills/senpai/rules/   ルールごとの説明（Skill の資料）
  tests/rules/examples.json                   違反例と正常例（ルールのテストが読む）

YAML を読むのは、このスクリプトだけである。読み込みには安全な方法（SafeLoader）だけを使う。
YAML の読み込みに使う PyYAML は、build.py.lock で版とハッシュを固定している。
"""
import datetime
import json
import os
import re
import sys

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(ROOT, "rules")
PLUGIN = os.path.join(ROOT, "plugins", "security-kit")
OUT_RULES_JSON = os.path.join(PLUGIN, "data", "rules.json")
OUT_SKILL_RULES = os.path.join(PLUGIN, "skills", "senpai", "rules")
OUT_EXAMPLES = os.path.join(ROOT, "tests", "rules", "examples.json")

SCHEMA_VERSION = 1
REVIEW_MONTHS = 6  # 最終見直し日からこの月数を過ぎたら警告する（FR-53）

GENERATED_NOTE = "<!-- build.py が rules/%s.yaml から生成。手で編集しない -->"

SEVERITY = {"block": "止める", "warn": "警告", "advise": "助言"}
DOMAIN = {
    "code": "コード", "api": "API", "ai": "AI・LLM・MCP", "dependency": "依存ライブラリ",
    "secret": "秘密情報", "config": "構成ファイル", "workflow": "GitHub Actions のワークフロー", "data": "データ",
}
KINDS = ("own", "mapped")
STATUSES = ("active", "draft", "retired")
CONFIDENCE = ("high", "medium", "low")
LEVELS = (1, 2)

# 検査ツールの番号で対応付ける検出方法
TOOL_IDS = ("gitleaks", "ruff", "semgrep", "bandit", "trivy", "osv", "zizmor")
# 違反例で確かめられる検出方法（違反例と正常例が必須になる）
TESTABLE = ("kit", "ruff", "semgrep", "bandit")

TOOL_LABEL = {
    "gitleaks": "gitleaks（作業の区切り・コミット前・PR 時）",
    "ruff": "Ruff（書いた直後。Python）",
    "semgrep": "Semgrep（作業の区切り・PR 時）",
    "bandit": "Bandit（PR 時）",
    "trivy": "Trivy（作業の区切り・PR 時）",
    "osv": "osv-scanner（PR 時）",
    "zizmor": "zizmor（PR 時）",
}
FENCE_LANG = {
    ".py": "python", ".js": "javascript", ".jsx": "jsx", ".ts": "typescript", ".tsx": "tsx",
    ".mjs": "javascript", ".cjs": "javascript", ".go": "go", ".yml": "yaml", ".yaml": "yaml",
    ".html": "html", ".htm": "html", ".vue": "vue", ".svelte": "svelte", ".json": "json",
}

RULE_KEYS = {
    "id", "name", "kind", "severity", "level", "domain", "status", "references", "message",
    "examples", "detection", "confidence", "owner", "last_reviewed", "feedback_applied",
}
DETECTION_KEYS = {
    "kit": {"tool", "id", "paths", "pattern"},
    "kit-secret": {"tool", "patterns"},
    "ai-review": {"tool", "categories"},
    "settings": {"tool", "deny"},
    "process": {"tool", "note"},
}
for _t in TOOL_IDS:
    DETECTION_KEYS[_t] = {"tool", "ids"}


class BuildError(Exception):
    pass


class UniqueKeyLoader(yaml.SafeLoader):
    """同じ項目が2回書かれていたら誤りにする SafeLoader（標準では後の値で黙って上書きされる）。"""


def _construct_mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise yaml.constructor.ConstructorError(
                None, None, "項目 %r が2回書かれている" % (key,), key_node.start_mark)
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


# ---------------------------------------------------------------- 読み込みと検査

def load_rules():
    files = sorted(n for n in os.listdir(RULES_DIR) if n.endswith((".yaml", ".yml")))
    if not files:
        raise BuildError("rules/ にルールがありません")
    rules, errors = [], []
    for name in files:
        path = os.path.join(RULES_DIR, name)
        try:
            with open(path, encoding="utf-8") as f:
                data = yaml.load(f, Loader=UniqueKeyLoader)  # noqa: S506  安全な読み込み方（SafeLoader の派生）
        except (OSError, yaml.YAMLError) as e:
            errors.append("%s: 読み込めない（%s）" % (name, e))
            continue
        errs = check_rule(name, data)
        if errs:
            errors += ["%s: %s" % (name, e) for e in errs]
        else:
            rules.append(normalize(data))
    errors += check_across(rules)
    if errors:
        raise BuildError("ルールに誤りがあります\n" + "\n".join("  - " + e for e in errors))
    return rules


def _text(value):
    return isinstance(value, str) and value.strip() != "" and "\n" not in value.strip()


def _date(value):
    if isinstance(value, datetime.date):
        return value
    if isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        try:
            return datetime.date.fromisoformat(value)
        except ValueError:
            return None
    return None


def _str_list(value, allow_empty=False):
    return isinstance(value, list) and (allow_empty or value) and all(_text(v) for v in value)


def check_rule(filename, r):
    """1つのルールの検査。誤りの一覧を返す。"""
    if not isinstance(r, dict):
        return ["ルールの形になっていない"]
    errs = []
    unknown = sorted(set(r) - RULE_KEYS)
    if unknown:
        errs.append("知らない項目がある: %s" % ", ".join(unknown))

    rid = r.get("id")
    if not (isinstance(rid, str) and re.fullmatch(r"R-\d{3}", rid)):
        errs.append("id は R- と3桁の数字にする")
    elif os.path.splitext(filename)[0] != rid:
        errs.append("ファイル名と id が合わない")

    for key, choices in (("kind", KINDS), ("severity", tuple(SEVERITY)), ("domain", tuple(DOMAIN)),
                         ("status", STATUSES), ("confidence", CONFIDENCE), ("level", LEVELS)):
        if r.get(key) not in choices:
            errs.append("%s は %s のどれかにする" % (key, " / ".join(map(str, choices))))
    for key in ("name", "owner"):
        if not _text(r.get(key)):
            errs.append("%s が無い" % key)
    if not _str_list(r.get("references")):
        errs.append("references（根拠）が無い")
    if _date(r.get("last_reviewed")) is None:
        errs.append("last_reviewed は YYYY-MM-DD の日付にする")
    if "feedback_applied" in r and _date(r.get("feedback_applied")) is None:
        errs.append("feedback_applied は YYYY-MM-DD の日付にする")
    if r.get("severity") == "block" and r.get("confidence") != "high":
        errs.append("「止める」のルールは confidence を high にする（誤検知がほぼ無いものだけを止める）")

    msg = r.get("message")
    # 対応付けのルールでは message は任意（データ設計書 3.2）だが、フックが通知文に使うため、
    # 有効にするルールには必ず書く
    if msg is not None or r.get("kind") == "own" or r.get("status") == "active":
        if not isinstance(msg, dict) or set(msg) != {"what", "why", "fix"} or not all(_text(v) for v in msg.values()):
            errs.append("message は what・why・fix の3つを1文ずつ書く")

    detection = r.get("detection")
    if not isinstance(detection, list) or not detection:
        errs.append("detection（検出方法）が無い")
        detection = []
    for i, d in enumerate(detection, 1):
        errs += ["detection の%d番目: %s" % (i, e) for e in check_detection(d)]

    if r.get("kind") == "own" or "examples" in r:
        errs += check_examples(r.get("examples"), detection)
    return errs


def check_detection(d):
    if not isinstance(d, dict) or d.get("tool") not in DETECTION_KEYS:
        return ["tool は %s のどれかにする" % " / ".join(DETECTION_KEYS)]
    tool = d["tool"]
    errs = []
    if set(d) != DETECTION_KEYS[tool]:
        errs.append("%s には %s を書く" % (tool, "・".join(sorted(DETECTION_KEYS[tool] - {"tool"}))))
        return errs
    if tool in TOOL_IDS and not _str_list(d["ids"]):
        errs.append("ids に検査ツールの番号を書く")
    elif tool == "kit":
        if not (isinstance(d["id"], str) and re.fullmatch(r"K-\d{3}", d["id"])):
            errs.append("id は K- と3桁の数字にする")
        if not _str_list(d["paths"]):
            errs.append("paths に対象のファイルの形を書く")
        errs += _check_regex(d["pattern"], d.get("id"))
    elif tool == "kit-secret":
        if not isinstance(d["patterns"], list) or not d["patterns"]:
            errs.append("patterns に種類と正規表現を書く")
        else:
            for p in d["patterns"]:
                if not isinstance(p, dict) or set(p) != {"id", "pattern"} or not _text(p.get("id")):
                    errs.append("patterns の各項目は id と pattern にする")
                else:
                    errs += _check_regex(p["pattern"], p["id"])
    elif tool == "ai-review":
        if not _str_list(d["categories"]) or not all(re.fullmatch(r"[a-z][a-z0-9-]*", c) for c in d["categories"]):
            errs.append("categories は英小文字とハイフンの名前にする")
    elif tool == "settings" and not _str_list(d["deny"]):
        errs.append("deny に禁止ルールを書く")
    elif tool == "process" and not _text(d["note"]):
        errs.append("note に守り方を1文で書く")
    return errs


def _check_regex(pattern, label):
    if not isinstance(pattern, str) or not pattern:
        return ["%s の正規表現が無い" % label]
    try:
        re.compile(pattern)
    except re.error as e:
        return ["%s の正規表現に誤りがある（%s）" % (label, e)]
    return []


def check_examples(ex, detection):
    if not isinstance(ex, dict) or not {"bad", "good"} <= set(ex) or set(ex) - {"bad", "good", "note"}:
        return ["examples は bad・good（と任意の note）で書く"]
    errs = []
    for side in ("bad", "good"):
        items = ex[side]
        if not isinstance(items, list):
            errs.append("examples.%s は一覧にする" % side)
            continue
        for item in items:
            if (not isinstance(item, dict) or set(item) - {"file", "code", "note"}
                    or not _text(item.get("file")) or not isinstance(item.get("code"), str)
                    or ("note" in item and not _text(item["note"]))):
                errs.append("examples.%s の各項目は file・code（と任意の note）にする" % side)
            elif item["file"].startswith("/") or ".." in item["file"].split("/"):
                errs.append("examples の file はリポジトリの中の相対パスにする")
    testable = any(d.get("tool") in TESTABLE for d in detection if isinstance(d, dict))
    if testable and not errs and (not ex["bad"] or not ex["good"]):
        errs.append("検査ツールで見つけるルールには、違反例と正常例を1つ以上書く（テストになる）")
    if "note" in ex and not _text(ex["note"]):
        errs.append("examples.note は1文で書く")
    return errs


def check_across(rules):
    """ルールをまたがる検査（重複と、対応付けの衝突）。"""
    errs = []
    seen = {}
    owners = {}  # (表の名前, 番号) → ルール ID
    for r in rules:
        if r["id"] in seen:
            errs.append("%s: id が重複している" % r["id"])
        seen[r["id"]] = True
        if r["status"] == "retired":
            continue
        for d in r["detection"]:
            for key in _map_keys(d):
                if key in owners and owners[key] != r["id"]:
                    errs.append("%s: %s %s はすでに %s に対応付けられている" % (r["id"], key[0], key[1], owners[key]))
                owners[key] = r["id"]
    return errs


def _map_keys(d):
    tool = d["tool"]
    if tool in TOOL_IDS:
        return [(tool, i) for i in d["ids"]]
    if tool == "kit":
        return [("kit", d["id"])]
    if tool == "kit-secret":
        return [("kit-secret", "*")] + [("kit-secret-pattern", p["id"]) for p in d["patterns"]]
    if tool == "ai-review":
        return [("ai-review", c) for c in d["categories"]]
    return []


def normalize(r):
    r = dict(r)
    r["last_reviewed"] = _date(r["last_reviewed"]).isoformat()
    if "feedback_applied" in r:
        r["feedback_applied"] = _date(r["feedback_applied"]).isoformat()
    r["examples"] = r.get("examples") or {"bad": [], "good": []}
    return r


def stale_warnings(rules, today):
    limit = today - datetime.timedelta(days=REVIEW_MONTHS * 30)
    return ["%s は最終見直し日（%s）から%dか月を過ぎている" % (r["id"], r["last_reviewed"], REVIEW_MONTHS)
            for r in rules if r["status"] == "active" and datetime.date.fromisoformat(r["last_reviewed"]) < limit]


# ---------------------------------------------------------------- 生成

def kit_version():
    with open(os.path.join(PLUGIN, ".claude-plugin", "plugin.json"), encoding="utf-8") as f:
        return json.load(f)["version"]


def build_rules_json(active):
    out = {
        "schema_version": SCHEMA_VERSION,
        "kit_version": kit_version(),
        "rules": {},
        "tool_map": {},
        "review_categories": {},
        "secret_patterns": [],
        "kit_checks": [],
    }
    for r in active:
        m = r["message"]
        out["rules"][r["id"]] = {"name": r["name"], "severity": r["severity"],
                                 "what": m["what"], "why": m["why"], "fix": m["fix"]}
        for d in r["detection"]:
            tool = d["tool"]
            if tool in TOOL_IDS:
                for i in d["ids"]:
                    out["tool_map"].setdefault(tool, {})[i] = r["id"]
            elif tool == "kit":
                out["tool_map"].setdefault("kit", {})[d["id"]] = r["id"]
                out["kit_checks"].append({"id": d["id"], "paths": d["paths"], "pattern": d["pattern"]})
            elif tool == "kit-secret":
                out["tool_map"].setdefault("kit-secret", {})["*"] = r["id"]
                out["secret_patterns"] += [{"id": p["id"], "pattern": p["pattern"]} for p in d["patterns"]]
            elif tool == "ai-review":
                for c in d["categories"]:
                    out["review_categories"][c] = r["id"]
    out["tool_map"] = {t: dict(sorted(m.items())) for t, m in sorted(out["tool_map"].items())}
    out["review_categories"] = dict(sorted(out["review_categories"].items()))
    out["kit_checks"].sort(key=lambda c: c["id"])
    return _json(out)


def build_examples_json(active):
    out = {}
    for r in active:
        tools = sorted({d["tool"] for d in r["detection"]})
        ex = r["examples"]
        if ex["bad"] or ex["good"]:
            out[r["id"]] = {
                "tools": tools,
                "bad": [{"file": e["file"], "code": e["code"]} for e in ex["bad"]],
                "good": [{"file": e["file"], "code": e["code"]} for e in ex["good"]],
            }
    return _json(out)


def _json(data):
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"


def _fence(code, filename):
    lang = FENCE_LANG.get(os.path.splitext(filename)[1], "")
    fence = "~~~~" if "```" in code else "```"
    return "%s%s\n%s%s%s" % (fence, lang, code, "" if code.endswith("\n") else "\n", fence)


def _detection_lines(d):
    tool = d["tool"]
    if tool in TOOL_IDS:
        ids = "全ルール" if d["ids"] == ["*"] else "、".join(d["ids"])
        return ["%s: %s" % (TOOL_LABEL[tool], ids)]
    if tool == "kit":
        return ["キット独自の簡易チェック %s（書いた直後。対象: %s）" % (d["id"], "、".join("`%s`" % p for p in d["paths"]))]
    if tool == "kit-secret":
        return ["キット内蔵の判定（書く前。形だけで秘密情報とわかるもの %d 種類）" % len(d["patterns"])]
    if tool == "ai-review":
        return ["AI レビュー（作業の区切り・コミットの直後）: 分類 %s" % "、".join("`%s`" % c for c in d["categories"])]
    if tool == "settings":
        return ["Claude Code の設定で止める: %s" % "、".join("`%s`" % x for x in d["deny"])]
    if tool == "process":
        return ["運用で守る: %s" % d["note"]]
    return []


def _exclude_mark(d):
    """検出方法ごとの、除外の印の説明（基本設計書 3.11）。"""
    tool = d["tool"]
    if tool in ("kit-secret", "gitleaks"):
        return "秘密情報の指摘: その行に `gitleaks:allow` と理由を書く。まとめて外すものは `.gitleaks.toml` に書く"
    if tool == "ruff":
        return "Ruff の指摘: その行に `# noqa: %s` と理由を書く" % d["ids"][0] + ("（番号は指摘されたもの）" if len(d["ids"]) > 1 else "")
    if tool in ("kit", "ai-review"):
        return "簡易チェック・AI レビューの指摘: その行に `security-kit:allow` と理由を書く"
    return None


def build_rule_doc(r):
    m = r["message"]
    lines = [
        GENERATED_NOTE % r["id"],
        "",
        "# %s %s" % (r["id"], r["name"]),
        "",
        "| 項目 | 内容 |",
        "|---|---|",
        "| 重大度 | %s |" % SEVERITY[r["severity"]],
        "| 領域 | %s |" % DOMAIN[r["domain"]],
        "| 根拠 | %s |" % "、".join(r["references"]),
        "",
        "## 伝え方",
        "",
        "- 何が危ないか: " + m["what"],
        "- なぜ危ないか: " + m["why"],
        "- どう直すか: " + m["fix"],
    ]
    ex = r["examples"]
    for side, title in (("bad", "違反例（指摘される書き方）"), ("good", "正常例（安全な書き方）")):
        if not ex[side]:
            continue
        lines += ["", "## " + title]
        for e in ex[side]:
            lines += ["", "`%s`%s" % (e["file"], "：" + e["note"] if e.get("note") else ""), "", _fence(e["code"], e["file"])]
    if ex.get("note"):
        lines += ["", "> " + ex["note"]]

    lines += ["", "## 見つけ方", ""]
    for d in r["detection"]:
        lines += ["- " + x for x in _detection_lines(d)]

    marks = []
    for d in r["detection"]:
        mark = _exclude_mark(d)
        if mark and mark not in marks:
            marks.append(mark)
    lines += ["", "## 当てはまらないとき", ""]
    if r["severity"] == "block" and not marks:
        lines.append("- 設定で止めるルールのため、印では外せない。外す必要があるときは、ルールの担当者に相談する。")
    else:
        lines += ["- " + x for x in marks]
        lines.append("- 印は、利用者が当てはまらないと判断したときだけ付ける。AI が自分の判断で付けてはいけない。印の追加は PR でレビューされる。")
        lines.append("- ルールそのものを一時的に外すときは、プロジェクトの `.claude/security-kit.json` に期限つきの例外を書き、PR で承認を受ける。")
    return "\n".join(lines) + "\n"


def build_index(active):
    lines = [
        "<!-- build.py が rules/*.yaml から生成。手で編集しない -->",
        "",
        "# ルールの一覧",
        "",
        "各ルールの詳しい説明は、同じフォルダの `R-NNN.md` にある。",
        "",
        "| ID | 名称 | 重大度 | 領域 |",
        "|---|---|---|---|",
    ]
    for r in active:
        lines.append("| [%s](%s.md) | %s | %s | %s |" % (r["id"], r["id"], r["name"], SEVERITY[r["severity"]], DOMAIN[r["domain"]]))
    return "\n".join(lines) + "\n"


def outputs(rules):
    """生成するファイルの一覧（場所 → 中身）。"""
    active = sorted((r for r in rules if r["status"] == "active"), key=lambda r: r["id"])
    files = {
        OUT_RULES_JSON: build_rules_json(active),
        OUT_EXAMPLES: build_examples_json(active),
        os.path.join(OUT_SKILL_RULES, "index.md"): build_index(active),
    }
    for r in active:
        files[os.path.join(OUT_SKILL_RULES, r["id"] + ".md")] = build_rule_doc(r)
    return files


def stale_files(files):
    """生成物のフォルダにある、もう生成しないファイル（廃止したルールの説明など）。"""
    if not os.path.isdir(OUT_SKILL_RULES):
        return []
    return sorted(p for p in (os.path.join(OUT_SKILL_RULES, n) for n in os.listdir(OUT_SKILL_RULES)) if p not in files)


def _read(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return None


def main(argv):
    check = "--check" in argv[1:]
    try:
        rules = load_rules()
    except BuildError as e:
        print(e, file=sys.stderr)
        return 1
    for w in stale_warnings(rules, datetime.date.today()):
        print("警告: " + w, file=sys.stderr)

    files = outputs(rules)
    stale = stale_files(files)
    rel = lambda p: os.path.relpath(p, ROOT)  # noqa: E731

    if check:
        diff = [rel(p) for p, text in sorted(files.items()) if _read(p) != text] + [rel(p) + "（不要）" for p in stale]
        if diff:
            print("生成物が元の YAML とずれています。uv run --locked build/build.py で作り直してください:", file=sys.stderr)
            for d in diff:
                print("  - " + d, file=sys.stderr)
            return 1
        print("生成物は元の YAML と一致しています（ルール %d 件）" % len(rules))
        return 0

    changed = 0
    for path, text in sorted(files.items()):
        if _read(path) != text:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write(text)
            changed += 1
            print("作成: " + rel(path))
    for path in stale:
        os.remove(path)
        print("削除: " + rel(path))
    active = sum(1 for r in rules if r["status"] == "active")
    print("ルール %d 件（有効 %d 件）。変更したファイル %d 件" % (len(rules), active, changed + len(stale)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
