"""フックで共通に使う処理（設定・ルール・状態・記録・通知文）。"""
import fcntl
import fnmatch
import hashlib
import json
import os
import re
import time

SEVERITY_LABEL = {"block": "止める", "warn": "警告", "advise": "助言"}

# キット独自の検査と AI レビューで使う、除外の印
ALLOW_MARK = "security-kit:allow"

# scripts/kit/core.py から見て3つ上がプラグインの場所
PLUGIN_ROOT = os.environ.get("CLAUDE_PLUGIN_ROOT") or os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

EXPLAIN_FIRST = "→ 黙って直さず、利用者に「ひとこと：〜」の形で理由と直し方を伝えてから修正してください。"


def which(name):
    """PATH からコマンドを探す。見つからなければ None。"""
    for d in os.environ.get("PATH", "").split(os.pathsep):
        p = os.path.join(d, name)
        if d and os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def state_dir():
    """各自の PC でのデータの置き場所（データ設計書 2章）。"""
    return os.environ.get("CLAUDE_PLUGIN_DATA") or os.path.join(
        os.path.expanduser("~"), ".local", "state", "security-kit"
    )


def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


class FileRef:
    """検査の対象になる1つのファイル。"""

    def __init__(self, ctx, path):
        self.abs_path = os.path.realpath(path if os.path.isabs(path) else os.path.join(ctx.root, path))
        self.in_project = (self.abs_path + os.sep).startswith(ctx.root + os.sep)
        if self.in_project:
            self.rel_path = os.path.relpath(self.abs_path, ctx.root)
        else:
            # プロジェクトの外のファイルは、PC のユーザー名が残らないよう ~ に置き換えて記録する
            home = os.path.expanduser("~")
            inside_home = self.abs_path.startswith(home + os.sep)
            self.rel_path = "~" + self.abs_path[len(home):] if inside_home else self.abs_path
        self.excluded = self.in_project and any(fnmatch.fnmatch(self.rel_path, pat) for pat in ctx.excludes)


class Context:
    """1回のフック呼び出しの情報をまとめたもの。"""

    def __init__(self, data):
        self.data = data
        self.tool = data.get("tool_name")
        self.tool_input = data.get("tool_input") or {}
        self.session = re.sub(r"[^A-Za-z0-9_-]", "", str(data.get("session_id") or ""))[:64] or "nosession"
        self.root = os.path.realpath(os.environ.get("CLAUDE_PROJECT_DIR") or data.get("cwd") or os.getcwd())

        self.config = load_json(os.path.join(self.root, ".claude", "security-kit.json"), {})
        if not isinstance(self.config, dict):
            self.config = {}
        self.mode = "warn" if self.config.get("mode") == "warn" else "enforce"
        self.excludes = [p for p in self.config.get("exclude") or [] if isinstance(p, str)]
        self.rules = load_json(os.path.join(PLUGIN_ROOT, "data", "rules.json"), {"rules": {}, "tool_map": {}})

        path = self.tool_input.get("file_path")
        self.target = FileRef(self, path) if path else None

    def file(self, path):
        return FileRef(self, path)

    def rule(self, rule_id):
        return self.rules.get("rules", {}).get(rule_id)

    def rule_for(self, tool, code):
        """検査ツールの番号から、自社のルール ID とルールを引く。無ければ (None, None)。"""
        table = self.rules.get("tool_map", {}).get(tool, {})
        rule_id = table.get(code) or table.get("*")
        return rule_id, self.rule(rule_id)

    def ai(self, key, default):
        """AI レビューの設定（プロジェクトの設定ファイルの ai_review）。"""
        section = self.config.get("ai_review")
        value = section.get(key, default) if isinstance(section, dict) else default
        return value if isinstance(value, type(default)) else default


def fingerprint(*parts):
    """指摘の指紋（データ設計書 8.3）。元に戻せない短い文字列。"""
    return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()[:16]


def read_lines(path, limit=2_000_000):
    """ファイルを行ごとに読む。大きすぎる・読めないときは空。"""
    try:
        if os.path.getsize(path) > limit:
            return []
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read().splitlines()
    except OSError:
        return []


def open_state(ctx):
    """セッションの状態を、ほかのフックと重ならないよう鍵をかけて開く。"""
    d = os.path.join(state_dir(), "sessions")
    os.makedirs(d, exist_ok=True)
    f = open(os.path.join(d, ctx.session + ".json"), "a+", encoding="utf-8")
    fcntl.flock(f, fcntl.LOCK_EX)
    f.seek(0)
    try:
        state = json.load(f)
    except ValueError:
        state = {}
    return f, state if isinstance(state, dict) else {}


def save_state(f, state):
    f.seek(0)
    f.truncate()
    json.dump(state, f, ensure_ascii=False)
    f.close()  # 閉じると鍵も外れる


def sweep_old_sessions(days=7):
    """古いセッションの状態を消す（データ設計書 7章）。"""
    d = os.path.join(state_dir(), "sessions")
    limit = time.time() - days * 86400
    try:
        for name in os.listdir(d):
            p = os.path.join(d, name)
            if os.path.getmtime(p) < limit:
                os.remove(p)
    except OSError:
        pass


def record(ctx, file="", **fields):
    """先輩役の記録を1行書く（データ設計書 8.1）。コードの中身は書かない。"""
    row = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "kit": ctx.rules.get("kit_version", ""),
        "project": os.path.basename(ctx.root),
        "session": ctx.session,
        "file": file,
        "mode": ctx.mode,
        "outcome": "unknown",
    }
    row.update(fields)
    d = os.path.join(state_dir(), "log")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, time.strftime("%Y-%m") + ".jsonl"), "a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


def notice(head_label, rule_id, rule, where, extra_lines=()):
    """Claude への通知文（基本設計書 3.6）。

    入れてよいのは、ルールの文章・ファイル名・行番号だけ。
    検査対象のコードの中身は入れない（NFR-13）。
    """
    lines = [
        "[security-kit] %s %s %s" % (head_label, rule_id, rule["name"]),
        "場所: " + where,
        "何が危ないか: " + rule["what"],
        "なぜ危ないか: " + rule["why"],
        "どう直すか: " + rule["fix"],
    ]
    return "\n".join(lines + list(extra_lines))


def where_text(rel_path, line_numbers):
    rows = sorted({n for n in line_numbers if n})
    return rel_path + (" " + "、".join("%d行目" % n for n in rows) if rows else "")
