#!/usr/bin/env python3
"""初期化コマンドの処理（基本設計書 9.3）。init Skill から呼ぶ。

使い方:
  python3 -I -S init.py                    予定を表示する（何も書き込まない）
  python3 -I -S init.py --apply 確認番号   表示した予定のとおりに書き込む

置くもの（templates/ のひな形。build.py がルールから作る）:
  .claude/settings.json       禁止ルール、キットの有効化、公式の security-guidance プラグインを止める指定
  .claude/security-kit.json   キットの動かし方（新しく作るときは警告モード）
  CLAUDE.md                   指摘を受けたときの振る舞い（印で囲んだキットの部分だけを足す・置き換える）
  AGENTS.md                   ほかの AI 向けのルールとレビューの基準（同上）

決まり:
- すでにあるファイルは、キットの部分だけを足すか置き換える。ほかの部分は変えない。
- 読めない・形が想定と違う・シンボリックリンクのファイルは変えない。
- 予定を見せてから書き込む。確認番号で、見せた予定と書き込む内容が同じであることを確かめる。
"""
import difflib
import hashlib
import json
import os
import subprocess
import sys
import tempfile

PLUGIN_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATES = os.path.join(PLUGIN_ROOT, "templates")
SELF = os.path.abspath(__file__)

# CLAUDE.md と AGENTS.md の、キットが書く部分の印（build.py と同じ値にする）
BEGIN = "<!-- security-kit:begin -->"
END = "<!-- security-kit:end -->"

SETTINGS = os.path.join(".claude", "settings.json")
CONFIG = os.path.join(".claude", "security-kit.json")
MAX_SIZE = 1_000_000


class Change:
    """1つのファイルへの変更の予定。"""

    def __init__(self, rel, action, old=None, new=None, note=""):
        self.rel = rel
        self.action = action  # create / append / update / same / skip
        self.old = old
        self.new = new
        self.note = note

    @property
    def writes(self):
        return self.action in ("create", "append", "update")


ACTION_LABEL = {"create": "作る", "append": "キットの部分を足す", "update": "変える", "same": "変更なし",
                "skip": "変えない"}


def project_root():
    """git で管理しているなら、その一番上。そうでなければ今いるフォルダ。"""
    try:
        r = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and r.stdout.strip():
            return os.path.realpath(r.stdout.strip()), True
    except (OSError, subprocess.SubprocessError):
        pass
    return os.path.realpath(os.getcwd()), False


def unsafe_reason(root, rel):
    """書き込んではいけない理由。問題が無ければ None。"""
    path = root
    for part in rel.split(os.sep):
        path = os.path.join(path, part)
        if os.path.islink(path):
            return "シンボリックリンクのため（リンク先のファイルを書き換えないよう）"
    full = os.path.join(root, rel)
    if os.path.exists(full) and not os.path.isfile(full):
        return "ファイルではないため"
    if os.path.isfile(full) and os.path.getsize(full) > MAX_SIZE:
        return "大きすぎるため"
    return None


def read_text(root, rel):
    try:
        with open(os.path.join(root, rel), encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return None


def template(name):
    with open(os.path.join(TEMPLATES, name), encoding="utf-8") as f:
        return f.read()


def dump_json(data):
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"


# ---------------------------------------------------------------- ファイルごとの予定

def plan_settings(root):
    tpl = json.loads(template("settings.json"))
    deny = tpl["permissions"]["deny"]
    cur_text = read_text(root, SETTINGS)
    if cur_text is None:
        return Change(SETTINGS, "create", None, dump_json(tpl),
                      "禁止ルール %d 件、security-kit を有効にする、公式の security-guidance を止める" % len(deny))
    try:
        cur = json.loads(cur_text)
    except ValueError:
        return Change(SETTINGS, "skip", note="JSON として読めないため")
    if not isinstance(cur, dict):
        return Change(SETTINGS, "skip", note="中身の形が想定と違うため")

    out = json.loads(json.dumps(cur))
    perms = out.setdefault("permissions", {})
    if not isinstance(perms, dict) or not isinstance(perms.setdefault("deny", []), list):
        return Change(SETTINGS, "skip", note="permissions の形が想定と違うため")
    added = [d for d in deny if d not in perms["deny"]]
    perms["deny"] += added
    notes = ["禁止ルールを %d 件足す" % len(added)] if added else []
    for key in ("enabledPlugins", "extraKnownMarketplaces"):
        section = out.setdefault(key, {})
        if not isinstance(section, dict):
            return Change(SETTINGS, "skip", note="%s の形が想定と違うため" % key)
        for k, v in tpl[key].items():
            if section.get(k) != v:
                section[k] = v
                notes.append({
                    "enabledPlugins": "%s を%s" % (k.split("@")[0], "有効にする" if v else "止める"),
                    "extraKnownMarketplaces": "キットの配布元（%s）を登録する" % k,
                }[key])
    if out == cur:
        return Change(SETTINGS, "same")
    return Change(SETTINGS, "update", cur_text, dump_json(out), "、".join(notes) + "。ほかの設定はそのまま")


def plan_config(root):
    tpl = json.loads(template("security-kit.json"))
    cur_text = read_text(root, CONFIG)
    if cur_text is None:
        return Change(CONFIG, "create", None, dump_json(tpl), "警告モードで作る。止めるルールも、止めずに伝える")
    try:
        cur = json.loads(cur_text)
    except ValueError:
        return Change(CONFIG, "skip", note="JSON として読めないため")
    if not isinstance(cur, dict):
        return Change(CONFIG, "skip", note="中身の形が想定と違うため")

    # 利用者が決めた値（モード、除外、例外など）は変えない。足りない項目を足し、キットの版だけを新しくする
    out = dict(cur)
    notes = []
    missing = [k for k in tpl if k not in out]
    for k in missing:
        out[k] = tpl[k]
    if missing:
        notes.append("足りない項目（%s）を足す" % "、".join(missing))
    if out.get("kit_version") != tpl["kit_version"]:
        notes.append("キットの版を %s から %s にする" % (cur.get("kit_version"), tpl["kit_version"]))
        out["kit_version"] = tpl["kit_version"]
    if out == cur:
        return Change(CONFIG, "same")
    return Change(CONFIG, "update", cur_text, dump_json(out), "、".join(notes) + "。モード・除外・例外はそのまま")


# CLAUDE.md と AGENTS.md に書く、キットの部分の中身（予定の表示に使う）
BLOCK_CONTENT = {
    "CLAUDE.md": "指摘を受けたときの振る舞い（説明してから直す、など）と、止めるルール",
    "AGENTS.md": "Claude 以外の AI（Codex など）向けの、レビューの基準と、有効なルールすべての表",
}


def plan_block(root, candidates, name):
    """印で囲んだキットの部分を、足すか置き換える。"""
    texts = {rel: read_text(root, rel) for rel in candidates}
    existing = [rel for rel in candidates if texts[rel] is not None]
    marked = [rel for rel in existing if BEGIN in texts[rel] or END in texts[rel]]
    rel = (marked or existing or candidates)[0]
    block = template(name)
    cur = texts[rel]
    if cur is None:
        return Change(rel, "create", None, block, "キットの部分だけのファイル。中身: " + BLOCK_CONTENT[name])

    b, e = cur.count(BEGIN), cur.count(END)
    if b == 0 and e == 0:
        sep = "" if cur == "" else ("\n" if cur.endswith("\n") else "\n\n")
        return Change(rel, "append", cur, cur + sep + block,
                      "末尾に足す。ほかの部分は変えない。中身: " + BLOCK_CONTENT[name])
    if b == 1 and e == 1 and cur.index(BEGIN) < cur.index(END):
        i = cur.index(BEGIN)
        j = cur.index(END) + len(END)
        if cur[j:j + 1] == "\n":
            j += 1
        new = cur[:i] + block + cur[j:]
        if new == cur:
            return Change(rel, "same")
        return Change(rel, "update", cur, new, "キットの部分を新しくする。ほかの部分は変えない")
    return Change(rel, "skip", note="キットの部分の印（%s と %s）がそろっていないため" % (BEGIN, END))


def make_plan(root):
    changes = [
        plan_settings(root),
        plan_config(root),
        plan_block(root, ["CLAUDE.md", os.path.join(".claude", "CLAUDE.md")], "CLAUDE.md"),
        plan_block(root, ["AGENTS.md"], "AGENTS.md"),
    ]
    for c in changes:
        reason = unsafe_reason(root, c.rel)
        if reason and c.action != "skip":
            c.action, c.old, c.new, c.note = "skip", None, None, reason
    return changes


def token(changes):
    """予定の確認番号。見せた予定と、書き込むときの予定が同じかを確かめる。"""
    h = hashlib.sha256()
    for c in changes:
        if c.writes:
            for part in (c.rel, c.action, c.old or "", c.new):
                h.update(part.encode("utf-8") + b"\x00")
    return h.hexdigest()[:8]


# ---------------------------------------------------------------- 表示と書き込み

def show_plan(root, in_git, changes):
    lines = ["[security-kit] 初期化の予定（まだ何も書き込んでいません）",
             "プロジェクト: " + os.path.basename(root)]
    if not in_git:
        lines.append("注意: git で管理していないフォルダです。今いるフォルダに置きます。")
    lines.append("")
    for c in changes:
        note = "（%s）" % c.note if c.note else ""
        lines.append("- %s: %s%s" % (c.rel, ACTION_LABEL[c.action], note))

    diffs = []
    for c in changes:
        if c.action in ("append", "update"):
            d = difflib.unified_diff(c.old.splitlines(), c.new.splitlines(), "a/" + c.rel, "b/" + c.rel,
                                     n=2, lineterm="")
            diffs.append("\n".join(d))
        elif c.action == "create" and c.rel.endswith(".json"):
            diffs.append("新しく作る %s:\n%s" % (c.rel, c.new.rstrip("\n")))
    if diffs:
        lines += ["", "中身（すでにあるファイルは差分）:", "```diff"] + diffs + ["```"]

    if any(c.writes for c in changes):
        lines += ["", "書き込むコマンド（確認番号 %s）:" % token(changes),
                  'python3 -I -S "%s" --apply %s' % (SELF, token(changes))]
    else:
        lines += ["", "書き込むものはありません。"]
    if any(c.action == "skip" for c in changes):
        lines.append("「変えない」のファイルは、理由を確かめて利用者が直してください。")
    return "\n".join(lines)


def write_atomic(path, text):
    """途中で止まっても壊れたファイルが残らないよう、別名で書いてから置き換える。"""
    mode = os.stat(path).st_mode & 0o777 if os.path.exists(path) else 0o644
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".security-kit-init-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def apply(root, changes):
    done = []
    for c in changes:
        if not c.writes:
            continue
        if unsafe_reason(root, c.rel):  # 予定を作った後にリンクが置かれた場合に備えて、もう一度確かめる
            continue
        path = os.path.join(root, c.rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        write_atomic(path, c.new)
        done.append(c)

    lines = ["[security-kit] 初期化しました", ""]
    lines += ["- %s: %s" % (c.rel, ACTION_LABEL[c.action]) for c in done]
    lines += ["", "次にすること:",
              "- 変わったファイルを確かめ、PR でレビューを受けてからコミットする（.claude/ の変更はレビューが必要な対象です）。",
              "- Claude Code を起動し直す（キットの有効化と、公式プラグインを止める指定を読み込むため）。"]
    if any(c.rel == CONFIG and c.action == "create" for c in done):
        lines.append("- 警告モード（止めずに伝える）で始まります。止める動きにするときは、%s の mode を enforce にする。" % CONFIG)
    lines.append("- コミット前チェック、PR 時のチェック、新しすぎるパッケージを入れない設定（cooldown）は、キットの次の版で足します。")
    return "\n".join(lines)


def main(argv):
    root, in_git = project_root()
    changes = make_plan(root)
    if argv[:1] == ["--apply"]:
        if len(argv) != 2 or argv[1] != token(changes) or not any(c.writes for c in changes):
            print("[security-kit] 確認番号が予定と合いません。予定を表示した後に、ファイルかキットが変わった可能性があります。"
                  "何も書き込んでいません。もう一度、予定を表示してください。")
            return 1
        print(apply(root, changes))
        return 0
    if argv:
        print("使い方: init.py（予定を表示する） / init.py --apply 確認番号（書き込む）")
        return 1
    print(show_plan(root, in_git, changes))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
