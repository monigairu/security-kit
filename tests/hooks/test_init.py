"""初期化コマンドのスクリプトと、ひな形のテスト（基本設計書 9.3）。

実行: python3 -m unittest discover -s tests -v
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from .test_hooks import PLUGIN

INIT = os.path.join(PLUGIN, "scripts", "init.py")
TEMPLATES = os.path.join(PLUGIN, "templates")


def load_template(name):
    with open(os.path.join(TEMPLATES, name), encoding="utf-8") as f:
        return f.read()


class InitTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="kit-init-")
        self.project = os.path.join(self.tmp, "project")
        os.makedirs(self.project)
        subprocess.run(["git", "init", "-q", self.project], check=True)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_init(self, *args, code=0):
        env = {k: v for k, v in os.environ.items() if k not in ("CLAUDE_PLUGIN_ROOT", "CLAUDE_PROJECT_DIR")}
        r = subprocess.run([sys.executable, "-I", "-S", INIT, *args], capture_output=True, text=True,
                           env=env, cwd=self.project, timeout=60)
        self.assertEqual(r.returncode, code, r.stdout + r.stderr)
        return r.stdout

    def plan_and_apply(self):
        out = self.run_init()
        m = re.search(r"--apply ([0-9a-f]{8})", out)
        self.assertIsNotNone(m, out)
        return out, self.run_init("--apply", m.group(1))

    def path(self, rel):
        return os.path.join(self.project, rel)

    def write(self, rel, text):
        os.makedirs(os.path.dirname(self.path(rel)), exist_ok=True)
        with open(self.path(rel), "w", encoding="utf-8") as f:
            f.write(text)

    def read(self, rel):
        with open(self.path(rel), encoding="utf-8") as f:
            return f.read()

    def snapshot(self):
        out = {}
        for d, _, files in os.walk(self.project):
            if ".git" in d.split(os.sep):
                continue
            for n in files:
                p = os.path.join(d, n)
                with open(p, encoding="utf-8") as f:
                    out[os.path.relpath(p, self.project)] = f.read()
        return out

    # ------------------------------------------------------------ 予定と確認番号

    def test_予定を表示するだけでは何も書き込まない(self):
        out = self.run_init()
        self.assertIn("まだ何も書き込んでいません", out)
        self.assertEqual(self.snapshot(), {})

    def test_確認番号が合わなければ何も書き込まない(self):
        self.run_init()
        out = self.run_init("--apply", "00000000", code=1)
        self.assertIn("何も書き込んでいません", out)
        self.assertEqual(self.snapshot(), {})

    def test_予定を見せた後にファイルが変わったら書き込まない(self):
        token = re.search(r"--apply ([0-9a-f]{8})", self.run_init()).group(1)
        self.write("CLAUDE.md", "# 後から書いた\n")
        self.run_init("--apply", token, code=1)
        self.assertEqual(self.snapshot(), {"CLAUDE.md": "# 後から書いた\n"})

    # ------------------------------------------------------------ 新しいプロジェクト

    def test_新しいプロジェクトに4つのファイルを作る(self):
        _, out = self.plan_and_apply()
        self.assertIn("初期化しました", out)
        self.assertEqual(self.read(".claude/settings.json"), load_template("settings.json"))
        self.assertEqual(self.read(".claude/security-kit.json"), load_template("security-kit.json"))
        self.assertEqual(self.read("CLAUDE.md"), load_template("CLAUDE.md"))
        self.assertEqual(self.read("AGENTS.md"), load_template("AGENTS.md"))
        self.assertEqual(json.loads(self.read(".claude/security-kit.json"))["mode"], "warn")
        self.assertIn("警告モード", out)

    def test_2回目は変更なし(self):
        self.plan_and_apply()
        before = self.snapshot()
        out = self.run_init()
        self.assertIn("書き込むものはありません", out)
        self.assertNotIn("--apply", out)
        self.assertEqual(self.snapshot(), before)

    def test_一時ファイルを残さない(self):
        self.plan_and_apply()
        names = [n for _, _, files in os.walk(self.project) for n in files]
        self.assertFalse([n for n in names if n.startswith(".security-kit-init-")])

    # ------------------------------------------------------------ すでにある設定

    def test_すでにある設定は残して禁止ルールとキットの指定を足す(self):
        self.write(".claude/settings.json", json.dumps({
            "permissions": {"allow": ["Bash(pytest:*)"], "deny": ["Read(**/.env)", "Bash(rm:*)"]},
            "model": "sonnet",
            "enabledPlugins": {"security-guidance@claude-plugins-official": True, "other@market": True},
        }))
        self.plan_and_apply()
        s = json.loads(self.read(".claude/settings.json"))
        self.assertEqual(s["permissions"]["allow"], ["Bash(pytest:*)"])
        self.assertEqual(s["model"], "sonnet")
        deny = s["permissions"]["deny"]
        self.assertEqual(deny[:2], ["Read(**/.env)", "Bash(rm:*)"])
        self.assertEqual(deny.count("Read(**/.env)"), 1)
        for d in json.loads(load_template("settings.json"))["permissions"]["deny"]:
            self.assertIn(d, deny)
        self.assertIs(s["enabledPlugins"]["security-guidance@claude-plugins-official"], False)
        self.assertIs(s["enabledPlugins"]["security-kit@security-kit"], True)
        self.assertIs(s["enabledPlugins"]["other@market"], True)

    def test_読めない設定ファイルは変えない(self):
        self.write(".claude/settings.json", "{ 壊れた JSON")
        out, _ = self.plan_and_apply()
        self.assertIn("JSON として読めない", out)
        self.assertEqual(self.read(".claude/settings.json"), "{ 壊れた JSON")

    def test_形が想定と違う設定ファイルは変えない(self):
        self.write(".claude/settings.json", '{"permissions": {"deny": "Read(**/.env)"}}')
        out, _ = self.plan_and_apply()
        self.assertIn("permissions の形が想定と違う", out)
        self.assertEqual(self.read(".claude/settings.json"), '{"permissions": {"deny": "Read(**/.env)"}}')

    def test_キットの設定は利用者の決めた値を変えない(self):
        mine = {"kit_version": "0.0.1", "mode": "enforce", "exclude": ["tests/fixtures/**"],
                "exceptions": [{"id": "EX-2026-001", "rule": "R-012"}]}
        self.write(".claude/security-kit.json", json.dumps(mine))
        out, _ = self.plan_and_apply()
        self.assertIn("キットの版を 0.0.1 から", out)
        c = json.loads(self.read(".claude/security-kit.json"))
        self.assertEqual(c["mode"], "enforce")
        self.assertEqual(c["exclude"], mine["exclude"])
        self.assertEqual(c["exceptions"], mine["exceptions"])
        self.assertEqual(c["kit_version"], json.loads(load_template("security-kit.json"))["kit_version"])
        self.assertIn("ai_review", c)

    def test_シンボリックリンクの設定ファイルは変えない(self):
        target = os.path.join(self.tmp, "outside.json")
        with open(target, "w", encoding="utf-8") as f:
            f.write("{}")
        os.makedirs(self.path(".claude"))
        os.symlink(target, self.path(".claude/settings.json"))
        out, _ = self.plan_and_apply()
        self.assertIn("シンボリックリンク", out)
        with open(target, encoding="utf-8") as f:
            self.assertEqual(f.read(), "{}")

    def test_シンボリックリンクのフォルダの中には書かない(self):
        outside = os.path.join(self.tmp, "outside")
        os.makedirs(outside)
        os.symlink(outside, self.path(".claude"))
        out, _ = self.plan_and_apply()
        self.assertIn("シンボリックリンク", out)
        self.assertEqual(os.listdir(outside), [])

    # ------------------------------------------------------------ CLAUDE.md と AGENTS.md

    def test_CLAUDE_mdの末尾にキットの部分を足しほかは変えない(self):
        mine = "# メモアプリ\n\n- テストは pytest で動かす\n"
        self.write("CLAUDE.md", mine)
        self.plan_and_apply()
        text = self.read("CLAUDE.md")
        self.assertTrue(text.startswith(mine + "\n"))
        self.assertTrue(text.endswith(load_template("CLAUDE.md")))

    def test_キットの部分だけを新しくする(self):
        block = load_template("CLAUDE.md")
        begin, end = block.splitlines()[0], block.splitlines()[-1]
        self.write("CLAUDE.md", "# 前\n\n%s\n古い内容\n%s\n\n# 後\n" % (begin, end))
        out, _ = self.plan_and_apply()
        self.assertIn("CLAUDE.md: 変える", out)
        self.assertEqual(self.read("CLAUDE.md"), "# 前\n\n" + block + "\n# 後\n")

    def test_印がそろっていなければ変えない(self):
        begin = load_template("CLAUDE.md").splitlines()[0]
        self.write("CLAUDE.md", "# 前\n%s\n終わりの印が無い\n" % begin)
        out, _ = self.plan_and_apply()
        self.assertIn("そろっていない", out)
        self.assertEqual(self.read("CLAUDE.md"), "# 前\n%s\n終わりの印が無い\n" % begin)

    def test_claudeフォルダのCLAUDE_mdがあればそちらに足す(self):
        self.write(".claude/CLAUDE.md", "# 決まり\n")
        self.plan_and_apply()
        self.assertFalse(os.path.exists(self.path("CLAUDE.md")))
        self.assertIn("security-kit:begin", self.read(".claude/CLAUDE.md"))


class TemplateTest(unittest.TestCase):
    """build.py が作るひな形の中身（Skill が読まれなくても、必要な指示が届くこと）"""

    def test_CLAUDE_mdとAGENTS_mdは初期化と同じ印で囲む(self):
        sys.path.insert(0, os.path.join(PLUGIN, "scripts"))
        try:
            import init
        finally:
            sys.path.pop(0)
        for name in ("CLAUDE.md", "AGENTS.md"):
            lines = load_template(name).splitlines()
            self.assertEqual(lines[0], init.BEGIN, name)
            self.assertEqual(lines[-1], init.END, name)

    def test_CLAUDE_mdに説明してから直すことを書く(self):
        text = load_template("CLAUDE.md")
        self.assertIn("黙って直さない", text)
        self.assertIn("ひとこと：", text)
        self.assertIn("利用者が認めたときだけ", text)
        self.assertIn("別の方法で同じことをしない", text)

    def test_止めるルールをCLAUDE_mdに載せる(self):
        with open(os.path.join(PLUGIN, "data", "rules.json"), encoding="utf-8") as f:
            rules = json.load(f)["rules"]
        text = load_template("CLAUDE.md")
        for rid, r in rules.items():
            if r["severity"] == "block":
                self.assertIn(rid, text)

    def test_AGENTS_mdに有効なルールをすべて載せる(self):
        with open(os.path.join(PLUGIN, "data", "rules.json"), encoding="utf-8") as f:
            rules = json.load(f)["rules"]
        text = load_template("AGENTS.md")
        self.assertIn("Review guidelines", text)
        for rid in rules:
            self.assertIn("| %s |" % rid, text)

    def test_設定のひな形で公式プラグインを止めて読み取りを禁止する(self):
        s = json.loads(load_template("settings.json"))
        self.assertIs(s["enabledPlugins"]["security-guidance@claude-plugins-official"], False)
        self.assertIn("Read(**/.env)", s["permissions"]["deny"])

    def test_キットの設定のひな形は警告モード(self):
        c = json.loads(load_template("security-kit.json"))
        self.assertEqual(c["mode"], "warn")
        self.assertEqual(c["exceptions"], [])


if __name__ == "__main__":
    unittest.main()
