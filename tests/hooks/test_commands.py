"""相談コマンドと報告コマンドから呼ぶスクリプトのテスト（基本設計書 3.8、3.9）。

実行: python3 -m unittest discover -s tests -v
"""
import json
import os
import subprocess
import sys
import unittest

from .test_hooks import FAKE_AWS_KEY, HAS_RUFF, PLUGIN, SQL_BAD, SQL_OK, HookTestCase

CONSULT = os.path.join(PLUGIN, "scripts", "consult.py")
REPORT = os.path.join(PLUGIN, "scripts", "report.py")


class CommandTestCase(HookTestCase):
    def run_script(self, script, *args):
        env = dict(os.environ, CLAUDE_PLUGIN_DATA=self.data)
        for name in ("CLAUDE_PLUGIN_ROOT", "CLAUDE_PROJECT_DIR"):
            env.pop(name, None)
        r = subprocess.run([sys.executable, "-I", "-S", script, *args], capture_output=True, text=True,
                           env=env, cwd=self.project, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout


@unittest.skipUnless(HAS_RUFF, "Ruff が入っていない")
class ConsultTest(CommandTestCase):
    """相談コマンドの検査"""

    def setUp(self):
        super().setUp()
        self.init_repo(**{"app/old.py": "def find(cur, user_id):\n    %s\n" % SQL_BAD})

    def test_対象が無ければまだコミットしていない変更の変えた行だけを見る(self):
        self.write("app/old.py", "def find(cur, user_id):\n    %s\n\ndef ok():\n    return 1\n" % SQL_BAD)
        self.write("app/new.py", "def find(cur, name):\n    %s\n" % SQL_BAD.replace("user_id", "name"))
        out = self.run_script(CONSULT)
        self.assertIn("警告 R-012", out)
        self.assertIn("app/new.py 2行目", out)
        self.assertNotIn("app/old.py", out)  # 以前からある問題は出さない
        self.assertNotIn("詳しく: /security-kit:consult", out)  # 相談の中では相談を勧めない

    def test_ファイルを名指しすれば以前からある問題も見る(self):
        out = self.run_script(CONSULT, "app/old.py")
        self.assertIn("app/old.py 2行目", out)
        self.assertIn("名指しされたファイルの全体", out)

    def test_秘密情報を見つけても値は表示しない(self):
        self.write("app/conf.py", 'KEY = "%s"\n' % FAKE_AWS_KEY)
        out = self.run_script(CONSULT)
        self.assertIn("止める R-001", out)
        self.assertNotIn(FAKE_AWS_KEY, out)

    def test_コードの中身は表示しない(self):
        self.write("app/new.py", "def find(cur, secret_column):\n    %s\n" % SQL_BAD.replace("user_id", "secret_column"))
        self.assertNotIn("secret_column", self.run_script(CONSULT))

    def test_ファイルを書き換えない(self):
        path = self.write("app/new.py", "def find(cur, user_id):\n    %s\n" % SQL_BAD)

        def read():
            with open(path, encoding="utf-8") as f:
                return f.read()

        before = read()
        self.run_script(CONSULT, "app")
        self.assertEqual(read(), before)

    def test_プロジェクトの外のファイルは検査しない(self):
        outside = os.path.join(self.tmp, "outside.py")
        with open(outside, "w", encoding="utf-8") as f:
            f.write("def find(cur, user_id):\n    %s\n" % SQL_BAD)
        out = self.run_script(CONSULT, outside)
        self.assertIn("プロジェクトの外", out)
        self.assertNotIn("R-012", out.split("\n\n", 1)[1] if "\n\n" in out else "")

    def test_問題が無ければそう伝える(self):
        self.write("app/new.py", "def find(cur, user_id):\n    %s\n" % SQL_OK)
        self.assertIn("指摘はありませんでした", self.run_script(CONSULT))

    def test_ルールの説明の場所を示す(self):
        out = self.run_script(CONSULT, "app/old.py")
        self.assertIn(os.path.join("skills", "senpai", "rules", "R-012.md"), out)
        self.assertTrue(os.path.isfile(os.path.join(PLUGIN, "skills", "senpai", "rules", "R-012.md")))


class ReportTest(CommandTestCase):
    """報告コマンドの下書きに使う情報"""

    def log(self, *rows):
        d = os.path.join(self.data, "log")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "2026-11.jsonl"), "a", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

    def test_このセッションの指摘だけをファイルの種類つきで出す(self):
        self.log(
            {"session": "s1", "timing": "post", "rule": "R-012", "severity": "warn", "tool": "ruff",
             "tool_rule": "S608", "file": "clinic-a/patients/db.py", "project": "clinic-a"},
            {"session": "s2", "timing": "post", "rule": "R-013", "severity": "warn", "tool": "ruff",
             "tool_rule": "S602", "file": "x.py"},
            {"session": "s1", "timing": "stop", "rule": "R-012", "action": "rechecked", "file": "db.py"},  # 指摘ではない
        )
        out = self.run_script(REPORT, "s1")
        self.assertIn("R-012 SQL インジェクション", out)
        self.assertIn("ファイルの種類 .py", out)
        self.assertNotIn("R-013", out)
        self.assertNotIn("clinic-a", out)  # ファイルの場所とプロジェクト名は出さない
        self.assertNotIn("patients", out)
        self.assertEqual(out.count("ruff S608"), 1)

    def test_報告先とキットの版を出す(self):
        out = self.run_script(REPORT, "s1")
        self.assertIn("--repo monigairu/security-kit", out)
        self.assertIn("キットの版: ", out)
        self.assertIn("記録はありません", out)

    def test_セッションIDの記号は取り除く(self):
        self.log({"session": "s1", "timing": "pre", "rule": "R-001", "severity": "block", "tool": "kit-secret",
                  "tool_rule": "aws-access-key", "file": ".env"})
        out = self.run_script(REPORT, "../s1")
        self.assertIn("R-001", out)
        self.assertIn("ファイルの種類 .env", out)


class NoticeTest(HookTestCase):
    """通知文とまとめ（Skill が読み込まれていなくても、必要な指示が届くこと）"""

    @unittest.skipUnless(HAS_RUFF, "Ruff が入っていない")
    def test_通知に相談コマンドを添える(self):
        self.write("app/db.py", "def find(cur, user_id):\n    %s\n" % SQL_BAD)
        self.assertIn("詳しく: /security-kit:consult R-012", self.post("app/db.py")["additionalContext"])

    @unittest.skipUnless(HAS_RUFF, "Ruff が入っていない")
    def test_警告では除外の印を勝手に付けないよう伝える(self):
        self.write("app/db.py", "def find(cur, user_id):\n    %s\n" % SQL_BAD)
        self.assertIn("利用者が認めたときだけ", self.post("app/db.py")["additionalContext"])

    def test_止めたときは別の方法で書かないよう伝える(self):
        reason = self.pre("app/config.py", 'KEY = "%s"\n' % FAKE_AWS_KEY)["permissionDecisionReason"]
        self.assertIn("別の方法で同じ内容を書かない", reason)
        self.assertIn("利用者が認めたときだけ", reason)

    @unittest.skipUnless(HAS_RUFF, "Ruff が入っていない")
    def test_ルールに対応付けのない助言は検査ツールの番号で示す(self):
        self.init_repo()
        self.turn_start()
        self.write("app/run.py", 'import subprocess\n\ndef run(name):\n    subprocess.run(["convert", name])\n')
        self.post("app/run.py")
        summary = self.stop()["systemMessage"]
        self.assertIn("ruff S60", summary)  # S603 など
        self.assertNotIn("（対応するルールなし）", summary)


if __name__ == "__main__":
    unittest.main()
