"""ルールの違反例と正常例のテスト（データ設計書 3.4、NFR-06）。

実行: python3 -m unittest discover -s tests -v

tests/rules/examples.json は、build.py が rules/*.yaml の examples から作る。
違反例ではそのルールの指摘が出ること、正常例では出ないことを、フックと同じ検査
（Ruff、キット独自の簡易チェック、キット内蔵の秘密情報の判定）で確かめる。
AI レビューだけで見つけるルールの例は、AI を呼ばないと確かめられないので、ここでは扱わない。
"""
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PLUGIN = os.path.join(REPO, "plugins", "security-kit")

# フックの部品は、読み込む時点でプラグインの場所を決めるので、先に環境変数を合わせる
os.environ["CLAUDE_PLUGIN_ROOT"] = PLUGIN
sys.path.insert(0, os.path.join(PLUGIN, "scripts"))
from kit import checks, core, secrets  # noqa: E402

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "examples.json"), encoding="utf-8") as _f:
    EXAMPLES = json.load(_f)

# 違反例で確かめられる検出方法
TESTABLE = {"kit", "ruff", "kit-secret"}
HAS_RUFF = shutil.which("ruff") is not None


def found_rules(root, rel, code):
    """例のファイルを置いて検査し、指摘されたルール ID の集まりを返す。"""
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(code)
    with mock.patch.dict(os.environ):
        os.environ.pop("CLAUDE_PROJECT_DIR", None)
        ctx = core.Context({"cwd": root, "session_id": "examples", "tool_input": {"file_path": path}})
        # git で管理していない場所なので、ファイル全体が検査の対象になる
        findings, _ = checks.scan_file(ctx, ctx.target, None)
        rules = {f["rule"] for f in findings}
        if secrets.scan(code, ctx):
            rules.add(ctx.rule_for("kit-secret", "*")[0])
    return rules


class RuleExamplesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="kit-examples-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def check(self, rule_id):
        ex = EXAMPLES[rule_id]
        if not TESTABLE & set(ex["tools"]):
            self.skipTest("AI レビューだけで見つけるルール")
        for n, item in enumerate(ex["bad"], 1):
            with self.subTest(side="違反例", n=n, file=item["file"]):
                root = os.path.join(self.tmp, "bad%d" % n)
                if rule_id not in found_rules(root, item["file"], item["code"]):
                    if item["file"].endswith(".py") and not HAS_RUFF:
                        self.skipTest("Ruff が入っていない")
                    self.fail("%s の違反例で指摘が出ない" % rule_id)
        for n, item in enumerate(ex["good"], 1):
            with self.subTest(side="正常例", n=n, file=item["file"]):
                root = os.path.join(self.tmp, "good%d" % n)
                self.assertNotIn(rule_id, found_rules(root, item["file"], item["code"]),
                                 "%s の正常例で指摘が出た" % rule_id)


def _make_test(rule_id):
    def test(self):
        self.check(rule_id)
    return test


for _rid in EXAMPLES:
    setattr(RuleExamplesTest, "test_" + _rid.replace("-", "_"), _make_test(_rid))


if __name__ == "__main__":
    unittest.main()
