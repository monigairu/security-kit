"""キット自体のワークフローの決まりのテスト（基本設計書 6.4、FR-35）。

実行: python3 -m unittest discover -s tests -v

検査ツール（zizmor）でも同じことを見るが、ここでは手元で、追加のインストールなしに確かめられる。
SHA が実在するかは、ここでは確かめられない（GitHub に問い合わせが要る）。
"""
import glob
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WORKFLOWS = sorted(glob.glob(os.path.join(ROOT, ".github", "workflows", "*.y*ml")))


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


class WorkflowTest(unittest.TestCase):
    def test_ワークフローがある(self):
        self.assertTrue(WORKFLOWS)

    def test_Actionはコミットのハッシュで固定する(self):
        for path in WORKFLOWS:
            for m in re.finditer(r"^\s*-?\s*uses:\s*(\S+)", read(path), re.M):
                ref = m.group(1)
                if ref.startswith("./"):
                    continue
                self.assertRegex(ref, r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$", "%s: %s" % (os.path.basename(path), ref))

    def test_既定の権限は空にする(self):
        for path in WORKFLOWS:
            self.assertRegex(read(path), r"(?m)^permissions:\s*\{\}\s*$", os.path.basename(path))

    def test_外部のPRで権限を持って動く起動方法は使わない(self):
        for path in WORKFLOWS:
            text = read(path)
            self.assertNotIn("pull_request_target", re.sub(r"(?m)^\s*#.*$", "", text), os.path.basename(path))
            self.assertNotIn("secrets.", text, os.path.basename(path))  # 秘密情報は渡さない

    def test_チェックアウトで認証情報を残さない(self):
        for path in WORKFLOWS:
            text = read(path)
            self.assertEqual(text.count("actions/checkout@"), text.count("persist-credentials: false"),
                             os.path.basename(path))


if __name__ == "__main__":
    unittest.main()
