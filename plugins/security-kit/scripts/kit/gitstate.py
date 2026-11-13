"""git を使って「このターンで変えた分」を求める。

ターンの始めに作業フォルダの状態を記録しておき（snapshot）、
あとでその時点との差を見る。リポジトリの中身（作業フォルダ、ステージ、ブランチ）には
手を加えない。記録のために、変更のあるファイルの写しが git の内部に置かれるだけである。
"""
import os
import re
import shutil
import subprocess
import tempfile

from . import core

HUNK = re.compile(r"^@@ -\S+ \+(\d+)(?:,(\d+))? @@", re.M)
SAFE_DIFF = ["--no-color", "--no-ext-diff", "--no-textconv"]


def _git(root, *args, env=None, timeout=10):
    git = core.which("git")
    if not git:
        return None
    try:
        return subprocess.run([git, "-C", root, *args], capture_output=True, text=True,
                              timeout=timeout, env=env, errors="replace")
    except (OSError, subprocess.TimeoutExpired):
        return None


def _ok(result):
    return result is not None and result.returncode == 0


def head(root):
    r = _git(root, "rev-parse", "--verify", "-q", "HEAD")
    return r.stdout.strip() if _ok(r) else None


def snapshot(root):
    """今の作業フォルダの状態を記録する。

    返す形: {"tree": 状態を表す番号, "untracked": git で管理していないファイルの一覧}
    git で管理していない場所では None。
    """
    gitdir = _git(root, "rev-parse", "--absolute-git-dir")
    if not _ok(gitdir):
        return None
    gitdir = gitdir.stdout.strip()

    # 利用者のステージに触れないよう、写しを作ってそちらで作業する
    os.makedirs(core.state_dir(), exist_ok=True)
    fd, tmp_index = tempfile.mkstemp(prefix="index-", dir=core.state_dir())
    os.close(fd)
    try:
        real_index = os.path.join(gitdir, "index")
        if os.path.isfile(real_index):
            shutil.copyfile(real_index, tmp_index)
        else:
            os.remove(tmp_index)
        env = dict(os.environ, GIT_INDEX_FILE=tmp_index)
        # 管理しているファイルの変更だけを写しに取り込む（管理外のファイルは名前だけ記録する）
        if not _ok(_git(root, "add", "-u", env=env, timeout=20)):
            return None
        tree = _git(root, "write-tree", env=env)
        if not _ok(tree):
            return None
    finally:
        for p in (tmp_index, tmp_index + ".lock"):
            if os.path.exists(p):
                os.remove(p)

    others = _git(root, "ls-files", "--others", "--exclude-standard", "-z")
    untracked = [p for p in others.stdout.split("\0") if p][:5000] if _ok(others) else []
    return {"tree": tree.stdout.strip(), "untracked": untracked}


def line_ranges(root, baseline, abs_path, rel_path):
    """このターンで変えた行の範囲の一覧を返す。

    None を返したときは「ファイル全体が対象」を意味する（このターンで新しく作った
    ファイル、git で管理していない場所など）。
    baseline が無いときは、まだコミットしていない変更を対象にする。
    """
    if baseline and baseline.get("tree"):
        if rel_path in (baseline.get("untracked") or []):
            return None  # ターンの始めから管理外にあったファイルは、差を取れないので全体を見る
        if not _ok(_git(root, "cat-file", "-e", "%s:%s" % (baseline["tree"], rel_path))):
            return None  # このターンで新しく作ったファイル
        diff = _git(root, "diff", "-U0", *SAFE_DIFF, baseline["tree"], "--", abs_path)
    else:
        status = _git(root, "status", "--porcelain", "--ignored", "--", abs_path)
        if not _ok(status) or status.stdout[:2] in ("??", "!!"):
            return None
        diff = _git(root, "diff", "-U0", *SAFE_DIFF, "HEAD", "--", abs_path)
    if not _ok(diff):
        return None
    return _ranges(diff.stdout)


def _ranges(diff_text):
    out = []
    for m in HUNK.finditer(diff_text):
        start, count = int(m.group(1)), int(m.group(2) or 1)
        if count:
            out.append((start, start + count - 1))
    return out


def changed_names(root, base_tree, end_tree):
    """2つの状態のあいだで変わった、管理しているファイルの名前。"""
    r = _git(root, "diff", "--name-only", "-z", *SAFE_DIFF, base_tree, end_tree)
    return [p for p in r.stdout.split("\0") if p] if _ok(r) else []


def diff_between(root, base, end, paths, context=3):
    """2つの状態（または2つのコミット）のあいだの差分を、ファイルごとに返す。"""
    if not paths:
        return {}
    r = _git(root, "diff", "-U%d" % context, *SAFE_DIFF, base, end, "--", *paths, timeout=30)
    if not _ok(r):
        return {}
    out = {}
    for chunk in re.split(r"(?m)^(?=diff --git )", r.stdout):
        m = re.search(r"(?m)^\+\+\+ b/(.+)$", chunk)
        if m and "\nBinary files " not in chunk:
            out[m.group(1).strip()] = chunk
    return out


def is_ancestor(root, older, newer):
    return _ok(_git(root, "merge-base", "--is-ancestor", older, newer))


def parent_of(root, commit):
    r = _git(root, "rev-parse", "--verify", "-q", commit + "~1")
    return r.stdout.strip() if _ok(r) else None


def empty_tree(root):
    r = _git(root, "hash-object", "-t", "tree", os.devnull)
    return r.stdout.strip() if _ok(r) else None
