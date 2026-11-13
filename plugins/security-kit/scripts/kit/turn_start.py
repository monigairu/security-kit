"""ターンの始め（利用者が指示を送った時点）の処理。

作業フォルダの状態を記録しておく。あとの検査で「このターンで変えた分」だけを見るため。
何も出力しない（このタイミングの出力は、そのまま Claude への入力になってしまうため）。
"""
from . import core, gitstate


def run(ctx):
    baseline = gitstate.snapshot(ctx.root)
    head = gitstate.head(ctx.root)

    f, state = core.open_state(ctx)
    try:
        if not state:
            core.sweep_old_sessions()
        state["baseline"] = baseline
        state["head"] = head
        state["changed_files"] = []
        state["turn_warns"] = []
        state["stop_continued"] = False
    finally:
        core.save_state(f, state)
    return None
