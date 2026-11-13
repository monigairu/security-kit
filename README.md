# security-qa-ai
サイバー攻撃の事例と対策を出典付きで質問できるAI

## フォルダ構成

フォルダは、最初のファイルを置くときに作ります（空のフォルダは作りません）。

```
security-kit/
├── docs/
│   ├── requirements/   要件定義
│   ├── design/         基本設計・データ設計
│   ├── specs/          詳細仕様（frontend / backend）
│   └── adr/            設計判断の記録（ADR）
├── rules/              チェックルール（YAML）※実装開始時に作成
├── tests/              テスト ※実装開始時に作成
└── .github/            CI・PRテンプレート ※CI導入時に作成
```

`rules/` やソースコードの配置は、基本設計で決まりしだい確定します。
