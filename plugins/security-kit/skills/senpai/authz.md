# 認可の確かめ方とテスト

認可の漏れ（他人のデータを見られる・変えられる）は、検査ツールではほとんど見つからない。コードを読んで確かめる。

## 確かめること

| 処理 | 確かめること |
|---|---|
| 1件を読む・更新する・消す | ID で取り出したあと、ログイン中の利用者が持ち主（または権限のある人）かを確かめているか |
| 一覧を返す | ログイン中の利用者の範囲で絞り込んでいるか |
| 別のデータを関連付ける | リクエストで受け取った別の ID（顧客 ID、案件 ID など）の持ち主を確かめているか |
| 権限の判断 | 利用者が書き換えられる値（リクエストのヘッダー、本文の role や is_admin）に頼っていないか |

- 読む処理に確認があっても、更新・削除・コメントなど、同じデータを扱うほかの処理に確認が無いことが多い。同じデータを扱う処理をすべて見る。
- 他人のデータのときは、「無い」ときと同じ応答（404）を返すと、そのデータがあるかどうかも知られずに済む。

## テストの例

テストの準備（ログインの仕方、データの作り方）は、プロジェクトにあるものを使う。無ければ、作ってよいかを利用者に確かめる。

Python（FastAPI と pytest）

```python
def test_他人の注文は見られない(client, login_as, create_order):
    alice = login_as("alice")
    bob_order_id = create_order(owner="bob")
    res = client.get(f"/orders/{bob_order_id}", headers=alice)
    assert res.status_code == 404
```

JavaScript（Express と Jest、supertest）

```javascript
test("他人の注文は見られない", async () => {
  const alice = await loginAs("alice");
  const bobOrderId = await createOrder({ owner: "bob" });
  const res = await request(app).get(`/orders/${bobOrderId}`).set("Authorization", alice);
  expect(res.status).toBe(404);
});
```

読む処理だけでなく、更新・削除の処理にも同じテストを書く。
