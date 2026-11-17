# GitHub Pages 用 静的デモ

Flask を使わず、ブラウザだけで動くデモ版です。
GitHub Pages の `main` ブランチ `/docs` を公開元にしています。

公開 URL: <https://cssu24038-rgb.github.io/matsulab/>

## 仕組み

- `index.html` … アプリの入口（1ページ）
- `assets/analyzer.js` … ドメイン判定のダミー実装（`analyzer.py` のブラウザ版）
- `assets/store.js` … 履歴・保存メールを `localStorage` に保存
- `assets/app.js` … ハッシュルーティング（`#/`、`#/result/<id>` など）と画面描画
- `assets/style.css` … Flask 版と共通のスタイル

画面は次のハッシュで切り替わります。

| 画面 | URL |
|---|---|
| ログイン | `#/login` |
| ホーム | `#/` |
| 判定結果 | `#/result/<id>` |
| くわしい表示 | `#/result/<id>/detail` |
| 保存したメール | `#/mails` |
| メール詳細 | `#/mails/<id>` |
| 調査履歴 | `#/history` |

## 注意

- 判定結果・保存データは **閲覧者のブラウザ内** にだけ保存されます。サーバーには送信されません。
- ログインはデモ用で、Google 認証は行いません。
- 判定ロジックはダミーです。本番では `analyzer.py` を VirusTotal などに置き換えます。
- データを初期状態に戻すには、ブラウザの開発者ツールから `dc_demo_v1_` で始まる localStorage を削除してください。

## ローカル確認

```bash
cd docs
python3 -m http.server 8765
# http://127.0.0.1:8765/ を開く
```

`file://` で直接開いても動きますが、localStorage の扱いが環境によって変わるため HTTP での確認を推奨します。
