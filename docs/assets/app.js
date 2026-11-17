/*
 * ドメイン検知 — 静的デモ（GitHub Pages 用）
 * ハッシュルーティングで画面を切り替える。判定・保存はブラウザ内のダミー。
 */
(function () {
  "use strict";

  var Analyzer = window.DomainAnalyzer;
  var Store = window.DomainStore;
  var appEl = document.getElementById("app");
  var pendingFlash = null;

  // ------------------------------------------------------------------
  // ユーティリティ
  // ------------------------------------------------------------------

  var ESCAPE_MAP = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  };

  function esc(value) {
    return String(value === null || value === undefined ? "" : value).replace(
      /[&<>"']/g,
      function (ch) { return ESCAPE_MAP[ch]; }
    );
  }

  function pad(n) {
    return n < 10 ? "0" + n : String(n);
  }

  function fmtDate(iso) {
    if (!iso) return "";
    var d = new Date(iso);
    if (isNaN(d.getTime())) return "";
    return (
      d.getFullYear() + "/" + pad(d.getMonth() + 1) + "/" + pad(d.getDate()) +
      " " + pad(d.getHours()) + ":" + pad(d.getMinutes())
    );
  }

  function showFlash(text, type) {
    pendingFlash = { text: text, type: type || "info" };
  }

  function go(path) {
    var target = "#" + path;
    if (window.location.hash === target) {
      render();
    } else {
      window.location.hash = target;
    }
  }

  function pill(score, label, large) {
    return (
      '<span class="level-pill ' + (large ? "level-pill-lg " : "") +
      "lv-" + score + '">' + esc(label) + "</span>"
    );
  }

  function gauge(score, large) {
    var segments = "";
    for (var i = 1; i <= 5; i += 1) {
      segments += '<span class="gauge-seg' + (i <= score ? " is-on" : "") + '"></span>';
    }
    return (
      '<div class="gauge' + (large ? " gauge-lg" : "") + '" role="img" aria-label="危険度 ' +
      score + ' / 5">' + segments + "</div>"
    );
  }

  function reasonIcon(severity) {
    var mark = severity === "good" ? "✓" : severity === "info" ? "i" : "!";
    return '<span class="reason-icon ' + esc(severity) + '" aria-hidden="true">' + mark + "</span>";
  }

  function shieldSvg() {
    return (
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" ' +
      'stroke-linecap="round" stroke-linejoin="round">' +
      '<path d="M12 3l7 3v5.5c0 4.5-3 7.5-7 9.5-4-2-7-5-7-9.5V6l7-3z"/>' +
      '<path d="M9 12l2 2 4-4"/></svg>'
    );
  }

  function searchSvg() {
    return (
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" ' +
      'stroke-linecap="round" stroke-linejoin="round">' +
      '<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/></svg>'
    );
  }

  function mailSvg() {
    return (
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" ' +
      'stroke-linecap="round" stroke-linejoin="round">' +
      '<path d="M4 6.5h16v11H4z"/><path d="M4 7l8 6 8-6"/></svg>'
    );
  }

  // ------------------------------------------------------------------
  // レイアウト
  // ------------------------------------------------------------------

  function headerHtml(active) {
    var user = Store.getUser();
    var mailCount = Store.getMails().length;

    var nav = "";
    if (user) {
      nav =
        '<nav class="main-nav" aria-label="メインメニュー">' +
        '<a href="#/" class="' +
        (active === "home" || active === "result" || active === "detail" ? "is-active" : "") +
        '">ホーム</a>' +
        '<a href="#/mails" class="' + (active === "mails" ? "is-active" : "") + '">保存したメール' +
        (mailCount ? '<span class="nav-count">' + mailCount + "</span>" : "") +
        "</a>" +
        '<a href="#/history" class="' + (active === "history" ? "is-active" : "") + '">調査履歴</a>' +
        "</nav>";
    }

    var userBox = "";
    if (user) {
      userBox =
        '<div class="user-box">' +
        '<span class="avatar" aria-hidden="true">' + esc(user.name.charAt(0)) + "</span>" +
        '<span class="user-name">' + esc(user.name) + "</span>" +
        '<form id="logout-form"><button class="btn btn-ghost btn-sm" type="submit">ログアウト</button></form>' +
        "</div>";
    }

    return (
      '<header class="site-header"><div class="header-inner">' +
      '<a class="brand" href="' + (user ? "#/" : "#/login") + '">' +
      '<span class="brand-mark" aria-hidden="true">' + shieldSvg() + "</span>" +
      '<span class="brand-text">ドメイン検知<small>Domain Checker</small></span></a>' +
      nav + userBox +
      "</div></header>"
    );
  }

  function flashHtml() {
    if (!pendingFlash) return "";
    var html =
      '<div class="flash-area"><div class="flash flash-' + esc(pendingFlash.type) +
      '" role="status">' + esc(pendingFlash.text) + "</div></div>";
    pendingFlash = null;
    return html;
  }

  function layout(content, active) {
    return (
      headerHtml(active) +
      '<main class="container">' + flashHtml() + content + "</main>" +
      '<footer class="site-footer">' +
      "<p>送信ドメイン信頼性評価アプリ — 画面遷移プロトタイプ</p>" +
      '<p class="muted">判定結果・保存データはすべてダミーです。ブラウザ内（localStorage）に保存されます。</p>' +
      "</footer>"
    );
  }

  // ------------------------------------------------------------------
  // 画面: ログイン
  // ------------------------------------------------------------------

  function loginView() {
    var points = [
      "危険度を5段階・色分けで表示",
      "むずかしい専門用語なしの「やさしい表示」",
      "調べた履歴と危険メールを保存",
    ].map(function (text) {
      return "<li><span class=\"dot dot-green\"></span>" + esc(text) + "</li>";
    }).join("");

    var previewAll =
      '<span class="gauge-seg is-on"></span><span class="gauge-seg is-on"></span>' +
      '<span class="gauge-seg is-on"></span><span class="gauge-seg is-on"></span>' +
      '<span class="gauge-seg is-on"></span>';
    var previewOne =
      '<span class="gauge-seg is-on"></span><span class="gauge-seg"></span>' +
      '<span class="gauge-seg"></span><span class="gauge-seg"></span>' +
      '<span class="gauge-seg"></span>';

    return (
      '<div class="login-wrap">' +
      '<section class="login-card">' +
      '<div class="login-badge" aria-hidden="true">' + mailSvg() + "</div>" +
      "<h1>送信ドメインの<br>信頼性をチェック</h1>" +
      '<p class="login-lead">届いたメールのドメインを調べて、危険度を5段階でお知らせします。' +
      "セキュリティの知識がない方でも、ひと目で判断できます。</p>" +
      '<ul class="login-points">' + points + "</ul>" +
      '<form id="login-form"><button class="google-btn" type="submit">' +
      '<span class="google-g" aria-hidden="true">G</span>Google でログイン</button></form>' +
      '<p class="demo-note">デモ用のログインです。データはこのブラウザにのみ保存されます。</p>' +
      "</section>" +
      '<section class="login-preview" aria-hidden="true">' +
      '<div class="preview-card lv-5">' +
      '<div class="preview-head"><span class="muted">判定結果の例</span>' +
      '<span class="level-pill lv-5">非常に危険</span></div>' +
      '<p class="preview-domain">paypa1-secure.top</p>' +
      '<div class="gauge">' + previewAll + "</div>" +
      '<div class="preview-reason"><span class="reason-icon bad">!</span>なりすまし対策が未設定です</div>' +
      '<div class="preview-reason"><span class="reason-icon warn">!</span>登録から12日しか経っていません</div>' +
      "</div>" +
      '<div class="preview-card preview-card-sub lv-1">' +
      '<div class="preview-head"><span class="muted">安全な例</span>' +
      '<span class="level-pill lv-1">安全</span></div>' +
      '<p class="preview-domain">gmail.com</p>' +
      '<div class="gauge">' + previewOne + "</div>" +
      "</div></section></div>"
    );
  }

  // ------------------------------------------------------------------
  // 画面: ホーム
  // ------------------------------------------------------------------

  var LEGEND = {
    1: "問題は見つかりませんでした",
    2: "ほぼ安全ですが念のため確認",
    3: "リンクを開く前に確認を",
    4: "開かずに削除をおすすめ",
    5: "開かずにすぐ削除してください",
  };

  function homeView() {
    var history = Store.getHistory(5);
    var mails = Store.getMails().slice(0, 3);
    var results = Store.getAllResults();

    var historyHtml = history.length
      ? '<ul class="list">' + history.map(function (item) {
          return (
            '<li><a class="list-row" href="#/result/' + encodeURIComponent(item.id) + '">' +
            pill(item.score, item.label) +
            '<span class="list-main"><span class="list-title">' + esc(item.domain) + "</span>" +
            '<span class="list-sub">' + (item.input_type === "email" ? "メールアドレス" : "ドメイン") +
            "・" + fmtDate(item.created_at) + "</span></span>" +
            '<span class="chevron" aria-hidden="true">›</span></a></li>'
          );
        }).join("") + "</ul>"
      : '<p class="empty">まだ調査履歴はありません。上のフォームから調べてみましょう。</p>';

    var mailsHtml = mails.length
      ? '<ul class="mail-mini-list">' + mails.map(function (mail) {
          var r = results[mail.result_id];
          return (
            '<li><a class="mail-mini" href="#/mails/' + encodeURIComponent(mail.id) + '">' +
            '<div class="mail-mini-top">' +
            (r ? '<span class="level-dot lv-' + r.score + '" title="' + esc(r.label) + '"></span>' : "") +
            '<span class="mail-mini-subject">' + esc(mail.subject) + "</span></div>" +
            '<div class="mail-mini-meta">' + esc(mail.sender_email) + "・" + fmtDate(mail.saved_at) +
            "</div></a></li>"
          );
        }).join("") + "</ul>"
      : '<p class="empty">保存したメールはありません。判定結果の画面から保存できます。</p>';

    var legendHtml = [1, 2, 3, 4, 5].map(function (score) {
      return (
        "<li>" + pill(score, Analyzer.LEVELS[score].label) +
        '<span class="legend-desc">' + esc(LEGEND[score]) + "</span></li>"
      );
    }).join("");

    return (
      '<section class="hero"><div class="hero-text">' +
      '<span class="eyebrow">送信ドメインの信頼性評価</span>' +
      "<h1>そのメール、<br>安全かどうか調べます。</h1>" +
      "<p>メールアドレス、またはドメインを入力してください。" +
      "なりすましの兆候や評判をもとに、危険度を5段階で判定します。</p></div>" +
      '<div class="hero-mark" aria-hidden="true">' + shieldSvg() + "</div></section>" +
      '<div class="dashboard"><div class="dashboard-main">' +
      '<section class="card search-card"><h2 class="card-title">ドメインを調べる</h2>' +
      '<form id="search-form" class="search-form">' +
      '<label class="sr-only" for="query">メールアドレスまたはドメイン</label>' +
      '<div class="input-wrap"><span class="input-icon" aria-hidden="true">' + searchSvg() + "</span>" +
      '<input id="query" name="query" type="text" autocomplete="off" ' +
      'placeholder="example.com / info@example.com" required></div>' +
      '<button class="btn btn-primary" type="submit">調べる</button></form>' +
      '<div class="samples"><span class="muted">入力例:</span>' +
      '<button type="button" class="chip" data-sample="gmail.com">gmail.com</button>' +
      '<button type="button" class="chip" data-sample="paypa1-secure.top">paypa1-secure.top</button>' +
      '<button type="button" class="chip" data-sample="support-center.net">support-center.net</button>' +
      '<button type="button" class="chip" data-sample="info@amazon.co.jp">info@amazon.co.jp</button>' +
      "</div></section>" +
      '<section class="card"><div class="card-head"><h2 class="card-title">最近の調査</h2>' +
      '<a href="#/history" class="text-link">すべて見る</a></div>' + historyHtml + "</section>" +
      "</div><aside class=\"dashboard-side\">" +
      '<section class="card"><div class="card-head"><h2 class="card-title">保存したメール</h2>' +
      '<a href="#/mails" class="text-link">一覧</a></div>' + mailsHtml + "</section>" +
      '<section class="card legend-card"><h2 class="card-title">危険度の見方</h2>' +
      '<ul class="legend">' + legendHtml + "</ul></section>" +
      "</aside></div>"
    );
  }

  // ------------------------------------------------------------------
  // 画面: 判定結果
  // ------------------------------------------------------------------

  function resultView(result) {
    var reasons = result.reasons.map(function (reason) {
      return (
        '<li class="reason-card">' + reasonIcon(reason.severity) +
        "<div><h3>" + esc(reason.title) + "</h3><p>" + esc(reason.detail) + "</p></div></li>"
      );
    }).join("");

    var defaultSenderEmail =
      result.input_type === "email" ? result.raw_input : "info@" + result.domain;

    return (
      '<nav class="breadcrumb" aria-label="パンくず"><a href="#/">ホーム</a>' +
      '<span aria-hidden="true">/</span><span>判定結果</span></nav>' +
      '<section class="result-hero lv-' + result.score + '">' +
      '<div class="result-hero-top"><div>' +
      '<p class="eyebrow">判定結果</p>' +
      '<h1 class="result-domain">' + esc(result.domain) + "</h1>" +
      '<p class="result-meta">' +
      (result.input_type === "email" ? "メールアドレスから抽出" : "ドメインを直接指定") +
      "・" + fmtDate(result.created_at) + " に調査</p></div>" +
      '<div class="result-verdict"><span class="verdict-score">' + result.score +
      "<small>/5</small></span>" + pill(result.score, result.label) + "</div></div>" +
      '<div class="gauge-wrap">' + gauge(result.score, true) +
      '<div class="gauge-labels"><span>安全</span><span>非常に危険</span></div></div>' +
      '<p class="result-one-liner">' + esc(result.one_liner) + "</p>" +
      '<p class="result-advice">' + esc(result.advice) + "</p>" +
      '<div class="result-actions">' +
      '<button class="btn btn-primary" type="button" id="scroll-save">このメールを保存する</button>' +
      '<a class="btn btn-secondary" href="#/result/' + encodeURIComponent(result.id) + '/detail">くわしい表示を見る</a>' +
      '<a class="btn btn-ghost" href="#/">もう一度調べる</a></div></section>' +
      '<div class="result-body">' +
      '<section class="card"><div class="card-head"><h2 class="card-title">判定の根拠</h2>' +
      '<span class="muted small">' + result.reasons.length + " 件</span></div>" +
      '<p class="section-lead">セキュリティの知識がない方にもわかる言葉で説明します。</p>' +
      '<ul class="reason-list">' + reasons + "</ul>" +
      '<div class="inline-note"><span class="inline-note-icon" aria-hidden="true">i</span>' +
      "<p>技術的な根拠（SPF / DKIM / DMARC、VirusTotal の検出数など）は" +
      '<a href="#/result/' + encodeURIComponent(result.id) + '/detail">くわしい表示</a>で確認できます。</p></div></section>' +
      '<section class="card save-card" id="save"><div class="card-head">' +
      '<h2 class="card-title">このメールを保存する</h2><span class="badge-demo">デモ</span></div>' +
      '<p class="section-lead">危険なメールを記録として残せます。保存したメールは' +
      "「保存したメール」一覧から確認・削除できます。</p>" +
      '<form id="save-form" class="form-grid">' +
      '<div class="field"><label for="subject">件名</label>' +
      '<input id="subject" name="subject" type="text" value="【要確認】重要なお知らせ"></div>' +
      '<div class="field"><label for="sender_name">差出人名</label>' +
      '<input id="sender_name" name="sender_name" type="text" value="サポートセンター"></div>' +
      '<div class="field"><label for="sender_email">差出人メールアドレス</label>' +
      '<input id="sender_email" name="sender_email" type="text" value="' +
      esc(defaultSenderEmail) + '"></div>' +
      '<div class="field field-full"><label for="memo">メモ（任意）</label>' +
      '<textarea id="memo" name="memo" rows="2" placeholder="例: 身に覚えのないメールだった"></textarea></div>' +
      '<div class="field-full form-actions"><button class="btn btn-primary" type="submit">保存する</button>' +
      '<span class="muted small">※ 保存処理はダミーです</span></div>' +
      "</form></section></div>"
    );
  }

  // ------------------------------------------------------------------
  // 画面: くわしい表示
  // ------------------------------------------------------------------

  function detailView(result) {
    var rows = result.evidence.map(function (item) {
      var statusLabel =
        item.status === "good" ? "問題なし" :
        item.status === "warn" ? "要注意" :
        item.status === "bad" ? "危険" : "参考情報";
      return (
        "<tr><th scope=\"row\">" + esc(item.label) + "</th>" +
        '<td class="mono">' + esc(item.value) + "</td>" +
        '<td><span class="status-chip status-' + esc(item.status) + '">' +
        statusLabel + "</span></td></tr>"
      );
    }).join("");

    var reasons = result.reasons.map(function (reason) {
      return (
        '<li class="reason-card">' + reasonIcon(reason.severity) +
        "<div><h3>" + esc(reason.title) + "</h3><p>" + esc(reason.technical) + "</p></div></li>"
      );
    }).join("");

    var checks = {};
    result.evidence.forEach(function (item) { checks[item.label] = item.value; });
    var raw = {
      domain: result.domain,
      score: result.score,
      label: result.label,
      checked_at: result.created_at,
      checks: checks,
    };

    return (
      '<nav class="breadcrumb" aria-label="パンくず"><a href="#/">ホーム</a>' +
      '<span aria-hidden="true">/</span>' +
      '<a href="#/result/' + encodeURIComponent(result.id) + '">判定結果</a>' +
      '<span aria-hidden="true">/</span><span>くわしい表示</span></nav>' +
      '<div class="detail-head"><div><p class="eyebrow">専門家向けの詳細</p>' +
      "<h1>" + esc(result.domain) + "</h1>" +
      '<p class="result-meta">' + fmtDate(result.created_at) + " に調査</p></div>" +
      pill(result.score, result.label + "（" + result.score + "/5）", true) + "</div>" +
      '<div class="view-tabs" role="tablist" aria-label="表示の切り替え">' +
      '<a class="view-tab" href="#/result/' + encodeURIComponent(result.id) + '">やさしい表示</a>' +
      '<a class="view-tab is-active" href="#/result/' + encodeURIComponent(result.id) + '/detail" aria-current="page">くわしい表示</a></div>' +
      '<section class="card"><div class="card-head"><h2 class="card-title">技術的なチェック結果</h2>' +
      '<span class="muted small">ダミーデータ</span></div>' +
      '<div class="table-wrap"><table class="table"><thead><tr>' +
      '<th scope="col">項目</th><th scope="col">結果</th><th scope="col">判定</th>' +
      "</tr></thead><tbody>" + rows + "</tbody></table></div></section>" +
      '<section class="card"><div class="card-head">' +
      '<h2 class="card-title">検出内容と技術的な根拠</h2></div>' +
      '<ul class="reason-list">' + reasons + "</ul></section>" +
      '<details class="card raw-card"><summary>生データ（JSON）を表示</summary>' +
      '<pre class="raw-json">' + esc(JSON.stringify(raw, null, 2)) + "</pre></details>" +
      '<div class="page-actions">' +
      '<a class="btn btn-secondary" href="#/result/' + encodeURIComponent(result.id) + '">← やさしい表示に戻る</a>' +
      '<a class="btn btn-ghost" href="#/">ホームへ</a></div>'
    );
  }

  // ------------------------------------------------------------------
  // 画面: 保存したメール
  // ------------------------------------------------------------------

  function mailsView() {
    var mails = Store.getMails();
    var results = Store.getAllResults();

    if (!mails.length) {
      return (
        '<div class="page-head"><div><span class="eyebrow">保存したメール</span>' +
        "<h1>危険メールの記録</h1><p class=\"muted\">判定したメールを保存して、あとから見返せます。</p></div></div>" +
        '<section class="card empty-state"><div class="empty-icon" aria-hidden="true">' + mailSvg() + "</div>" +
        "<h2>まだ保存されたメールはありません</h2>" +
        "<p>ドメインを調べたあと、判定結果の画面から「このメールを保存する」を押すとここに追加されます。</p>" +
        '<a class="btn btn-primary" href="#/">ドメインを調べる</a></section>'
      );
    }

    var items = mails.map(function (mail) {
      var r = results[mail.result_id];
      return (
        '<li class="mail-item"><div class="mail-item-main">' +
        '<div class="mail-item-top">' +
        (r ? pill(r.score, r.label) : pill(3, "判定なし")) +
        '<a class="mail-subject" href="#/mails/' + encodeURIComponent(mail.id) + '">' +
        esc(mail.subject) + "</a></div>" +
        '<p class="mail-from">' + esc(mail.sender_name) + " &lt;" + esc(mail.sender_email) + "&gt;</p>" +
        '<p class="mail-dates">受信 ' + fmtDate(mail.received_at) + " ／ 保存 " +
        fmtDate(mail.saved_at) + "</p></div>" +
        '<div class="mail-item-actions">' +
        '<a class="btn btn-secondary btn-sm" href="#/mails/' + encodeURIComponent(mail.id) + '">詳細</a>' +
        '<form data-delete-mail="' + esc(mail.id) + '">' +
        '<button class="btn btn-danger-ghost btn-sm" type="submit">削除</button></form>' +
        "</div></li>"
      );
    }).join("");

    return (
      '<div class="page-head"><div><span class="eyebrow">保存したメール</span>' +
      "<h1>危険メールの記録</h1>" +
      '<p class="muted">判定したメールを保存して、あとから見返せます。保存・削除はデモ動作です。</p></div>' +
      '<a class="btn btn-primary" href="#/">新しく調べる</a></div>' +
      '<section class="card"><div class="card-head"><h2 class="card-title">保存一覧</h2>' +
      '<span class="muted small">' + mails.length + " 件</span></div>" +
      '<ul class="mail-list">' + items + "</ul></section>"
    );
  }

  function mailDetailView(mail) {
    var result = Store.getResult(mail.result_id);
    var fallbackDomain = mail.sender_email.indexOf("@") !== -1
      ? mail.sender_email.split("@").pop()
      : mail.sender_email;

    var resultCard = "";
    if (result) {
      resultCard =
        '<section class="card result-mini lv-' + result.score + '">' +
        '<p class="eyebrow">このメールの判定</p>' +
        '<div class="result-mini-top"><strong>' + esc(result.domain) + "</strong>" +
        pill(result.score, result.label) + "</div>" +
        gauge(result.score) +
        '<p class="result-mini-text">' + esc(result.one_liner) + "</p>" +
        '<div class="stacked-actions">' +
        '<a class="btn btn-secondary btn-sm" href="#/result/' + encodeURIComponent(result.id) + '">判定結果を見る</a>' +
        '<a class="btn btn-ghost btn-sm" href="#/result/' + encodeURIComponent(result.id) + '/detail">くわしい表示</a>' +
        "</div></section>";
    }

    return (
      '<nav class="breadcrumb" aria-label="パンくず"><a href="#/mails">保存したメール</a>' +
      '<span aria-hidden="true">/</span><span>メール詳細</span></nav>' +
      '<div class="detail-head"><div><p class="eyebrow">保存したメール</p>' +
      '<h1 class="mail-detail-subject">' + esc(mail.subject) + "</h1>" +
      '<p class="result-meta">' + esc(mail.sender_name) + " &lt;" + esc(mail.sender_email) + "&gt;</p></div>" +
      (result ? pill(result.score, result.label + "（" + result.score + "/5）", true) : "") + "</div>" +
      '<div class="mail-detail-grid"><section class="card">' +
      '<h2 class="card-title">メール情報</h2><dl class="meta-list">' +
      "<div><dt>差出人</dt><dd>" + esc(mail.sender_name) + " &lt;" + esc(mail.sender_email) + "&gt;</dd></div>" +
      "<div><dt>件名</dt><dd>" + esc(mail.subject) + "</dd></div>" +
      "<div><dt>受信日時</dt><dd>" + fmtDate(mail.received_at) + "</dd></div>" +
      "<div><dt>保存日時</dt><dd>" + fmtDate(mail.saved_at) + "</dd></div>" +
      '<div><dt>対象ドメイン</dt><dd class="mono">' + esc(result ? result.domain : fallbackDomain) + "</dd></div>" +
      "</dl>" +
      '<h3 class="sub-heading">本文（ダミー）</h3>' +
      '<div class="mail-body">' + esc(mail.body_preview) + "</div>" +
      (mail.memo
        ? '<h3 class="sub-heading">メモ</h3><div class="mail-memo">' + esc(mail.memo) + "</div>"
        : "") +
      "</section>" +
      '<aside class="mail-detail-side">' + resultCard +
      '<section class="card"><h2 class="card-title">操作</h2><div class="stacked-actions">' +
      '<form data-delete-mail="' + esc(mail.id) + '">' +
      '<button class="btn btn-danger btn-block" type="submit">このメールを削除</button></form>' +
      '<a class="btn btn-ghost btn-block" href="#/mails">一覧に戻る</a></div>' +
      '<p class="muted small">※ 削除はデモ動作です。</p></section></aside></div>'
    );
  }

  // ------------------------------------------------------------------
  // 画面: 履歴
  // ------------------------------------------------------------------

  function historyView() {
    var history = Store.getHistory();
    if (!history.length) {
      return (
        '<div class="page-head"><div><span class="eyebrow">調査履歴</span>' +
        "<h1>これまでに調べたドメイン</h1></div></div>" +
        '<section class="card empty-state"><h2>まだ調査履歴はありません</h2>' +
        "<p>ホームからメールアドレスまたはドメインを調べると、ここに履歴が残ります。</p>" +
        '<a class="btn btn-primary" href="#/">ドメインを調べる</a></section>'
      );
    }

    var rows = history.map(function (item) {
      return (
        "<tr><td>" + pill(item.score, item.label) + "</td>" +
        '<td class="mono">' + esc(item.domain) + "</td>" +
        '<td class="muted">' + (item.input_type === "email" ? "メールアドレス" : "ドメイン") + "</td>" +
        '<td class="muted">' + fmtDate(item.created_at) + "</td>" +
        '<td class="align-right"><a class="text-link" href="#/result/' +
        encodeURIComponent(item.id) + '">結果を見る →</a></td></tr>'
      );
    }).join("");

    return (
      '<div class="page-head"><div><span class="eyebrow">調査履歴</span>' +
      "<h1>これまでに調べたドメイン</h1>" +
      '<p class="muted">判定したドメインの記録です。デモのためブラウザ内に保存されます。</p></div>' +
      '<a class="btn btn-primary" href="#/">新しく調べる</a></div>' +
      '<section class="card"><div class="card-head"><h2 class="card-title">履歴一覧</h2>' +
      '<span class="muted small">' + history.length + " 件</span></div>" +
      '<div class="table-wrap"><table class="table history-table"><thead><tr>' +
      '<th scope="col">危険度</th><th scope="col">ドメイン</th><th scope="col">入力</th>' +
      '<th scope="col">調査日時</th><th scope="col"></th></tr></thead>' +
      "<tbody>" + rows + "</tbody></table></div></section>"
    );
  }

  function notFoundView() {
    return (
      '<section class="card empty-state"><p class="error-code">404</p>' +
      "<h1>ページが見つかりません</h1>" +
      "<p>URL が変わったか、データがリセットされた可能性があります。</p>" +
      '<a class="btn btn-primary" href="#/">ホームへ戻る</a></section>'
    );
  }

  // ------------------------------------------------------------------
  // ルーティング
  // ------------------------------------------------------------------

  function parseRoute() {
    var hash = window.location.hash.replace(/^#/, "");
    var parts = hash.split("/").filter(Boolean);
    if (!parts.length) return { name: "home" };
    if (parts[0] === "login") return { name: "login" };
    if (parts[0] === "result" && parts[1]) {
      return { name: parts[2] === "detail" ? "detail" : "result", id: parts[1] };
    }
    if (parts[0] === "mails") {
      return parts[1] ? { name: "mail", id: parts[1] } : { name: "mails" };
    }
    if (parts[0] === "history") return { name: "history" };
    return { name: "notfound" };
  }

  function render() {
    var user = Store.getUser();
    var route = parseRoute();

    if (!user && route.name !== "login") {
      window.location.replace("#/login");
      return;
    }
    if (user && route.name === "login") {
      window.location.replace("#/");
      return;
    }

    document.body.className = route.name === "login" ? "login-page" : "";
    appEl.innerHTML = renderRoute(route, user);
    document.documentElement.scrollTop = 0;
    document.body.scrollTop = 0;
    bindEvents(route);
  }

  function renderRoute(route, user) {
    if (route.name === "login") return layout(loginView(), "login");

    if (route.name === "home") return layout(homeView(), "home");

    if (route.name === "result" || route.name === "detail") {
      var result = Store.getResult(route.id);
      if (!result) return layout(notFoundView(), "home");
      return route.name === "result"
        ? layout(resultView(result), "result")
        : layout(detailView(result), "detail");
    }

    if (route.name === "mails") return layout(mailsView(), "mails");

    if (route.name === "mail") {
      var mail = Store.getMail(route.id);
      if (!mail) return layout(notFoundView(), "mails");
      return layout(mailDetailView(mail), "mails");
    }

    if (route.name === "history") return layout(historyView(), "history");

    return layout(notFoundView(), user ? "home" : "login");
  }

  // ------------------------------------------------------------------
  // イベント
  // ------------------------------------------------------------------

  function bindEvents(route) {
    var loginForm = document.getElementById("login-form");
    if (loginForm) {
      loginForm.addEventListener("submit", function (event) {
        event.preventDefault();
        Store.login();
        showFlash("Google アカウントでログインしました（デモ）", "success");
        go("/");
      });
    }

    var logoutForm = document.getElementById("logout-form");
    if (logoutForm) {
      logoutForm.addEventListener("submit", function (event) {
        event.preventDefault();
        Store.logout();
        showFlash("ログアウトしました", "info");
        go("/login");
      });
    }

    var searchForm = document.getElementById("search-form");
    if (searchForm) {
      searchForm.addEventListener("submit", function (event) {
        event.preventDefault();
        var input = document.getElementById("query");
        var value = input ? input.value.trim() : "";
        if (!value) {
          showFlash("メールアドレスまたはドメインを入力してください", "error");
          render();
          return;
        }
        if (value.indexOf(".") === -1) {
          showFlash("ドメインの形式で入力してください（例: example.com）", "error");
          render();
          return;
        }
        var result = Analyzer.analyzeDomain(value);
        Store.addResult(result);
        go("/result/" + encodeURIComponent(result.id));
      });
    }

    Array.prototype.forEach.call(document.querySelectorAll("[data-sample]"), function (button) {
      button.addEventListener("click", function () {
        var input = document.getElementById("query");
        if (!input) return;
        input.value = button.getAttribute("data-sample");
        input.focus();
      });
    });

    var scrollSave = document.getElementById("scroll-save");
    if (scrollSave) {
      scrollSave.addEventListener("click", function () {
        var save = document.getElementById("save");
        if (save && save.scrollIntoView) {
          try {
            save.scrollIntoView({ behavior: "smooth", block: "start" });
          } catch (error) {
            /* スクロール非対応の環境では何もしない */
          }
        }
      });
    }

    var saveForm = document.getElementById("save-form");
    if (saveForm) {
      saveForm.addEventListener("submit", function (event) {
        event.preventDefault();
        var result = Store.getResult(route.id);
        if (!result) return;
        var mail = Store.saveMail({
          result_id: result.id,
          subject: document.getElementById("subject").value,
          sender_name: document.getElementById("sender_name").value,
          sender_email: document.getElementById("sender_email").value,
          memo: document.getElementById("memo").value,
        });
        showFlash("「" + mail.subject + "」を保存しました（デモ）", "success");
        go("/mails");
      });
    }

    Array.prototype.forEach.call(
      document.querySelectorAll("form[data-delete-mail]"),
      function (form) {
        form.addEventListener("submit", function (event) {
          event.preventDefault();
          var id = form.getAttribute("data-delete-mail");
          var mail = Store.getMail(id);
          if (!mail) return;
          if (!window.confirm("「" + mail.subject + "」を削除しますか？")) return;
          Store.deleteMail(id);
          showFlash("「" + mail.subject + "」を削除しました（デモ）", "info");
          go("/mails");
        });
      }
    );
  }

  // ------------------------------------------------------------------
  // 起動
  // ------------------------------------------------------------------

  window.addEventListener("hashchange", render);
  render();
})();
