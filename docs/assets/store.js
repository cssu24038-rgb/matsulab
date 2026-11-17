/*
 * 画面確認用のデータストア（ブラウザ用）
 * localStorage に保存する。localStorage が使えない環境では
 * ページを開いている間だけメモリに保持する。
 */
(function (global) {
  "use strict";

  var Analyzer = global.DomainAnalyzer;
  var PREFIX = "dc_demo_v1_";
  var memory = {};

  function read(key, fallback) {
    try {
      var raw = global.localStorage.getItem(PREFIX + key);
      if (raw !== null) return JSON.parse(raw);
    } catch (error) {
      /* localStorage が使えない場合はメモリを使う */
    }
    return Object.prototype.hasOwnProperty.call(memory, key) ? memory[key] : fallback;
  }

  function write(key, value) {
    memory[key] = value;
    try {
      global.localStorage.setItem(PREFIX + key, JSON.stringify(value));
    } catch (error) {
      /* 保存できなくても画面は動かす */
    }
  }

  function getAllResults() {
    return read("results", {});
  }

  function getResult(id) {
    return getAllResults()[id] || null;
  }

  function getHistory(limit) {
    var results = getAllResults();
    var ids = read("history", []);
    var list = ids
      .map(function (id) { return results[id]; })
      .filter(Boolean)
      .sort(function (a, b) {
        return new Date(b.created_at) - new Date(a.created_at);
      });
    return typeof limit === "number" ? list.slice(0, limit) : list;
  }

  function addResult(result) {
    var results = getAllResults();
    results[result.id] = result;
    write("results", results);

    var history = read("history", []);
    if (history.indexOf(result.id) === -1) {
      history.unshift(result.id);
      write("history", history);
    }
    return result;
  }

  function getMails() {
    return read("mails", []);
  }

  function getMail(id) {
    return getMails().filter(function (mail) { return mail.id === id; })[0] || null;
  }

  function saveMail(fields) {
    var now = new Date().toISOString();
    var mail = {
      id: Math.random().toString(16).slice(2, 12),
      subject: (fields.subject || "").trim() || "（件名なし）",
      sender_name: (fields.sender_name || "").trim() || "不明な差出人",
      sender_email: (fields.sender_email || "").trim() || "unknown@example.com",
      received_at: now,
      saved_at: now,
      result_id: fields.result_id,
      memo: (fields.memo || "").trim(),
      body_preview:
        "お客様のアカウントに異常なアクセスを検知しました。" +
        "以下のリンクから本人確認をお願いします。" +
        "（この本文はダミーです）",
    };
    var mails = getMails();
    mails.unshift(mail);
    write("mails", mails);
    return mail;
  }

  function deleteMail(id) {
    var mails = getMails();
    var next = mails.filter(function (mail) { return mail.id !== id; });
    if (next.length === mails.length) return false;
    write("mails", next);
    return true;
  }

  function getUser() {
    return read("user", null);
  }

  function login() {
    var user = { name: "山田 太郎", email: "taro.yamada@gmail.com" };
    write("user", user);
    return user;
  }

  function logout() {
    write("user", null);
  }

  function seedIfNeeded() {
    if (read("seeded", false)) return;

    var now = Date.now();
    var samples = [
      { domain: "amazon.co.jp", offset: 2 * 86400000 + 3 * 3600000 },
      { domain: "paypa1-secure.top", offset: 6 * 3600000 },
      { domain: "gmail.com", offset: 86400000 + 5 * 3600000 },
      { domain: "support-center.net", offset: 3 * 86400000 + 2 * 3600000 },
      { domain: "bank-alert.net", offset: 4 * 86400000 + 3600000 },
    ];

    var results = {};
    var history = [];
    var byDomain = {};

    samples.forEach(function (sample) {
      var result = Analyzer.analyzeDomain(sample.domain);
      result.created_at = new Date(now - sample.offset).toISOString();
      results[result.id] = result;
      history.push(result.id);
      byDomain[sample.domain] = result;
    });

    write("results", results);
    write("history", history);

    var mails = [
      {
        id: "seedmail001",
        subject: "【重要】アカウントの本人確認が必要です",
        sender_name: "PayPal サポート",
        sender_email: "support@paypa1-secure.top",
        received_at: new Date(now - 7 * 3600000).toISOString(),
        saved_at: new Date(now - 5 * 3600000).toISOString(),
        result_id: byDomain["paypa1-secure.top"].id,
        memo: "身に覚えのない本人確認メール。リンク先が不審。",
        body_preview:
          "お客様のアカウントに異常なアクセスを検知しました。" +
          "以下のリンクから本人確認をお願いします。" +
          "（この本文はダミーです）",
      },
      {
        id: "seedmail002",
        subject: "ご注文ありがとうございます（注文番号 123-4567890）",
        sender_name: "Amazon.co.jp",
        sender_email: "no-reply@amazon.co.jp",
        received_at: new Date(now - 2 * 86400000 - 4 * 3600000).toISOString(),
        saved_at: new Date(now - 2 * 86400000 - 3 * 3600000).toISOString(),
        result_id: byDomain["amazon.co.jp"].id,
        memo: "",
        body_preview:
          "このたびはご注文いただきありがとうございます。" +
          "商品の発送準備が整いましたことをお知らせします。" +
          "（この本文はダミーです）",
      },
    ];
    write("mails", mails);
    write("seeded", true);
  }

  seedIfNeeded();

  var api = {
    getUser: getUser,
    login: login,
    logout: logout,
    getAllResults: getAllResults,
    getResult: getResult,
    getHistory: getHistory,
    addResult: addResult,
    getMails: getMails,
    getMail: getMail,
    saveMail: saveMail,
    deleteMail: deleteMail,
  };

  global.DomainStore = api;
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
})(typeof window !== "undefined" ? window : globalThis);
