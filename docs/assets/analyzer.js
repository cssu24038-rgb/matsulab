/*
 * ドメイン判定のダミー実装（ブラウザ用）
 * analyzer.py と同じ考え方で、ドメイン名から決定的に疑似結果を作る。
 * 同じドメインなら何度調べても同じ結果になる。
 */
(function (global) {
  "use strict";

  var LEVELS = {
    1: { label: "安全", oneLiner: "安全なドメインです" },
    2: { label: "ほぼ安全", oneLiner: "ほぼ安全ですが、念のため確認を" },
    3: { label: "注意", oneLiner: "注意が必要なドメインです" },
    4: { label: "危険", oneLiner: "危険な可能性が高いドメインです" },
    5: { label: "非常に危険", oneLiner: "非常に危険なドメインです" },
  };

  var ADVICE = {
    1: "このドメインからのメールは信頼できます。ただし、本文中のリンクや添付ファイルには常に注意してください。",
    2: "大きな問題は見つかりませんでした。心当たりのないメールの場合は、リンクを開く前に差出人を確認しましょう。",
    3: "少し注意が必要です。本文のリンクを開いたり、個人情報を入力したりする前に、送信元を別の方法で確認してください。",
    4: "危険です。リンクや添付ファイルを開かず、返信もせずに削除することをおすすめします。",
    5: "非常に危険です。開かずに削除してください。もし開いてしまった場合は、パスワード変更や管理者への連絡を行ってください。",
  };

  var TRUSTED = {
    "gmail.com": 1,
    "google.com": 1,
    "microsoft.com": 1,
    "apple.com": 1,
    "github.com": 1,
    "amazon.co.jp": 2,
    "yahoo.co.jp": 2,
    "rakuten.co.jp": 2,
  };

  var SUSPICIOUS_TLDS = [
    ".top", ".xyz", ".click", ".zip", ".mov", ".loan",
    ".work", ".buzz", ".rest", ".country", ".cam", ".monster",
  ];

  var BAD_WORDS = [
    "secure", "login", "verify", "account", "update", "support",
    "billing", "paypa", "amaz0n", "rakuten-", "apple-", "microsoft-",
  ];

  var REGISTRARS = [
    "Gandi SAS",
    "GoDaddy.com, LLC",
    "Namecheap, Inc.",
    "お名前.com",
    "Cloudflare, Inc.",
    "Alibaba Cloud Computing Ltd.",
  ];

  // ------------------------------------------------------------------
  // 乱数（ドメイン名から固定シード）
  // ------------------------------------------------------------------

  function hashString(str) {
    var h1 = 0xdeadbeef;
    var h2 = 0x41c6ce57;
    for (var i = 0; i < str.length; i += 1) {
      var ch = str.charCodeAt(i);
      h1 = Math.imul(h1 ^ ch, 2654435761);
      h2 = Math.imul(h2 ^ ch, 1597334677);
    }
    h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
    h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
    return 4294967296 * (2097151 & h2) + (h1 >>> 0);
  }

  function mulberry32(seed) {
    var a = seed >>> 0;
    return function () {
      a |= 0;
      a = (a + 0x6d2b79f5) | 0;
      var t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  function pick(rng, list) {
    return list[Math.floor(rng() * list.length)];
  }

  function weightedPick(rng, list, weights) {
    var total = weights.reduce(function (sum, w) { return sum + w; }, 0);
    var target = rng() * total;
    for (var i = 0; i < list.length; i += 1) {
      target -= weights[i];
      if (target <= 0) return list[i];
    }
    return list[list.length - 1];
  }

  // ------------------------------------------------------------------
  // 入力の正規化
  // ------------------------------------------------------------------

  function normalizeInput(raw) {
    var value = String(raw || "").trim();
    var isEmail = value.indexOf("@") !== -1;
    var domain = isEmail ? value.split("@").pop() : value;
    domain = domain.toLowerCase().trim().replace(/\.+$/, "");
    domain = domain.replace(/^https?:\/\//, "");
    domain = domain.split("/")[0].split(":")[0];
    return {
      domain: domain,
      inputType: isEmail ? "email" : "domain",
    };
  }

  // ------------------------------------------------------------------
  // 疑似チェック
  // ------------------------------------------------------------------

  function trustedChecks(rng) {
    return {
      spf: true,
      dkim: true,
      dmarc: true,
      age_days: pick(rng, [1200, 1800, 2400, 3200, 4500]),
      vt_detections: 0,
      vt_total: 94,
      blacklist: 0,
      ssl: true,
      registrar: pick(rng, REGISTRARS.slice(0, 3)),
      ip: "142.250." + Math.floor(rng() * 250 + 1) + "." + Math.floor(rng() * 250 + 1),
      mx: "mx1." + pick(rng, ["example-mail", "mail", "smtp"]) + ".net",
      suspicious_tld: false,
      bad_word: false,
    };
  }

  function buildChecks(rng, domain) {
    var suspiciousTld = SUSPICIOUS_TLDS.some(function (tld) {
      return domain.slice(-tld.length) === tld;
    });
    var badWord = BAD_WORDS.some(function (word) { return domain.indexOf(word) !== -1; });

    var riskBias = 0.25;
    if (suspiciousTld) riskBias += 0.35;
    if (badWord) riskBias += 0.25;
    if ((domain.match(/-/g) || []).length >= 2) riskBias += 0.1;
    riskBias = Math.min(riskBias, 0.85);

    var highRisk = riskBias > 0.5;
    return {
      spf: rng() > riskBias,
      dkim: rng() > Math.min(riskBias + 0.05, 0.95),
      dmarc: rng() > Math.min(riskBias + 0.1, 0.95),
      age_days: weightedPick(
        rng,
        [4, 12, 28, 60, 150, 400, 800, 1600, 2600, 4000],
        highRisk ? [3, 3, 3, 2, 2, 2, 2, 1, 1, 1] : [1, 1, 1, 2, 2, 3, 3, 3, 2, 2]
      ),
      vt_detections: weightedPick(
        rng,
        [0, 1, 2, 4, 7, 12, 18],
        highRisk ? [5, 1, 1, 1, 1, 1, 1] : [14, 2, 1, 1, 0, 0, 0]
      ),
      vt_total: 94,
      blacklist: weightedPick(
        rng,
        [0, 1, 2, 3, 5],
        highRisk ? [4, 2, 2, 2, 2] : [16, 2, 1, 0, 0]
      ),
      ssl: rng() > riskBias * 0.5,
      registrar: pick(rng, REGISTRARS),
      ip:
        Math.floor(rng() * 197 + 23) + "." +
        Math.floor(rng() * 254 + 1) + "." +
        Math.floor(rng() * 254 + 1) + "." +
        Math.floor(rng() * 254 + 1),
      mx: (rng() > 0.3 ? "mx." : "mail.") + domain,
      suspicious_tld: suspiciousTld,
      bad_word: badWord,
    };
  }

  function scoreChecks(checks) {
    var points = 0;
    if (!checks.spf) points += 2;
    if (!checks.dkim) points += 1;
    if (!checks.dmarc) points += 2;
    if (checks.age_days < 30) points += 2;
    else if (checks.age_days < 180) points += 1;
    if (checks.vt_detections >= 5) points += 3;
    else if (checks.vt_detections >= 1) points += 2;
    if (checks.blacklist >= 3) points += 3;
    else if (checks.blacklist >= 1) points += 2;
    if (checks.suspicious_tld) points += 2;
    if (checks.bad_word) points += 1;
    if (!checks.ssl) points += 1;

    if (points <= 1) return 1;
    if (points <= 3) return 2;
    if (points <= 5) return 3;
    if (points <= 7) return 4;
    return 5;
  }

  // ------------------------------------------------------------------
  // 表示用データ
  // ------------------------------------------------------------------

  function ageText(days) {
    if (days < 30) return days + "日前";
    if (days < 365) return "約" + Math.floor(days / 30) + "か月前";
    return "約" + Math.floor(days / 365) + "年前";
  }

  function buildReasons(checks, score) {
    var reasons = [];

    if (!checks.spf) {
      reasons.push({
        title: "送信元のなりすまし対策（SPF）が未設定",
        detail: "このドメインは「なりすまし」を防ぐ設定がされておらず、別人を装ったメールが送られる可能性があります。",
        technical: "SPF レコードが存在しない、または送信元 IP を許可していません。Return-Path のドメインと送信元 IP の整合性を検証できません。",
        severity: "bad",
      });
    }
    if (!checks.dmarc) {
      reasons.push({
        title: "メールの偽装を防ぐ設定（DMARC）が不十分",
        detail: "送信元が本物かどうかを確認する仕組みが整っていません。詐欺メールに悪用されるおそれがあります。",
        technical: "DMARC レコードが未設定、または p=none でポリシーが適用されていません。From ヘッダのドメインと SPF/DKIM のアラインメントが保証されません。",
        severity: score >= 4 ? "bad" : "warn",
      });
    }
    if (!checks.dkim) {
      reasons.push({
        title: "メールの改ざん検知（DKIM）が確認できません",
        detail: "メールの内容が途中で書き換えられていないかを確認する仕組みが見つかりませんでした。",
        technical: "DKIM 署名用のセレクタを解決できませんでした。本文ハッシュの検証ができないため、転送経路での改ざん検知が不可能です。",
        severity: "warn",
      });
    }
    if (checks.age_days < 30) {
      reasons.push({
        title: "ドメインが最近登録されたばかりです",
        detail: "このドメインは登録から" + ageText(checks.age_days) + "しか経っていません。短期間だけ使われるドメインは詐欺に使われやすい傾向があります。",
        technical: "WHOIS の登録日は " + checks.age_days + " 日前。短命ドメインは使い捨てのフィッシングサイトで多用されます。",
        severity: "bad",
      });
    } else if (checks.age_days < 180) {
      reasons.push({
        title: "ドメインの利用歴が短めです",
        detail: "登録から" + ageText(checks.age_days) + "のドメインです。信頼できるか判断するには情報が少なめです。",
        technical: "WHOIS の登録日は " + checks.age_days + " 日前。新規登録ドメインは評判データが蓄積されていません。",
        severity: "warn",
      });
    }
    if (checks.vt_detections >= 1) {
      reasons.push({
        title: "ウイルス対策サービスが不審と判定",
        detail: "VirusTotal の調査で、" + checks.vt_total + " 件中 " + checks.vt_detections + " 件がこのドメインを危険と判定しました。",
        technical: "VirusTotal の検出数: " + checks.vt_detections + "/" + checks.vt_total + "。複数のエンジンがマルウェア配布・フィッシングとして検出しています。",
        severity: checks.vt_detections >= 5 ? "bad" : "warn",
      });
    }
    if (checks.blacklist >= 1) {
      reasons.push({
        title: "危険なドメインのリストに登録されています",
        detail: "このドメインは、迷惑メールや詐欺に使われたとして登録されています。",
        technical: "公開ブラックリスト " + checks.blacklist + " 件に登録。Spamhaus 等の DNSBL に該当します。",
        severity: checks.blacklist >= 3 ? "bad" : "warn",
      });
    }
    if (checks.suspicious_tld) {
      reasons.push({
        title: "注意が必要な種類のドメインです",
        detail: "このドメインは、詐欺サイトで使われることの多い末尾（.top など）を持っています。",
        technical: "gTLD の悪用率が高い TLD に該当します。登録コストが低く、使い捨てドメインとして利用されやすい傾向があります。",
        severity: "warn",
      });
    }
    if (checks.bad_word) {
      reasons.push({
        title: "ドメイン名に不安をあおる言葉が含まれています",
        detail: "「secure」「login」など、本物らしく見せるための言葉がドメイン名に含まれています。",
        technical: "ブランド名や認証関連のキーワードを含む typosquatting の可能性があります。正規ドメインとの編集距離を確認してください。",
        severity: "warn",
      });
    }
    if (!checks.ssl) {
      reasons.push({
        title: "安全な通信（HTTPS）が確認できません",
        detail: "このドメインは暗号化されていない通信を使っている可能性があります。個人情報を入力しないでください。",
        technical: "TLS 証明書の検証に失敗、または HTTPS での接続が確立できませんでした。",
        severity: "warn",
      });
    }

    if (score <= 2) {
      if (checks.spf && checks.dkim && checks.dmarc) {
        reasons.push({
          title: "なりすまし対策がしっかり設定されています",
          detail: "送信元が本物かどうかを確認する仕組み（SPF・DKIM・DMARC）がすべて整っています。",
          technical: "SPF: pass / DKIM: pass / DMARC: p=reject。From ドメインのアラインメントが成立しています。",
          severity: "good",
        });
      }
      reasons.push({
        title: "ドメインの利用歴が長い",
        detail: "このドメインは登録から" + ageText(checks.age_days) + "経っており、継続的に使われています。",
        technical: "WHOIS 登録日から " + checks.age_days + " 日経過。長期間運用されているドメインは信頼性が高い傾向があります。",
        severity: "good",
      });
      reasons.push({
        title: "評判データベースで問題が見つかりません",
        detail: "ウイルス対策サービスや危険ドメインのリストで、問題は見つかりませんでした。",
        technical: "VirusTotal 検出 0/" + checks.vt_total + " 件、ブラックリスト登録 0 件。",
        severity: "good",
      });
    }

    if (reasons.length < 3) {
      reasons.push({
        title: "判定に使える情報が限られています",
        detail: "このドメインについて公開されている情報が少ないため、判定は参考程度にしてください。",
        technical: "WHOIS・DNS・評判データの取得結果が一部不足しています。追加の調査を推奨します。",
        severity: "info",
      });
    }
    if (reasons.length < 3) {
      reasons.push({
        title: "メール本文は判定していません",
        detail: "このアプリはドメインだけを調べます。本文の内容や添付ファイルは別途確認してください。",
        technical: "本バージョンはドメイン評価のみを対象とし、本文・添付ファイルのスキャンは行いません。",
        severity: "info",
      });
    }

    return reasons;
  }

  function buildEvidence(checks) {
    function status(ok, warn) {
      return ok ? "good" : warn ? "warn" : "bad";
    }
    var age = checks.age_days;
    return [
      { label: "SPF", value: checks.spf ? "pass" : "未設定 / fail", status: status(checks.spf) },
      { label: "DKIM", value: checks.dkim ? "pass" : "署名を確認できず", status: status(checks.dkim) },
      { label: "DMARC", value: checks.dmarc ? "p=reject" : "未設定", status: status(checks.dmarc) },
      {
        label: "ドメイン登録から",
        value: age + " 日（" + ageText(age) + "）",
        status: age >= 365 ? "good" : age >= 30 ? "warn" : "bad",
      },
      {
        label: "VirusTotal 検出",
        value: checks.vt_detections + " / " + checks.vt_total + " エンジン",
        status: checks.vt_detections === 0 ? "good" : checks.vt_detections < 5 ? "warn" : "bad",
      },
      {
        label: "ブラックリスト",
        value: checks.blacklist + " 件",
        status: checks.blacklist === 0 ? "good" : checks.blacklist < 3 ? "warn" : "bad",
      },
      { label: "TLS / HTTPS", value: checks.ssl ? "有効" : "確認できず", status: status(checks.ssl, true) },
      { label: "レジストラ", value: checks.registrar, status: "info" },
      { label: "A レコード", value: checks.ip, status: "info" },
      { label: "MX レコード", value: checks.mx, status: "info" },
    ];
  }

  function newId() {
    return Math.random().toString(16).slice(2, 12);
  }

  function analyzeDomain(rawInput) {
    var normalized = normalizeInput(rawInput);
    var domain = normalized.domain;
    var rng = mulberry32(hashString(domain));
    var checks;
    var score;

    if (Object.prototype.hasOwnProperty.call(TRUSTED, domain)) {
      checks = trustedChecks(rng);
      score = TRUSTED[domain];
    } else {
      checks = buildChecks(rng, domain);
      score = scoreChecks(checks);
    }

    var level = LEVELS[score];
    return {
      id: newId(),
      raw_input: String(rawInput || "").trim(),
      domain: domain,
      input_type: normalized.inputType,
      score: score,
      label: level.label,
      one_liner: level.oneLiner,
      advice: ADVICE[score],
      reasons: buildReasons(checks, score),
      evidence: buildEvidence(checks),
      created_at: new Date().toISOString(),
    };
  }

  var api = {
    LEVELS: LEVELS,
    ADVICE: ADVICE,
    normalizeInput: normalizeInput,
    analyzeDomain: analyzeDomain,
  };

  global.DomainAnalyzer = api;
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
})(typeof window !== "undefined" ? window : globalThis);
