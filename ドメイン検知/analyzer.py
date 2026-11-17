"""ドメイン判定のダミー実装。

本番では VirusTotal API や DNS ルックアップ（SPF / DKIM / DMARC）に
置き換える。ここでは入力ドメインから決定的に疑似データを作り、
画面遷移の確認に必要な判定結果を返す。

差し替え方:
    analyze(raw_input) が Result を返すように実装すればよい。
"""

from __future__ import annotations

import hashlib
import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List

# ---------------------------------------------------------------------------
# 5段階のレベル定義
# ---------------------------------------------------------------------------

LEVELS = {
    1: {"label": "安全", "short": "安全", "one_liner": "安全なドメインです"},
    2: {"label": "ほぼ安全", "short": "ほぼ安全", "one_liner": "ほぼ安全ですが、念のため確認を"},
    3: {"label": "注意", "short": "注意", "one_liner": "注意が必要なドメインです"},
    4: {"label": "危険", "short": "危険", "one_liner": "危険な可能性が高いドメインです"},
    5: {"label": "非常に危険", "short": "非常に危険", "one_liner": "非常に危険なドメインです"},
}

LEVEL_ADVICE = {
    1: "このドメインからのメールは信頼できます。ただし、本文中のリンクや添付ファイルには常に注意してください。",
    2: "大きな問題は見つかりませんでした。心当たりのないメールの場合は、リンクを開く前に差出人を確認しましょう。",
    3: "少し注意が必要です。本文のリンクを開いたり、個人情報を入力したりする前に、送信元を別の方法で確認してください。",
    4: "危険です。リンクや添付ファイルを開かず、返信もせずに削除することをおすすめします。",
    5: "非常に危険です。開かずに削除してください。もし開いてしまった場合は、パスワード変更や管理者への連絡を行ってください。",
}

# 安全とみなす既知ドメイン（デモ用）
TRUSTED = {
    "gmail.com": 1,
    "google.com": 1,
    "microsoft.com": 1,
    "apple.com": 1,
    "github.com": 1,
    "amazon.co.jp": 2,
    "yahoo.co.jp": 2,
    "rakuten.co.jp": 2,
}

SUSPICIOUS_TLDS = (
    ".top", ".xyz", ".click", ".zip", ".mov", ".loan",
    ".work", ".buzz", ".rest", ".country", ".cam", ".monster",
)

BAD_WORDS = (
    "secure", "login", "verify", "account", "update", "support",
    "billing", "paypa", "amaz0n", "rakuten-", "apple-", "microsoft-",
)

REGISTRARS = (
    "Gandi SAS",
    "GoDaddy.com, LLC",
    "Namecheap, Inc.",
    "お名前.com",
    "Cloudflare, Inc.",
    "Alibaba Cloud Computing Ltd.",
)


# ---------------------------------------------------------------------------
# データ構造
# ---------------------------------------------------------------------------

@dataclass
class Reason:
    title: str
    detail: str          # やさしい表示（知識がない人向け）
    technical: str       # くわしい表示（知識がある人向け）
    severity: str        # good / info / warn / bad


@dataclass
class Evidence:
    label: str
    value: str
    status: str          # good / warn / bad / info


@dataclass
class Result:
    id: str
    raw_input: str
    domain: str
    input_type: str      # "email" / "domain"
    score: int
    label: str
    one_liner: str
    advice: str
    reasons: List[Reason] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)

    @property
    def color_key(self) -> str:
        return f"lv-{self.score}"

    def raw_json(self) -> dict:
        return {
            "domain": self.domain,
            "score": self.score,
            "label": self.label,
            "checked_at": self.created_at.isoformat(timespec="seconds"),
            "checks": {e.label: e.value for e in self.evidence},
        }


# ---------------------------------------------------------------------------
# 入力の正規化
# ---------------------------------------------------------------------------

def normalize_input(raw: str) -> tuple[str, str]:
    """入力から (ドメイン, 種別) を取り出す。"""
    value = raw.strip()
    is_email = "@" in value

    if is_email:
        domain = value.rsplit("@", 1)[1]
    else:
        domain = value

    domain = domain.strip().lower().rstrip(".")
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split("/", 1)[0].split(":", 1)[0]

    return domain, ("email" if is_email else "domain")


# ---------------------------------------------------------------------------
# 判定ロジック（ダミー）
# ---------------------------------------------------------------------------

def _rng_for(domain: str) -> random.Random:
    digest = hashlib.md5(domain.encode("utf-8")).hexdigest()
    return random.Random(int(digest, 16))


def _points_to_score(points: int) -> int:
    if points <= 1:
        return 1
    if points <= 3:
        return 2
    if points <= 5:
        return 3
    if points <= 7:
        return 4
    return 5


def _build_trusted_checks(rng: random.Random) -> dict:
    return {
        "spf": True,
        "dkim": True,
        "dmarc": True,
        "age_days": rng.choice([1200, 1800, 2400, 3200, 4500]),
        "vt_detections": 0,
        "vt_total": 94,
        "blacklist": 0,
        "ssl": True,
        "registrar": rng.choice(REGISTRARS[:3]),
        "ip": f"142.250.{rng.randint(1, 250)}.{rng.randint(1, 250)}",
        "mx": f"mx1.{rng.choice(['example-mail', 'mail', 'smtp'])}.net",
    }


def _build_checks(rng: random.Random, domain: str) -> dict:
    suspicious_tld = domain.endswith(SUSPICIOUS_TLDS)
    bad_word = any(w in domain for w in BAD_WORDS)

    risk_bias = 0.25
    if suspicious_tld:
        risk_bias += 0.35
    if bad_word:
        risk_bias += 0.25
    if domain.count("-") >= 2:
        risk_bias += 0.10
    risk_bias = min(risk_bias, 0.85)

    age_options = [4, 12, 28, 60, 150, 400, 800, 1600, 2600, 4000]
    age_weights = [3, 3, 3, 2, 2, 2, 2, 1, 1, 1] if risk_bias > 0.5 else [1, 1, 1, 2, 2, 3, 3, 3, 2, 2]

    return {
        "spf": rng.random() > risk_bias,
        "dkim": rng.random() > min(risk_bias + 0.05, 0.95),
        "dmarc": rng.random() > min(risk_bias + 0.10, 0.95),
        "age_days": rng.choices(age_options, weights=age_weights, k=1)[0],
        "vt_detections": rng.choices(
            [0, 1, 2, 4, 7, 12, 18],
            weights=([5, 1, 1, 1, 1, 1, 1] if risk_bias > 0.5 else [14, 2, 1, 1, 0, 0, 0]),
            k=1,
        )[0],
        "vt_total": 94,
        "blacklist": rng.choices(
            [0, 1, 2, 3, 5],
            weights=([4, 2, 2, 2, 2] if risk_bias > 0.5 else [16, 2, 1, 0, 0]),
            k=1,
        )[0],
        "ssl": rng.random() > risk_bias * 0.5,
        "registrar": rng.choice(REGISTRARS),
        "ip": f"{rng.randint(23, 220)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}",
        "mx": f"mx.{domain}" if rng.random() > 0.3 else f"mail.{domain}",
        "suspicious_tld": suspicious_tld,
        "bad_word": bad_word,
    }


def _score_checks(checks: dict) -> int:
    points = 0
    if not checks["spf"]:
        points += 2
    if not checks["dkim"]:
        points += 1
    if not checks["dmarc"]:
        points += 2
    if checks["age_days"] < 30:
        points += 2
    elif checks["age_days"] < 180:
        points += 1
    if checks["vt_detections"] >= 5:
        points += 3
    elif checks["vt_detections"] >= 1:
        points += 2
    if checks["blacklist"] >= 3:
        points += 3
    elif checks["blacklist"] >= 1:
        points += 2
    if checks.get("suspicious_tld"):
        points += 2
    if checks.get("bad_word"):
        points += 1
    if not checks["ssl"]:
        points += 1
    return _points_to_score(points)


# ---------------------------------------------------------------------------
# 表示用データの組み立て
# ---------------------------------------------------------------------------

def _age_text(days: int) -> str:
    if days < 30:
        return f"{days}日前"
    if days < 365:
        return f"約{days // 30}か月前"
    return f"約{days // 365}年前"


def _build_reasons(checks: dict, score: int) -> List[Reason]:
    reasons: List[Reason] = []

    if not checks["spf"]:
        reasons.append(Reason(
            "送信元のなりすまし対策（SPF）が未設定",
            "このドメインは「なりすまし」を防ぐ設定がされておらず、別人を装ったメールが送られる可能性があります。",
            "SPF レコードが存在しない、または送信元 IP を許可していません。Return-Path のドメインと送信元 IP の整合性を検証できません。",
            "bad",
        ))
    if not checks["dmarc"]:
        reasons.append(Reason(
            "メールの偽装を防ぐ設定（DMARC）が不十分",
            "送信元が本物かどうかを確認する仕組みが整っていません。詐欺メールに悪用されるおそれがあります。",
            "DMARC レコードが未設定、または p=none でポリシーが適用されていません。From ヘッダのドメインと SPF/DKIM のアラインメントが保証されません。",
            "bad" if score >= 4 else "warn",
        ))
    if not checks["dkim"]:
        reasons.append(Reason(
            "メールの改ざん検知（DKIM）が確認できません",
            "メールの内容が途中で書き換えられていないかを確認する仕組みが見つかりませんでした。",
            "DKIM 署名用のセレクタを解決できませんでした。本文ハッシュの検証ができないため、転送経路での改ざん検知が不可能です。",
            "warn",
        ))
    if checks["age_days"] < 30:
        reasons.append(Reason(
            "ドメインが最近登録されたばかりです",
            f"このドメインは登録から{_age_text(checks['age_days'])}しか経っていません。短期間だけ使われるドメインは詐欺に使われやすい傾向があります。",
            f"WHOIS の登録日は {checks['age_days']} 日前。短命ドメインは使い捨てのフィッシングサイトで多用されます。",
            "bad",
        ))
    elif checks["age_days"] < 180:
        reasons.append(Reason(
            "ドメインの利用歴が短めです",
            f"登録から{_age_text(checks['age_days'])}のドメインです。信頼できるか判断するには情報が少なめです。",
            f"WHOIS の登録日は {checks['age_days']} 日前。新規登録ドメインは評判データが蓄積されていません。",
            "warn",
        ))
    if checks["vt_detections"] >= 1:
        severity = "bad" if checks["vt_detections"] >= 5 else "warn"
        reasons.append(Reason(
            "ウイルス対策サービスが不審と判定",
            f"VirusTotal の調査で、{checks['vt_total']} 件中 {checks['vt_detections']} 件がこのドメインを危険と判定しました。",
            f"VirusTotal の検出数: {checks['vt_detections']}/{checks['vt_total']}。複数のエンジンがマルウェア配布・フィッシングとして検出しています。",
            severity,
        ))
    if checks["blacklist"] >= 1:
        reasons.append(Reason(
            "危険なドメインのリストに登録されています",
            "このドメインは、迷惑メールや詐欺に使われたとして登録されています。",
            f"公開ブラックリスト {checks['blacklist']} 件に登録。Spamhaus 等の DNSBL に該当します。",
            "bad" if checks["blacklist"] >= 3 else "warn",
        ))
    if checks.get("suspicious_tld"):
        reasons.append(Reason(
            "注意が必要な種類のドメインです",
            "このドメインは、詐欺サイトで使われることの多い末尾（.top など）を持っています。",
            "gTLD の悪用率が高い TLD に該当します。登録コストが低く、使い捨てドメインとして利用されやすい傾向があります。",
            "warn",
        ))
    if checks.get("bad_word"):
        reasons.append(Reason(
            "ドメイン名に不安をあおる言葉が含まれています",
            "「secure」「login」など、本物らしく見せるための言葉がドメイン名に含まれています。",
            "ブランド名や認証関連のキーワードを含む typosquatting の可能性があります。正規ドメインとの編集距離を確認してください。",
            "warn",
        ))
    if not checks["ssl"]:
        reasons.append(Reason(
            "安全な通信（HTTPS）が確認できません",
            "このドメインは暗号化されていない通信を使っている可能性があります。個人情報を入力しないでください。",
            "TLS 証明書の検証に失敗、または HTTPS での接続が確立できませんでした。",
            "warn",
        ))

    # 安全側の理由（良い点）
    if score <= 2:
        if checks["spf"] and checks["dkim"] and checks["dmarc"]:
            reasons.append(Reason(
                "なりすまし対策がしっかり設定されています",
                "送信元が本物かどうかを確認する仕組み（SPF・DKIM・DMARC）がすべて整っています。",
                "SPF: pass / DKIM: pass / DMARC: p=reject。From ドメインのアラインメントが成立しています。",
                "good",
            ))
        reasons.append(Reason(
            "ドメインの利用歴が長い",
            f"このドメインは登録から{_age_text(checks['age_days'])}経っており、継続的に使われています。",
            f"WHOIS 登録日から {checks['age_days']} 日経過。長期間運用されているドメインは信頼性が高い傾向があります。",
            "good",
        ))
        reasons.append(Reason(
            "評判データベースで問題が見つかりません",
            "ウイルス対策サービスや危険ドメインのリストで、問題は見つかりませんでした。",
            f"VirusTotal 検出 0/{checks['vt_total']} 件、ブラックリスト登録 0 件。",
            "good",
        ))

    # 理由が少ない場合の補足
    if len(reasons) < 3:
        reasons.append(Reason(
            "判定に使える情報が限られています",
            "このドメインについて公開されている情報が少ないため、判定は参考程度にしてください。",
            "WHOIS・DNS・評判データの取得結果が一部不足しています。追加の調査を推奨します。",
            "info",
        ))
    if len(reasons) < 3:
        reasons.append(Reason(
            "メール本文は判定していません",
            "このアプリはドメインだけを調べます。本文の内容や添付ファイルは別途確認してください。",
            "本バージョンはドメイン評価のみを対象とし、本文・添付ファイルのスキャンは行いません。",
            "info",
        ))

    return reasons


def _build_evidence(checks: dict) -> List[Evidence]:
    def status(ok: bool, warn: bool = False) -> str:
        return "good" if ok else ("warn" if warn else "bad")

    age = checks["age_days"]
    evidence = [
        Evidence("SPF", "pass" if checks["spf"] else "未設定 / fail", status(checks["spf"])),
        Evidence("DKIM", "pass" if checks["dkim"] else "署名を確認できず", status(checks["dkim"])),
        Evidence("DMARC", "p=reject" if checks["dmarc"] else "未設定", status(checks["dmarc"])),
        Evidence(
            "ドメイン登録から",
            f"{age} 日（{_age_text(age)}）",
            "good" if age >= 365 else ("warn" if age >= 30 else "bad"),
        ),
        Evidence(
            "VirusTotal 検出",
            f"{checks['vt_detections']} / {checks['vt_total']} エンジン",
            "good" if checks["vt_detections"] == 0 else ("warn" if checks["vt_detections"] < 5 else "bad"),
        ),
        Evidence(
            "ブラックリスト",
            f"{checks['blacklist']} 件",
            "good" if checks["blacklist"] == 0 else ("warn" if checks["blacklist"] < 3 else "bad"),
        ),
        Evidence("TLS / HTTPS", "有効" if checks["ssl"] else "確認できず", status(checks["ssl"], warn=True)),
        Evidence("レジストラ", checks["registrar"], "info"),
        Evidence("A レコード", checks["ip"], "info"),
        Evidence("MX レコード", checks["mx"], "info"),
    ]
    return evidence


# ---------------------------------------------------------------------------
# 公開 API
# ---------------------------------------------------------------------------

def analyze(raw_input: str) -> Result:
    """入力（メールアドレス or ドメイン）からダミーの判定結果を作る。"""
    domain, input_type = normalize_input(raw_input)
    rng = _rng_for(domain)

    trusted_score = TRUSTED.get(domain)
    if trusted_score:
        checks = _build_trusted_checks(rng)
        score = trusted_score
        # 既知ドメインはレベルに合わせて軽微な指摘だけ追加
        checks["suspicious_tld"] = False
        checks["bad_word"] = False
    else:
        checks = _build_checks(rng, domain)
        score = _score_checks(checks)

    level = LEVELS[score]
    return Result(
        id=uuid.uuid4().hex[:10],
        raw_input=raw_input.strip(),
        domain=domain,
        input_type=input_type,
        score=score,
        label=level["label"],
        one_liner=level["one_liner"],
        advice=LEVEL_ADVICE[score],
        reasons=_build_reasons(checks, score),
        evidence=_build_evidence(checks),
        created_at=datetime.now(),
    )
