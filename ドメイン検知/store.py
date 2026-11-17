"""画面確認用のインメモリストア。

DB 導入までの仮置き。アプリを再起動すると初期データに戻る。
後から SQLite に置き換えるときは、このモジュールの関数だけを
DB アクセスに差し替えればよい。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import uuid

from analyzer import Result, analyze


@dataclass
class Mail:
    id: str
    subject: str
    sender_name: str
    sender_email: str
    received_at: datetime
    saved_at: datetime
    result_id: str
    memo: str = ""
    body_preview: str = ""


RESULTS: Dict[str, Result] = {}
HISTORY: List[str] = []          # 新しい順
SAVED_MAILS: List[Mail] = []     # 新しい順


def add_result(result: Result) -> Result:
    RESULTS[result.id] = result
    HISTORY.insert(0, result.id)
    return result


def get_result(result_id: str) -> Optional[Result]:
    return RESULTS.get(result_id)


def get_history(limit: Optional[int] = None) -> List[Result]:
    results = [RESULTS[i] for i in HISTORY if i in RESULTS]
    results.sort(key=lambda r: r.created_at, reverse=True)
    return results[:limit] if limit else results


def save_mail(
    *,
    result_id: str,
    subject: str,
    sender_name: str,
    sender_email: str,
    received_at: Optional[datetime] = None,
    memo: str = "",
) -> Mail:
    mail = Mail(
        id=uuid.uuid4().hex[:10],
        subject=subject.strip() or "（件名なし）",
        sender_name=sender_name.strip() or "不明な差出人",
        sender_email=sender_email.strip() or "unknown@example.com",
        received_at=received_at or datetime.now(),
        saved_at=datetime.now(),
        result_id=result_id,
        memo=memo.strip(),
        body_preview=(
            "お客様のアカウントに異常なアクセスを検知しました。"
            "以下のリンクから本人確認をお願いします。"
            "（この本文はダミーです）"
        ),
    )
    SAVED_MAILS.insert(0, mail)
    return mail


def get_mail(mail_id: str) -> Optional[Mail]:
    return next((m for m in SAVED_MAILS if m.id == mail_id), None)


def delete_mail(mail_id: str) -> bool:
    mail = get_mail(mail_id)
    if mail is None:
        return False
    SAVED_MAILS.remove(mail)
    return True


def seed_demo_data() -> None:
    """初回起動時に画面確認用のデータを入れておく。"""
    if RESULTS:
        return

    now = datetime.now()

    samples = [
        ("amazon.co.jp", now - timedelta(days=2, hours=3)),
        ("paypa1-secure.top", now - timedelta(hours=6)),
        ("gmail.com", now - timedelta(days=1, hours=5)),
        ("support-center.net", now - timedelta(days=3, hours=2)),
        ("microsoft-login.com", now - timedelta(days=4, hours=1)),
    ]
    results: Dict[str, Result] = {}
    for domain, checked_at in samples:
        result = analyze(domain)
        result.created_at = checked_at
        add_result(result)
        results[domain] = result

    save_mail(
        result_id=results["paypa1-secure.top"].id,
        subject="【重要】アカウントの本人確認が必要です",
        sender_name="PayPal サポート",
        sender_email="support@paypa1-secure.top",
        received_at=now - timedelta(hours=7),
        memo="身に覚えのない本人確認メール。リンク先が不審。",
    )
    save_mail(
        result_id=results["amazon.co.jp"].id,
        subject="ご注文ありがとうございます（注文番号 123-4567890）",
        sender_name="Amazon.co.jp",
        sender_email="no-reply@amazon.co.jp",
        received_at=now - timedelta(days=2, hours=4),
    )
