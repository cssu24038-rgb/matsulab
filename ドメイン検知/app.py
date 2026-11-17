"""送信ドメイン信頼性評価アプリ — 画面遷移のプロトタイプ。

現段階では判定・保存はすべてダミー。
画面のつながりと UI を確認するための実装。
"""

from __future__ import annotations

import os
from datetime import datetime
from functools import wraps

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

import store
from analyzer import LEVELS, analyze

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-domain-checker")

DEMO_USER = {
    "name": "山田 太郎",
    "email": "taro.yamada@gmail.com",
}


# ---------------------------------------------------------------------------
# ヘルパー
# ---------------------------------------------------------------------------

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


@app.template_filter("jpdate")
def jpdate(value: datetime) -> str:
    if not value:
        return ""
    return value.strftime("%Y/%m/%d %H:%M")


@app.context_processor
def inject_globals():
    return {
        "levels": LEVELS,
        "current_user": session.get("user"),
        "saved_mail_count": len(store.SAVED_MAILS),
    }


# ---------------------------------------------------------------------------
# ログイン
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        session["user"] = dict(DEMO_USER)
        flash("Google アカウントでログインしました（デモ）", "success")
        next_url = request.args.get("next") or url_for("index")
        if not next_url.startswith("/") or next_url.startswith("//"):
            next_url = url_for("index")
        return redirect(next_url)
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.pop("user", None)
    flash("ログアウトしました", "info")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# ホーム / 判定
# ---------------------------------------------------------------------------

@app.route("/")
@login_required
def index():
    return render_template(
        "index.html",
        history=store.get_history(limit=5),
        mails=store.SAVED_MAILS[:3],
        results_by_id=store.RESULTS,
    )


@app.route("/analyze", methods=["POST"])
@login_required
def analyze_domain():
    query = (request.form.get("query") or "").strip()
    if not query:
        flash("メールアドレスまたはドメインを入力してください", "error")
        return redirect(url_for("index"))
    if "." not in query:
        flash("ドメインの形式で入力してください（例: example.com）", "error")
        return redirect(url_for("index"))

    result = store.add_result(analyze(query))
    return redirect(url_for("result", result_id=result.id))


@app.route("/result/<result_id>")
@login_required
def result(result_id):
    data = store.get_result(result_id)
    if data is None:
        abort(404)

    default_sender_email = data.raw_input if data.input_type == "email" else f"info@{data.domain}"
    return render_template(
        "result.html",
        result=data,
        default_subject="【要確認】重要なお知らせ",
        default_sender_name="サポートセンター",
        default_sender_email=default_sender_email,
    )


@app.route("/result/<result_id>/detail")
@login_required
def detail(result_id):
    data = store.get_result(result_id)
    if data is None:
        abort(404)
    return render_template("detail.html", result=data)


@app.route("/result/<result_id>/save", methods=["POST"])
@login_required
def save_mail(result_id):
    data = store.get_result(result_id)
    if data is None:
        abort(404)

    mail = store.save_mail(
        result_id=data.id,
        subject=request.form.get("subject", ""),
        sender_name=request.form.get("sender_name", ""),
        sender_email=request.form.get("sender_email", ""),
        memo=request.form.get("memo", ""),
    )
    flash(f"「{mail.subject}」を保存しました（デモ）", "success")
    return redirect(url_for("mails"))


# ---------------------------------------------------------------------------
# 保存したメール
# ---------------------------------------------------------------------------

@app.route("/mails")
@login_required
def mails():
    return render_template(
        "mails.html", mails=store.SAVED_MAILS, results_by_id=store.RESULTS
    )


@app.route("/mails/<mail_id>")
@login_required
def mail_detail(mail_id):
    mail = store.get_mail(mail_id)
    if mail is None:
        abort(404)
    result_data = store.get_result(mail.result_id)
    return render_template("mail_detail.html", mail=mail, result=result_data)


@app.route("/mails/<mail_id>/delete", methods=["POST"])
@login_required
def delete_mail(mail_id):
    mail = store.get_mail(mail_id)
    if mail is None:
        abort(404)
    store.delete_mail(mail_id)
    flash(f"「{mail.subject}」を削除しました（デモ）", "info")
    return redirect(url_for("mails"))


# ---------------------------------------------------------------------------
# 履歴
# ---------------------------------------------------------------------------

@app.route("/history")
@login_required
def history():
    return render_template("history.html", history=store.get_history())


# ---------------------------------------------------------------------------
# エラー
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="ページが見つかりません"), 404


if __name__ == "__main__":
    store.seed_demo_data()
    app.run(debug=True, port=5050)
else:
    store.seed_demo_data()
