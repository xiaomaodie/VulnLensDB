"""Course accounts. Creating an administrator requires an explicit cloud CLI action."""
import getpass
import hmac
import re
import secrets
import sys

import pymysql
from flask import Blueprint, abort, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from .catalog import connect
from .library_db import refresh_stats

accounts=Blueprint("accounts",__name__)


def token():
    if "_token" not in session: session["_token"]=secrets.token_urlsafe(24)
    return session["_token"]


def require_token():
    if not hmac.compare_digest(session.get("_token","missing"),request.form.get("_token","")):
        abort(400)


def user():
    if "account" not in g:
        g.account=None
        if session.get("uid"):
            with connect() as db,db.cursor() as cur:
                cur.execute("SELECT id,username,role FROM course_account WHERE id=%s",(session["uid"],))
                g.account=cur.fetchone()
    return g.account


@accounts.app_context_processor
def auth_context():
    return dict(account=user(),csrf_token=token)


@accounts.route("/account",methods=["GET","POST"])
def account_page():
    error=None
    if request.method=="POST":
        require_token()
        op=request.form.get("op")
        if op=="logout":
            session.clear();return redirect("/")
        name=request.form.get("username","").strip()
        password=request.form.get("password","")
        if op not in ("login","register") or not re.fullmatch(r"[A-Za-z0-9_.-]{3,48}",name) or not 1<=len(password)<=200:
            error="用户名应为 3–48 位字母、数字或 _.-，请检查登录信息。"
        elif op=="register" and len(password)<10:
            error="注册密码至少 10 个字符。"
        else:
            with connect() as db,db.cursor() as c:
                if op=="register":
                    try:
                        c.execute("INSERT INTO course_account(username,password_hash) VALUES (%s,%s)",(name,generate_password_hash(password)))
                        db.commit()
                    except pymysql.err.IntegrityError:
                        error="此用户名无法注册。"
                if not error:
                    c.execute("SELECT id,password_hash FROM course_account WHERE username=%s",(name,))
                    record=c.fetchone()
                    if record and check_password_hash(record["password_hash"],password):
                        session.clear();session["uid"]=record["id"]
                        return redirect(url_for("accounts.account_page"))
                    error="用户名或密码有误。"
    history=[]
    if user():
        with connect() as db,db.cursor() as cur:
            cur.execute("SELECT created,components,findings,uncertain FROM course_scan WHERE account_id=%s ORDER BY id DESC LIMIT 40",(user()["id"],))
            history=cur.fetchall()
    return render_template("account.html",error=error,history=history),400 if error else 200


def save_summary(pins,result):
    require_token()
    if not user():abort(403)
    with connect() as db,db.cursor() as cur:
        cur.execute("INSERT INTO course_scan(account_id,components,findings,uncertain) VALUES (%s,%s,%s,%s)",
                    (user()["id"],len(pins),sum(row[3]=="命中" for row in result),sum(row[3]=="待核对" for row in result)))
        db.commit()


@accounts.post("/account/refresh-stats")
def refresh():
    require_token()
    if not user() or user()["role"]!="admin":abort(403)
    with connect() as db,db.cursor() as cur:
        refresh_stats(cur);db.commit()
    return redirect(url_for("library.reports"))


if __name__=="__main__":
    if len(sys.argv)!=2 or not re.fullmatch(r"[A-Za-z0-9_.-]{3,48}",sys.argv[1]):
        raise SystemExit("Usage: python -m backend.accounts ADMIN_USERNAME")
    password=getpass.getpass("New administrator password: ")
    if not 12<=len(password)<=200:raise SystemExit("Use 12–200 characters")
    with connect() as db,db.cursor() as c:
        c.execute("INSERT INTO course_account(username,password_hash,role) VALUES (%s,%s,'admin')",
                  (sys.argv[1],generate_password_hash(password)))
        db.commit()
