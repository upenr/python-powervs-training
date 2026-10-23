import datetime
import logging
import os
import sys
import time
from collections import defaultdict

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from werkzeug.middleware.proxy_fix import ProxyFix

load_dotenv()

RELEASE_VERSION = "3.0"
RATE_LIMIT = 3
RATE_WINDOW = 24 * 60 * 60

IAM_TOKEN_URL = "https://iam.cloud.ibm.com/identity/token"
USER_MGMT_BASE = "https://user-management.cloud.ibm.com"
IAM_BASE = "https://iam.cloud.ibm.com"
ACCESS_GROUPS_BASE = f"{IAM_BASE}/v2/groups"
POLICIES_V2 = f"{IAM_BASE}/v2/policies"

IBM_API_KEY = os.getenv("IBM_API_KEY")
ACCOUNT_ID = os.getenv("ACCOUNT_ID")
RESOURCE_GROUP_ID = os.getenv("RESOURCE_GROUP_ID")
ACCESS_GROUP_ID = os.getenv("ACCESS_GROUP_ID")
ACCESS_GROUP_NAME = os.getenv("ACCESS_GROUP_NAME", "QZD35G-student-access")
ROLE_ID = os.getenv("ROLE_ID", "crn:v1:bluemix:public:iam::::role:Viewer")
SITE_TOKEN = os.getenv("SITE_TOKEN")
PORT = int(os.getenv("PORT", "8080"))
ALLOWED_ACCESS_DAYS = int(os.getenv("ALLOWED_ACCESS_DAYS", "7"))

CLOUDANT_URL = os.getenv("CLOUDANT_URL", "").rstrip("/")
CLOUDANT_APIKEY = os.getenv("CLOUDANT_APIKEY")
CLOUDANT_DB = os.getenv("CLOUDANT_DB", "qzc51g-feedback")

required = {
    "IBM_API_KEY": IBM_API_KEY,
    "ACCOUNT_ID": ACCOUNT_ID,
    "RESOURCE_GROUP_ID": RESOURCE_GROUP_ID,
    "SITE_TOKEN": SITE_TOKEN,
    "CLOUDANT_URL": CLOUDANT_URL,
    "CLOUDANT_APIKEY": CLOUDANT_APIKEY,
}
missing = [name for name, value in required.items() if not value]
if missing:
    raise RuntimeError(f"Missing environment variables: {', '.join(missing)}")

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("powervs-training")

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
request_log = defaultdict(list)


def client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    return forwarded.split(",")[0].strip() if forwarded else request.remote_addr or "unknown"


def is_rate_limited(ip):
    now = time.time()
    request_log[ip] = [t for t in request_log[ip] if now - t < RATE_WINDOW]
    if len(request_log[ip]) >= RATE_LIMIT:
        return True
    request_log[ip].append(now)
    return False


def check_site_token():
    if request.headers.get("X-SITE-TOKEN") != SITE_TOKEN:
        return jsonify({"ok": False, "error": "invalid SITE_TOKEN"}), 403
    return None


def log_api_error(operation, response):
    try:
        message = response.json()
    except ValueError:
        message = response.text[:2000]
    transaction_id = (
        response.headers.get("Transaction-Id")
        or response.headers.get("X-Global-Transaction-ID")
    )
    logger.error(
        "%s failed: status=%s transaction_id=%s response=%s",
        operation,
        response.status_code,
        transaction_id,
        message,
    )
    return transaction_id


def auth_headers(iam_token, json_content=False):
    headers = {"Authorization": f"Bearer {iam_token}", "Accept": "application/json"}
    if json_content:
        headers["Content-Type"] = "application/json"
    return headers


def get_iam_token(api_key):
    response = requests.post(
        IAM_TOKEN_URL,
        data={
            "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
            "apikey": api_key,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=30,
    )
    if not response.ok:
        log_api_error("get IAM token", response)
    response.raise_for_status()
    return response.json()["access_token"]


def find_access_group_id(iam_token):
    if ACCESS_GROUP_ID:
        return ACCESS_GROUP_ID
    response = requests.get(
        ACCESS_GROUPS_BASE,
        params={"account_id": ACCOUNT_ID, "name": ACCESS_GROUP_NAME},
        headers=auth_headers(iam_token),
        timeout=30,
    )
    if not response.ok:
        log_api_error("find access group", response)
    response.raise_for_status()
    groups = response.json().get("groups") or response.json().get("resources") or []
    for group in groups:
        if group.get("name") == ACCESS_GROUP_NAME or group.get("display_name") == ACCESS_GROUP_NAME:
            return group.get("id")
    return None


def invite_user(iam_token, email, first_name, last_name, group_id):
    user = {"email": email}
    if first_name:
        user["first_name"] = first_name
    if last_name:
        user["last_name"] = last_name
    response = requests.post(
        f"{USER_MGMT_BASE}/v2/accounts/{ACCOUNT_ID}/users",
        json={"users": [user], "access_groups": [group_id]},
        headers=auth_headers(iam_token, json_content=True),
        timeout=30,
    )
    if not response.ok:
        log_api_error("invite user", response)
    return response


def list_group_members(iam_token, group_id):
    response = requests.get(
        f"{ACCESS_GROUPS_BASE}/{group_id}/members",
        params={"limit": 100, "verbose": "true"},
        headers=auth_headers(iam_token),
        timeout=30,
    )
    if not response.ok:
        log_api_error("list group members", response)
    response.raise_for_status()
    return response.json().get("members") or []


def cors_headers():
    return {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
    }


@app.get("/")
def index():
    return jsonify({
        "ok": True,
        "service": "PowerVS Student Invite API",
        "release_version": RELEASE_VERSION,
        "health": "/health",
        "diagnostics": "/diagnostics",
        "invite": "POST /invite",
        "cleanup": "POST /cleanup",
        "feedback": "POST /feedback",
    })


@app.get("/health")
def health():
    return jsonify({
        "ok": True,
        "release_version": RELEASE_VERSION,
        "access_group_name": ACCESS_GROUP_NAME,
        "cloudant_configured": bool(CLOUDANT_URL and CLOUDANT_APIKEY),
        "feedback_database": CLOUDANT_DB,
    })


@app.get("/diagnostics")
def diagnostics():
    token_error = check_site_token()
    if token_error:
        return token_error
    try:
        iam_token = get_iam_token(IBM_API_KEY)
        group_id = find_access_group_id(iam_token)
        return jsonify({
            "ok": bool(group_id),
            "iam_token": "ok",
            "access_group_id": group_id,
            "resource_group_configured": bool(RESOURCE_GROUP_ID),
            "cloudant_configured": bool(CLOUDANT_URL and CLOUDANT_APIKEY and CLOUDANT_DB),
            "release_version": RELEASE_VERSION,
        }), 200 if group_id else 404
    except requests.HTTPError as error:
        transaction_id = log_api_error("diagnostics", error.response)
        return jsonify({
            "ok": False,
            "status": error.response.status_code,
            "transaction_id": transaction_id,
        }), 502


@app.post("/invite")
def invite():
    token_error = check_site_token()
    if token_error:
        return token_error

    ip = client_ip()
    if is_rate_limited(ip):
        return jsonify({"ok": False, "error": "rate limit exceeded"}), 429

    body = request.get_json(silent=True) or {}
    email = str(body.get("email", "")).strip().lower()
    first_name = str(body.get("first_name") or body.get("firstName") or "").strip()
    last_name = str(body.get("last_name") or body.get("lastName") or "").strip()
    if not email:
        return jsonify({"ok": False, "error": "missing email"}), 400

    try:
        iam_token = get_iam_token(IBM_API_KEY)
        group_id = find_access_group_id(iam_token)
        if not group_id:
            return jsonify({"ok": False, "error": "access group not found"}), 404

        invitation = invite_user(iam_token, email, first_name, last_name, group_id)
        if not invitation.ok:
            transaction_id = log_api_error("invite user", invitation)
            return jsonify({
                "ok": False,
                "stage": "invite_user",
                "status": invitation.status_code,
                "transaction_id": transaction_id,
            }), 502

        logger.info(
            "Invite completed: email=%s ip=%s access_group_id=%s",
            email,
            ip,
            group_id,
        )
        return jsonify({
            "ok": True,
            "email": email,
            "invite_status": invitation.status_code,
            "access_group_id": group_id,
            "access_days": ALLOWED_ACCESS_DAYS,
        })
    except requests.HTTPError as error:
        transaction_id = log_api_error("IBM Cloud API", error.response)
        return jsonify({
            "ok": False,
            "status": error.response.status_code,
            "transaction_id": transaction_id,
        }), 502
    except Exception:
        logger.exception("Unexpected invitation failure")
        return jsonify({"ok": False, "error": "unexpected invitation failure"}), 500


@app.route("/feedback", methods=["POST", "OPTIONS"])
def feedback():
    cors = cors_headers()
    if request.method == "OPTIONS":
        return "", 204, cors

    body = request.get_json(silent=True) or {}
    document = {
        "type": "course_feedback",
        "course": str(body.get("course", "")).strip()[:10],
        "class_number": str(body.get("class_number", "")).strip()[:7],
        "name": str(body.get("name", "")).strip()[:80],
        "feedback": str(body.get("feedback", "")).strip()[:512],
        "submitted_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    if not all(document[key] for key in ("course", "class_number", "name", "feedback")):
        return jsonify({"ok": False, "error": "all fields are required"}), 400, cors

    try:
        token = get_iam_token(CLOUDANT_APIKEY)
        response = requests.post(
            f"{CLOUDANT_URL}/{CLOUDANT_DB}",
            json=document,
            headers=auth_headers(token, json_content=True),
            timeout=30,
        )
        if not response.ok:
            log_api_error("save feedback", response)
        response.raise_for_status()
        logger.info("Feedback saved: document_id=%s", response.json().get("id"))
        return jsonify({"ok": True, "message": "feedback saved"}), 201, cors
    except requests.HTTPError as error:
        transaction_id = log_api_error("save feedback", error.response)
        return jsonify({
            "ok": False,
            "error": "feedback could not be saved",
            "transaction_id": transaction_id,
        }), 502, cors
    except Exception:
        logger.exception("Unexpected feedback failure")
        return jsonify({"ok": False, "error": "feedback could not be saved"}), 500, cors


@app.post("/cleanup")
def cleanup():
    token_error = check_site_token()
    if token_error:
        return token_error
    try:
        iam_token = get_iam_token(IBM_API_KEY)
        group_id = find_access_group_id(iam_token)
        if not group_id:
            return jsonify({"ok": False, "error": "access group not found"}), 404

        members = list_group_members(iam_token, group_id)
        now = datetime.datetime.now(datetime.timezone.utc)
        deleted, skipped, failed = [], [], []

        for member in members:
            iam_id = member.get("iam_id") or member.get("id")
            created = member.get("created_at") or member.get("created")
            if not iam_id or not created:
                skipped.append({"iam_id": iam_id, "reason": "missing creation date"})
                continue
            try:
                created_date = datetime.datetime.fromisoformat(created.replace("Z", "+00:00"))
            except ValueError:
                skipped.append({"iam_id": iam_id, "reason": "invalid creation date"})
                continue
            if now - created_date < datetime.timedelta(days=ALLOWED_ACCESS_DAYS):
                continue

            response = requests.delete(
                f"{USER_MGMT_BASE}/v2/accounts/{ACCOUNT_ID}/users/{iam_id}",
                headers=auth_headers(iam_token),
                timeout=30,
            )
            if response.ok:
                deleted.append({"iam_id": iam_id, "status": response.status_code})
            else:
                failed.append({
                    "iam_id": iam_id,
                    "status": response.status_code,
                    "transaction_id": log_api_error("delete expired user", response),
                })

        return jsonify({
            "ok": not failed,
            "checked": len(members),
            "deleted": deleted,
            "failed": failed,
            "skipped": skipped,
        }), 200 if not failed else 207
    except requests.HTTPError as error:
        transaction_id = log_api_error("cleanup", error.response)
        return jsonify({
            "ok": False,
            "status": error.response.status_code,
            "transaction_id": transaction_id,
        }), 502
    except Exception:
        logger.exception("Unexpected cleanup failure")
        return jsonify({"ok": False, "error": "unexpected cleanup failure"}), 500


if __name__ == "__main__":
    logger.info("Starting PowerVS Student Invite API %s", RELEASE_VERSION)
    app.run(host="0.0.0.0", port=PORT, debug=False)