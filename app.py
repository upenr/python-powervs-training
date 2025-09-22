# app.py
# Flask app: invite users into account + add to access-group + create 7-day time-limited policy
# Also: /cleanup endpoint to remove users older than 7 days from that access group.
# Logs invites to invites.log

import os
import datetime
import requests
import logging
from flask import Flask, request, jsonify
from dotenv import load_dotenv
from collections import defaultdict
import time

RATE_LIMIT = 3  # max requests
RATE_WINDOW = 24 * 60 * 60  # 24 hours in seconds
RELEASE_VERSION = "2.5"
request_log = defaultdict(list)  # stores timestamps per IP

def is_rate_limited(ip):
    now = time.time()
    timestamps = request_log[ip]

    # Remove timestamps older than 24 hours
    request_log[ip] = [t for t in timestamps if now - t < RATE_WINDOW]

    if len(request_log[ip]) >= RATE_LIMIT:
        return True

    request_log[ip].append(now)
    return False

load_dotenv()
app = Flask(__name__)

IAM_TOKEN_URL = "https://iam.cloud.ibm.com/identity/token"
USER_MGMT_BASE = "https://user-management.cloud.ibm.com"
IAM_BASE = "https://iam.cloud.ibm.com"
ACCESS_GROUPS_BASE = f"{IAM_BASE}/v2/groups"
POLICIES_V2 = f"{IAM_BASE}/v2/policies"

# Env variables
IBM_API_KEY = os.getenv("IBM_API_KEY")
ACCOUNT_ID = os.getenv("ACCOUNT_ID")
RESOURCE_GROUP_ID = os.getenv("RESOURCE_GROUP_ID")
ACCESS_GROUP_NAME = os.getenv("ACCESS_GROUP_NAME", "QZD35G-student-access")
ROLE_ID = os.getenv("ROLE_ID", "crn:v1:bluemix:public:iam::::role:Viewer")
SITE_TOKEN = os.getenv("SITE_TOKEN")
PORT = int(os.getenv("PORT", "8080"))

if not IBM_API_KEY or not ACCOUNT_ID:
    raise RuntimeError("Please set IBM_API_KEY and ACCOUNT_ID environment variables")


# --- Helpers ---
def get_iam_token():
    data = {"grant_type": "urn:ibm:params:oauth:grant-type:apikey", "apikey": IBM_API_KEY}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    r = requests.post(IAM_TOKEN_URL, data=data, headers=headers, timeout=20)
    r.raise_for_status()
    return r.json()["access_token"]


def find_access_group_id(iam_token, group_name):
    params = {"account_id": ACCOUNT_ID, "name": group_name}
    headers = {"Authorization": f"Bearer {iam_token}", "Accept": "application/json"}
    r = requests.get(ACCESS_GROUPS_BASE, params=params, headers=headers, timeout=20)
    r.raise_for_status()
    js = r.json()
    groups = js.get("groups") or js.get("resources") or []
    for g in groups:
        if g.get("name") == group_name or g.get("display_name") == group_name:
            return g.get("id")
    return None


def list_access_group_members(iam_token, access_group_id):
    url = f"{ACCESS_GROUPS_BASE}/{access_group_id}/members"
    headers = {"Authorization": f"Bearer {iam_token}", "Accept": "application/json"}
    members = []
    params = {"limit": 100}
    while True:
        r = requests.get(url, headers=headers, params=params, timeout=20)
        r.raise_for_status()
        js = r.json()
        page_members = js.get("members") or js.get("resources") or js.get("users") or []
        members.extend(page_members)
        if js.get("next"):
            url = js["next"]
            params = None
            continue
        break
    return members


def invite_user_to_account(iam_token, email, first_name=None, last_name=None, access_group_id=None):
    url = f"{USER_MGMT_BASE}/v2/accounts/{ACCOUNT_ID}/users"
    headers = {"Authorization": f"Bearer {iam_token}", "Content-Type": "application/json", "Accept": "application/json"}
    user_obj = {"email": email}
    if first_name:
        user_obj["first_name"] = first_name
    if last_name:
        user_obj["last_name"] = last_name
    payload = {"users": [user_obj]}
    if access_group_id:
        payload["access_groups"] = [access_group_id]
    r = requests.post(url, json=payload, headers=headers, timeout=30)
    try:
        js = r.json()
    except:
        js = None
    return r.status_code, r.text, js


def create_time_limited_policy(iam_token, access_group_id, resource_group_id, email):
    now = datetime.datetime.utcnow()
    start_iso = now.strftime("%Y-%m-%dT%H:%M:%S+00:00")
    end_iso = (now + datetime.timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S+00:00")

    headers = {"Authorization": f"Bearer {iam_token}", "Accept": "application/json"}
    existing_policies = requests.get(POLICIES_V2, headers=headers, timeout=20).json().get("resources", [])

    # Skip if a policy already exists for this access group and email
    for p in existing_policies:
        subj_attrs = p.get("subject", {}).get("attributes", [])
        desc = p.get("description", "")
        if any(a.get("key") == "access_group_id" and a.get("value") == access_group_id for a in subj_attrs):
            if email in desc:
                return p

    payload = {
        "type": "access",
        "description": f"Temporary access for {email} (expires in 7 days)",
        "subject": {"attributes": [{"key": "access_group_id", "operator": "stringEquals", "value": access_group_id}]},
        "resource": {"attributes": [{"key": "accountId", "operator": "stringEquals", "value": ACCOUNT_ID},
                                    {"key": "resourceGroupId", "operator": "stringEquals", "value": resource_group_id}]},
        "control": {"grant": {"roles": [{"role_id": ROLE_ID}]}},
        "pattern": "time-based-conditions:once",
        "rule": {"operator": "and",
                 "conditions": [
                     {"key": "{{environment.attributes.current_date_time}}", "operator": "dateTimeGreaterThanOrEquals", "value": start_iso},
                     {"key": "{{environment.attributes.current_date_time}}", "operator": "dateTimeLessThanOrEquals", "value": end_iso}
                 ]}
    }

    r = requests.post(POLICIES_V2, json=payload, headers={"Authorization": f"Bearer {iam_token}", "Content-Type": "application/json"}, timeout=30)
    r.raise_for_status()
    return r.json()


def log_invite(email, first_name, last_name):
    with open("invites.log", "a") as f:
        f.write(f"{datetime.datetime.now(datetime.UTC).isoformat()} - Invited {email} ({first_name} {last_name})\n")
    logging.info(f"Invited {email} ({first_name} {last_name})")
    print(f"Invited {email} ({first_name} {last_name})")

# --- Routes ---
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "ok": True,
        "access_group_name": ACCESS_GROUP_NAME,
        "release_version": RELEASE_VERSION
    }), 200

@app.route("/invite", methods=["POST"])
def invite():
    if SITE_TOKEN and request.headers.get("X-SITE-TOKEN") != SITE_TOKEN:
        return jsonify({"error": "invalid SITE_TOKEN"}), 403

    client_ip = request.remote_addr
    if is_rate_limited(client_ip):
        return jsonify({"error": f"rate limit exceeded ({RATE_LIMIT} invites per 24h)"}), 429

    body = request.get_json(force=True, silent=True) or {}
    email = body.get("email")
    first_name = body.get("first_name") or body.get("firstName")
    last_name = body.get("last_name") or body.get("lastName")
    if not email:
        return jsonify({"error": "missing email"}), 400

    iam_token = get_iam_token()
    group_id = find_access_group_id(iam_token, ACCESS_GROUP_NAME)
    if not group_id:
        return jsonify({"error": "access group not found"}), 404

    log_invite(email, first_name or "", last_name or "")

    # Invite user
    status, text, js = invite_user_to_account(iam_token, email, first_name, last_name, group_id)
    result = {"invite_status": status}

    # Policy
    try:
        policy_resp = create_time_limited_policy(iam_token, group_id, RESOURCE_GROUP_ID, email)
        result["policy_created"] = True
    except requests.HTTPError:
        result["policy_created"] = False
    except Exception:
        result["policy_created"] = False

    return jsonify(result), 200

@app.route("/cleanup", methods=["POST"])
def cleanup():
    if SITE_TOKEN and request.headers.get("X-SITE-TOKEN") != SITE_TOKEN:
        return jsonify({"error": "invalid SITE_TOKEN"}), 403

    iam_token = get_iam_token()
    group_id = find_access_group_id(iam_token, ACCESS_GROUP_NAME)
    if not group_id:
        return jsonify({"error": "access group not found"}), 404

    members = list_access_group_members(iam_token, group_id)
    deleted = []
    now = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
    for m in members:
        iam_id = m.get("iam_id") or m.get("id")
        if not iam_id:
            continue
        created_dt = m.get("added_on") or m.get("addedOn")
        if not created_dt:
            continue
        try:
            created_dt = datetime.datetime.fromisoformat(created_dt.replace("Z", "+00:00"))
        except:
            continue
        if (now - created_dt).days >= 7:
            st = requests.delete(f"{USER_MGMT_BASE}/v2/accounts/{ACCOUNT_ID}/users/{iam_id}",
                                 headers={"Authorization": f"Bearer {iam_token}"}).status_code
            deleted.append({"iam_id": iam_id, "delete_status": st})
    return jsonify({"deleted": deleted, "checked": len(members)}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
