# app.py
# Flask app: invite users into account + add to access-group + create v2 time-limited policy (7 days)
# Also: /cleanup endpoint to remove users older than 7 days from that access group.
#
# Required ENV:
#   IBM_API_KEY
#   ACCOUNT_ID
#   RESOURCE_GROUP_ID
# Optional:
#   ACCESS_GROUP_NAME (default QZD35G-student-access)
#   ROLE_ID (default Viewer role crn)
#   SITE_TOKEN (if set, endpoint requires header X-SITE-TOKEN)
#   PORT (default 8080)

import os
import datetime
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

IAM_TOKEN_URL = "https://iam.cloud.ibm.com/identity/token"
USER_MGMT_BASE = "https://user-management.cloud.ibm.com"
IAM_BASE = "https://iam.cloud.ibm.com"
ACCESS_GROUPS_BASE = f"{IAM_BASE}/v2/groups"
POLICIES_V2 = f"{IAM_BASE}/v2/policies"

# env
IBM_API_KEY = os.getenv("IBM_API_KEY")
ACCOUNT_ID = os.getenv("ACCOUNT_ID")
RESOURCE_GROUP_ID = os.getenv("RESOURCE_GROUP_ID")  # used when scoping the policy
ACCESS_GROUP_NAME = os.getenv("ACCESS_GROUP_NAME", "QZD35G-student-access")
ROLE_ID = os.getenv("ROLE_ID", "crn:v1:bluemix:public:iam::::role:Viewer")
SITE_TOKEN = os.getenv("SITE_TOKEN")
PORT = int(os.getenv("PORT", "8080"))

if not IBM_API_KEY or not ACCOUNT_ID:
    raise RuntimeError("Please set IBM_API_KEY and ACCOUNT_ID environment variables")

def get_iam_token():
    data = {
        "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
        "apikey": IBM_API_KEY
    }
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
        if g.get("group") and g["group"].get("name") == group_name:
            return g["group"].get("id")
    # fallback substring
    for g in groups:
        if group_name in (g.get("name") or g.get("display_name") or ""):
            return g.get("id")
    return None

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
    # return status + raw text + json (if any)
    try:
        js = r.json()
    except Exception:
        js = None
    return r.status_code, r.text, js

def create_time_limited_policy(iam_token, access_group_id, resource_group_id, days=7, email=None):
    # create v2 policy payload (correct schema for /v2/policies)
    now = datetime.datetime.utcnow()
    start = now
    end = now + datetime.timedelta(days=days)
    # use explicit offset +00:00
    start_iso = start.strftime("%Y-%m-%dT%H:%M:%S+00:00")
    end_iso = end.strftime("%Y-%m-%dT%H:%M:%S+00:00")

    payload = {
        "type": "access",
        "description": f"Temporary access for {email or 'student'} (expires in {days} days)",
        "subjects": [
            {
                "attributes": [
                    {"name": "access_group_id", "value": access_group_id}
                ]
            }
        ],
        "roles": [
            {"role_id": ROLE_ID}
        ],
        "resources": [
            {
                "attributes": [
                    {"name": "accountId", "value": ACCOUNT_ID},
                    {"name": "resource_group_id", "value": resource_group_id}
                ]
            }
        ],
        "pattern": "time-based-conditions:once",
        "rule": {
            "operator": "and",
            "conditions": [
                {
                    "key": "{{environment.attributes.current_date_time}}",
                    "operator": "dateTimeGreaterThanOrEquals",
                    "value": start_iso
                },
                {
                    "key": "{{environment.attributes.current_date_time}}",
                    "operator": "dateTimeLessThanOrEquals",
                    "value": end_iso
                }
            ]
        }
    }
    headers = {"Authorization": f"Bearer {iam_token}", "Content-Type": "application/json", "Accept": "application/json"}
    r = requests.post(POLICIES_V2, json=payload, headers=headers, timeout=30)
    r.raise_for_status()
    return r.json()

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
        # pagination handling
        if js.get("next"):
            url = js["next"]
            params = None
            continue
        break
    return members

def get_user_profile(iam_token, iam_id):
    url = f"{USER_MGMT_BASE}/v2/accounts/{ACCOUNT_ID}/users/{iam_id}"
    headers = {"Authorization": f"Bearer {iam_token}", "Accept": "application/json"}
    r = requests.get(url, headers=headers, timeout=20)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()

def parse_user_created_at(profile_json):
    if not profile_json:
        return None
    # try common fields
    for k in ("added_on", "addedOn", "created", "created_at", "createdAt", "created_on"):
        v = profile_json.get(k)
        if v:
            try:
                from dateutil import parser as _p
                return _p.parse(v)
            except Exception:
                pass
    # try nested 'resources' etc.
    resources = profile_json.get("resources") or profile_json.get("users") or []
    if isinstance(resources, list) and resources:
        first = resources[0]
        for k in ("added_on", "addedOn", "created", "created_at", "createdAt", "created_on"):
            v = first.get(k)
            if v:
                try:
                    from dateutil import parser as _p
                    return _p.parse(v)
                except Exception:
                    pass
    return None

def delete_user(iam_token, iam_id):
    url = f"{USER_MGMT_BASE}/v2/accounts/{ACCOUNT_ID}/users/{iam_id}"
    headers = {"Authorization": f"Bearer {iam_token}", "Accept": "application/json"}
    r = requests.delete(url, headers=headers, timeout=20)
    return r.status_code, r.text

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "access_group": ACCESS_GROUP_NAME}), 200

@app.route("/invite", methods=["POST"])
def invite():
    if SITE_TOKEN:
        header_token = request.headers.get("X-SITE-TOKEN")
        if not header_token or header_token != SITE_TOKEN:
            return jsonify({"error": "missing/invalid SITE_TOKEN"}), 403

    body = request.get_json(force=True, silent=True) or {}
    email = body.get("email")
    first_name = body.get("first_name") or body.get("firstName")
    last_name = body.get("last_name") or body.get("lastName")
    if not email:
        return jsonify({"error": "missing email in JSON body"}), 400

    iam_token = get_iam_token()

    group_id = find_access_group_id(iam_token, ACCESS_GROUP_NAME)
    if not group_id:
        return jsonify({"error": f"access group named '{ACCESS_GROUP_NAME}' not found"}), 404

    status, text, js = invite_user_to_account(iam_token, email, first_name=first_name, last_name=last_name, access_group_id=group_id)
    result = {"invite_status": status, "invite_response": text}
    if js and isinstance(js, dict):
        result["invite_json"] = js

    # create time-limited policy (7 days fixed)
    try:
        policy_resp = create_time_limited_policy(iam_token, group_id, RESOURCE_GROUP_ID, days=7, email=email)
        result["policy"] = policy_resp
        return jsonify(result), 200
    except requests.HTTPError as he:
        resp = he.response
        try:
            body = resp.json()
        except Exception:
            body = resp.text
        result["warning"] = "policy creation failed"
        result["policy_error_status"] = resp.status_code
        result["policy_error_body"] = body
        # invite succeeded; return 202 so caller knows invite accepted but policy failed
        return jsonify(result), 202
    except Exception as e:
        result["warning"] = "policy creation error"
        result["policy_error"] = str(e)
        return jsonify(result), 202

@app.route("/cleanup", methods=["POST"])
def cleanup():
    if SITE_TOKEN:
        header_token = request.headers.get("X-SITE-TOKEN")
        if not header_token or header_token != SITE_TOKEN:
            return jsonify({"error": "missing/invalid SITE_TOKEN"}), 403

    iam_token = get_iam_token()
    group_id = find_access_group_id(iam_token, ACCESS_GROUP_NAME)
    if not group_id:
        return jsonify({"error": f"access group named '{ACCESS_GROUP_NAME}' not found"}), 404

    members = list_access_group_members(iam_token, group_id)
    deleted = []
    now = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
    for m in members:
        iam_id = m.get("iam_id") or m.get("iamId") or m.get("id") or m.get("principal_id") or m.get("user_id")
        if not iam_id:
            continue
        profile = get_user_profile(iam_token, iam_id)
        created_dt = parse_user_created_at(profile)
        if not created_dt:
            continue
        if created_dt.tzinfo is None:
            created_dt = created_dt.replace(tzinfo=datetime.timezone.utc)
        age = now - created_dt
        if age.days >= 7:
            st, body = delete_user(iam_token, iam_id)
            deleted.append({"iam_id": iam_id, "delete_status": st, "delete_body": body})

    return jsonify({"deleted": deleted, "checked": len(members)}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)