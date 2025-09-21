# app.py
#
# My Flask app to:
# 1) Invite a user email to your IBM Cloud account
# 2) Add it to my default access group (default QZD35G-student-access)
# 3) Create a time-limited IAM policy granting the Viewer role
# 4) Prefill first_name and last_name in the invite payload

import os
import datetime
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# Endpoints
IAM_TOKEN_URL       = "https://iam.cloud.ibm.com/identity/token"
USER_MGMT_BASE      = "https://user-management.cloud.ibm.com/v2/accounts"
ACCESS_GROUPS_BASE  = "https://iam.cloud.ibm.com/v2/groups"
POLICIES_V2         = "https://iam.cloud.ibm.com/v2/policies"

# Config from env
IBM_API_KEY       = os.getenv("IBM_API_KEY")
ACCOUNT_ID        = os.getenv("ACCOUNT_ID")
RESOURCE_GROUP_ID = os.getenv("RESOURCE_GROUP_ID")
ACCESS_GROUP_NAME = os.getenv("ACCESS_GROUP_NAME", "QZD35G-student-access")
ROLE_ID           = os.getenv("ROLE_ID", "crn:v1:bluemix:public:iam::::role:Viewer")
SITE_TOKEN        = os.getenv("SITE_TOKEN")
PORT              = int(os.getenv("PORT", "8080"))

if not IBM_API_KEY or not ACCOUNT_ID or not RESOURCE_GROUP_ID:
    raise RuntimeError("Please set IBM_API_KEY, ACCOUNT_ID, and RESOURCE_GROUP_ID environment variables")

def get_iam_token():
    """Exchange API key for Bearer token."""
    data = {"grant_type": "urn:ibm:params:oauth:grant-type:apikey", "apikey": IBM_API_KEY}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    r = requests.post(IAM_TOKEN_URL, data=data, headers=headers, timeout=15)
    r.raise_for_status()
    return r.json()["access_token"]

def find_access_group_id(iam_token, group_name):
    """Resolve access group ID by name."""
    params = {"account_id": ACCOUNT_ID, "name": group_name}
    headers = {"Authorization": f"Bearer {iam_token}", "Accept": "application/json"}
    r = requests.get(ACCESS_GROUPS_BASE, params=params, headers=headers, timeout=15)
    r.raise_for_status()
    resp = r.json()
    groups = resp.get("groups") or resp.get("resources") or []
    for g in groups:
        if g.get("name") == group_name or g.get("display_name") == group_name:
            return g.get("id")
    return None

def invite_user(iam_token, email, access_group_id=None, first_name=None, last_name=None):
    """Invite a user to the account, optionally adding them to an access group and prefill name."""
    url = f"{USER_MGMT_BASE}/{ACCOUNT_ID}/users"
    headers = {"Authorization": f"Bearer {iam_token}", "Content-Type": "application/json", "Accept": "application/json"}
    user_obj = {"email": email, "account_role": "Member"}
    if first_name: user_obj["first_name"] = first_name
    if last_name:  user_obj["last_name"] = last_name
    payload = {"users": [user_obj]}
    if access_group_id:
        payload["access_groups"] = [access_group_id]
    r = requests.post(url, json=payload, headers=headers, timeout=20)
    return r.status_code, r.text

def create_time_limited_policy(iam_token, access_group_id, resource_group_id, email_for_desc=None):
    """Create a fixed 7-day IAM policy attached to access group."""
    now = datetime.datetime.utcnow()
    start_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_iso   = (now + datetime.timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")

    payload = {
        "type": "access",
        "description": f"Temporary 7-day access for student ({email_for_desc})",
        "subjects": [
            {"attributes": [{"name": "access_group_id", "value": access_group_id}]}
        ],
        "roles": [{"role_id": ROLE_ID}],
        "resources": [
            {"attributes": [
                {"name": "accountId", "value": ACCOUNT_ID},
                {"name": "resourceGroupId", "value": resource_group_id}
            ]}
        ],
        "pattern": "time-based-conditions:once",
        "rule": {
            "operator": "and",
            "conditions": [
                {"key": "{{environment.attributes.current_date_time}}",
                 "operator": "dateTimeGreaterThanOrEquals",
                 "value": start_iso},
                {"key": "{{environment.attributes.current_date_time}}",
                 "operator": "dateTimeLessThanOrEquals",
                 "value": end_iso}
            ]
        }
    }
    headers = {"Authorization": f"Bearer {iam_token}", "Content-Type": "application/json"}
    r = requests.post(POLICIES_V2, headers=headers, json=payload, timeout=20)
    r.raise_for_status()
    return r.json()

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "access_group_name": ACCESS_GROUP_NAME})

@app.route("/invite", methods=["POST"])
def invite():
    # Optional SITE_TOKEN check
    if SITE_TOKEN:
        token = request.headers.get("X-SITE-TOKEN")
        if token != SITE_TOKEN:
            return jsonify({"error": "Unauthorized SITE_TOKEN"}), 403

    body = request.get_json(force=True) or {}
    email = body.get("email")
    if not email:
        return jsonify({"error": "Missing email"}), 400
    first_name = body.get("first_name")
    last_name  = body.get("last_name")

    iam_token = get_iam_token()
    group_id = find_access_group_id(iam_token, ACCESS_GROUP_NAME)
    if not group_id:
        return jsonify({"error": f"Access group '{ACCESS_GROUP_NAME}' not found"}), 404

    # Step 1: Invite
    status, text = invite_user(iam_token, email, access_group_id=group_id,
                               first_name=first_name, last_name=last_name)
    if status not in (200, 201, 202):
        app.logger.error("Invite failed: %s %s", status, text)
        return jsonify({"error": "Invite failed", "status": status, "response": text}), 500

    # Step 2: Policy (fixed 7-day)
    try:
        policy_resp = create_time_limited_policy(iam_token, group_id, RESOURCE_GROUP_ID,
                                                 email_for_desc=email)
    except Exception as e:
        app.logger.exception("Policy creation failed")
        return jsonify({
            "warning": "Invite created but policy creation failed",
            "invite_status": status,
            "invite_response": text,
            "policy_error": str(e)
        }), 500

    return jsonify({
        "invited_email": email,
        "first_name": first_name,
        "last_name": last_name,
        "access_group_id": group_id,
        "invite_api_status": status,
        "invite_api_response": text,
        "policy_response": policy_resp,
        "duration_days": 7
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)