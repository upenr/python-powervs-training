# app.py
#
# Flask app to: (1) invite an email to your IBM Cloud account,
# (2) add it to access group QZD35G-student-access,
# (3) create a time-limited /v2 policy granting the access group the Viewer role
#
# ENV required:
#   IBM_API_KEY, ACCOUNT_ID, RESOURCE_GROUP_ID
# Optional:
#   ACCESS_GROUP_NAME (default QZD35G-student-access)
#   ROLE_ID (default crn:v1:bluemix:public:iam::::role:Viewer)
#   SITE_TOKEN (if set, endpoint requires header X-SITE-TOKEN)
#   PORT (default 8080)

import os
import time
import datetime
import requests
from flask import Flask, request, jsonify, abort

app = Flask(__name__)

IAM_TOKEN_URL = "https://iam.cloud.ibm.com/identity/token"
USER_MGMT_BASE = "https://user-management.cloud.ibm.com"
IAM_BASE = "https://iam.cloud.ibm.com"
ACCESS_GROUPS_BASE = "https://iam.cloud.ibm.com/v2/groups"
POLICIES_V2 = f"{IAM_BASE}/v2/policies"

# Config from env
IBM_API_KEY = os.getenv("IBM_API_KEY")
ACCOUNT_ID = os.getenv("ACCOUNT_ID")
RESOURCE_GROUP_ID = os.getenv("RESOURCE_GROUP_ID")
ACCESS_GROUP_NAME = os.getenv("ACCESS_GROUP_NAME", "QZD35G-student-access")
ROLE_ID = os.getenv("ROLE_ID", "crn:v1:bluemix:public:iam::::role:Viewer")
SITE_TOKEN = os.getenv("SITE_TOKEN")
PORT = int(os.getenv("PORT", "8080"))

if not IBM_API_KEY or not ACCOUNT_ID or not RESOURCE_GROUP_ID:
    raise RuntimeError("Please set IBM_API_KEY, ACCOUNT_ID, and RESOURCE_GROUP_ID environment variables")

def get_iam_token():
    """Exchange API key for an IAM access token (Bearer)."""
    data = {
        "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
        "apikey": IBM_API_KEY
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    r = requests.post(IAM_TOKEN_URL, data=data, headers=headers, timeout=15)
    r.raise_for_status()
    return r.json()["access_token"]

def find_access_group_id(iam_token, group_name):
    """Find access group by name in the account."""
    params = {"account_id": ACCOUNT_ID, "name": group_name}
    headers = {"Authorization": f"Bearer {iam_token}", "Accept": "application/json"}
    r = requests.get(ACCESS_GROUPS_BASE, params=params, headers=headers, timeout=15)
    r.raise_for_status()
    resp = r.json()
    # The API returns "groups" array
    groups = resp.get("groups") or resp.get("resources") or []
    for g in groups:
        # group object has 'id' and 'name' fields
        if g.get("name") == group_name or g.get("display_name") == group_name:
            return g.get("id")
        # sometimes API returns nested structure
        if g.get("group") and g["group"].get("name") == group_name:
            return g["group"].get("id")
    # fallback: return first match by name
    for g in groups:
        if group_name in (g.get("name") or g.get("display_name") or ""):
            return g.get("id")
    return None

def invite_user_to_account(iam_token, email, access_group_id=None):
    """
    Invite user via User Management API.
    The docs show inviting via POST /v2/accounts/{account_id}/users.
    We'll pass the 'users' array and 'access_group' assignment if possible.
    """
    url = f"{USER_MGMT_BASE}/v2/accounts/{ACCOUNT_ID}/users"
    headers = {
        "Authorization": f"Bearer {iam_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    payload = {
        "users": [
            {
                "email": email,
                "account_role": "Member"
            }
        ]
    }
    # include access_groups if we have one: this matches the CLI behavior (ibmcloud account user-invite --access-groups ...)
    if access_group_id:
        # The API accepts "access_groups": [<id>] in many documented examples
        payload["access_groups"] = [access_group_id]

    r = requests.post(url, json=payload, headers=headers, timeout=20)
    # return r.status_code and body for debugging
    return r.status_code, r.text

def create_time_limited_policy(iam_token, access_group_id, resource_group_id, duration_days=7, email_for_description=None):
    """
    Create a /v2 policy with a time-based condition (one-time).
    Uses dateTimeGreaterThanOrEquals / dateTimeLessThanOrEquals with environment.attributes.current_date_time.
    """
    now = datetime.datetime.utcnow()
    start = now
    end = now + datetime.timedelta(days=duration_days)

    # Format: ISO 8601 with timezone offset. IBM docs accept e.g. "2025-09-26T09:00:00-05:00"
    # We'll use Z (UTC) as offset: "YYYY-MM-DDThh:mm:ssZ" and it should be acceptable.
    start_iso = start.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_iso = end.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Build v2 policy JSON according to IBM docs /v2/policies schema examples.
    # Note: the exact JSON shape accepted is the /v2/policies format; examples in IBM docs
    # include "subject", "resource", "control"/"grant", and "rule"/"conditions"/"pattern".
    payload = {
        "type": "access",
        "description": f"Temporary access for students (invited {email_for_description})",
        # subject: the access group (so all members inherit the policy)
        "subject": {
            "attributes": [
                {
                    "key": "access_group_id",
                    "operator": "stringEquals",
                    "value": access_group_id
                }
            ]
        },
        # resource: restrict to the resource group in this account
        "resource": [
            {
                "attributes": [
                    {
                        "key": "accountId",
                        "operator": "stringEquals",
                        "value": ACCOUNT_ID
                    },
                    {
                        "key": "resource_group_id",
                        "operator": "stringEquals",
                        "value": resource_group_id
                    }
                ]
            }
        ],
        # grant the requested role to the subject
        "control": {
            "grant": {
                "roles": [
                    {
                        "role_id": ROLE_ID
                    }
                ]
            }
        },
        # use the time-based pattern 'once' with explicit dateTime conditions
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
    r = requests.post(POLICIES_V2, json=payload, headers=headers, timeout=20)
    r.raise_for_status()
    return r.json()

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "access_group_name": ACCESS_GROUP_NAME}), 200

@app.route("/invite", methods=["POST"])
def invite():
    # optional site-token check
    if SITE_TOKEN:
        header_token = request.headers.get("X-SITE-TOKEN")
        if not header_token or header_token != SITE_TOKEN:
            return jsonify({"error": "missing/invalid SITE_TOKEN"}), 403

    body = request.get_json(force=True, silent=True) or {}
    email = body.get("email") or body.get("user") or request.form.get("email")
    if not email:
        return jsonify({"error": "missing email in JSON body (e.g. {\"email\":\"student@example.com\"})"}), 400

    try:
        duration = int(body.get("duration_days", 7))
        if duration <= 0:
            duration = 7
    except Exception:
        duration = 7

    iam_token = get_iam_token()

    # 1) resolve access group id by name (hardcoded name)
    group_id = find_access_group_id(iam_token, ACCESS_GROUP_NAME)
    if not group_id:
        return jsonify({"error": f"access group named '{ACCESS_GROUP_NAME}' not found in account {ACCOUNT_ID}"}), 404

    # 2) invite user (assign to access group)
    status, text = invite_user_to_account(iam_token, email, access_group_id=group_id)
    if status not in (200, 201, 202):
        # return the API response for debugging
        return jsonify({"error": "invite failed", "status": status, "response": text}), 500

    # 3) create time-limited policy attached to the access group
    try:
        policy_resp = create_time_limited_policy(iam_token, group_id, RESOURCE_GROUP_ID, duration_days=duration, email_for_description=email)
    except Exception as e:
        # it's possible invite succeeded but policy creation failed
        return jsonify({"warning": "invite created but policy creation failed", "invite_status": status, "invite_response": text, "policy_error": str(e)}), 500

    return jsonify({
        "invited_email": email,
        "access_group_id": group_id,
        "invite_api_status": status,
        "invite_api_response": text,
        "policy": policy_resp,
        "duration_days": duration
    }), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)