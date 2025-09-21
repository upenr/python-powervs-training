# Student Invite API

This is a small Flask web service that allows students to request temporary access to an IBM Cloud PowerVS account.  
When a student calls the `/invite` endpoint with their email address, the service automatically:

- Invites the user to the IBM Cloud account.
- Adds them to my IBM Cloud access group.
- Creates a time-limited IAM policy (default: 7 days) that restricts their access to the target resource group.

---

## Prerequisites

- Python 3.9+ (for local runs)
- IBM Cloud account with **IAM admin rights**
- An **IBM API key** with authority to invite users and assign IAM policies
- A configured **Code Engine project** if deploying serverless

---

## Configuration

The app expects several environment variables (set these in your Code Engine project or locally with a `.env` file):

- `IBM_API_KEY` – IBM Cloud API key (user key, not service ID)
- `ACCOUNT_ID` – Your IBM Cloud account ID
- `RESOURCE_GROUP_ID` – ID of the resource group students should see
- `ACCESS_GROUP_ID` – ID of the access group (For example, `QZD35G-student-access` I've hardcoded)
- `SITE_TOKEN` – Shared secret token to restrict who can call the endpoint

---

## How to run locally

Clone this repo and install dependencies:

```bash
pip install -r requirements.txt

```

Create a .env file with your environment variables:

````bash
IBM_API_KEY=your-ibm-api-key
ACCOUNT_ID=your-account-id
RESOURCE_GROUP_ID=your-resource-group-id
ACCESS_GROUP_ID=your-access-group-id
SITE_TOKEN=your-secret-token
```

Run the app:

```bash
python app.py

````

It will listen on http://localhost:8080.

Test with curl:

```bash
curl -X POST http://localhost:8080/invite \
  -H "Content-Type: application/json" \
  -H "X-SITE-TOKEN: <your-site-token>" \
  -d '{"email":"student@example.com"}'
```
