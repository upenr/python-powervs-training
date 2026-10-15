# PowerVS Student Access and Course Feedback API

A Flask service for IBM PowerVS technical training labs. This app provides students with temporary access to IBM Cloud and stores their course feedback in IBM Cloudant, a NoSQL database running on IBM Cloud.

## Features

- Invites a student to an IBM Cloud account.
- Adds the student to a configured IAM access group.
- Creates a time-limited IAM policy for a specific resource group.
- Removes expired users through the cleanup endpoint.
- Stores course feedback in an IBM Cloudant database.
- Protects administrative endpoints with an `X-SITE-TOKEN` header.
- The student-facing HTML that calls this backend is intentionally excluded from this repository. Reach out to me if you need it.

## Endpoints

- `GET /health` - Displays service health and configuration status.
- `GET /diagnostics` - Tests IBM Cloud configuration. Requires `X-SITE-TOKEN`.
- `POST /invite` - Invites a student and creates temporary access. Requires `X-SITE-TOKEN`.
- `POST /cleanup` - Removes expired student accounts. Requires `X-SITE-TOKEN`.
- `POST /feedback` - Stores course feedback in Cloudant.

## Requirements

- Python 3.9 or later
- IBM Cloud account and API key with the required IAM permissions
- IBM Cloud access group and target resource group
- IBM Cloudant instance and database
- IBM Code Engine project for deployment

## Environment variables

Create a `.env` file for local testing or configure these values in Code Engine:

```dotenv
IBM_API_KEY=your-ibm-cloud-api-key
ACCOUNT_ID=your-account-id
RESOURCE_GROUP_ID=your-resource-group-id
ACCESS_GROUP_ID=your-access-group-id
ACCESS_GROUP_NAME=QZD35G-student-access
SITE_TOKEN=your-secret-site-token
ALLOWED_ACCESS_DAYS=7
CLOUDANT_URL=https://your-cloudant-instance-url
CLOUDANT_APIKEY=your-cloudant-api-key
CLOUDANT_DB=qzc51g-feedback
PORT=8080
```

`ACCESS_GROUP_ID` is optional when `ACCESS_GROUP_NAME` can be used to locate the group.

## Run locally

```bash
python -m pip install -r requirements.txt
python app.py
```

The service listens on `http://localhost:8080` by default.

## Test the invite endpoint

```bash
curl -X POST http://localhost:8080/invite \
  -H "Content-Type: application/json" \
  -H "X-SITE-TOKEN: your-site-token" \
  -d '{"email":"student@example.com"}'
```

## Test the feedback endpoint

```bash
curl -X POST http://localhost:8080/feedback \
  -H "Content-Type: application/json" \
  -d '{"course":"QZC51G","class_number":"1234567","name":"Test Student","feedback":"The course is going well."}'
```
