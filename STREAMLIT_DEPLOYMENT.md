# Streamlit Cloud Deployment Guide

## Prerequisites

1. **GitHub Repository**: The code is already pushed to https://github.com/itaigooz-alt/offerwall-ab-test
2. **Streamlit Cloud Account**: Sign up at https://streamlit.io/cloud
3. **Google Cloud Service Account**: For BigQuery access

## Deployment Steps

### 1. Create Service Account Credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Navigate to **IAM & Admin** > **Service Accounts**
3. Create a new service account or use an existing one
4. Grant **BigQuery Data Viewer** and **BigQuery Job User** roles
5. Create a JSON key:
   - Click on the service account
   - Go to **Keys** tab
   - Click **Add Key** > **Create new key**
   - Choose **JSON** format
   - Download the key file

### 2. Deploy to Streamlit Cloud

1. **Sign in to Streamlit Cloud**:
   - Go to https://share.streamlit.io/
   - Sign in with your GitHub account

2. **Create New App**:
   - Click **"New app"**
   - Select repository: `itaigooz-alt/offerwall-ab-test`
   - Branch: `main`
   - Main file path: `offerwall_dashboard.py`
   - App URL: Choose a custom name (e.g., `offerwall-ab-test`)

3. **Configure Secrets**:
   - Click **"Advanced settings"** or **"Secrets"** tab
   - Add the following secrets in TOML format:

```toml
[GOOGLE_APPLICATION_CREDENTIALS_JSON]
type = "service_account"
project_id = "yotam-395120"
private_key_id = "YOUR_PRIVATE_KEY_ID"
private_key = """-----BEGIN PRIVATE KEY-----
YOUR_PRIVATE_KEY_HERE
-----END PRIVATE KEY-----"""
client_email = "YOUR_SERVICE_ACCOUNT_EMAIL@yotam-395120.iam.gserviceaccount.com"
client_id = "YOUR_CLIENT_ID"
auth_uri = "https://accounts.google.com/o/oauth2/auth"
token_uri = "https://oauth2.googleapis.com/token"
auth_provider_x509_cert_url = "https://www.googleapis.com/oauth2/v1/certs"
client_x509_cert_url = "YOUR_CERT_URL"

[GOOGLE_OAUTH_CLIENT_ID]
value = "YOUR_OAUTH_CLIENT_ID"

[GOOGLE_OAUTH_CLIENT_SECRET]
value = "YOUR_OAUTH_CLIENT_SECRET"

[STREAMLIT_REDIRECT_URI]
value = "https://offerwall-ab-test.streamlit.app/"
```

**Important**: 
- Replace all placeholder values with your actual credentials
- For `GOOGLE_APPLICATION_CREDENTIALS_JSON`, paste the entire JSON content from your service account key file
- The private key should be wrapped in triple quotes `"""` if it contains newlines

### 3. Alternative: Simplified Secrets (Without OAuth)

If you want to skip OAuth authentication (less secure, for testing only):

```toml
[GOOGLE_APPLICATION_CREDENTIALS_JSON]
type = "service_account"
project_id = "yotam-395120"
private_key_id = "YOUR_PRIVATE_KEY_ID"
private_key = """-----BEGIN PRIVATE KEY-----
YOUR_PRIVATE_KEY_HERE
-----END PRIVATE KEY-----"""
client_email = "YOUR_SERVICE_ACCOUNT_EMAIL@yotam-395120.iam.gserviceaccount.com"
client_id = "YOUR_CLIENT_ID"
auth_uri = "https://accounts.google.com/o/oauth2/auth"
token_uri = "https://oauth2.googleapis.com/token"
auth_provider_x509_cert_url = "https://www.googleapis.com/oauth2/v1/certs"
client_x509_cert_url = "YOUR_CERT_URL"
```

Then set environment variable `SKIP_AUTH=true` in Streamlit Cloud settings (not recommended for production).

### 4. Deploy

1. Click **"Deploy!"**
2. Wait for the deployment to complete
3. Your app will be available at: `https://offerwall-ab-test.streamlit.app/`

## Troubleshooting

### Common Issues

1. **"No valid credentials found"**:
   - Check that `GOOGLE_APPLICATION_CREDENTIALS_JSON` is correctly formatted
   - Ensure the service account has BigQuery permissions
   - Verify the JSON is valid TOML format

2. **"Table not found"**:
   - Verify the table `yotam-395120.peerplay.offerwall_dec_ab_test` exists
   - Check service account has access to the dataset

3. **"Authentication error"**:
   - Verify OAuth credentials if using authentication
   - Check redirect URI matches Streamlit Cloud URL

4. **Import errors**:
   - Ensure `requirements.txt` includes all dependencies
   - Check Python version compatibility

## Environment Variables

You can also set these in Streamlit Cloud settings:

- `GCP_PROJECT_ID`: `yotam-395120` (default)
- `BQ_DATASET_ID`: `peerplay` (default)
- `TABLE_ID`: `offerwall_dec_ab_test` (default)
- `SKIP_AUTH`: `true` or `false` (for local dev only)

## Post-Deployment

1. **Test the dashboard**: Verify all filters and views work correctly
2. **Monitor logs**: Check Streamlit Cloud logs for any errors
3. **Share access**: Add team members who need access
4. **Set up monitoring**: Consider setting up alerts for errors

## Security Notes

- Never commit credentials to Git
- Use Streamlit Cloud secrets for all sensitive data
- Regularly rotate service account keys
- Limit service account permissions to minimum required
- Use OAuth authentication for production deployments

---

**Repository**: https://github.com/itaigooz-alt/offerwall-ab-test

**Last Updated**: December 2024

