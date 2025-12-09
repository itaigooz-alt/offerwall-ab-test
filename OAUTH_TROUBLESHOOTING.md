# OAuth Authentication Troubleshooting Guide

## Common Issues and Solutions

### Issue: "OAuth configuration not found" Error

This error appears when the dashboard cannot find the OAuth credentials in Streamlit Cloud secrets.

### Solution 1: Verify Secrets Format

In Streamlit Cloud, your secrets should be formatted like this:

```toml
GOOGLE_OAUTH_CLIENT_ID = "your-client-id.apps.googleusercontent.com"
GOOGLE_OAUTH_CLIENT_SECRET = "your-client-secret-here"
STREAMLIT_REDIRECT_URI = "https://offerwall-ab-test-6v7uq4xgov7ep6uzxntqvj.streamlit.app/"
```

**Important:**
- Secrets must be at the **top level** (not inside a table like `[GOOGLE_APPLICATION_CREDENTIALS_JSON]`)
- No quotes around the key names
- Values should be in quotes
- Make sure there are no extra spaces or typos

### Solution 2: Check Redirect URI Match

The redirect URI in **Google Cloud Console** must **exactly match** your Streamlit app URL:

1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials?project=yotam-395120)
2. Find your OAuth 2.0 Client ID
3. Check "Authorized redirect URIs"
4. Make sure it includes: `https://your-app-url.streamlit.app/` (with trailing slash)

**Common mistakes:**
- Missing trailing slash `/`
- Using `http://` instead of `https://`
- Wrong subdomain
- Extra path after the domain

### Solution 3: Verify Secrets Are Saved

1. Go to Streamlit Cloud: https://share.streamlit.io
2. Select your app
3. Click **"Settings"** → **"Secrets"**
4. Verify the secrets are there
5. **Click "Save"** (important!)
6. **Click "Reboot app"** or **"Redeploy"**

### Solution 4: Check Secret Names

The secret names must be **exactly**:
- `GOOGLE_OAUTH_CLIENT_ID` (not `GOOGLE_OAUTH_CLIENT_ID_VALUE` or similar)
- `GOOGLE_OAUTH_CLIENT_SECRET` (not `GOOGLE_OAUTH_SECRET` or similar)
- `STREAMLIT_REDIRECT_URI` (optional, but recommended)

### Solution 5: Test Secret Access

If you're still having issues, you can temporarily add debug code to see what secrets are available:

```python
# Temporary debug (remove after testing)
if hasattr(st, 'secrets'):
    st.write("Available secrets:", list(st.secrets.keys()))
    if 'GOOGLE_OAUTH_CLIENT_ID' in st.secrets:
        st.write("Client ID found:", st.secrets['GOOGLE_OAUTH_CLIENT_ID'][:20] + "...")
```

## Step-by-Step Setup

### 1. Create OAuth Credentials in Google Cloud

1. Go to: https://console.cloud.google.com/apis/credentials?project=yotam-395120
2. Click **"Create Credentials"** → **"OAuth client ID"**
3. Application type: **"Web application"**
4. Name: `Offerwall AB Test Dashboard`
5. **Authorized redirect URIs**: Add your Streamlit app URL:
   ```
   https://offerwall-ab-test-6v7uq4xgov7ep6uzxntqvj.streamlit.app/
   ```
   (Replace with your actual app URL)
6. Click **"Create"**
7. Copy the **Client ID** and **Client Secret**

### 2. Add Secrets to Streamlit Cloud

1. Go to: https://share.streamlit.io
2. Select your app: `offerwall-ab-test`
3. Click **"Settings"** (gear icon)
4. Click **"Secrets"** tab
5. Paste this format (replace with your actual values):

```toml
GOOGLE_OAUTH_CLIENT_ID = "123456789-abcdefghijklmnop.apps.googleusercontent.com"
GOOGLE_OAUTH_CLIENT_SECRET = "GOCSPX-abcdefghijklmnopqrstuvwxyz"
STREAMLIT_REDIRECT_URI = "https://offerwall-ab-test-6v7uq4xgov7ep6uzxntqvj.streamlit.app/"
```

6. Click **"Save"**
7. Click **"Reboot app"** or **"Redeploy"**

### 3. Verify It Works

1. Open your app URL
2. You should see "Authentication Required" page
3. Click "Click here to sign in with Google"
4. Sign in with your Google account
5. You should be redirected back to the dashboard

## Still Not Working?

### Check Streamlit Cloud Logs

1. Go to Streamlit Cloud
2. Click **"Manage app"**
3. Click **"Logs"** tab
4. Look for any error messages related to OAuth

### Common Error Messages

- **"redirect_uri_mismatch"**: Redirect URI in Google Cloud doesn't match Streamlit URL
- **"invalid_client"**: Client ID or secret is wrong
- **"access_denied"**: User denied permission (this is normal, just try again)

### Alternative: Skip Authentication (Not Recommended)

If you need to bypass authentication temporarily for testing:

1. In Streamlit Cloud secrets, add:
```toml
SKIP_AUTH = "true"
```

2. Reboot the app

**Warning**: This disables authentication completely. Only use for testing!

## Need Help?

If you're still having issues:

1. Check that all three secrets are present in Streamlit Cloud
2. Verify the redirect URI matches exactly (including trailing slash)
3. Make sure you clicked "Save" and "Reboot app" after adding secrets
4. Check Streamlit Cloud logs for specific error messages
5. Try creating new OAuth credentials in Google Cloud Console

---

**Last Updated**: December 2024

