#!/usr/bin/env python3
"""
Offerwall AB Test Dashboard
Connects to BigQuery offerwall_dec_ab_test table and displays AB test analytics
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from google.cloud import bigquery
from google.auth import default
from google.oauth2 import service_account
from google_auth_oauthlib.flow import Flow
import json
from datetime import datetime, timedelta
import os
import streamlit.components.v1 as components

# Page configuration
st.set_page_config(
    page_title="Offerwall AB Test Dashboard",
    page_icon="🧪",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================================
# CUSTOM CSS FOR MODERN UI/UX
# ============================================================================

def inject_custom_css():
    """Inject custom CSS for modern UI/UX"""
    st.markdown("""
    <style>
        /* Main theme colors */
        :root {
            --primary-color: #1f77b4;
            --secondary-color: #ff7f0e;
            --success-color: #2ca02c;
            --danger-color: #d62728;
            --bg-color: #f8f9fa;
            --card-bg: #ffffff;
            --text-primary: #1e1e1e;
            --text-secondary: #6c757d;
            --border-color: #dee2e6;
        }
        
        /* Main container styling */
        .main .block-container {
            padding-top: 2rem;
            padding-bottom: 2rem;
        }
        
        /* Header styling */
        h1 {
            color: #1e1e1e;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }
        
        h2 {
            color: #1e1e1e;
            font-weight: 600;
            margin-top: 1.5rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid #e9ecef;
        }
        
        h3 {
            color: #1e1e1e;
            font-weight: 600;
            margin-top: 1.25rem;
            margin-bottom: 0.75rem;
        }
        
        /* Sidebar styling */
        .css-1d391kg {
            background-color: #ffffff;
        }
        
        [data-testid="stSidebar"] {
            background-color: #f8f9fa;
            border-right: 1px solid #dee2e6;
        }
        
        [data-testid="stSidebar"] .css-1d391kg {
            background-color: #f8f9fa;
        }
        
        /* Card-like containers */
        .metric-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 1.5rem;
            border-radius: 10px;
            color: white;
            margin-bottom: 1rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        /* Button styling */
        .stButton > button {
            border-radius: 8px;
            border: none;
            padding: 0.5rem 1.5rem;
            font-weight: 500;
            transition: all 0.3s ease;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        
        .stButton > button:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
        }
        
        /* Selectbox and multiselect styling */
        .stSelectbox > div > div {
            border-radius: 8px;
        }
        
        .stMultiSelect > div > div {
            border-radius: 8px;
        }
        
        /* Tab styling */
        .stTabs [data-baseweb="tab-list"] {
            gap: 8px;
            background-color: #f8f9fa;
            padding: 0.5rem;
            border-radius: 10px;
        }
        
        .stTabs [data-baseweb="tab"] {
            border-radius: 8px;
            padding: 0.75rem 1.5rem;
            font-weight: 500;
            transition: all 0.3s ease;
        }
        
        .stTabs [aria-selected="true"] {
            background-color: #667eea;
            color: white;
        }
        
        /* Dataframe styling */
        .dataframe {
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }
        
        /* Info boxes */
        .stInfo {
            border-radius: 8px;
            border-left: 4px solid #17a2b8;
        }
        
        .stWarning {
            border-radius: 8px;
            border-left: 4px solid #ffc107;
        }
        
        .stSuccess {
            border-radius: 8px;
            border-left: 4px solid #28a745;
        }
        
        /* Metric containers */
        [data-testid="stMetricValue"] {
            font-size: 1.5rem;
            font-weight: 600;
        }
        
        [data-testid="stMetricLabel"] {
            font-size: 0.9rem;
            color: #6c757d;
        }
        
        /* Spacing improvements */
        .element-container {
            margin-bottom: 1.5rem;
        }
        
        /* Status indicators */
        .status-green {
            color: #28a745;
            font-size: 1.2rem;
        }
        
        .status-red {
            color: #dc3545;
            font-size: 1.2rem;
        }
        
        .status-neutral {
            color: #6c757d;
            font-size: 1.2rem;
        }
        
        /* Divider styling */
        hr {
            margin: 2rem 0;
            border: none;
            border-top: 2px solid #e9ecef;
        }
        
        /* Sidebar section headers */
        [data-testid="stSidebar"] h3 {
            color: #495057;
            font-size: 1rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 0.75rem;
            margin-bottom: 0.5rem;
        }
        
        /* Reduce spacing in sidebar */
        [data-testid="stSidebar"] .element-container {
            margin-bottom: 0.75rem;
        }
        
        [data-testid="stSidebar"] .stMarkdown {
            margin-bottom: 0.5rem;
        }
        
        [data-testid="stSidebar"] hr {
            margin: 0.75rem 0;
        }
        
        /* Filter section styling */
        .filter-section {
            background-color: #ffffff;
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 1rem;
            border: 1px solid #dee2e6;
        }
        
        /* Plotly chart container */
        .js-plotly-plot {
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }
        
        /* Loading spinner */
        .stSpinner > div {
            border-color: #667eea;
        }
    </style>
    """, unsafe_allow_html=True)

# ============================================================================
# GOOGLE OAUTH AUTHENTICATION
# ============================================================================

# Allowed email domains (Peerplay employees)
ALLOWED_DOMAINS = ['peerplay.com', 'peerplay.io']
ALLOWED_EMAILS = []

def check_authorization(email):
    """Check if user's email is authorized"""
    if not email:
        return False
    
    if ALLOWED_EMAILS and email.lower() in [e.lower() for e in ALLOWED_EMAILS]:
        return True
    
    email_domain = email.split('@')[-1].lower() if '@' in email else ''
    return email_domain in [d.lower() for d in ALLOWED_DOMAINS]

def get_google_oauth_url():
    """Get Google OAuth URL for authentication"""
    # Get OAuth config from secrets or environment
    client_id = None
    client_secret = None
    
    # Try to get from secrets (TOML format) - multiple methods
    if hasattr(st, 'secrets'):
        try:
            # Method 1: Direct access at top level
            if 'GOOGLE_OAUTH_CLIENT_ID' in st.secrets:
                client_id = st.secrets['GOOGLE_OAUTH_CLIENT_ID']
            # Method 2: get() method at top level
            elif hasattr(st.secrets, 'get'):
                client_id = st.secrets.get('GOOGLE_OAUTH_CLIENT_ID')
            # Method 3: Check inside GOOGLE_APPLICATION_CREDENTIALS_JSON (if nested)
            if not client_id and 'GOOGLE_APPLICATION_CREDENTIALS_JSON' in st.secrets:
                creds_json = st.secrets['GOOGLE_APPLICATION_CREDENTIALS_JSON']
                # Handle both dict and AttrDict (Streamlit's dict-like type)
                try:
                    if hasattr(creds_json, 'get'):
                        client_id = creds_json.get('GOOGLE_OAUTH_CLIENT_ID')
                    elif hasattr(creds_json, '__getitem__'):
                        if 'GOOGLE_OAUTH_CLIENT_ID' in creds_json:
                            client_id = creds_json['GOOGLE_OAUTH_CLIENT_ID']
                except:
                    pass
        except (KeyError, AttributeError, TypeError):
            pass
        
        try:
            # Method 1: Direct access at top level
            if 'GOOGLE_OAUTH_CLIENT_SECRET' in st.secrets:
                client_secret = st.secrets['GOOGLE_OAUTH_CLIENT_SECRET']
            # Method 2: get() method at top level
            elif hasattr(st.secrets, 'get'):
                client_secret = st.secrets.get('GOOGLE_OAUTH_CLIENT_SECRET')
            # Method 3: Check inside GOOGLE_APPLICATION_CREDENTIALS_JSON (if nested)
            if not client_secret and 'GOOGLE_APPLICATION_CREDENTIALS_JSON' in st.secrets:
                creds_json = st.secrets['GOOGLE_APPLICATION_CREDENTIALS_JSON']
                # Handle both dict and AttrDict (Streamlit's dict-like type)
                try:
                    if hasattr(creds_json, 'get'):
                        client_secret = creds_json.get('GOOGLE_OAUTH_CLIENT_SECRET')
                    elif hasattr(creds_json, '__getitem__'):
                        if 'GOOGLE_OAUTH_CLIENT_SECRET' in creds_json:
                            client_secret = creds_json['GOOGLE_OAUTH_CLIENT_SECRET']
                except:
                    pass
        except (KeyError, AttributeError, TypeError):
            pass
    
    # Fallback to environment variables
    if not client_id:
        client_id = os.environ.get('GOOGLE_OAUTH_CLIENT_ID')
    if not client_secret:
        client_secret = os.environ.get('GOOGLE_OAUTH_CLIENT_SECRET')
    
    if not client_id or not client_secret:
        return None
    
    # Get redirect URI from secrets or environment
    redirect_uri = None
    if hasattr(st, 'secrets'):
        try:
            # Method 1: Direct access at top level
            if 'STREAMLIT_REDIRECT_URI' in st.secrets:
                redirect_uri = st.secrets['STREAMLIT_REDIRECT_URI']
            # Method 2: get() method at top level
            elif hasattr(st.secrets, 'get'):
                redirect_uri = st.secrets.get('STREAMLIT_REDIRECT_URI')
            # Method 3: Check inside GOOGLE_APPLICATION_CREDENTIALS_JSON (if nested)
            if not redirect_uri and 'GOOGLE_APPLICATION_CREDENTIALS_JSON' in st.secrets:
                creds_json = st.secrets['GOOGLE_APPLICATION_CREDENTIALS_JSON']
                # Handle both dict and AttrDict (Streamlit's dict-like type)
                try:
                    if hasattr(creds_json, 'get'):
                        redirect_uri = creds_json.get('STREAMLIT_REDIRECT_URI')
                    elif hasattr(creds_json, '__getitem__'):
                        if 'STREAMLIT_REDIRECT_URI' in creds_json:
                            redirect_uri = creds_json['STREAMLIT_REDIRECT_URI']
                except:
                    pass
        except (KeyError, AttributeError, TypeError):
            pass
    
    if not redirect_uri:
        redirect_uri = os.environ.get('STREAMLIT_REDIRECT_URI')
    
    if not redirect_uri:
        # Default fallback - try to get from Streamlit's URL
        try:
            # Try to get current URL from Streamlit
            if hasattr(st, 'server'):
                redirect_uri = f"https://{st.server.serverAddress}/"
            else:
                redirect_uri = "https://offerwall-ab-test.streamlit.app/"
        except:
            redirect_uri = "https://offerwall-ab-test.streamlit.app/"
    
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": client_id,
                "client_secret": client_secret,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [redirect_uri]
            }
        },
        scopes=["openid", "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"],
        redirect_uri=redirect_uri
    )
    
    authorization_url, _ = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='false',
        prompt='consent'
    )
    
    return authorization_url

def is_oauth_configured():
    """Check if OAuth credentials are configured"""
    client_id = None
    client_secret = None
    
    # Try to get from secrets (TOML format) - multiple methods
    if hasattr(st, 'secrets'):
        try:
            # Method 1: Direct access at top level
            if 'GOOGLE_OAUTH_CLIENT_ID' in st.secrets:
                client_id = st.secrets['GOOGLE_OAUTH_CLIENT_ID']
            # Method 2: get() method at top level
            elif hasattr(st.secrets, 'get'):
                client_id = st.secrets.get('GOOGLE_OAUTH_CLIENT_ID')
            # Method 3: Check inside GOOGLE_APPLICATION_CREDENTIALS_JSON (if nested)
            if not client_id and 'GOOGLE_APPLICATION_CREDENTIALS_JSON' in st.secrets:
                creds_json = st.secrets['GOOGLE_APPLICATION_CREDENTIALS_JSON']
                try:
                    if hasattr(creds_json, 'get'):
                        client_id = creds_json.get('GOOGLE_OAUTH_CLIENT_ID')
                    elif hasattr(creds_json, '__getitem__'):
                        if 'GOOGLE_OAUTH_CLIENT_ID' in creds_json:
                            client_id = creds_json['GOOGLE_OAUTH_CLIENT_ID']
                except:
                    pass
        except (KeyError, AttributeError, TypeError):
            pass
        
        try:
            # Method 1: Direct access at top level
            if 'GOOGLE_OAUTH_CLIENT_SECRET' in st.secrets:
                client_secret = st.secrets['GOOGLE_OAUTH_CLIENT_SECRET']
            # Method 2: get() method at top level
            elif hasattr(st.secrets, 'get'):
                client_secret = st.secrets.get('GOOGLE_OAUTH_CLIENT_SECRET')
            # Method 3: Check inside GOOGLE_APPLICATION_CREDENTIALS_JSON (if nested)
            if not client_secret and 'GOOGLE_APPLICATION_CREDENTIALS_JSON' in st.secrets:
                creds_json = st.secrets['GOOGLE_APPLICATION_CREDENTIALS_JSON']
                try:
                    if hasattr(creds_json, 'get'):
                        client_secret = creds_json.get('GOOGLE_OAUTH_CLIENT_SECRET')
                    elif hasattr(creds_json, '__getitem__'):
                        if 'GOOGLE_OAUTH_CLIENT_SECRET' in creds_json:
                            client_secret = creds_json['GOOGLE_OAUTH_CLIENT_SECRET']
                except:
                    pass
        except (KeyError, AttributeError, TypeError):
            pass
    
    # Fallback to environment variables
    if not client_id:
        client_id = os.environ.get('GOOGLE_OAUTH_CLIENT_ID')
    if not client_secret:
        client_secret = os.environ.get('GOOGLE_OAUTH_CLIENT_SECRET')
    
    return client_id is not None and client_secret is not None

def authenticate_user():
    """Authenticate user with Google OAuth (optional)"""
    # Check if OAuth is configured
    if not is_oauth_configured():
        # OAuth not configured - skip authentication
        if 'authenticated' not in st.session_state:
            st.session_state.authenticated = True
            st.session_state.user_email = "public-user@streamlit.app"
            st.session_state.user_name = "Public User"
        return st.session_state.user_email
    
    # OAuth is configured - proceed with authentication
    if 'authenticated' in st.session_state and st.session_state.authenticated:
        if 'user_email' in st.session_state:
            return st.session_state.user_email
        return True
    
    query_params = st.query_params
    code = query_params.get('code')
    
    if code:
        try:
            client_id = None
            client_secret = None
            
            # Try to get from secrets first, then environment
            client_id = None
            client_secret = None
            
            if hasattr(st, 'secrets'):
                try:
                    # Try top level first
                    if 'GOOGLE_OAUTH_CLIENT_ID' in st.secrets:
                        client_id = st.secrets['GOOGLE_OAUTH_CLIENT_ID']
                    elif hasattr(st.secrets, 'get'):
                        client_id = st.secrets.get('GOOGLE_OAUTH_CLIENT_ID')
                    # If not found, check inside GOOGLE_APPLICATION_CREDENTIALS_JSON
                    if not client_id and 'GOOGLE_APPLICATION_CREDENTIALS_JSON' in st.secrets:
                        creds_json = st.secrets['GOOGLE_APPLICATION_CREDENTIALS_JSON']
                        try:
                            if hasattr(creds_json, 'get'):
                                client_id = creds_json.get('GOOGLE_OAUTH_CLIENT_ID')
                            elif hasattr(creds_json, '__getitem__'):
                                if 'GOOGLE_OAUTH_CLIENT_ID' in creds_json:
                                    client_id = creds_json['GOOGLE_OAUTH_CLIENT_ID']
                        except:
                            pass
                except:
                    pass
                
                try:
                    # Try top level first
                    if 'GOOGLE_OAUTH_CLIENT_SECRET' in st.secrets:
                        client_secret = st.secrets['GOOGLE_OAUTH_CLIENT_SECRET']
                    elif hasattr(st.secrets, 'get'):
                        client_secret = st.secrets.get('GOOGLE_OAUTH_CLIENT_SECRET')
                    # If not found, check inside GOOGLE_APPLICATION_CREDENTIALS_JSON
                    if not client_secret and 'GOOGLE_APPLICATION_CREDENTIALS_JSON' in st.secrets:
                        creds_json = st.secrets['GOOGLE_APPLICATION_CREDENTIALS_JSON']
                        try:
                            if hasattr(creds_json, 'get'):
                                client_secret = creds_json.get('GOOGLE_OAUTH_CLIENT_SECRET')
                            elif hasattr(creds_json, '__getitem__'):
                                if 'GOOGLE_OAUTH_CLIENT_SECRET' in creds_json:
                                    client_secret = creds_json['GOOGLE_OAUTH_CLIENT_SECRET']
                        except:
                            pass
                except:
                    pass
            
            # Fallback to environment
            if not client_id:
                client_id = os.environ.get('GOOGLE_OAUTH_CLIENT_ID')
            if not client_secret:
                client_secret = os.environ.get('GOOGLE_OAUTH_CLIENT_SECRET')
            
            if not client_id or not client_secret:
                st.error("OAuth configuration missing. Please contact administrator.")
                return None
            
            # Get redirect URI - same as in get_google_oauth_url
            redirect_uri = None
            if hasattr(st, 'secrets'):
                try:
                    # Method 1: Direct access at top level
                    if 'STREAMLIT_REDIRECT_URI' in st.secrets:
                        redirect_uri = st.secrets['STREAMLIT_REDIRECT_URI']
                    # Method 2: get() method at top level
                    elif hasattr(st.secrets, 'get'):
                        redirect_uri = st.secrets.get('STREAMLIT_REDIRECT_URI')
                    # Method 3: Check inside GOOGLE_APPLICATION_CREDENTIALS_JSON (if nested)
                    if not redirect_uri and 'GOOGLE_APPLICATION_CREDENTIALS_JSON' in st.secrets:
                        creds_json = st.secrets['GOOGLE_APPLICATION_CREDENTIALS_JSON']
                        try:
                            if hasattr(creds_json, 'get'):
                                redirect_uri = creds_json.get('STREAMLIT_REDIRECT_URI')
                            elif hasattr(creds_json, '__getitem__'):
                                if 'STREAMLIT_REDIRECT_URI' in creds_json:
                                    redirect_uri = creds_json['STREAMLIT_REDIRECT_URI']
                        except:
                            pass
                except (KeyError, AttributeError, TypeError):
                    pass
            
            if not redirect_uri:
                redirect_uri = os.environ.get('STREAMLIT_REDIRECT_URI')
            
            if not redirect_uri:
                # Default fallback - try to get from Streamlit's URL
                try:
                    if hasattr(st, 'server'):
                        redirect_uri = f"https://{st.server.serverAddress}/"
                    else:
                        redirect_uri = "https://offerwall-ab-test.streamlit.app/"
                except:
                    redirect_uri = "https://offerwall-ab-test.streamlit.app/"
            
            flow = Flow.from_client_config(
                {
                    "web": {
                        "client_id": client_id,
                        "client_secret": client_secret,
                        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                        "token_uri": "https://oauth2.googleapis.com/token",
                        "redirect_uris": [redirect_uri]
                    }
                },
                scopes=["openid", "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"],
                redirect_uri=redirect_uri
            )
            
            flow.fetch_token(code=code)
            credentials = flow.credentials
            
            from google.oauth2.credentials import Credentials
            import requests
            
            user_info_response = requests.get(
                'https://www.googleapis.com/oauth2/v2/userinfo',
                headers={'Authorization': f'Bearer {credentials.token}'}
            )
            user_info = user_info_response.json()
            user_email = user_info.get('email', '')
            
            if check_authorization(user_email):
                st.session_state.authenticated = True
                st.session_state.user_email = user_email
                st.session_state.user_name = user_info.get('name', '')
                st.query_params.clear()
                st.rerun()
                return user_email
            else:
                st.error(f"❌ Access Denied: {user_email} is not authorized to access this dashboard.")
                st.info("This dashboard is restricted to Peerplay employees only.")
                return None
                
        except Exception as e:
            st.error(f"Authentication error: {e}")
            return None
    
    # Show login page (only if OAuth is configured)
    if is_oauth_configured():
        st.title("🔐 Authentication Required")
        st.markdown("Please sign in with your Google account to access the Offerwall AB Test Dashboard.")
        
        auth_url = get_google_oauth_url()
        if auth_url:
            st.markdown(f"[**Click here to sign in with Google**]({auth_url})")
        else:
            st.error("OAuth configuration error. Please check your OAuth credentials.")
            st.markdown("### Debug Information")
            st.markdown("""
            **Troubleshooting Steps:**
            1. Check that `GOOGLE_OAUTH_CLIENT_ID` and `GOOGLE_OAUTH_CLIENT_SECRET` are in Streamlit Cloud secrets
            2. Verify secrets are at the top level (not inside a table)
            3. Make sure you clicked "Save" and "Reboot app" after adding secrets
            4. Check that the redirect URI in Google Cloud Console matches your Streamlit app URL
            """)
        
        st.stop()
        return None
    else:
        # OAuth not configured - show helpful message
        st.title("🔐 Authentication Setup Required")
        st.warning("OAuth credentials are not configured. The dashboard will work without authentication, but it's recommended to set up OAuth for security.")
        
        st.markdown("### Setup Instructions")
        st.markdown("""
        To enable Google OAuth authentication:
        
        1. **Create Google OAuth credentials**:
           - Go to: https://console.cloud.google.com/apis/credentials?project=yotam-395120
           - Create OAuth 2.0 Client ID (Web application)
           - Add authorized redirect URI: Your Streamlit app URL (e.g., `https://offerwall-ab-test-6v7uq4xgov7ep6uzxntqvj.streamlit.app/`)
        
        2. **Add to Streamlit Cloud Secrets**:
           - Go to your app settings in Streamlit Cloud
           - Click "Secrets" tab
           - Add these secrets at the **top level** (not inside a table):
             ```toml
             GOOGLE_OAUTH_CLIENT_ID = "your-client-id.apps.googleusercontent.com"
             GOOGLE_OAUTH_CLIENT_SECRET = "your-client-secret"
             STREAMLIT_REDIRECT_URI = "https://your-app-url.streamlit.app/"
             ```
        
        3. **Save and Reboot** the app in Streamlit Cloud
        
        **Note**: Make sure the redirect URI in Google Cloud Console **exactly matches** your Streamlit app URL (including the trailing slash).
        """)
        
        # Allow bypass for now
        if st.button("Continue Without Authentication (Not Recommended)"):
            if 'authenticated' not in st.session_state:
                st.session_state.authenticated = True
                st.session_state.user_email = "public-user@streamlit.app"
                st.session_state.user_name = "Public User"
            st.rerun()
        
        st.stop()
        return None

# Authenticate user before showing dashboard
SKIP_AUTH = os.environ.get('SKIP_AUTH', 'false').lower() == 'true'
if not SKIP_AUTH:
    user_email = authenticate_user()
    if not user_email:
        st.stop()
else:
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = True
        st.session_state.user_email = "local-dev@peerplay.com"
        st.session_state.user_name = "Local Developer"

# Configuration
PROJECT_ID = os.environ.get('GCP_PROJECT_ID', 'yotam-395120')
DATASET_ID = os.environ.get('BQ_DATASET_ID', 'peerplay')
TABLE_ID = os.environ.get('TABLE_ID', 'offerwall_dec_ab_test')
FULL_TABLE = f'{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}'

# Initialize BigQuery client
@st.cache_resource
def get_bigquery_client():
    """Initialize and return BigQuery client with multiple authentication methods"""
    try:
        # Method 1: Service account JSON from Streamlit Cloud secrets
        try:
            if hasattr(st, 'secrets'):
                available_secrets = list(st.secrets.keys()) if hasattr(st.secrets, 'keys') else []
                
                possible_keys = [
                    'GOOGLE_APPLICATION_CREDENTIALS_JSON',
                    'google_application_credentials_json',
                    'GOOGLE_APPLICATION_CREDENTIALS'
                ]
                
                service_account_data = None
                
                if 'GOOGLE_APPLICATION_CREDENTIALS_JSON' in st.secrets:
                    secret_value = st.secrets['GOOGLE_APPLICATION_CREDENTIALS_JSON']
                    if isinstance(secret_value, dict):
                        creds_dict = secret_value
                        credentials = service_account.Credentials.from_service_account_info(
                            creds_dict,
                            scopes=["https://www.googleapis.com/auth/cloud-platform"]
                        )
                        client = bigquery.Client(credentials=credentials, project=PROJECT_ID)
                        return client
                    else:
                        service_account_data = secret_value
                
                if service_account_data:
                    if isinstance(service_account_data, str):
                        try:
                            creds_dict = json.loads(service_account_data)
                        except (json.JSONDecodeError, ValueError) as json_err:
                            cleaned = service_account_data.strip()
                            if cleaned.startswith('"') and cleaned.endswith('"'):
                                cleaned = cleaned[1:-1]
                            elif cleaned.startswith("'") and cleaned.endswith("'"):
                                cleaned = cleaned[1:-1]
                            cleaned = cleaned.replace('\\"', '"')
                            cleaned = cleaned.replace("\\'", "'")
                            try:
                                creds_dict = json.loads(cleaned)
                            except (json.JSONDecodeError, ValueError):
                                cleaned = cleaned.replace('\\n', '\n')
                                creds_dict = json.loads(cleaned)
                    else:
                        creds_dict = dict(service_account_data)
                    
                    required_fields = ['type', 'project_id', 'private_key', 'client_email']
                    if not all(field in creds_dict for field in required_fields):
                        raise ValueError(f"Missing required fields. Found: {list(creds_dict.keys())}")
                    
                    credentials = service_account.Credentials.from_service_account_info(
                        creds_dict,
                        scopes=["https://www.googleapis.com/auth/cloud-platform"]
                    )
                    client = bigquery.Client(credentials=credentials, project=PROJECT_ID)
                    return client
        except Exception as e:
            pass
        
        # Method 2: Environment variable with JSON string
        creds_json_str = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS_JSON')
        if creds_json_str:
            try:
                creds_dict = json.loads(creds_json_str)
                credentials = service_account.Credentials.from_service_account_info(
                    creds_dict,
                    scopes=["https://www.googleapis.com/auth/cloud-platform"]
                )
                client = bigquery.Client(credentials=credentials, project=PROJECT_ID)
                return client
            except Exception as e:
                pass
        
        # Method 3: Service account file path
        creds_path = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS')
        if creds_path and os.path.exists(creds_path):
            credentials = service_account.Credentials.from_service_account_file(
                creds_path,
                scopes=["https://www.googleapis.com/auth/cloud-platform"]
            )
            client = bigquery.Client(credentials=credentials, project=PROJECT_ID)
            return client
        
        # Method 4: Application Default Credentials (for local development)
        try:
            credentials, project = default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
            client = bigquery.Client(credentials=credentials, project=PROJECT_ID)
            return client
        except Exception as adc_error:
            st.error("❌ Failed to initialize BigQuery client")
            st.error("**Authentication Error:** No valid credentials found.")
            st.markdown("""
            **For Streamlit Cloud deployment:**
            1. Go to your app settings in Streamlit Cloud
            2. Click "Secrets" tab
            3. Add secret named: GOOGLE_APPLICATION_CREDENTIALS_JSON
            4. Paste your service account JSON in TOML format with triple quotes
            5. Save and redeploy the app
            
            **For local development:**
            Run: gcloud auth application-default login
            """)
            return None
            
    except Exception as e:
        st.error(f"❌ Failed to initialize BigQuery client: {e}")
        st.markdown("""
        **Troubleshooting:**
        - Check that service account has BigQuery permissions
        - Verify credentials are correctly set in Streamlit Cloud secrets
        - Make sure the secret name is exactly: `GOOGLE_APPLICATION_CREDENTIALS_JSON`
        - For local: Run `gcloud auth application-default login`
        """)
        return None

@st.cache_data(ttl=60)  # Cache for 60 seconds
def load_data(_client, date_filter=None, test_group_filter=None, chapters_bucket_filter=None, first_mediasource_filter=None):
    """Load data from BigQuery"""
    try:
        query = f"""
        SELECT *
        FROM `{FULL_TABLE}`
        WHERE 1=1
        """
        
        if date_filter:
            if isinstance(date_filter, list) and len(date_filter) == 2:
                # Date range
                query += f" AND DATE(date) >= DATE('{date_filter[0]}') AND DATE(date) <= DATE('{date_filter[1]}')"
            elif isinstance(date_filter, list) and len(date_filter) > 2:
                # Multiple specific dates
                date_list = ','.join([f"DATE('{d}')" for d in date_filter])
                query += f" AND DATE(date) IN ({date_list})"
            elif isinstance(date_filter, str):
                # Single date
                query += f" AND DATE(date) = DATE('{date_filter}')"
        
        if test_group_filter:
            if isinstance(test_group_filter, list):
                if 'test' in test_group_filter and 'control' in test_group_filter:
                    pass  # Show both
                elif 'test' in test_group_filter:
                    query += " AND is_odd = 1"
                elif 'control' in test_group_filter:
                    query += " AND is_odd = 0"
        
        if chapters_bucket_filter and len(chapters_bucket_filter) > 0:
            chapters_list = ','.join([f"'{b}'" for b in chapters_bucket_filter])
            query += f" AND chapters_bucket IN ({chapters_list})"
        
        if first_mediasource_filter and len(first_mediasource_filter) > 0:
            mediasources_list = ','.join([f"'{m}'" for m in first_mediasource_filter])
            query += f" AND first_mediasource IN ({mediasources_list})"
        
        query += " ORDER BY date, is_odd"
        
        df = _client.query(query).to_dataframe()
        
        # Ensure proper data types
        if len(df) > 0:
            if 'date' in df.columns:
                df['date'] = pd.to_datetime(df['date'])
            
            if 'is_odd' in df.columns:
                df['test_group'] = df['is_odd'].map({1: 'test', 0: 'control'})
            
            # Ensure test_start_date is datetime if present
            if 'test_start_date' in df.columns:
                df['test_start_date'] = pd.to_datetime(df['test_start_date'], errors='coerce')
        
        return df
        
    except Exception as e:
        st.error(f"Error loading data: {e}")
        import traceback
        st.error(f"Traceback: {traceback.format_exc()}")
        return pd.DataFrame()

def get_filter_options(df):
    """Get unique values for filters"""
    options = {
        'test_group': ['test', 'control'],
        'chapters_bucket': sorted(df['chapters_bucket'].dropna().unique().tolist()) if len(df) > 0 and 'chapters_bucket' in df.columns else [],
        'first_mediasource': sorted(df['first_mediasource'].dropna().unique().tolist()) if len(df) > 0 and 'first_mediasource' in df.columns else [],
    }
    return options

def apply_filters(df, filters):
    """Apply filters to dataframe"""
    filtered_df = df.copy()
    
    if filters.get('test_group'):
        if len(filters['test_group']) == 1:
            if 'test' in filters['test_group']:
                filtered_df = filtered_df[filtered_df['is_odd'] == 1]
            elif 'control' in filters['test_group']:
                filtered_df = filtered_df[filtered_df['is_odd'] == 0]
    
    if filters.get('chapters_bucket'):
        filtered_df = filtered_df[filtered_df['chapters_bucket'].isin(filters['chapters_bucket'])]
    
    if filters.get('first_mediasource'):
        filtered_df = filtered_df[filtered_df['first_mediasource'].isin(filters['first_mediasource'])]
    
    return filtered_df

def calculate_kpis(df, period='all'):
    """Calculate KPIs for the dataframe (assumes daily aggregated data)"""
    if len(df) == 0:
        return {}
    
    # Determine date range for period separation
    if period == 'before' and 'test_start_date' in df.columns and len(df) > 0:
        test_start = df['test_start_date'].iloc[0]
        df = df[df['date'] < test_start]
    elif period == 'during' and 'test_start_date' in df.columns and len(df) > 0:
        test_start = df['test_start_date'].iloc[0]
        df = df[df['date'] >= test_start]
    
    if len(df) == 0:
        return {}
    
    # Get column names (exact names from table)
    dau_col = 'dau' if 'dau' in df.columns else None
    revenue_col = 'revenue' if 'revenue' in df.columns else None
    paid_col = 'payers' if 'payers' in df.columns else None
    purchases_col = 'purchases' if 'purchases' in df.columns else None
    chapters_col = 'chapters_completed' if 'chapters_completed' in df.columns else None
    generation_col = 'daily_generation' if 'daily_generation' in df.columns else ('generation' if 'generation' in df.columns else None)
    merge_col = 'daily_merge' if 'daily_merge' in df.columns else ('merge' if 'merge' in df.columns else None)
    spend_col = 'daily_generation_spend' if 'daily_generation_spend' in df.columns else ('generation_spend' if 'generation_spend' in df.columns else None)
    retention_col = 'is_returned_next_day' if 'is_returned_next_day' in df.columns else None
    
    # Calculate totals (sum across all days)
    total_dau = df[dau_col].sum() if dau_col and dau_col in df.columns else 0
    total_revenue = df[revenue_col].sum() if revenue_col and revenue_col in df.columns else 0
    total_paid_today = df[paid_col].sum() if paid_col and paid_col in df.columns else 0
    total_purchases = df[purchases_col].sum() if purchases_col and purchases_col in df.columns else 0
    total_chapters_completed = df[chapters_col].sum() if chapters_col and chapters_col in df.columns else 0
    total_daily_generation = df[generation_col].sum() if generation_col and generation_col in df.columns else 0
    total_daily_merge = df[merge_col].sum() if merge_col and merge_col in df.columns else 0
    total_daily_generation_spend = df[spend_col].sum() if spend_col and spend_col in df.columns else 0
    total_returned_next_day = df[retention_col].sum() if retention_col and retention_col in df.columns else 0
    
    num_days = df['date'].nunique() if 'date' in df.columns else 1
    
    # Calculate KPIs
    avg_daily_dau = total_dau / num_days if num_days > 0 else 0
    avg_daily_revenue = total_revenue / num_days if num_days > 0 else 0
    arpdau = total_revenue / total_dau if total_dau > 0 else 0
    pct_pu_dau = (total_paid_today / total_dau * 100) if total_dau > 0 else 0
    arppu = total_revenue / total_paid_today if total_paid_today > 0 else 0
    transactions_per_payer = total_purchases / total_paid_today if total_paid_today > 0 else 0
    atv = total_revenue / total_purchases if total_purchases > 0 else 0
    chapters_per_player = total_chapters_completed / total_dau if total_dau > 0 else 0
    generations_per_player = total_daily_generation / total_dau if total_dau > 0 else 0
    merges_per_player = total_daily_merge / total_dau if total_dau > 0 else 0
    credits_spend_per_player = total_daily_generation_spend / total_dau if total_dau > 0 else 0
    dod_retention = (total_returned_next_day / total_dau * 100) if total_dau > 0 else 0
    
    return {
        'Avg Daily DAU': avg_daily_dau,
        'Avg Daily Revenue': avg_daily_revenue,
        'ARPUDAU': arpdau,
        '%PU/DAU': pct_pu_dau,
        'ARPPU': arppu,
        'Transactions per Payer': transactions_per_payer,
        'ATV': atv,
        'Chapters per Player': chapters_per_player,
        'Generations per Player': generations_per_player,
        'Merges per Player': merges_per_player,
        'Credits Spend per Player': credits_spend_per_player,
        'DOD Retention': dod_retention
    }

def create_kpis_comparison_table(df, test_start_date=None):
    """Create comparison table of KPIs before vs during test using Period column"""
    if len(df) == 0:
        return pd.DataFrame()
    
    # Ensure date column is datetime
    if 'date' in df.columns:
        df['date'] = pd.to_datetime(df['date'])
    
    # Check if Period column exists
    if 'Period' not in df.columns:
        st.warning("'Period' column not found in data. Cannot determine before/during periods.")
        return pd.DataFrame()
    
    # Calculate KPIs for each test group, then reorganize by KPI
    kpi_data = {}
    
    for test_group in ['test', 'control']:
        group_df = df[df['test_group'] == test_group].copy()
        
        if len(group_df) == 0:
            continue
        
        # Split by Period column
        before_df = group_df[group_df['Period'].str.lower() == 'before'].copy() if 'Period' in group_df.columns else pd.DataFrame()
        during_df = group_df[group_df['Period'].str.lower() == 'during'].copy() if 'Period' in group_df.columns else pd.DataFrame()
        
        before_kpis = calculate_kpis(before_df, period='all')
        during_kpis = calculate_kpis(during_df, period='all')
        
        # Get all unique KPI names from both periods
        all_kpis = set(before_kpis.keys()) | set(during_kpis.keys())
        
        for kpi_name in all_kpis:
            if kpi_name not in kpi_data:
                kpi_data[kpi_name] = {}
            
            before_value = before_kpis.get(kpi_name, 0)
            during_value = during_kpis.get(kpi_name, 0)
            change = during_value - before_value
            change_pct = (change / before_value * 100) if before_value != 0 else (0 if during_value == 0 else float('inf'))
            
            kpi_data[kpi_name][test_group] = {
                'Before': before_value,
                'During': during_value,
                'Change': change,
                'Change %': change_pct if change_pct != float('inf') else 0
            }
    
    # Reorganize data: Group by KPI first, then split by test/control
    results = []
    
    # Define KPI order (custom order as specified)
    kpi_order = [
        'Avg Daily DAU',
        'Avg Daily Revenue',
        'ARPUDAU',
        '%PU/DAU',
        'ARPPU',
        'ATV',
        'Transactions per Payer',
        'DOD Retention',
        'Chapters per Player',
        'Credits Spend per Player',
        'Generations per Player',
        'Merges per Player'
    ]
    
    # Get all KPIs in the specified order
    all_kpi_names = []
    # First add KPIs in the specified order
    for kpi in kpi_order:
        if kpi in kpi_data:
            all_kpi_names.append(kpi)
    # Then add any remaining KPIs not in the list (sorted)
    remaining_kpis = sorted([k for k in kpi_data.keys() if k not in kpi_order])
    all_kpi_names.extend(remaining_kpis)
    
    # Define which KPIs have "lower is better" (for win/loss determination)
    # For most metrics, higher is better, but some like "Credits Spend per Player" might be lower is better
    lower_is_better_kpis = ['Credits Spend per Player']  # Add more if needed
    
    for kpi_name in all_kpi_names:
        kpi_info = kpi_data[kpi_name]
        
        # Get test and control data
        test_data = kpi_info.get('test', {})
        control_data = kpi_info.get('control', {})
        
        test_during = test_data.get('During', 0)
        control_during = control_data.get('During', 0)
        test_change_pct = test_data.get('Change %', 0)
        control_change_pct = control_data.get('Change %', 0)
        
        # Determine win/loss indicator
        # Priority: Compare change percentages when both groups changed in same direction
        # This ensures we correctly identify winners even when both are dropping/increasing
        
        if kpi_name in lower_is_better_kpis:
            # For metrics where lower is better (e.g., Credits Spend per Player)
            # First check if both changed in same direction
            if test_change_pct < 0 and control_change_pct < 0:
                # Both dropping: test wins if it dropped less (smaller negative = better)
                is_winning = test_change_pct > control_change_pct
            elif test_change_pct > 0 and control_change_pct > 0:
                # Both increasing: test wins if it increased less (smaller positive = better for lower-is-better)
                is_winning = test_change_pct < control_change_pct
            else:
                # Different directions or one unchanged: compare absolute During values
                if test_during < control_during:
                    is_winning = True
                elif test_during > control_during:
                    is_winning = False
                else:
                    is_winning = None
        else:
            # For metrics where higher is better (most KPIs)
            # First check if both changed in same direction
            if test_change_pct < 0 and control_change_pct < 0:
                # Both dropping: test wins if it dropped less (smaller negative = better)
                # Example: Test -27% vs Control -32% → Test wins (less negative)
                is_winning = test_change_pct > control_change_pct
            elif test_change_pct > 0 and control_change_pct > 0:
                # Both increasing: test wins if it increased more (larger positive = better)
                is_winning = test_change_pct > control_change_pct
            else:
                # Different directions or one unchanged: compare absolute During values
                if test_during > control_during:
                    is_winning = True
                elif test_during < control_during:
                    is_winning = False
                else:
                    is_winning = None
        
        # Calculate diff between test and control change %
        # (test_change_pct and control_change_pct are already defined above)
        diff_change_pct = test_change_pct - control_change_pct
        
        # Add Test row
        if 'test' in kpi_info:
            test_data = kpi_info['test']
            results.append({
                'KPI': kpi_name,
                'Test Group': 'Test',
                'Before': test_data['Before'],
                'During': test_data['During'],
                'Change': test_data['Change'],
                'Change %': test_data['Change %'],
                'Diff (Test-Control)': diff_change_pct,
                'Status': '🟢' if is_winning else ('🔴' if is_winning is False else '⚪')
            })
        
        # Add Control row
        if 'control' in kpi_info:
            control_data = kpi_info['control']
            results.append({
                'KPI': kpi_name,
                'Test Group': 'Control',
                'Before': control_data['Before'],
                'During': control_data['During'],
                'Change': control_data['Change'],
                'Change %': control_data['Change %'],
                'Diff (Test-Control)': '',  # Empty for control row
                'Status': ''  # No status for control group
            })
    
    return pd.DataFrame(results)

def calculate_daily_kpi(df, kpi_name):
    """Calculate daily KPI value from daily aggregated row (sum if multiple rows per day)"""
    if len(df) == 0:
        return 0
    
    # Get column names (exact names from table)
    dau_col = 'dau' if 'dau' in df.columns else None
    revenue_col = 'revenue' if 'revenue' in df.columns else None
    paid_col = 'payers' if 'payers' in df.columns else None
    purchases_col = 'purchases' if 'purchases' in df.columns else None
    chapters_col = 'chapters_completed' if 'chapters_completed' in df.columns else None
    generation_col = 'daily_generation' if 'daily_generation' in df.columns else ('generation' if 'generation' in df.columns else None)
    merge_col = 'daily_merge' if 'daily_merge' in df.columns else ('merge' if 'merge' in df.columns else None)
    spend_col = 'daily_generation_spend' if 'daily_generation_spend' in df.columns else ('generation_spend' if 'generation_spend' in df.columns else None)
    retention_col = 'is_returned_next_day' if 'is_returned_next_day' in df.columns else None
    
    # For daily data, sum across all rows for the day (in case of multiple dimensions)
    dau = df[dau_col].sum() if dau_col and dau_col in df.columns else 0
    revenue = df[revenue_col].sum() if revenue_col and revenue_col in df.columns else 0
    paid_today = df[paid_col].sum() if paid_col and paid_col in df.columns else 0
    purchases = df[purchases_col].sum() if purchases_col and purchases_col in df.columns else 0
    chapters = df[chapters_col].sum() if chapters_col and chapters_col in df.columns else 0
    generation = df[generation_col].sum() if generation_col and generation_col in df.columns else 0
    merge = df[merge_col].sum() if merge_col and merge_col in df.columns else 0
    spend = df[spend_col].sum() if spend_col and spend_col in df.columns else 0
    returned = df[retention_col].sum() if retention_col and retention_col in df.columns else 0
    
    # Map KPI names to calculations
    kpi_map = {
        'Avg Daily DAU': dau,
        'Avg Daily Revenue': revenue,
        'ARPUDAU': revenue / dau if dau > 0 else 0,
        '%PU/DAU': (paid_today / dau * 100) if dau > 0 else 0,
        'ARPPU': revenue / paid_today if paid_today > 0 else 0,
        'Transactions per Payer': purchases / paid_today if paid_today > 0 else 0,
        'ATV': revenue / purchases if purchases > 0 else 0,
        'Chapters per Player': chapters / dau if dau > 0 else 0,
        'Generations per Player': generation / dau if dau > 0 else 0,
        'Merges per Player': merge / dau if dau > 0 else 0,
        'Credits Spend per Player': spend / dau if dau > 0 else 0,
        'DOD Retention': (returned / dau * 100) if dau > 0 else 0
    }
    
    return kpi_map.get(kpi_name, 0)

def create_daily_trends_chart(df, kpi_name, test_start_date=None):
    """Create daily trends line chart for a specific KPI using Period column"""
    if len(df) == 0:
        return None
    
    # Ensure date column is datetime
    if 'date' in df.columns:
        df['date'] = pd.to_datetime(df['date'])
    
    # Check if Period column exists
    if 'Period' not in df.columns:
        st.warning("'Period' column not found in data. Cannot create trends chart.")
        return None
    
    # Find the first "during" date for the vertical line
    during_dates = df[df['Period'].str.lower() == 'during']['date'].dropna()
    first_during_date = pd.to_datetime(during_dates.min()) if len(during_dates) > 0 else None
    
    # Calculate daily KPI values
    daily_data = []
    
    for test_group in ['test', 'control']:
        group_df = df[df['test_group'] == test_group].copy()
        
        if len(group_df) == 0:
            continue
        
        for date in sorted(group_df['date'].unique()):
            day_df = group_df[group_df['date'] == date]
            value = calculate_daily_kpi(day_df, kpi_name)
            
            daily_data.append({
                'date': date,
                'test_group': test_group,
                'value': value
            })
    
    if not daily_data:
        return None
    
    trend_df = pd.DataFrame(daily_data)
    
    # Create line chart with only 2 lines (Test and Control)
    fig = go.Figure()
    
    for test_group in ['test', 'control']:
        group_df = trend_df[trend_df['test_group'] == test_group]
        
        if len(group_df) > 0:
            line_color = 'blue' if test_group == 'test' else 'red'
            
            fig.add_trace(go.Scatter(
                x=group_df['date'],
                y=group_df['value'],
                mode='lines+markers',
                name=test_group.title(),
                line=dict(color=line_color),
                opacity=1.0
            ))
    
    # Add vertical line at first "during" date
    if first_during_date is not None:
        try:
            # Convert to string format that plotly expects
            vline_date = first_during_date
            if isinstance(vline_date, pd.Timestamp):
                vline_date = vline_date.to_pydatetime()
            
            fig.add_vline(
                x=vline_date,
                line_dash="dot",
                line_color="gray",
                line_width=2,
                annotation_text="Test Start",
                annotation_position="top",
                annotation=dict(font_size=12, font_color="gray")
            )
        except Exception as e:
            # Try alternative method
            try:
                fig.add_shape(
                    type="line",
                    x0=first_during_date,
                    x1=first_during_date,
                    y0=0,
                    y1=1,
                    yref="paper",
                    line=dict(color="gray", width=2, dash="dot")
                )
                fig.add_annotation(
                    x=first_during_date,
                    y=1,
                    yref="paper",
                    text="Test Start",
                    showarrow=False,
                    xanchor="left",
                    font=dict(size=12, color="gray")
                )
            except:
                pass
    
    fig.update_layout(
        title=f'{kpi_name} - Daily Trends',
        xaxis_title='Date',
        yaxis_title=kpi_name,
        hovermode='x unified',
        legend=dict(yanchor="top", y=0.99, xanchor="left", x=0.01)
    )
    
    return fig

def main():
    """Main dashboard function"""
    # Inject custom CSS
    inject_custom_css()
    
    # Modern header with gradient
    st.markdown(f"""
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                padding: 2rem; 
                border-radius: 15px; 
                margin-bottom: 2rem;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
        <h1 style="color: white; margin: 0; font-size: 2.5rem; font-weight: 700;">
            🧪 Offerwall AB Test Dashboard
        </h1>
        <p style="color: rgba(255, 255, 255, 0.9); margin: 0.5rem 0 0 0; font-size: 1.1rem;">
            Analyze AB test performance and compare test vs control groups
        </p>
        <p style="color: rgba(255, 255, 255, 0.8); margin: 0.5rem 0 0 0; font-size: 0.9rem;">
            <strong>Data Source:</strong> {FULL_TABLE}
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Show user info in sidebar
    if 'user_email' in st.session_state:
        st.sidebar.markdown("### 👤 User")
        st.sidebar.markdown(f"**Email**: {st.session_state.user_email}")
        if 'user_name' in st.session_state:
            st.sidebar.markdown(f"**Name**: {st.session_state.user_name}")
        if st.sidebar.button("🚪 Sign Out"):
            for key in list(st.session_state.keys()):
                if key.startswith('authenticated') or key.startswith('user_'):
                    del st.session_state[key]
            st.rerun()
        st.sidebar.markdown("<br>", unsafe_allow_html=True)  # Small spacer
    
    # Initialize BigQuery client
    client = get_bigquery_client()
    if client is None:
        st.stop()
        return
    
    # Refresh button
    col1, col2 = st.columns([1, 5])
    with col1:
        if st.button("🔄 Refresh Now"):
            st.cache_data.clear()
            st.rerun()
    
    # Initialize session state for filters
    if 'filter_applied' not in st.session_state:
        st.session_state.filter_applied = {
            'date': None,
            'test_group': [],
            'chapters_bucket': [],
            'first_mediasource': []
        }
    
    if 'filter_temp' not in st.session_state:
        st.session_state.filter_temp = st.session_state.filter_applied.copy()
    
    # Load initial data first (needed for Dimension Selector and Test Period)
    with st.spinner("Loading data from BigQuery..."):
        initial_df_for_dates = load_data(
            client,
            date_filter=None,
            test_group_filter=None
        )
    
    # Sidebar: Modern header
    st.sidebar.markdown("""
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                padding: 0.75rem; 
                border-radius: 10px; 
                margin-bottom: 0.75rem;
                text-align: center;">
        <h3 style="color: white; margin: 0; font-size: 1.1rem;">
            ⚙️ Dashboard Controls
        </h3>
    </div>
    """, unsafe_allow_html=True)
    
    # Dimension selector (moved above filters)
    if len(initial_df_for_dates) > 0:
        st.sidebar.markdown("### 🔀 Dimension Selector")
        st.sidebar.markdown("<small>Select one dimension to split views by:</small>", unsafe_allow_html=True)
        
        dimension_options = {
            'None': None,
            'Chapters Bucket': 'chapters_bucket',
            'First Mediasource': 'first_mediasource'
        }
        
        # Initialize dimension in session state if not exists
        if 'selected_dimension' not in st.session_state:
            st.session_state.selected_dimension = 'None'
        
        # Get current index
        current_dim_index = 0
        if st.session_state.selected_dimension in dimension_options:
            current_dim_index = list(dimension_options.keys()).index(st.session_state.selected_dimension)
        
        selected_dimension = st.sidebar.selectbox(
            "Dimension",
            options=list(dimension_options.keys()),
            index=current_dim_index,
            key="dimension_selector"
        )
        
        st.session_state.selected_dimension = selected_dimension
        dimension = dimension_options[selected_dimension]
        
        # Check if dimension is valid
        if dimension and dimension not in initial_df_for_dates.columns:
            original_dim = dimension
            dimension = None
            st.sidebar.warning(f"Dimension '{original_dim}' not available in data")
    else:
        dimension = None
    
    # Test Period (moved above filters)
    if len(initial_df_for_dates) > 0 and 'Period' in initial_df_for_dates.columns:
        # Determine test start date from Period column
        during_dates = initial_df_for_dates[initial_df_for_dates['Period'].str.lower() == 'during']['date'].dropna()
        if len(during_dates) > 0:
            test_start_date_sidebar = pd.to_datetime(during_dates.min())
            st.sidebar.markdown("### 📅 Test Period")
            st.sidebar.info(f"**Test Start**: {test_start_date_sidebar.strftime('%Y-%m-%d')}")
        else:
            st.sidebar.markdown("### 📅 Test Period")
            st.sidebar.info("Using 'Period' column from data")
    elif len(initial_df_for_dates) > 0:
        st.sidebar.markdown("### 📅 Test Period")
        st.sidebar.info("'Period' column not found in data")
    
    # Sidebar filters
    # Sidebar: Filters section with visual separator
    st.sidebar.markdown("<hr style='margin: 0.75rem 0;'>", unsafe_allow_html=True)
    st.sidebar.markdown("### 🔍 Filters")
    
    # Date filter - multiselect
    st.sidebar.markdown("#### Date Filter")
    if len(initial_df_for_dates) > 0 and 'date' in initial_df_for_dates.columns:
        # Get unique dates and sort them
        available_dates = sorted(initial_df_for_dates['date'].dropna().unique())
        date_options = [str(date.date()) if isinstance(date, pd.Timestamp) else str(date) for date in available_dates]
        
        # Get current selection
        current_selection = []
        if st.session_state.filter_temp['date']:
            if isinstance(st.session_state.filter_temp['date'], list):
                if len(st.session_state.filter_temp['date']) == 2:
                    # If it's a date range, convert to list of dates in range
                    try:
                        start_date = pd.to_datetime(st.session_state.filter_temp['date'][0])
                        end_date = pd.to_datetime(st.session_state.filter_temp['date'][1])
                        date_range = pd.date_range(start=start_date, end=end_date, freq='D')
                        current_selection = [str(d.date()) for d in date_range if str(d.date()) in date_options]
                    except:
                        current_selection = [d for d in st.session_state.filter_temp['date'] if d in date_options]
                else:
                    current_selection = [d for d in st.session_state.filter_temp['date'] if d in date_options]
            elif isinstance(st.session_state.filter_temp['date'], str):
                if st.session_state.filter_temp['date'] in date_options:
                    current_selection = [st.session_state.filter_temp['date']]
        
        selected_dates = st.sidebar.multiselect(
            "Select Dates",
            options=date_options,
            default=current_selection if current_selection else [],
            key="date_multiselect_filter"
        )
        
        if len(selected_dates) == 0:
            st.session_state.filter_temp['date'] = None
        elif len(selected_dates) == 1:
            # Single date as range
            st.session_state.filter_temp['date'] = [selected_dates[0], selected_dates[0]]
        else:
            # Multiple dates - store as list for IN query
            st.session_state.filter_temp['date'] = selected_dates
    else:
        st.sidebar.info("No date data available")
        st.session_state.filter_temp['date'] = None
    
    # Test group filter
    st.sidebar.markdown("#### Test Group")
    test_group_options = ['test', 'control']
    selected_test_groups = st.sidebar.multiselect(
        "Select Test Groups",
        options=test_group_options,
        default=st.session_state.filter_temp['test_group'] if st.session_state.filter_temp['test_group'] else test_group_options,
        key="test_group_filter"
    )
    st.session_state.filter_temp['test_group'] = selected_test_groups
    
    # Load initial data to get filter options (use the dates we already loaded)
    initial_df = initial_df_for_dates.copy() if len(initial_df_for_dates) > 0 else pd.DataFrame()
    
    # Apply date filter if set (handled in load_data query, but also filter here for consistency)
    if st.session_state.filter_temp['date'] and len(initial_df) > 0 and 'date' in initial_df.columns:
        date_filter = st.session_state.filter_temp['date']
        if isinstance(date_filter, list):
            if len(date_filter) == 2:
                # Date range
                initial_df = initial_df[
                    (initial_df['date'] >= pd.to_datetime(date_filter[0])) & 
                    (initial_df['date'] <= pd.to_datetime(date_filter[1]))
                ]
            elif len(date_filter) > 2:
                # Multiple specific dates
                date_list = [pd.to_datetime(d) for d in date_filter]
                initial_df = initial_df[initial_df['date'].isin(date_list)]
    
    if len(initial_df) == 0:
        st.warning("No data found in the table. Please check your BigQuery connection and table.")
        st.stop()
        return
    
    filter_options = get_filter_options(initial_df)
    
    # Chapters bucket filter
    st.sidebar.markdown("#### Chapters Bucket")
    if filter_options['chapters_bucket']:
        selected_chapters = st.sidebar.multiselect(
            "Select Chapters Buckets",
            options=filter_options['chapters_bucket'],
            default=st.session_state.filter_temp['chapters_bucket'] if st.session_state.filter_temp['chapters_bucket'] else filter_options['chapters_bucket'],
            key="chapters_bucket_filter"
        )
        st.session_state.filter_temp['chapters_bucket'] = selected_chapters
    else:
        st.sidebar.info("No chapters_bucket data available")
        st.session_state.filter_temp['chapters_bucket'] = []
    
    # First mediasource filter
    st.sidebar.markdown("#### First Mediasource")
    if filter_options['first_mediasource']:
        selected_mediasources = st.sidebar.multiselect(
            "Select First Mediasources",
            options=filter_options['first_mediasource'],
            default=st.session_state.filter_temp['first_mediasource'] if st.session_state.filter_temp['first_mediasource'] else filter_options['first_mediasource'],
            key="first_mediasource_filter"
        )
        st.session_state.filter_temp['first_mediasource'] = selected_mediasources
    else:
        st.sidebar.info("No first_mediasource data available")
        st.session_state.filter_temp['first_mediasource'] = []
    
    # Apply/Reset buttons with modern styling
    st.sidebar.markdown("---")
    col1, col2 = st.sidebar.columns(2)
    with col1:
        if st.button("✅ Apply Filters", use_container_width=True, type="primary"):
            st.session_state.filter_applied = st.session_state.filter_temp.copy()
            st.rerun()
    
    with col2:
        if st.button("🔄 Reset All", use_container_width=True):
            st.session_state.filter_temp = {
                'date': None,
                'test_group': test_group_options,
                'chapters_bucket': filter_options['chapters_bucket'],
                'first_mediasource': filter_options['first_mediasource']
            }
            st.session_state.filter_applied = {
                'date': None,
                'test_group': test_group_options,
                'chapters_bucket': filter_options['chapters_bucket'],
                'first_mediasource': filter_options['first_mediasource']
            }
            st.rerun()
    
    # Use applied filters
    filters = st.session_state.filter_applied.copy()
    
    # Load filtered data
    with st.spinner("Loading filtered data..."):
        df = load_data(
            client,
            date_filter=filters['date'],
            test_group_filter=filters['test_group'],
            chapters_bucket_filter=filters['chapters_bucket'],
            first_mediasource_filter=filters['first_mediasource']
        )
    
    # Apply additional filters (for dimensions)
    df = apply_filters(df, filters)
    
    # Ensure date column is datetime
    if 'date' in df.columns:
        df['date'] = pd.to_datetime(df['date'])
    
    # Sidebar: Data summary with modern cards
    st.sidebar.markdown("<hr style='margin: 0.75rem 0;'>", unsafe_allow_html=True)
    st.sidebar.markdown("### 📊 Data Summary")
    if len(df) > 0:
        st.sidebar.markdown(f"""
        <div style="background-color: #e7f3ff; 
                    padding: 0.75rem; 
                    border-radius: 8px; 
                    border-left: 4px solid #1f77b4;
                    margin-bottom: 0.5rem;">
            <p style="margin: 0; font-weight: 600; color: #1e1e1e; font-size: 0.9rem;">Total Rows</p>
            <p style="margin: 0.25rem 0 0 0; font-size: 1.3rem; color: #1f77b4; font-weight: 700;">
                {len(df):,}
            </p>
        </div>
        """, unsafe_allow_html=True)
        
        if 'date' in df.columns:
            date_min = df['date'].min().date()
            date_max = df['date'].max().date()
            st.sidebar.markdown(f"""
            <div style="background-color: #fff3cd; 
                        padding: 0.75rem; 
                        border-radius: 8px; 
                        border-left: 4px solid #ffc107;">
                <p style="margin: 0; font-weight: 600; color: #1e1e1e; font-size: 0.9rem;">Date Range</p>
                <p style="margin: 0.25rem 0 0 0; font-size: 0.85rem; color: #856404;">
                    {date_min} to {date_max}
                </p>
            </div>
            """, unsafe_allow_html=True)
    
    # Get dimension from session state (set earlier)
    if 'selected_dimension' in st.session_state:
        dimension_options_map = {
            'None': None,
            'Chapters Bucket': 'chapters_bucket',
            'First Mediasource': 'first_mediasource'
        }
        dimension = dimension_options_map.get(st.session_state.selected_dimension, None)
    else:
        dimension = None
    
    # Determine test start date from Period column (for use in charts)
    test_start_date = None
    if 'Period' in df.columns and len(df) > 0:
        # Get the first "during" date
        during_dates = df[df['Period'].str.lower() == 'during']['date'].dropna()
        if len(during_dates) > 0:
            test_start_date = pd.to_datetime(during_dates.min())
    
    # Main content area
    if len(df) == 0:
        st.warning("No data matches the selected filters. Please adjust your filters.")
        return
    
    # Initialize KPI selection in session state (before tabs to preserve across reruns)
    if 'selected_kpi' not in st.session_state:
        st.session_state.selected_kpi = 'Avg Daily DAU'
    
    # Create tabs for different views
    # Streamlit tabs use URL hash fragments (#tab-0, #tab-1) which should be preserved
    tab1, tab2 = st.tabs(["📊 Overall KPIs Comparison", "📈 Daily Trends Comparison"])
    
    # Tab 1: Overall KPIs Comparison
    with tab1:
        # Modern section header
        st.markdown("""
        <div style="background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%); 
                    padding: 1.5rem; 
                    border-radius: 10px; 
                    margin-bottom: 2rem;
                    border-left: 5px solid #667eea;">
            <h2 style="margin: 0; color: #1e1e1e; font-size: 1.5rem;">
                📊 Overall KPIs Comparison
            </h2>
            <p style="margin: 0.5rem 0 0 0; color: #6c757d;">
                Compare test vs control groups: Before vs During test period
            </p>
        </div>
        """, unsafe_allow_html=True)
        
        # KPI filter - multiselect dropdown in a card
        st.markdown("""
        <div style="background-color: #ffffff; 
                    padding: 1rem; 
                    border-radius: 8px; 
                    margin-bottom: 1.5rem;
                    border: 1px solid #dee2e6;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);">
            <h4 style="margin: 0 0 0.75rem 0; color: #495057; font-weight: 600;">
                🎯 Select KPIs to Display
            </h4>
        </div>
        """, unsafe_allow_html=True)
        all_kpi_options = [
            'Avg Daily DAU',
            'Avg Daily Revenue',
            'ARPUDAU',
            '%PU/DAU',
            'ARPPU',
            'ATV',
            'Transactions per Payer',
            'DOD Retention',
            'Chapters per Player',
            'Credits Spend per Player',
            'Generations per Player',
            'Merges per Player'
        ]
        
        # Initialize selected KPIs in session state
        if 'selected_kpis_overall' not in st.session_state:
            st.session_state.selected_kpis_overall = all_kpi_options
        
        selected_kpis = st.multiselect(
            "Choose KPIs",
            options=all_kpi_options,
            default=st.session_state.selected_kpis_overall,
            key="kpi_multiselect_overall",
            label_visibility="collapsed"
        )
        
        # Update session state
        if len(selected_kpis) > 0:
            st.session_state.selected_kpis_overall = selected_kpis
        else:
            # If nothing selected, show all
            st.session_state.selected_kpis_overall = all_kpi_options
            selected_kpis = all_kpi_options
        
        if dimension:
            # Split by dimension
            for dim_value in sorted(df[dimension].dropna().unique()):
                st.markdown(f"#### {dimension}: {dim_value}")
                dim_df = df[df[dimension] == dim_value]
                
                comparison_table = create_kpis_comparison_table(dim_df, test_start_date)
                if len(comparison_table) > 0:
                    # Filter by selected KPIs
                    if selected_kpis:
                        comparison_table = comparison_table[comparison_table['KPI'].isin(selected_kpis)]
                    
                    if len(comparison_table) > 0:
                        # Format numeric columns for better display
                        display_table = comparison_table.copy()
                        numeric_cols = ['Before', 'During', 'Change', 'Change %', 'Diff (Test-Control)']
                        for col in numeric_cols:
                            if col in display_table.columns:
                                if col == 'Change %' or col == 'Diff (Test-Control)':
                                    display_table[col] = display_table[col].apply(
                                        lambda x: f"{x:.2f}%" if isinstance(x, (int, float)) else str(x)
                                    )
                                else:
                                    display_table[col] = display_table[col].apply(
                                        lambda x: f"{x:,.2f}" if isinstance(x, (int, float)) else str(x)
                                    )
                        
                        # Reorder columns: KPI first, then Test Group, then metrics, then Status
                        column_order = ['KPI', 'Test Group', 'Before', 'During', 'Change', 'Change %', 'Diff (Test-Control)', 'Status']
                        # Only include columns that exist
                        column_order = [col for col in column_order if col in display_table.columns]
                        display_table = display_table[column_order]
                    
                    # Modern table display with styling
                    st.markdown("""
                    <div style="margin-top: 1.5rem;">
                    </div>
                    """, unsafe_allow_html=True)
                    
                    st.dataframe(
                        display_table,
                        use_container_width=True,
                        hide_index=True,
                        height=400
                    )
                else:
                    st.info(f"No data available for {dimension} = {dim_value}")
        else:
            # Show aggregated view
            comparison_table = create_kpis_comparison_table(df, test_start_date)
            if len(comparison_table) > 0:
                # Filter by selected KPIs
                if selected_kpis:
                    comparison_table = comparison_table[comparison_table['KPI'].isin(selected_kpis)]
                
                if len(comparison_table) > 0:
                    # Format numeric columns for better display
                    display_table = comparison_table.copy()
                    numeric_cols = ['Before', 'During', 'Change', 'Change %', 'Diff (Test-Control)']
                    for col in numeric_cols:
                        if col in display_table.columns:
                            if col == 'Change %' or col == 'Diff (Test-Control)':
                                display_table[col] = display_table[col].apply(
                                    lambda x: f"{x:.2f}%" if isinstance(x, (int, float)) else str(x)
                                )
                            else:
                                display_table[col] = display_table[col].apply(
                                    lambda x: f"{x:,.2f}" if isinstance(x, (int, float)) else str(x)
                                )
                    
                    # Reorder columns: KPI first, then Test Group, then metrics, then Status
                    column_order = ['KPI', 'Test Group', 'Before', 'During', 'Change', 'Change %', 'Diff (Test-Control)', 'Status']
                    # Only include columns that exist
                    column_order = [col for col in column_order if col in display_table.columns]
                    display_table = display_table[column_order]
                
                st.dataframe(
                    display_table,
                    use_container_width=True,
                    hide_index=True
                )
            else:
                st.info("No data available for comparison")
    
    # Tab 2: Daily Trends Comparison
    with tab2:
        # Modern section header
        st.markdown("""
        <div style="background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%); 
                    padding: 1.5rem; 
                    border-radius: 10px; 
                    margin-bottom: 2rem;
                    border-left: 5px solid #667eea;">
            <h2 style="margin: 0; color: #1e1e1e; font-size: 1.5rem;">
                📈 Daily Trends Comparison
            </h2>
            <p style="margin: 0.5rem 0 0 0; color: #6c757d;">
                Track daily performance trends for test vs control groups
            </p>
        </div>
        """, unsafe_allow_html=True)
        
        # KPI selector in a card
        st.markdown("""
        <div style="background-color: #ffffff; 
                    padding: 1rem; 
                    border-radius: 8px; 
                    margin-bottom: 1.5rem;
                    border: 1px solid #dee2e6;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);">
            <h4 style="margin: 0 0 0.75rem 0; color: #495057; font-weight: 600;">
                📊 Select KPI to View
            </h4>
        </div>
        """, unsafe_allow_html=True)

        # KPI selector - use session state to preserve selection
        kpi_options = [
            'Avg Daily DAU',
            'Avg Daily Revenue',
            'ARPUDAU',
            '%PU/DAU',
            'ARPPU',
            'Transactions per Payer',
            'ATV',
            'Chapters per Player',
            'Generations per Player',
            'Merges per Player',
            'Credits Spend per Player',
            'DOD Retention'
        ]
        
        # Get current index from session state
        current_kpi_index = 0
        if st.session_state.selected_kpi in kpi_options:
            current_kpi_index = kpi_options.index(st.session_state.selected_kpi)
        
        # KPI selector - use unique key and ensure it doesn't conflict
        # The key helps Streamlit track the widget state across reruns
        selected_kpi = st.selectbox(
            "Choose KPI",
            options=kpi_options,
            label_visibility="collapsed", 
            index=current_kpi_index,
            key="daily_trends_kpi_selector"
        )
        
        # Update session state
        st.session_state.selected_kpi = selected_kpi
        
        # Inject JavaScript to preserve tab hash after rerun
        # This runs after the page loads to restore the tab
        components.html("""
        <script>
        (function() {
            // Check if we should be on tab-1 (Daily Trends)
            var shouldBeOnTab1 = true; // We're in tab2 context
            var currentHash = window.location.hash;
            
            // If hash is missing or wrong, restore it
            if (currentHash !== '#tab-1') {
                // Use a small delay to ensure Streamlit has rendered
                setTimeout(function() {
                    window.location.hash = '#tab-1';
                    // Force a scroll to ensure hash is applied
                    window.scrollTo(0, 0);
                }, 50);
            }
        })();
        </script>
        """, height=0)
        
        if dimension:
            # Split by dimension
            for dim_value in sorted(df[dimension].dropna().unique()):
                st.markdown(f"#### {dimension}: {dim_value}")
                dim_df = df[df[dimension] == dim_value]
                
                fig = create_daily_trends_chart(dim_df, selected_kpi, test_start_date)
                if fig:
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info(f"No data available for {dimension} = {dim_value}")
        else:
            # Show aggregated view
            fig = create_daily_trends_chart(df, selected_kpi, test_start_date)
            if fig:
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No data available for trends")
    
    # Footer
    st.markdown("---")
    st.markdown(f"**Last Updated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    st.markdown(f"**Data Source:** `{FULL_TABLE}`")

if __name__ == '__main__':
    main()

