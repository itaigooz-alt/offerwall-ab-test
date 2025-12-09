# Offerwall AB Test Dashboard

**Analytics dashboard for Offerwall AB Test data using BigQuery and Streamlit**

---

## 📋 Table of Contents

1. [Project Overview](#project-overview)
2. [Quick Start](#quick-start)
3. [Dashboard Features](#dashboard-features)
4. [Setup & Configuration](#setup--configuration)
5. [Usage](#usage)

---

## Project Overview

This project provides an analytics dashboard for analyzing Offerwall AB Test data, including:

- **BigQuery table**: `yotam-395120.peerplay.offerwall_dec_ab_test`
- **Interactive Streamlit dashboard** with multiple views and filters
- **Before vs During test comparison** for all KPIs
- **Daily trends visualization** with test period indicators

### Key Features

- ✅ Overall KPIs comparison table (before vs during test)
- ✅ Daily trends line charts (before vs during test)
- ✅ Multiple filter options (date, test group, chapters bucket, first mediasource)
- ✅ Dimension selector for split views
- ✅ Test group comparison (test vs control)

---

## Quick Start

### Prerequisites

- Python 3.8+
- Google Cloud SDK (`gcloud`)
- BigQuery access to `yotam-395120.peerplay` dataset

### Installation

1. **Navigate to project directory**:
   ```bash
   cd "offerwall ab test"
   ```

2. **Set up Python environment**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Authenticate with Google Cloud**:
   ```bash
   gcloud auth application-default login
   ```

4. **Run the dashboard**:
   ```bash
   streamlit run offerwall_dashboard.py
   ```

5. **Access dashboard**:
   - **Local**: http://localhost:8501

---

## Dashboard Features

### Views

#### 1. Overall KPIs Comparison (Table View)
- Compares performance before and during the test
- Shows metrics for both test and control groups
- Displays absolute change and percentage change

**KPIs Included**:
- Avg Daily DAU
- Avg Daily Revenue
- ARPUDAU (Total revenue/DAU)
- %PU/DAU (Paid today/DAU)
- ARPPU (Total revenue/Paid today)
- Transactions per Payer (Total purchases/Paid today)
- ATV (Total revenue/Total purchases)
- Chapters per Player (Chapters completed/DAU)
- Generations per Player (Daily generation/DAU)
- Merges per Player (Daily merge/DAU)
- Credits Spend per Player (Daily generation spend/DAU)
- DOD Retention (Is returned next day/DAU)

#### 2. Daily Trends Comparison (Line Chart View)
- Shows daily trends for selected KPIs
- Visualizes before and during test periods
- Separate lines for test and control groups
- Vertical line indicating test start date

### Filters

- **Date Range**: Filter data by date range
- **Test Group**: Select test group(s) - test (is_odd=1) or control (is_odd=0)
- **Chapters Bucket**: Filter by chapters bucket
- **First Mediasource**: Filter by first mediasource

### Dimension Selector

Split views by:
- None (aggregated)
- Chapters Bucket
- First Mediasource

---

## Setup & Configuration

### BigQuery Configuration

- **Project ID**: `yotam-395120`
- **Dataset ID**: `peerplay`
- **Table ID**: `offerwall_dec_ab_test`
- **Full Table Path**: `yotam-395120.peerplay.offerwall_dec_ab_test`

### Authentication

1. **Application Default Credentials (ADC)** (for local development):
   ```bash
   gcloud auth application-default login
   ```

2. **Service Account** (for Streamlit Cloud deployment):
   - Set `GOOGLE_APPLICATION_CREDENTIALS_JSON` in Streamlit Cloud secrets
   - Or provide credentials path via `GOOGLE_APPLICATION_CREDENTIALS` environment variable

### Environment Variables

- `GCP_PROJECT_ID`: Google Cloud Project ID (default: `yotam-395120`)
- `BQ_DATASET_ID`: BigQuery dataset name (default: `peerplay`)
- `TABLE_ID`: BigQuery table name (default: `offerwall_dec_ab_test`)
- `SKIP_AUTH`: Set to `true` to skip authentication (for local dev)

---

## Usage

### Running Locally

```bash
streamlit run offerwall_dashboard.py
```

### Deploying to Streamlit Cloud

1. Push code to GitHub repository
2. Connect repository to Streamlit Cloud
3. Add secrets in Streamlit Cloud settings:
   - `GOOGLE_APPLICATION_CREDENTIALS_JSON`: Service account JSON credentials
   - `GOOGLE_OAUTH_CLIENT_ID`: OAuth client ID (optional, for authentication)
   - `GOOGLE_OAUTH_CLIENT_SECRET`: OAuth client secret (optional, for authentication)
   - `STREAMLIT_REDIRECT_URI`: OAuth redirect URI (optional)

### Table Schema Requirements

The dashboard expects the following columns in the `offerwall_dec_ab_test` table:

- `date`: Date column
- `is_odd`: Integer (1 for test, 0 for control)
- `dau`: Daily active users
- `total_revenue` or `revenue`: Revenue amount
- `paid_today`: Number of paying users
- `total_purchases`: Number of purchases/transactions
- `chapters_completed`: Number of chapters completed
- `daily_generation`: Daily generation count
- `daily_merge`: Daily merge count
- `daily_generation_spend`: Daily generation spend (credits)
- `is_returned_next_day`: Day-over-day retention flag
- `chapters_bucket`: Chapters bucket category
- `first_mediasource`: First mediasource
- `test_start_date`: Test start date (optional, will be inferred if not present)

---

## Troubleshooting

### Dashboard Issues

- **No data showing**: Check BigQuery authentication (`gcloud auth application-default login`)
- **Missing dependencies**: Install requirements (`pip install -r requirements.txt`)
- **Caching issues**: Click "Apply" button or clear Streamlit cache

### BigQuery Issues

- **Permission errors**: Ensure service account has BigQuery access
- **Table not found**: Verify table exists and path is correct
- **Date range errors**: Check date column format in table

---

## Project Structure

```
offerwall ab test/
├── offerwall_dashboard.py    # Main Streamlit dashboard
├── requirements.txt          # Python dependencies
└── README.md                # This file
```

---

**Last Updated**: December 2024

**Project Version**: 1.0

