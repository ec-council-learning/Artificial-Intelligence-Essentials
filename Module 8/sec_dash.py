import streamlit as st
import pandas as pd
import sqlite3
import plotly.express as px
import os
import re
import numpy as np
from datetime import datetime

# Configuration
threshold = 0.7
st.set_page_config(
    page_title="Email & Zeek Security Dashboard",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Auto-refresh every 5 seconds
auto_refresh_js = """
<script>
setTimeout(function(){window.location.reload();}, 5000);
</script>
"""
st.markdown(auto_refresh_js, unsafe_allow_html=True)

# Title and description
st.title("Email Analyzer & Zeek Security Dashboard")
st.markdown("Real-time threat intelligence from email analysis report and Zeek network logs")

# Sidebar navigation
page = st.sidebar.radio("Select View", [
    "Email Analysis",
    "Zeek Network Traffic",
    "Zeek HTTP Analysis",
    "Zeek DNS Analysis",
    "Combined Security Intel"
])

# Paths
EMAIL_REPORT_PATH = os.path.join(os.getcwd(), "email_analysis_report.txt")
EMAIL_DB_PATH = os.path.join(os.getcwd(), "email_analyzer.db")
ZEEK_LOG_DIR = "/usr/local/zeek/spool/zeek"

# Load email analysis report text
@st.cache_data(ttl=5)
def load_email_report_text():
    if os.path.isfile(EMAIL_REPORT_PATH):
        with open(EMAIL_REPORT_PATH, encoding='utf-8') as f:
            return f.read()
    return ""

# Load recent email runs from SQLite
def load_email_runs():
    if not os.path.isfile(EMAIL_DB_PATH):
        return pd.DataFrame()
    conn = sqlite3.connect(EMAIL_DB_PATH)
    df = pd.read_sql_query(
        "SELECT filename, threat_score, created_at FROM reports ORDER BY created_at DESC LIMIT 10", conn
    )
    conn.close()
    df['created_at'] = pd.to_datetime(df['created_at'])
    return df

# Zeek log loader
def load_zeek_log(log_type):
    path = f"{ZEEK_LOG_DIR}/{log_type}.log"
    if not os.path.isfile(path):
        return pd.DataFrame()
    header = None
    with open(path) as f:
        for line in f:
            if line.startswith('#fields'):
                header = line[len('#fields '):].strip().split('\t')
                break
    if header:
        df = pd.read_csv(path, sep='\t', comment='#', names=header)
    else:
        df = pd.read_csv(path, sep='\t', comment='#', header=None)
    if 'ts' in df.columns:
        df['ts'] = pd.to_datetime(df['ts'], unit='s', errors='coerce')
    return df

# Email Analysis Page
if page == "Email Analysis":
    report = load_email_report_text()
    st.subheader("📄 Latest Email Analysis Report")
    if not report:
        st.warning("No email analysis report found.")
    else:
        # Extract metrics and lists
        total = re.search(r"Total emails analyzed:\s*(\d+)", report)
        avg_spam = re.search(r"Average SpamAssassin score:\s*([0-9\.]+)", report)
        spam_above = re.search(r"Number of emails above threshold:\s*(\d+)", report)
        top_domains = re.findall(r"^\s*([\w\.-]+):\s*(\d+) emails", report, re.MULTILINE)
        vt_domains = re.findall(r"^\s*([\w\.-]+): Threat score ([0-9\.]+)", report, re.MULTILINE)
        avg_content = re.search(r"Average scam content score:\s*([0-9\.]+)", report)
        high_scam = re.search(r"Emails with high scam score.*?:\s*(\d+)", report)
        action_info = re.search(r"Emails with action phrases in subject:\s*(\d+) \(([0-9\.]+)%\)", report)
        threat_bins = dict(re.findall(r"^  (High|Medium|Low|Minimal): (\d+) emails", report, re.MULTILINE))

        # Top-level metrics
        cols = st.columns(3)
        cols[0].metric("Total Emails", total.group(1) if total else "-")
        cols[1].metric("Avg. Spam Score", avg_spam.group(1) if avg_spam else "-")
        cols[2].metric("Spam > Threshold", spam_above.group(1) if spam_above else "-")

        # Top Domains Analyzed
        st.markdown("---")
        st.subheader("Top Domains Analyzed")
        if top_domains:
            dom_df = pd.DataFrame(top_domains, columns=["Domain","Emails"]).astype({"Emails":int})
            st.table(dom_df.head(10))
        else:
            st.info("No domain data available.")

        # VirusTotal Threat Analysis
        st.markdown("---")
        st.subheader("VirusTotal Threat Analysis")
        if vt_domains:
            vt_df = pd.DataFrame(vt_domains, columns=["Domain","Threat Score"]).astype({"Threat Score":float})
            st.table(vt_df)
        else:
            st.info("No VirusTotal threat data available.")

        # Content & Action Analysis
        st.markdown("---")
        st.subheader("Content & Action Analysis")
        c1, c2, c3 = st.columns(3)
        c1.metric("Avg. Scam Content Score", avg_content.group(1) if avg_content else "-")
        c2.metric("High Scam Emails", high_scam.group(1) if high_scam else "-")
        if action_info:
            c3.metric("Action Phrase Emails", f"{action_info.group(1)} ({action_info.group(2)}%)")
        else:
            c3.metric("Action Phrase Emails", "-")

        # Threat Levels Section
        st.markdown("---")
        st.subheader("Threat Levels")
        t1, t2, t3, t4 = st.columns(4)
        t1.metric("High", threat_bins.get('High', 0))
        t2.metric("Medium", threat_bins.get('Medium', 0))
        t3.metric("Low", threat_bins.get('Low', 0))
        t4.metric("Minimal", threat_bins.get('Minimal', 0))

# Zeek Network Traffic
elif page == "Zeek Network Traffic":
    df = load_zeek_log('conn')
    st.subheader("🌐 Connection Stats")
    st.metric("Total Connections", len(df))
    if not df.empty and 'ts' in df.columns:
        start, end = st.sidebar.date_input("Range", [df['ts'].dt.date.min(), df['ts'].dt.date.max()])
        df = df[df['ts'].dt.date.between(start, end)]
    if not df.empty:
        # Determine and filter valid source/dest
        src_vals = df['id.orig_h'].dropna()
        src_vals = src_vals[src_vals != 'undefined']
        src = src_vals.value_counts().head(10)
        dst_vals = df['id.resp_h'].dropna()
        dst_vals = dst_vals[dst_vals != 'undefined']
        dst = dst_vals.value_counts().head(10)

        col1, col2, col3 = st.columns(3)
        col1.subheader("Top Source IPs"); col1.bar_chart(src)
        col2.subheader("Top Destination IPs"); col2.bar_chart(dst)
        col3.subheader("Protocol Mix"); col3.plotly_chart(
            px.pie(values=df['proto'].value_counts().values, names=df['proto'].value_counts().index),
            use_container_width=True
        )
    else:
        st.info("No connection data.")

# Zeek HTTP Analysis
elif page == "Zeek HTTP Analysis":
    df = load_zeek_log('http')
    st.subheader("📡 HTTP Traffic")
    st.metric("Requests", len(df))
    if not df.empty:
        df['status_code'] = pd.to_numeric(df.get('status_code', []), errors='coerce')
        grp = df['status_code'].dropna().apply(lambda x: f"{int(x/100)}xx").value_counts()
        st.plotly_chart(
            px.pie(values=grp.values, names=grp.index, title='Status Categories'),
            use_container_width=True
        )
        st.subheader("Top Clients")
        clients = df['id.orig_h'].fillna('unknown').value_counts().head(10)
        st.bar_chart(clients)
        if 'host' in df.columns:
            st.subheader("Top Hosts"); st.bar_chart(df['host'].value_counts().head(10))
    else:
        st.info("No HTTP data.")

# Zeek DNS Analysis
elif page == "Zeek DNS Analysis":
    df = load_zeek_log('dns')
    st.subheader("🌐 DNS Queries")
    st.metric("Queries", len(df))
    if not df.empty and 'qtype_name' in df.columns:
        st.bar_chart(df['qtype_name'].value_counts().head(10))
    else:
        st.info("No DNS data.")

# Combined Security Intel
elif page == "Combined Security Intel":
    # Email report summary from SQLite
    runs = load_email_runs()
    st.subheader("Email Report Runs")
    if not runs.empty:
        df_disp = runs.rename(columns={'filename':'File','threat_score':'Threat Score','created_at':'Date'})
        st.dataframe(df_disp)
    else:
        st.info("No email runs available.")

    # Zeek metrics
    df_c = load_zeek_log('conn')
    df_h = load_zeek_log('http')
    df_d = load_zeek_log('dns')
    high_count = runs[runs['threat_score']>threshold].shape[0] if not runs.empty else 0
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Connections", len(df_c))
    c2.metric("HTTP Requests", len(df_h))
    c3.metric("DNS Queries", len(df_d))
    c4.metric("High Threat Emails", high_count)

    # Drill-down expanders
    with st.expander("Latest Email Run Log"): 
        log_text = load_email_report_text()
        st.text(log_text.splitlines()[0] if log_text else "No report text.")
    with st.expander("Connection Details"): st.dataframe(df_c.head(10))
    with st.expander("HTTP Details"): st.dataframe(df_h.head(10))
    with st.expander("DNS Details"): st.dataframe(df_d.head(10))
