import os
import re
import io
import time
import json
import base64
import sqlite3
import socket
import nltk
import tldextract
import requests
import numpy as np
import pandas as pd
from collections import Counter
from datetime import datetime
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns
from urllib.parse import urlparse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA

import whois  # Explicitly import whois to fix WHOIS lookup errors

from flask import Flask, request, render_template_string, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash

# Try to import VirusTotal library
try:
    import vt
    VT_AVAILABLE = True
except ImportError:
    VT_AVAILABLE = False

# Download necessary NLTK data, including punkt_tab to fix the LookupError
for pkg in ['punkt', 'stopwords', 'wordnet', 'averaged_perceptron_tagger', 'punkt_tab']:
    try:
        nltk.download(pkg, quiet=True)
    except Exception:
        pass

# ----------------- EmailAnalyzer Class -----------------
class EmailAnalyzer:
    def __init__(self):
        self.df = None
        self.domain_stats = None
        self.email_stats = None
        self.clusters = None
        self.text_features = None
        self.vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        self.charts = {}  # Holds base64 encoded chart images
        self.log_messages = []
        self.log("Email Analyzer+ initialized with threat assessment capabilities.")

    def log(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] {message}"
        self.log_messages.append(entry)
        print(entry)

    def load_file(self, file_path):
        self.log("=== LOADING EMAIL DATA ===")
        if not os.path.exists(file_path):
            self.log(f"File not found: {file_path}")
            return False
        try:
            self.log(f"Attempting to load file: {file_path}")
            encodings = ['utf-8', 'latin1', 'iso-8859-1', 'cp1252']
            for encoding in encodings:
                try:
                    self.log(f"Trying encoding: {encoding}")
                    self.df = pd.read_csv(file_path, encoding=encoding)
                    self.log(f"Successfully loaded file using {encoding} encoding.")
                    break
                except Exception as e:
                    self.log(f"Failed with encoding {encoding}: {str(e)}")
                    continue
            if self.df is None:
                raise Exception("Unable to read file with any supported encoding")
            required_columns = ['sender_email', 'subject']
            missing_columns = [col for col in required_columns if col not in self.df.columns]
            if missing_columns:
                self.log(f"Warning: Missing required columns: {', '.join(missing_columns)}")
                self.log("Will attempt to continue with available columns.")
                if 'sender_email' in missing_columns and 'sender' in self.df.columns:
                    self.log("Using 'sender' column as 'sender_email'")
                    self.df['sender_email'] = self.df['sender']
                    missing_columns.remove('sender_email')
                if missing_columns:
                    self.log("Missing critical columns. Cannot continue analysis.")
                    return False
            if 'sender_domain' not in self.df.columns:
                self.log("Extracting domains from sender_email column...")
                self.df['sender_domain'] = self.df['sender_email'].apply(
                    lambda x: str(x).split('@')[-1] if '@' in str(x) else 'unknown'
                )
            self.log(f"Successfully loaded {len(self.df)} records.")
            self.log(f"Columns in dataset: {', '.join(self.df.columns)}")
            return True
        except Exception as e:
            self.log(f"Error loading file: {str(e)}")
            return False

    def analyze_domains(self):
        if self.df is None:
            self.log("No data available for domain analysis")
            return False
        self.log("=== DOMAIN ANALYSIS ===")
        if 'sender_domain' not in self.df.columns:
            self.log("No sender_domain column found in the dataset")
            if 'sender_email' in self.df.columns:
                self.log("Extracting domains from sender_email column...")
                self.df['sender_domain'] = self.df['sender_email'].apply(
                    lambda x: x.split('@')[-1] if '@' in str(x) else 'unknown'
                )
                self.log("Domain extraction complete.")
            else:
                self.log("Cannot perform domain analysis without sender domain information.")
                return False
        self.log("Counting domain frequencies...")
        domain_counts = self.df['sender_domain'].value_counts().reset_index()
        domain_counts.columns = ['domain', 'count']
        self.log(f"Found {len(domain_counts)} unique domains")
        self.domain_stats = domain_counts.sort_values('count', ascending=False)
        self.log("Top 10 sender domains:")
        for i, (_, row) in enumerate(self.domain_stats.head(10).iterrows()):
            self.log(f"{i+1}. {row['domain']}: {row['count']} emails")
        total_emails = len(self.df)
        domain_entropy = self._calculate_entropy(self.domain_stats['count'] / total_emails)
        self.log(f"Domain distribution entropy: {domain_entropy:.2f}")
        self.log(f"Higher entropy (closer to {np.log2(len(self.domain_stats)):.2f}) means more diverse domains")
        self.log(f"Lower entropy means concentration around fewer domains")
        return True

    def analyze_emails(self):
        if self.df is None:
            self.log("No data available for email analysis")
            return False
        self.log("=== EMAIL ADDRESS ANALYSIS ===")
        if 'sender_email' not in self.df.columns:
            self.log("No sender_email column found in the dataset")
            return False
        self.log("Counting email address frequencies...")
        email_counts = self.df['sender_email'].value_counts().reset_index()
        email_counts.columns = ['email', 'count']
        self.log(f"Found {len(email_counts)} unique email addresses")
        self.email_stats = email_counts.sort_values('count', ascending=False)
        self.log("Top 10 sender email addresses:")
        for i, (_, row) in enumerate(self.email_stats.head(10).iterrows()):
            self.log(f"{i+1}. {row['email']}: {row['count']} emails")
        self.log("Analyzing email address patterns...")
        self.df['username'] = self.df['sender_email'].apply(
            lambda x: str(x).split('@')[0] if '@' in str(x) else str(x)
        )
        usernames = self.df['username'].tolist()
        usernames_with_numbers = sum(1 for u in usernames if any(c.isdigit() for c in u))
        percent_with_numbers = usernames_with_numbers / len(usernames) * 100
        self.log(f"Usernames containing numbers: {usernames_with_numbers} ({percent_with_numbers:.1f}%)")
        usernames_with_underscores = sum(1 for u in usernames if '_' in u)
        percent_with_underscores = usernames_with_underscores / len(usernames) * 100
        self.log(f"Usernames containing underscores: {usernames_with_underscores} ({percent_with_underscores:.1f}%)")
        avg_length = sum(len(u) for u in usernames) / len(usernames)
        self.log(f"Average username length: {avg_length:.1f} characters")
        return True

    def analyze_subject_actions(self):
        if self.df is None:
            self.log("No data available for subject analysis")
            return False
        self.log("=== SUBJECT ACTION ANALYSIS ===")
        if 'subject' not in self.df.columns:
            self.log("No subject column found in the dataset")
            return False
        self.log("Analyzing subject lines for action-oriented language...")
        action_phrases = [
            'action required', 'act now', 'urgent', 'immediate', 'attention',
            'response needed', 'respond', 'reply', 'click', 'open', 'download',
            'activate', 'verify', 'confirm', 'update', 'validate', 'important',
            'time-sensitive', 'limited time', 'expires', 'deadline', 'last chance',
            'final notice', "don't miss", 'hurry', 'quick', 'asap', 'promptly'
        ]
        def contains_action_phrase(subject):
            if not subject or pd.isna(subject):
                return False
            subject = str(subject).lower()
            return any(phrase in subject for phrase in action_phrases)
        self.df['has_action_phrase'] = self.df['subject'].apply(contains_action_phrase)
        action_count = self.df['has_action_phrase'].sum()
        action_percentage = action_count / len(self.df) * 100
        self.log(f"Found {action_count} emails ({action_percentage:.1f}%) with action-oriented phrases in subjects")
        phrase_counts = {}
        for phrase in action_phrases:
            count = self.df['subject'].str.lower().str.contains(phrase).sum()
            if count > 0:
                phrase_counts[phrase] = count
        sorted_phrases = sorted(phrase_counts.items(), key=lambda x: x[1], reverse=True)
        self.log("Top action phrases found in subject lines:")
        for i, (phrase, count) in enumerate(sorted_phrases[:10]):
            percentage = count / len(self.df) * 100
            self.log(f"{i+1}. '{phrase}': {count} emails ({percentage:.1f}%)")
        return True

    def extract_text_features(self):
        if self.df is None:
            self.log("No data available for text feature extraction")
            return False
        self.log("=== TEXT FEATURE EXTRACTION ===")
        if 'subject' not in self.df.columns:
            self.log("No subject column found for feature extraction")
            return False
        self.log("Preparing text for analysis...")
        texts = []
        for _, row in self.df.iterrows():
            parts = []
            if 'subject' in self.df.columns and not pd.isna(row['subject']):
                parts.append(str(row['subject']))
            if 'body' in self.df.columns and not pd.isna(row['body']):
                parts.append(str(row['body'])[:500])
            text = " ".join(parts)
            texts.append(text if text else "empty")
        self.log(f"Prepared {len(texts)} text samples for analysis")
        try:
            self.log("Applying TF-IDF vectorization...")
            self.text_features = self.vectorizer.fit_transform(texts)
            feature_names = self.vectorizer.get_feature_names_out()
            self.log(f"Successfully extracted {len(feature_names)} text features")
            feature_sum = np.array(self.text_features.sum(axis=0)).flatten()
            top_indices = feature_sum.argsort()[-10:][::-1]
            self.log("Top terms across all emails:")
            for idx in top_indices:
                self.log(f"  {feature_names[idx]}: {feature_sum[idx]:.2f}")
            return True
        except Exception as e:
            self.log(f"Error in text feature extraction: {str(e)}")
            return False

    def perform_clustering(self, n_clusters=4):
        if self.text_features is None:
            self.log("No text features available. Run extract_text_features first.")
            success = self.extract_text_features()
            if not success:
                return False
        self.log(f"=== CLUSTERING EMAILS INTO {n_clusters} GROUPS ===")
        try:
            self.log("Applying K-means clustering...")
            kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
            self.clusters = kmeans.fit_predict(self.text_features)
            self.df['cluster'] = self.clusters
            cluster_counts = self.df['cluster'].value_counts().sort_index()
            self.log("Cluster distribution:")
            for cluster, count in cluster_counts.items():
                percentage = count / len(self.df) * 100
                self.log(f"  Cluster {cluster}: {count} emails ({percentage:.1f}%)")
            self.log("Most common words in each cluster:")
            feature_names = self.vectorizer.get_feature_names_out()
            centers = kmeans.cluster_centers_
            for cluster in range(n_clusters):
                top_indices = centers[cluster].argsort()[-10:][::-1]
                top_terms = [feature_names[i] for i in top_indices]
                self.log(f"Cluster {cluster} top terms:")
                for term in top_terms:
                    self.log(f"  {term}")
            self.log("Domain distribution by cluster:")
            for cluster in range(n_clusters):
                cluster_df = self.df[self.df['cluster'] == cluster]
                domain_counts = cluster_df['sender_domain'].value_counts().reset_index()
                domain_counts.columns = ['domain', 'count']
                top_domains = domain_counts.head(3)
                self.log(f"Cluster {cluster} top domains:")
                for _, row in top_domains.iterrows():
                    domain_count = row['count']
                    domain_name = row['domain']
                    percentage = domain_count / len(cluster_df) * 100
                    self.log(f"  {domain_name}: {domain_count} emails ({percentage:.1f}%)")
            return True
        except Exception as e:
            self.log(f"Error in clustering: {str(e)}")
            return False

    def visualize_clusters_2d(self):
        if self.clusters is None or self.text_features is None:
            self.log("No cluster data available. Run perform_clustering first.")
            return False
        self.log("=== VISUALIZING EMAIL CLUSTERS ===")
        try:
            self.log("Reducing dimensions with PCA...")
            pca = PCA(n_components=2, random_state=42)
            reduced_features = pca.fit_transform(self.text_features.toarray())
            plot_df = pd.DataFrame({
                'x': reduced_features[:, 0],
                'y': reduced_features[:, 1],
                'cluster': self.df['cluster'],
                'domain': self.df['sender_domain']
            })
            plt.figure(figsize=(14, 10))
            colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd',
                      '#8c564b', '#e377c2', '#7f7f7f', '#bcbd22', '#17becf']
            for i, cluster in enumerate(sorted(plot_df['cluster'].unique())):
                cluster_data = plot_df[plot_df['cluster'] == cluster]
                plt.scatter(
                    cluster_data['x'], 
                    cluster_data['y'],
                    label=f'Cluster {cluster}',
                    alpha=0.7,
                    s=50,
                    color=colors[i % len(colors)]
                )
            cluster_domain_info = {}
            for cluster in sorted(plot_df['cluster'].unique()):
                cluster_df = self.df[self.df['cluster'] == cluster]
                top_domains = cluster_df['sender_domain'].value_counts().head(3)
                domain_info = ", ".join([str(d) for d in top_domains.index])
                cluster_domain_info[cluster] = domain_info
            for cluster in sorted(plot_df['cluster'].unique()):
                cluster_data = plot_df[plot_df['cluster'] == cluster]
                center_x = cluster_data['x'].mean()
                center_y = cluster_data['y'].mean()
                domain_info = cluster_domain_info[cluster]
                plt.annotate(
                    f"Cluster {cluster}:\n{domain_info}", 
                    (center_x, center_y),
                    fontsize=9,
                    bbox=dict(boxstyle="round,pad=0.3", fc="white", alpha=0.8),
                    ha='center', 
                    va='center'
                )
            plt.title('Email Clusters with Domain Information', fontsize=14)
            plt.xlabel('Principal Component 1', fontsize=12)
            plt.ylabel('Principal Component 2', fontsize=12)
            plt.legend(fontsize=10)
            plt.grid(alpha=0.3)
            plt.tight_layout()
            chart_buffer = io.BytesIO()
            plt.savefig(chart_buffer, format='png')
            chart_buffer.seek(0)
            self.charts['clusters'] = base64.b64encode(chart_buffer.getvalue()).decode('utf-8')
            plt.close()
            self.log("Cluster visualization created.")
            return True
        except Exception as e:
            self.log(f"Error in cluster visualization: {str(e)}")
            return False

    def _calculate_entropy(self, probabilities):
        probabilities = probabilities[probabilities > 0]
        return -np.sum(probabilities * np.log2(probabilities))

    def analyze_domain_age(self):
        if self.df is None or 'sender_domain' not in self.df.columns:
            self.log("No domain data available for WHOIS analysis")
            return False
        self.log("=== DOMAIN AGE ANALYSIS ===")
        if self.domain_stats is None:
            self.log("Running domain analysis first to identify top domains...")
            self.analyze_domains()
        top_domains = self.domain_stats.head(25)['domain'].tolist()
        self.log("Analyzing age for top 25 domains only...")
        self.df['domain_age_days'] = None
        self.df['domain_creation_date'] = None
        self.df['registration_info_available'] = False
        unique_domains = [domain for domain in self.df['sender_domain'].unique() if domain in top_domains]
        self.log(f"Analyzing age for {len(unique_domains)} unique top domains...")
        domain_age_results = {}
        for domain in unique_domains:
            retries = 3
            while retries > 0:
                try:
                    if domain == 'unknown' or '.' not in domain:
                        break
                    domain_info = whois.whois(domain)
                    if 'creation_date' in domain_info:
                        creation_date = domain_info['creation_date']
                        if isinstance(creation_date, list):
                            creation_date = creation_date[0]
                        current_date = datetime.now()
                        age_days = (current_date - creation_date).days
                        domain_age_results[domain] = {
                            'creation_date': creation_date,
                            'age_days': age_days,
                            'available': True
                        }
                        self.log(f"Domain {domain}: {age_days} days old (created: {creation_date.strftime('%Y-%m-%d')})")
                        break
                    else:
                        self.log(f"Domain {domain}: Creation date not available")
                        domain_age_results[domain] = {'available': False}
                        break
                except (socket.error, Exception) as e:
                    self.log(f"Error retrieving WHOIS info for {domain}: {str(e)}. Retries left: {retries-1}")
                    retries -= 1
                    time.sleep(5)
            if retries == 0 and domain not in domain_age_results:
                domain_age_results[domain] = {'available': False}
        for index, row in self.df.iterrows():
            domain = row['sender_domain']
            if domain in domain_age_results and domain_age_results[domain].get('available'):
                self.df.at[index, 'domain_age_days'] = domain_age_results[domain]['age_days']
                self.df.at[index, 'domain_creation_date'] = domain_age_results[domain]['creation_date']
                self.df.at[index, 'registration_info_available'] = True
        domains_with_age = self.df[self.df['registration_info_available'] == True]
        if len(domains_with_age) > 0:
            avg_age = domains_with_age['domain_age_days'].mean()
            min_age = domains_with_age['domain_age_days'].min()
            max_age = domains_with_age['domain_age_days'].max()
            self.log(f"Domain age statistics:")
            self.log(f"Average domain age: {avg_age:.1f} days ({avg_age/365.25:.1f} years)")
            self.log(f"Newest domain: {min_age:.1f} days ({min_age/365.25:.1f} years)")
            self.log(f"Oldest domain: {max_age:.1f} days ({max_age/365.25:.1f} years)")
            suspicious_domains = domains_with_age[domains_with_age['domain_age_days'] < 30]
            if len(suspicious_domains) > 0:
                self.log(f"WARNING: Found {len(suspicious_domains)} emails from recently created domains (<30 days):")
                for domain in suspicious_domains['sender_domain'].unique():
                    count = len(suspicious_domains[suspicious_domains['sender_domain'] == domain])
                    age = suspicious_domains[suspicious_domains['sender_domain'] == domain]['domain_age_days'].iloc[0]
                    self.log(f"  {domain}: {age:.1f} days old, {count} emails")
        return True

    def analyze_domain_threats(self, api_key=None):
        if self.df is None or 'sender_domain' not in self.df.columns:
            self.log("No domain data available for threat analysis")
            return False
        common_keywords = ["yahoo", "hotmail", "gmail", "microsoft", "aol", "outlook", "live", "msn"]
        if api_key is None:
            self.log("VirusTotal API key required for threat analysis")
            return False
        self.log("=== DOMAIN THREAT ANALYSIS ===")
        if self.domain_stats is None:
            self.log("Running domain analysis first to identify top domains...")
            self.analyze_domains()
        top_domains = self.domain_stats.head(25)['domain'].tolist()
        self.log("Analyzing threats for top 25 domains only...")
        self.df['vt_positives'] = None
        self.df['vt_total'] = None
        self.df['vt_score'] = None
        self.df['vt_categories'] = None
        unique_domains = [domain for domain in self.df['sender_domain'].unique() if domain in top_domains]
        self.log(f"Analyzing threats for {len(unique_domains)} unique top domains...")
        domain_threat_results = {}
        if not VT_AVAILABLE:
            self.log("VirusTotal Python library not available. Please install using: pip install vt-py")
            return False
        try:
            client = vt.Client(api_key)
            for domain in unique_domains:
                if any(keyword in domain.lower() for keyword in common_keywords):
                    self.log(f"Skipping common domain: {domain}")
                    continue
                try:
                    if domain == 'unknown' or '.' not in domain:
                        continue
                    self.log(f"Querying VirusTotal for {domain}...")
                    domain_obj = client.get_object("/domains/{}", domain)
                    last_analysis_stats = domain_obj.get("last_analysis_stats", {})
                    categories = domain_obj.get("categories", {})
                    malicious = last_analysis_stats.get('malicious', 0)
                    suspicious = last_analysis_stats.get('suspicious', 0)
                    total = sum(last_analysis_stats.values())
                    threat_score = (malicious + suspicious) / total if total > 0 else 0
                    categories_str = ', '.join([f"{k}: {v}" for k, v in categories.items()])
                    domain_threat_results[domain] = {
                        'positives': malicious + suspicious,
                        'total': total,
                        'score': threat_score,
                        'categories': categories_str
                    }
                    self.log(f"Domain {domain}: {malicious + suspicious}/{total} detections (Score: {threat_score:.3f})")
                    if categories_str:
                        self.log(f"  Categories: {categories_str}")
                except Exception as e:
                    self.log(f"Error querying VirusTotal for {domain}: {str(e)}")
                time.sleep(15)
            client.close()
            for index, row in self.df.iterrows():
                domain = row['sender_domain']
                if domain in domain_threat_results:
                    self.df.at[index, 'vt_positives'] = domain_threat_results[domain]['positives']
                    self.df.at[index, 'vt_total'] = domain_threat_results[domain]['total']
                    self.df.at[index, 'vt_score'] = domain_threat_results[domain]['score']
                    self.df.at[index, 'vt_categories'] = domain_threat_results[domain]['categories']
            high_threat_domains = self.df[self.df['vt_score'] > 0.1]
            if len(high_threat_domains) > 0:
                self.log("WARNING: Found {} emails from potentially malicious domains:".format(len(high_threat_domains)))
                for domain in high_threat_domains['sender_domain'].unique():
                    domain_df = high_threat_domains[high_threat_domains['sender_domain'] == domain]
                    count = len(domain_df)
                    score = domain_df['vt_score'].iloc[0]
                    positives = domain_df['vt_positives'].iloc[0]
                    total = domain_df['vt_total'].iloc[0]
                    self.log(f"  {domain}: {positives}/{total} detections (Score: {score:.3f}), {count} emails")
            return True
        except Exception as e:
            self.log(f"Error in VirusTotal analysis: {str(e)}")
            return False

    def setup_nltk(self):
        self.log("Setting up NLTK resources...")
        try:
            nltk.download('punkt', quiet=True)
            nltk.download('stopwords', quiet=True)
            nltk.download('wordnet', quiet=True)
            nltk.download('averaged_perceptron_tagger', quiet=True)
            return True
        except Exception as e:
            self.log(f"Error setting up NLTK: {str(e)}")
            return False

    def analyze_email_content(self):
        if self.df is None:
            self.log("No data available for content analysis")
            return False
        if 'body' not in self.df.columns:
            self.log("No email body content found for analysis")
            return False
        if not self.setup_nltk():
            return False
        self.log("=== EMAIL CONTENT ANALYSIS ===")
        self.df['contains_monetary'] = False
        self.df['contains_urgency'] = False
        self.df['contains_suspicious_links'] = False
        self.df['contains_credential_request'] = False
        self.df['scam_score'] = 0.0
        self.df['scam_category'] = None
        monetary_patterns = [
            r'\$\d+', r'money', r'payment', r'deposit', r'bank', r'cash', r'transfer',
            r'credit card', r'bitcoin', r'btc', r'wallet', r'account', r'fund', r'wire',
            r'loan', r'dollars', r'euros', r'rupees', r'income', r'investment', r'profit'
        ]
        urgency_patterns = [
            r'urgent', r'immediately', r'quick', r'fast', r'promptly', r'asap',
            r'deadline', r'limited time', r'expire', r'act now', r'today only',
            r'final notice', r'last chance', r"don't miss", r'hurry', r'emergency'
        ]
        link_patterns = [
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
            r'click here', r'visit', r'website', r'link', r'log ?in', r'sign ?in'
        ]
        credential_patterns = [
            r'password', r'username', r'account', r'login', r'verify', r'credential',
            r'authentication', r'confirm', r'validate', r'security', r'identity'
        ]
        scam_categories = {
            'financial': ['money', 'payment', 'bank', 'cash', 'transfer', 'credit', 'investment'],
            'lottery': ['win', 'winner', 'prize', 'lottery', 'jackpot', 'award', 'claim'],
            'phishing': ['verify', 'confirm', 'update', 'account', 'password', 'login', 'secure'],
            'romance': ['love', 'relationship', 'meet', 'dating', 'friend', 'marriage', 'partner'],
            'job': ['job', 'employment', 'salary', 'position', 'career', 'opportunity', 'work'],
            'blackmail': ['photo', 'video', 'camera', 'record', 'private', 'embarrass'],
            'malware': ['download', 'attachment', 'file', 'document', 'open', 'view']
        }
        self.log("Analyzing email content patterns...")
        for index, row in self.df.iterrows():
            body = str(row['body']) if pd.notna(row['body']) else ""
            if not body:
                continue
            tokens = nltk.word_tokenize(body.lower())
            stop_words = set(nltk.corpus.stopwords.words('english'))
            filtered_tokens = [w for w in tokens if w.isalnum() and w not in stop_words]
            has_monetary = any(re.search(pattern, body, re.IGNORECASE) for pattern in monetary_patterns)
            has_urgency = any(re.search(pattern, body, re.IGNORECASE) for pattern in urgency_patterns)
            has_links = any(re.search(pattern, body, re.IGNORECASE) for pattern in link_patterns)
            has_credential_request = any(re.search(pattern, body, re.IGNORECASE) for pattern in credential_patterns)
            detected_categories = []
            for category, keywords in scam_categories.items():
                if any(keyword in filtered_tokens for keyword in keywords):
                    detected_categories.append(category)
            scam_score = 0.0
            if has_monetary: scam_score += 0.25
            if has_urgency: scam_score += 0.25
            if has_links: scam_score += 0.2
            if has_credential_request: scam_score += 0.3
            if len(detected_categories) >= 2:
                scam_score += 0.2
            scam_score = min(scam_score, 1.0)
            self.df.at[index, 'contains_monetary'] = has_monetary
            self.df.at[index, 'contains_urgency'] = has_urgency
            self.df.at[index, 'contains_suspicious_links'] = has_links
            self.df.at[index, 'contains_credential_request'] = has_credential_request
            self.df.at[index, 'scam_score'] = scam_score
            self.df.at[index, 'scam_category'] = ', '.join(detected_categories) if detected_categories else None
        high_risk_emails = self.df[self.df['scam_score'] > 0.5]
        self.log("Content analysis complete:")
        self.log(f"Emails with monetary content: {self.df['contains_monetary'].sum()} ({self.df['contains_monetary'].mean()*100:.1f}%)")
        self.log(f"Emails with urgency indicators: {self.df['contains_urgency'].sum()} ({self.df['contains_urgency'].mean()*100:.1f}%)")
        self.log(f"Emails with suspicious links: {self.df['contains_suspicious_links'].sum()} ({self.df['contains_suspicious_links'].mean()*100:.1f}%)")
        self.log(f"Emails with credential requests: {self.df['contains_credential_request'].sum()} ({self.df['contains_credential_request'].mean()*100:.1f}%)")
        self.log(f"Identified {len(high_risk_emails)} high-risk emails (scam score > 0.5)")
        if not self.df['scam_category'].isna().all():
            category_counts = {}
            for categories in self.df['scam_category'].dropna():
                for category in categories.split(', '):
                    if category in category_counts:
                        category_counts[category] += 1
                    else:
                        category_counts[category] = 1
            self.log("Detected scam categories:")
            for category, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
                self.log(f"  {category}: {count} emails")
        return True

    def analyze_urls(self):
        if self.df is None:
            self.log("No data available for URL analysis")
            return False
        if 'body' not in self.df.columns:
            self.log("No email body content found for URL analysis")
            return False
        self.log("=== URL ANALYSIS ===")
        self.df['contains_urls'] = False
        self.df['url_count'] = 0
        self.df['suspicious_url_count'] = 0
        self.df['url_score'] = 0.0
        all_urls = []
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
        shortener_domains = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'tiny.cc', 'is.gd', 
            'cli.gs', 'pic.gd', 'DwarfURL.com', 'ow.ly', 'snipurl.com', 
            'short.to', 'BudURL.com', 'ping.fm', 'post.ly', 'Just.as', 
            'bkite.com', 'snipr.com', 'fic.kr', 'loopt.us', 'doiop.com', 
            'twitthis.com', 'htxt.it', 'AltURL.com', 'RedirX.com', 'DigBig.com',
            'short.ie', 'tr.im', 'zu.ma', 'twurl.nl', 'ito.mx', 'fwd4.me', 
            'su.pr', 'twurl.cc', 'firsturl.de', 'hurl.me', 'snurl.com', 
            'youtu.be', 'y2u.be', 'v.gd'
        ]
        suspicious_tlds = [
            '.top', '.xyz', '.info', '.club', '.site', '.stream', '.gq', '.cf', 
            '.tk', '.ml', '.ga', '.cc', '.pw', '.biz', '.loan', '.party', '.review',
            '.trade', '.date', '.win', '.work', '.men', '.bid', '.download', '.racing',
            '.online', '.ren', '.wang', '.click', '.space', '.link', '.ws'
        ]
        self.log("Extracting and analyzing URLs...")
        for index, row in self.df.iterrows():
            body = str(row['body']) if pd.notna(row['body']) else ""
            if not body:
                continue
            urls = re.findall(url_pattern, body)
            url_count = len(urls)
            if url_count == 0:
                continue
            self.df.at[index, 'contains_urls'] = True
            self.df.at[index, 'url_count'] = url_count
            all_urls.extend(urls)
            suspicious_count = 0
            url_suspicion_scores = []
            for url in urls:
                suspicion_score = 0
                parsed = urlparse(url)
                if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', parsed.netloc):
                    suspicion_score += 0.5
                if any(shortener in parsed.netloc for shortener in shortener_domains):
                    suspicion_score += 0.3
                domain_parts = tldextract.extract(url)
                if domain_parts.suffix in [tld.strip('.') for tld in suspicious_tlds]:
                    suspicion_score += 0.3
                if len(parsed.netloc.split('.')) > 3:
                    suspicion_score += 0.2
                subdomain_count = len(domain_parts.subdomain.split('.'))
                if subdomain_count > 2:
                    suspicion_score += 0.1 * subdomain_count
                trusted_brands = ['paypal', 'apple', 'microsoft', 'google', 'amazon', 'facebook', 
                                  'instagram', 'netflix', 'bank', 'chase', 'wellsfargo', 'citibank']
                domain_str = domain_parts.domain.lower()
                subdomain_str = domain_parts.subdomain.lower()
                if any(brand in subdomain_str for brand in trusted_brands) and not any(brand in domain_str for brand in trusted_brands):
                    suspicion_score += 0.5
                suspicious_paths = ['login', 'signin', 'verify', 'secure', 'account', 'confirm', 'update']
                if any(path_elem in parsed.path.lower() for path_elem in suspicious_paths):
                    suspicion_score += 0.2
                if suspicion_score > 0.3:
                    suspicious_count += 1
                url_suspicion_scores.append(suspicion_score)
            self.df.at[index, 'suspicious_url_count'] = suspicious_count
            url_score = sum(url_suspicion_scores) / len(url_suspicion_scores) if url_suspicion_scores else 0
            self.df.at[index, 'url_score'] = url_score
        emails_with_urls = self.df[self.df['contains_urls'] == True]
        emails_with_suspicious_urls = self.df[self.df['suspicious_url_count'] > 0]
        self.log("URL analysis complete:")
        self.log(f"Emails containing URLs: {len(emails_with_urls)} ({len(emails_with_urls)/len(self.df)*100:.1f}%)")
        self.log(f"Total unique URLs found: {len(set(all_urls))}")
        self.log(f"Emails with suspicious URLs: {len(emails_with_suspicious_urls)} ({len(emails_with_suspicious_urls)/len(self.df)*100:.1f}%)")
        if len(all_urls) > 0:
            self.log("Top domains in URLs:")
            domain_counts = Counter([tldextract.extract(url).registered_domain for url in all_urls])
            for domain, count in domain_counts.most_common(10):
                self.log(f"  {domain}: {count} occurrences")
        return True

    def calculate_comprehensive_threat_score(self):
        if self.df is None:
            self.log("No data available for threat scoring")
            return False
        self.log("=== COMPREHENSIVE THREAT SCORING ===")
        weights = {
            'domain_age': 0.15,
            'vt_score': 0.25,
            'content_score': 0.25,
            'url_score': 0.15,
            'action_phrases': 0.1,
            'domain_entropy': 0.1
        }
        self.df['threat_score'] = 0.0
        if 'domain_age_days' in self.df.columns and not self.df['domain_age_days'].isna().all():
            self.log("Calculating domain age component...")
            max_age = 365 * 10
            self.df['age_score'] = self.df['domain_age_days'].apply(
                lambda x: 1.0 if pd.isna(x) else max(0, 1 - (x / max_age))
            )
            self.df['threat_score'] += weights['domain_age'] * self.df['age_score']
        if 'vt_score' in self.df.columns and not self.df['vt_score'].isna().all():
            self.log("Calculating VirusTotal component...")
            vt_scores = pd.to_numeric(self.df['vt_score'], errors='coerce').fillna(0)
            self.df['threat_score'] += weights['vt_score'] * vt_scores
        if 'scam_score' in self.df.columns:
            self.log("Calculating content analysis component...")
            self.df['threat_score'] += weights['content_score'] * self.df['scam_score']
        if 'url_score' in self.df.columns:
            self.log("Calculating URL analysis component...")
            self.df['threat_score'] += weights['url_score'] * self.df['url_score']
        if 'has_action_phrase' in self.df.columns:
            self.log("Calculating action phrases component...")
            self.df['threat_score'] += weights['action_phrases'] * self.df['has_action_phrase'].astype(float)
        self.log("Classifying threat levels...")
        self.df['threat_level'] = self.df['threat_score'].apply(
            lambda score: 'Critical' if score > 0.8 else
                          'High' if score > 0.6 else
                          'Medium' if score > 0.4 else
                          'Low' if score > 0.2 else
                          'Minimal'
        )
        ordered_levels = ['Low', 'Critical', 'High', 'Minimal', 'Medium']
        threat_counts = {level: self.df[self.df['threat_level'] == level].shape[0] for level in ordered_levels}
        self.log("Threat level distribution:")
        for level in ordered_levels:
            count = threat_counts.get(level, 0)
            percentage = count / len(self.df) * 100
            self.log(f"  {level}: {count} emails ({percentage:.1f}%)")
        critical_threats = self.df[self.df['threat_level'] == 'Critical']
        if len(critical_threats) > 0:
            self.log("CRITICAL THREAT DETAILS:")
            for _, row in critical_threats.iterrows():
                threat_details = []
                if 'sender_email' in row:
                    threat_details.append(f"Sender: {row['sender_email']}")
                if 'sender_domain' in row:
                    threat_details.append(f"Domain: {row['sender_domain']}")
                if 'subject' in row:
                    threat_details.append(f"Subject: {row['subject']}")
                if 'vt_score' in row and not pd.isna(row['vt_score']):
                    threat_details.append(f"VT Score: {row['vt_score']:.3f}")
                if 'domain_age_days' in row and not pd.isna(row['domain_age_days']):
                    threat_details.append(f"Domain Age: {row['domain_age_days']:.1f} days")
                if 'scam_category' in row and not pd.isna(row['scam_category']):
                    threat_details.append(f"Scam Type: {row['scam_category']}")
                self.log("  " + " | ".join(threat_details))
        self._visualize_threat_analysis()
        return True

    def _visualize_threat_analysis(self):
        if 'threat_level' not in self.df.columns:
            return
        try:
            plt.figure(figsize=(15, 10))
            # Pie chart for threat level distribution
            plt.subplot(2, 2, 1)
            ordered_levels = ['Low', 'Critical', 'High', 'Minimal', 'Medium']
            threat_counts = [self.df[self.df['threat_level'] == level].shape[0] for level in ordered_levels]
            colors = {
                'Critical': '#d62728',
                'High': '#ff7f0e',
                'Medium': '#ffdd57',
                'Low': '#1f77b4',
                'Minimal': '#2ca02c'
            }
            ordered_colors = [colors[level] for level in ordered_levels]
            explode = [0, 0.1, 0.1, 0, 0]
            plt.pie(threat_counts, labels=ordered_levels, autopct='%1.1f%%', colors=ordered_colors, explode=explode, startangle=90)
            plt.title('Email Threat Level Distribution')
            
            # Bar chart for Average Threat Component Contributions
            plt.subplot(2, 2, 2)
            components = {}
            if 'age_score' in self.df.columns:
                components['Domain Age'] = (self.df['age_score'] * 0.15).mean()
            if 'vt_score' in self.df.columns:
                vt_comp = pd.to_numeric(self.df['vt_score'], errors='coerce').fillna(0)
                components['VirusTotal'] = (vt_comp * 0.25).mean()
            if 'scam_score' in self.df.columns:
                components['Content Analysis'] = (self.df['scam_score'] * 0.25).mean()
            if 'url_score' in self.df.columns:
                components['URL Analysis'] = (self.df['url_score'] * 0.15).mean()
            if 'has_action_phrase' in self.df.columns:
                components['Action Phrases'] = (self.df['has_action_phrase'].astype(float) * 0.1).mean()
            bars = plt.bar(components.keys(), components.values(), color='#1f77b4')
            plt.title('Average Threat Component Contributions')
            plt.xticks(rotation=45, ha='right')
            plt.ylabel('Average Contribution to Threat Score')
            for bar in bars:
                height = bar.get_height()
                plt.annotate(f'{height:.3f}', xy=(bar.get_x() + bar.get_width() / 2, height),
                             xytext=(0, 3), textcoords="offset points", ha='center', va='bottom')
            
            # Scatter: Domain Age vs. Threat Score
            plt.subplot(2, 2, 3)
            plot_data = self.df[self.df['domain_age_days'].notna()]
            x = plot_data['domain_age_days'].astype(float).values
            y = plot_data['threat_score'].astype(float).values
            scatter = plt.scatter(x, y, c=y, cmap='YlOrRd', alpha=0.7)
            plt.colorbar(scatter, label='Threat Score')
            plt.title('Domain Age vs. Threat Score')
            plt.xlabel('Domain Age (days)')
            plt.ylabel('Threat Score')
            if len(x) > 1:
                z = np.polyfit(x, y, 1)
                p = np.poly1d(z)
                plt.plot(x, p(x), "r--", alpha=0.8)
            
            # Bar chart for Top Scam Categories
            plt.subplot(2, 2, 4)
            category_counts = {}
            for categories in self.df['scam_category'].dropna():
                for category in categories.split(', '):
                    if category in category_counts:
                        category_counts[category] += 1
                    else:
                        category_counts[category] = 1
            sorted_categories = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)
            labels = [x[0] for x in sorted_categories]
            counts = [x[1] for x in sorted_categories]
            bars2 = plt.bar(labels[:10], counts[:10], color='#ff7f0e')
            plt.title('Top Scam Categories')
            plt.xticks(rotation=45, ha='right')
            plt.ylabel('Number of Emails')
            for bar in bars2:
                height = bar.get_height()
                plt.annotate(f'{height}', xy=(bar.get_x() + bar.get_width() / 2, height),
                             xytext=(0, 3), textcoords="offset points", ha='center', va='bottom')
            
            plt.tight_layout()
            chart_buffer = io.BytesIO()
            plt.savefig(chart_buffer, format='png')
            chart_buffer.seek(0)
            self.charts['threat_analysis'] = base64.b64encode(chart_buffer.getvalue()).decode('utf-8')
            plt.close()
            self.log("Threat analysis visualization created.")
        except Exception as e:
            self.log(f"Error creating threat visualizations: {str(e)}")

    def generate_report(self, output_path="email_analysis_report.txt"):
        if self.df is None:
            self.log("No data available for report generation")
            return None
        self.log(f"Generating analysis report to {output_path}...")
        report = []
        report.append("===== MALICIOUS EMAIL ANALYSIS REPORT =====")
        report.append(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Total emails analyzed: {len(self.df)}")
        if self.domain_stats is not None:
            report.append("\n=== DOMAIN ANALYSIS ===")
            report.append(f"Total unique domains: {len(self.domain_stats)}")
            report.append("\nTop 15 sender domains:")
            for i, (_, row) in enumerate(self.domain_stats.head(15).iterrows()):
                report.append(f"{i+1}. {row['domain']}: {row['count']} emails")
            total_emails = len(self.df)
            domain_entropy = self._calculate_entropy(self.domain_stats['count'] / total_emails)
            report.append(f"\nDomain distribution entropy: {domain_entropy:.2f}")
            report.append(f"Maximum possible entropy: {np.log2(len(self.domain_stats)):.2f}")
        if self.email_stats is not None:
            report.append("\n=== EMAIL ADDRESS ANALYSIS ===")
            report.append(f"Total unique email addresses: {len(self.email_stats)}")
            report.append("\nTop 15 sender email addresses:")
            for i, (_, row) in enumerate(self.email_stats.head(15).iterrows()):
                report.append(f"{i+1}. {row['email']}: {row['count']} emails")
            if 'username' in self.df.columns:
                usernames = self.df['username'].tolist()
                usernames_with_numbers = sum(1 for u in usernames if any(c.isdigit() for c in u))
                percent_with_numbers = usernames_with_numbers / len(usernames) * 100
                usernames_with_underscores = sum(1 for u in usernames if '_' in u)
                percent_with_underscores = usernames_with_underscores / len(usernames) * 100
                avg_length = sum(len(u) for u in usernames) / len(usernames)
                report.append("\nUsername pattern analysis:")
                report.append(f"- Usernames with numbers: {usernames_with_numbers} ({percent_with_numbers:.1f}%)")
                report.append(f"- Usernames with underscores: {usernames_with_underscores} ({percent_with_underscores:.1f}%)")
                report.append(f"- Average username length: {avg_length:.1f} characters")
        if 'has_action_phrase' in self.df.columns:
            action_count = self.df['has_action_phrase'].sum()
            action_percentage = action_count / len(self.df) * 100
            report.append("\n=== SUBJECT ACTION ANALYSIS ===")
            report.append(f"Emails with action-oriented phrases: {action_count} ({action_percentage:.1f}%)")
        if 'domain_age_days' in self.df.columns and not self.df['domain_age_days'].isna().all():
            domains_with_age = self.df[self.df['registration_info_available'] == True]
            if len(domains_with_age) > 0:
                avg_age = domains_with_age['domain_age_days'].mean()
                min_age = domains_with_age['domain_age_days'].min()
                max_age = domains_with_age['domain_age_days'].max()
                report.append("\n=== DOMAIN AGE ANALYSIS ===")
                report.append(f"Domains with registration information: {len(domains_with_age)}")
                report.append(f"Average domain age: {avg_age:.1f} days ({avg_age/365.25:.1f} years)")
                report.append(f"Newest domain: {min_age:.1f} days ({min_age/365.25:.1f} years)")
                report.append(f"Oldest domain: {max_age:.1f} days ({max_age/365.25:.1f} years)")
                suspicious_domains = domains_with_age[domains_with_age['domain_age_days'] < 30]
                if len(suspicious_domains) > 0:
                    report.append("\nRecently created domains (<30 days):")
                    for domain in suspicious_domains['sender_domain'].unique():
                        count = len(suspicious_domains[suspicious_domains['sender_domain'] == domain])
                        age = suspicious_domains[suspicious_domains['sender_domain'] == domain]['domain_age_days'].iloc[0]
                        report.append(f"  {domain}: {age:.1f} days old, {count} emails")
        if 'vt_score' in self.df.columns and not self.df['vt_score'].isna().all():
            domains_with_vt = self.df[self.df['vt_score'].notna()]
            if len(domains_with_vt) > 0:
                avg_score = domains_with_vt['vt_score'].mean()
                report.append("\n=== VIRUSTOTAL DOMAIN ANALYSIS ===")
                report.append(f"Domains analyzed with VirusTotal: {len(domains_with_vt['sender_domain'].unique())}")
                report.append(f"Average detection score: {avg_score:.3f}")
                high_threat_domains = domains_with_vt[domains_with_vt['vt_score'] > 0.1]
                if len(high_threat_domains) > 0:
                    report.append("\nDomains with significant detections:")
                    for domain in high_threat_domains['sender_domain'].unique():
                        domain_df = high_threat_domains[high_threat_domains['sender_domain'] == domain]
                        count = len(domain_df)
                        score = domain_df['vt_score'].iloc[0]
                        positives = domain_df['vt_positives'].iloc[0]
                        total = domain_df['vt_total'].iloc[0]
                        report.append(f"  {domain}: {positives}/{total} detections (Score: {score:.3f}), {count} emails")
        if 'scam_score' in self.df.columns:
            report.append("\n=== EMAIL CONTENT ANALYSIS ===")
            report.append(f"Emails with monetary content: {self.df['contains_monetary'].sum()} ({self.df['contains_monetary'].mean()*100:.1f}%)")
            report.append(f"Emails with urgency indicators: {self.df['contains_urgency'].sum()} ({self.df['contains_urgency'].mean()*100:.1f}%)")
            report.append(f"Emails with suspicious links: {self.df['contains_suspicious_links'].sum()} ({self.df['contains_suspicious_links'].mean()*100:.1f}%)")
            report.append(f"Emails with credential requests: {self.df['contains_credential_request'].sum()} ({self.df['contains_credential_request'].mean()*100:.1f}%)")
            if not self.df['scam_category'].isna().all():
                category_counts = {}
                for categories in self.df['scam_category'].dropna():
                    for category in categories.split(', '):
                        if category in category_counts:
                            category_counts[category] += 1
                        else:
                            category_counts[category] = 1
                report.append("\nScam Category Distribution:")
                for category, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
                    report.append(f"  {category}: {count} emails")
        if 'threat_score' in self.df.columns:
            report.append("\n=== COMPREHENSIVE THREAT SCORING ===")
            report.append("Threat Score distribution by email:")
            for level in ['Critical', 'High', 'Medium', 'Low', 'Minimal']:
                level_count = (self.df['threat_level'] == level).sum()
                report.append(f"{level}: {level_count} emails")
        report.append("\n=== INTELLIGENCE SUMMARY & RECOMMENDATIONS ===")
        avg_threat = self.df['threat_score'].mean()
        report.append(f"Overall average threat score: {avg_threat:.3f}")
        report.append("Analysis:")
        if avg_threat > 0.5:
            report.append("  - The overall threat score is high, indicating a significant risk from spam and phishing emails.")
            report.append("  - A high VirusTotal detection rate on several domains suggests these sources may be compromised.")
            report.append("  - Elevated scam scores indicate that the email content often contains suspicious language and links.")
        else:
            report.append("  - The overall threat score is moderate, suggesting that while some risk exists, it may be within acceptable limits.")
        if 'vt_score' in self.df.columns:
            high_vt = self.df[self.df['vt_score'] > 0.1]
            if not high_vt.empty:
                common_malicious = high_vt['sender_domain'].value_counts().head(5)
                report.append("VirusTotal analysis shows that the following domains have high threat scores:")
                for domain, count in common_malicious.items():
                    report.append(f"  - {domain}: {count} emails")
                report.append("Recommendation: Consider flagging or blocking these domains to reduce risk.")
        if 'scam_score' in self.df.columns:
            high_scam = self.df[self.df['scam_score'] > 0.5]
            if not high_scam.empty:
                report.append("A significant number of emails have high scam scores, indicating the presence of fraudulent language and tactics.")
                report.append("Recommendation: Review and enhance content-based filtering rules, focusing on keywords and patterns common in scam emails.")
        report.append("Overall Recommendation: Integrate this threat analysis into your email security operations.")
        report.append("Use these metrics to drive proactive threat intelligence by continuously monitoring these indicators and adjusting preventive measures accordingly.")
        final_report = "\n".join(report)
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(final_report)
            self.log(f"Report successfully written to {output_path}")
        except Exception as e:
            self.log(f"Error writing report to file: {str(e)}")
        return final_report

# ----------------- SQLite Database Functions -----------------
DB_PATH = "analysis_results.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # Table for saving reports
    cur.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            filename TEXT,
            report TEXT,
            avg_threat REAL
        )
    ''')
    # New table for users (username/password)
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    ''')
    conn.commit()
    conn.close()

def save_report(filename, report_text, avg_threat):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('''
        INSERT INTO reports (timestamp, filename, report, avg_threat)
        VALUES (?, ?, ?, ?)
    ''', (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), filename, report_text, avg_threat))
    conn.commit()
    conn.close()

def get_all_reports():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('SELECT id, timestamp, filename, avg_threat FROM reports ORDER BY id DESC')
    rows = cur.fetchall()
    conn.close()
    return rows

def get_report_by_id(report_id):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('SELECT * FROM reports WHERE id = ?', (report_id,))
    row = cur.fetchone()
    conn.close()
    return row

# ----------------- Flask Web App with User Authentication -----------------
app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a secure key
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
init_db()

# HTML Templates
INDEX_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Email Analyzer Upload</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 2em; }
    label { display: block; margin-top: 1em; }
    input[type="file"], input[type="text"] { width: 100%; padding: 0.5em; }
    button { padding: 0.7em 1.2em; margin-top: 1em; }
  </style>
</head>
<body>
  <h1>Email Analyzer Upload</h1>
  <p>Welcome, {{ session['username'] }}! (<a href="{{ url_for('logout') }}">Logout</a>)</p>
  <form method="POST" action="/" enctype="multipart/form-data">
    <label for="file">Select CSV File:</label>
    <input type="file" name="file" id="file" required aria-required="true">
    <label for="vt_key">VirusTotal API Key (optional):</label>
    <input type="text" name="vt_key" id="vt_key" placeholder="Enter VirusTotal API key">
    <button type="submit">Upload and Analyze</button>
  </form>
  <p><a href="{{ url_for('list_reports') }}">View Past Reports</a></p>
</body>
</html>
"""

RESULT_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Analysis Results</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 2em; }
    pre { background: #f4f4f4; padding: 1em; overflow-x: auto; }
    img { max-width: 100%; height: auto; }
    .chart { margin-bottom: 2em; }
  </style>
</head>
<body>
  <h1>Analysis Results</h1>
  <p><a href="{{ url_for('logout') }}">Logout</a> | <a href="{{ url_for('index') }}">Analyze Another File</a> | <a href="{{ url_for('list_reports') }}">View Past Reports</a></p>
  <h2>Log Messages</h2>
  <pre>{{ logs }}</pre>
  <h2>Charts</h2>
  {% if charts.clusters %}
    <div class="chart">
      <h3>Email Clusters</h3>
      <img src="data:image/png;base64,{{ charts.clusters }}" alt="Cluster Visualization">
    </div>
  {% endif %}
  {% if charts.threat_analysis %}
    <div class="chart">
      <h3>Threat Analysis</h3>
      <img src="data:image/png;base64,{{ charts.threat_analysis }}" alt="Threat Analysis Chart">
    </div>
  {% endif %}
  <h2>Full Report</h2>
  <pre>{{ report }}</pre>
</body>
</html>
"""

REPORT_LIST_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Saved Reports</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 2em; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 0.5em; border: 1px solid #ccc; text-align: left; }
    a { text-decoration: none; color: #007BFF; }
  </style>
</head>
<body>
  <h1>Saved Reports</h1>
  <p><a href="{{ url_for('index') }}">Upload New File</a> | <a href="{{ url_for('logout') }}">Logout</a></p>
  {% if reports %}
  <table>
    <tr>
      <th>ID</th>
      <th>Timestamp</th>
      <th>Filename</th>
      <th>Average Threat Score</th>
      <th>Action</th>
    </tr>
    {% for rep in reports %}
    <tr>
      <td>{{ rep[0] }}</td>
      <td>{{ rep[1] }}</td>
      <td>{{ rep[2] }}</td>
      <td>{{ rep[3] }}</td>
      <td><a href="{{ url_for('view_report', report_id=rep[0]) }}">View</a></td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
    <p>No reports saved yet.</p>
  {% endif %}
</body>
</html>
"""

REPORT_DETAIL_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Report {{ report[0] }}</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 2em; }
    pre { background: #f4f4f4; padding: 1em; overflow-x: auto; }
    a { text-decoration: none; color: #007BFF; }
  </style>
</head>
<body>
  <h1>Report ID {{ report[0] }}</h1>
  <p><strong>Timestamp:</strong> {{ report[1] }}</p>
  <p><strong>Filename:</strong> {{ report[2] }}</p>
  <p><strong>Average Threat Score:</strong> {{ report[4] }}</p>
  <h2>Full Report</h2>
  <pre>{{ report[3] }}</pre>
  <p><a href="{{ url_for('list_reports') }}">Back to Reports</a> | <a href="{{ url_for('index') }}">Upload Another File</a></p>
</body>
</html>
"""

LOGIN_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Login</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 2em; }
    label { display: block; margin-top: 1em; }
    input[type="text"], input[type="password"] { width: 100%; padding: 0.5em; }
    button { padding: 0.7em 1.2em; margin-top: 1em; }
  </style>
</head>
<body>
  <h1>Login</h1>
  <form method="POST" action="{{ url_for('login') }}">
    <label for="username">Username:</label>
    <input type="text" name="username" id="username" required>
    <label for="password">Password:</label>
    <input type="password" name="password" id="password" required>
    <button type="submit">Login</button>
  </form>
  <p>Don't have an account? <a href="{{ url_for('register') }}">Register here</a></p>
</body>
</html>
"""

REGISTER_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Register</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 2em; }
    label { display: block; margin-top: 1em; }
    input[type="text"], input[type="password"] { width: 100%; padding: 0.5em; }
    button { padding: 0.7em 1.2em; margin-top: 1em; }
  </style>
</head>
<body>
  <h1>Register</h1>
  <form method="POST" action="{{ url_for('register') }}">
    <label for="username">Username:</label>
    <input type="text" name="username" id="username" required>
    <label for="password">Password:</label>
    <input type="password" name="password" id="password" required>
    <button type="submit">Register</button>
  </form>
  <p>Already have an account? <a href="{{ url_for('login') }}">Login here</a></p>
</body>
</html>
"""

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT id, password FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        conn.close()
        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            session['username'] = username
            flash("Logged in successfully.")
            return redirect(url_for("index"))
        else:
            flash("Invalid username or password.")
            return redirect(url_for("login"))
    return render_template_string(LOGIN_HTML)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            flash("Please fill out both fields.")
            return redirect(url_for("register"))
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        try:
            hashed_pw = generate_password_hash(password)
            cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
            conn.commit()
            flash("Registration successful! Please log in.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already exists.")
            return redirect(url_for("register"))
        finally:
            conn.close()
    return render_template_string(REGISTER_HTML)

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.")
    return redirect(url_for("login"))

@app.route("/", methods=["GET", "POST"])
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        if 'file' not in request.files:
            flash("No file part in the request")
            return redirect(request.url)
        file = request.files['file']
        if file.filename == "":
            flash("No file selected")
            return redirect(request.url)
        vt_key = request.form.get('vt_key')
        filename = file.filename
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)
        analyzer = EmailAnalyzer()
        if not analyzer.load_file(file_path):
            flash("Failed to load the file for analysis.")
            return redirect(request.url)
        analyzer.analyze_domains()
        analyzer.analyze_emails()
        analyzer.analyze_subject_actions()
        analyzer.extract_text_features()
        analyzer.perform_clustering(n_clusters=4)
        analyzer.visualize_clusters_2d()
        analyzer.analyze_domain_age()
        if vt_key:
            analyzer.analyze_domain_threats(api_key=vt_key)
        else:
            analyzer.log("Skipping VirusTotal threat analysis (no API key provided).")
        analyzer.analyze_email_content()
        analyzer.analyze_urls()
        analyzer.calculate_comprehensive_threat_score()
        report_text = analyzer.generate_report(output_path="email_analysis_report.txt")
        avg_threat = float(analyzer.df['threat_score'].mean()) if analyzer.df is not None else 0.0
        save_report(filename, report_text, avg_threat)
        return render_template_string(RESULT_HTML, logs="\n".join(analyzer.log_messages),
                                      charts=analyzer.charts, report=report_text)
    return render_template_string(INDEX_HTML)

@app.route("/reports")
def list_reports():
    if "user_id" not in session:
        return redirect(url_for("login"))
    reports = get_all_reports()
    return render_template_string(REPORT_LIST_HTML, reports=reports)

@app.route("/report/<int:report_id>")
def view_report(report_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    report = get_report_by_id(report_id)
    if not report:
        flash("Report not found.")
        return redirect(url_for('list_reports'))
    return render_template_string(REPORT_DETAIL_HTML, report=report)

if __name__ == '__main__':
    app.run(debug=True)

















