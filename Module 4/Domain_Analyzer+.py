import pandas as pd
import numpy as np
import os
import re
from collections import Counter
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
import whois  # Using python-whois instead of whois
import requests
import time
import socket
import nltk
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from urllib.parse import urlparse
import tldextract
import vt  # vt-py module

class EmailAnalyzer:
    def __init__(self):
        self.df = None
        self.domain_stats = None
        self.email_stats = None
        self.clusters = None
        self.text_features = None
        self.vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        print("Email Analyzer+ initialized with threat assessment capabilities.")
    
    def load_file(self, default_path="processed_emails.csv"):
        print("\n=== LOADING EMAIL DATA ===")
        if os.path.exists(default_path):
            print(f"Found default file: {default_path}")
            file_path = default_path
        else:
            print(f"Default file {default_path} not found.")
            print("Please enter the full path to your processed email file (.csv):")
            file_path = input().strip('"').strip("'")
        if not os.path.exists(file_path):
            print("File not found. Exiting.")
            return False
        try:
            print(f"Attempting to load file: {file_path}")
            encodings = ['utf-8', 'latin1', 'iso-8859-1', 'cp1252']
            for encoding in encodings:
                try:
                    print(f"Trying encoding: {encoding}")
                    self.df = pd.read_csv(file_path, encoding=encoding)
                    print(f"Successfully loaded file using {encoding} encoding.")
                    break
                except Exception as e:
                    print(f"Failed with encoding {encoding}: {str(e)}")
                    continue
            if self.df is None:
                raise Exception("Unable to read file with any supported encoding")
            required_columns = ['sender_email', 'subject']
            missing_columns = [col for col in required_columns if col not in self.df.columns]
            if missing_columns:
                print(f"Warning: Missing required columns: {', '.join(missing_columns)}")
                print("Will attempt to continue with available columns.")
                if 'sender_email' in missing_columns and 'sender' in self.df.columns:
                    print("Using 'sender' column as 'sender_email'")
                    self.df['sender_email'] = self.df['sender']
                    missing_columns.remove('sender_email')
                if missing_columns:
                    print("Missing critical columns. Cannot continue analysis.")
                    return False
            if 'sender_domain' not in self.df.columns:
                print("Extracting domains from sender_email column...")
                self.df['sender_domain'] = self.df['sender_email'].apply(
                    lambda x: str(x).split('@')[-1] if '@' in str(x) else 'unknown'
                )
            print(f"Successfully loaded {len(self.df)} records.")
            print(f"Columns in dataset: {', '.join(self.df.columns)}")
            return True
        except Exception as e:
            print(f"Error loading file: {str(e)}")
            return False
    
    def analyze_domains(self):
        if self.df is None:
            print("No data available for domain analysis")
            return
        print("\n=== DOMAIN ANALYSIS ===")
        if 'sender_domain' not in self.df.columns:
            print("No sender_domain column found in the dataset")
            if 'sender_email' in self.df.columns:
                print("Extracting domains from sender_email column...")
                self.df['sender_domain'] = self.df['sender_email'].apply(
                    lambda x: x.split('@')[-1] if '@' in str(x) else 'unknown'
                )
                print("Domain extraction complete.")
            else:
                print("Cannot perform domain analysis without sender domain information.")
                return
        print("Counting domain frequencies...")
        domain_counts = self.df['sender_domain'].value_counts().reset_index()
        domain_counts.columns = ['domain', 'count']
        print(f"Found {len(domain_counts)} unique domains")
        self.domain_stats = domain_counts.sort_values('count', ascending=False)
        print("\nTop 10 sender domains:")
        for i, (_, row) in enumerate(self.domain_stats.head(10).iterrows()):
            print(f"{i+1}. {row['domain']}: {row['count']} emails")
        total_emails = len(self.df)
        domain_entropy = self._calculate_entropy(self.domain_stats['count'] / total_emails)
        print(f"\nDomain distribution entropy: {domain_entropy:.2f}")
        print(f"Higher entropy (closer to {np.log2(len(self.domain_stats)):.2f}) means more diverse domains")
        print(f"Lower entropy means concentration around fewer domains")
    
    def analyze_emails(self):
        if self.df is None:
            print("No data available for email analysis")
            return
        print("\n=== EMAIL ADDRESS ANALYSIS ===")
        if 'sender_email' not in self.df.columns:
            print("No sender_email column found in the dataset")
            return
        print("Counting email address frequencies...")
        email_counts = self.df['sender_email'].value_counts().reset_index()
        email_counts.columns = ['email', 'count']
        print(f"Found {len(email_counts)} unique email addresses")
        self.email_stats = email_counts.sort_values('count', ascending=False)
        print("\nTop 10 sender email addresses:")
        for i, (_, row) in enumerate(self.email_stats.head(10).iterrows()):
            print(f"{i+1}. {row['email']}: {row['count']} emails")
        print("\nAnalyzing email address patterns...")
        self.df['username'] = self.df['sender_email'].apply(
            lambda x: str(x).split('@')[0] if '@' in str(x) else str(x)
        )
        usernames = self.df['username'].tolist()
        usernames_with_numbers = sum(1 for u in usernames if any(c.isdigit() for c in u))
        percent_with_numbers = usernames_with_numbers / len(usernames) * 100
        print(f"Usernames containing numbers: {usernames_with_numbers} ({percent_with_numbers:.1f}%)")
        usernames_with_underscores = sum(1 for u in usernames if '_' in u)
        percent_with_underscores = usernames_with_underscores / len(usernames) * 100
        print(f"Usernames containing underscores: {usernames_with_underscores} ({percent_with_underscores:.1f}%)")
        avg_length = sum(len(u) for u in usernames) / len(usernames)
        print(f"Average username length: {avg_length:.1f} characters")
    
    def analyze_subject_actions(self):
        if self.df is None:
            print("No data available for subject analysis")
            return
        print("\n=== SUBJECT ACTION ANALYSIS ===")
        if 'subject' not in self.df.columns:
            print("No subject column found in the dataset")
            return
        print("Analyzing subject lines for action-oriented language...")
        action_phrases = [
            'action required', 'act now', 'urgent', 'immediate', 'attention',
            'response needed', 'respond', 'reply', 'click', 'open', 'download',
            'activate', 'verify', 'confirm', 'update', 'validate', 'important',
            'time-sensitive', 'limited time', 'expires', 'deadline', 'last chance',
            'final notice', 'don\'t miss', 'hurry', 'quick', 'asap', 'promptly'
        ]
        def contains_action_phrase(subject):
            if not subject or pd.isna(subject):
                return False
            subject = str(subject).lower()
            return any(phrase in subject for phrase in action_phrases)
        self.df['has_action_phrase'] = self.df['subject'].apply(contains_action_phrase)
        action_count = self.df['has_action_phrase'].sum()
        action_percentage = action_count / len(self.df) * 100
        print(f"\nFound {action_count} emails ({action_percentage:.1f}%) with action-oriented phrases in subjects")
        phrase_counts = {}
        for phrase in action_phrases:
            count = self.df['subject'].str.lower().str.contains(phrase).sum()
            if count > 0:
                phrase_counts[phrase] = count
        sorted_phrases = sorted(phrase_counts.items(), key=lambda x: x[1], reverse=True)
        print("\nTop action phrases found in subject lines:")
        for i, (phrase, count) in enumerate(sorted_phrases[:10]):
            percentage = count / len(self.df) * 100
            print(f"{i+1}. '{phrase}': {count} emails ({percentage:.1f}%)")
    
    def extract_text_features(self):
        if self.df is None:
            print("No data available for text feature extraction")
            return
        print("\n=== TEXT FEATURE EXTRACTION ===")
        if 'subject' not in self.df.columns:
            print("No subject column found for feature extraction")
            return
        print("Preparing text for analysis...")
        texts = []
        for _, row in self.df.iterrows():
            parts = []
            if 'subject' in self.df.columns and not pd.isna(row['subject']):
                parts.append(str(row['subject']))
            if 'body' in self.df.columns and not pd.isna(row['body']):
                parts.append(str(row['body'])[:500])
            text = " ".join(parts)
            texts.append(text if text else "empty")
        print(f"Prepared {len(texts)} text samples for analysis")
        try:
            print("Applying TF-IDF vectorization...")
            self.text_features = self.vectorizer.fit_transform(texts)
            feature_names = self.vectorizer.get_feature_names_out()
            print(f"Successfully extracted {len(feature_names)} text features")
            feature_sum = np.array(self.text_features.sum(axis=0)).flatten()
            top_indices = feature_sum.argsort()[-10:][::-1]
            print("\nTop terms across all emails:")
            for idx in top_indices:
                print(f"  {feature_names[idx]}: {feature_sum[idx]:.2f}")
            return True
        except Exception as e:
            print(f"Error in text feature extraction: {str(e)}")
            return False
    
    def perform_clustering(self, n_clusters=4):
        if self.text_features is None:
            print("No text features available. Run extract_text_features first.")
            success = self.extract_text_features()
            if not success:
                return False
        print(f"\n=== CLUSTERING EMAILS INTO {n_clusters} GROUPS ===")
        try:
            print("Applying K-means clustering...")
            kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
            self.clusters = kmeans.fit_predict(self.text_features)
            self.df['cluster'] = self.clusters
            cluster_counts = self.df['cluster'].value_counts().sort_index()
            print("\nCluster distribution:")
            for cluster, count in cluster_counts.items():
                percentage = count / len(self.df) * 100
                print(f"  Cluster {cluster}: {count} emails ({percentage:.1f}%)")
            print("\nMost common words in each cluster:")
            feature_names = self.vectorizer.get_feature_names_out()
            centers = kmeans.cluster_centers_
            for cluster in range(n_clusters):
                top_indices = centers[cluster].argsort()[-10:][::-1]
                top_terms = [feature_names[i] for i in top_indices]
                print(f"\nCluster {cluster} top terms:")
                for term in top_terms:
                    print(f"  {term}")
            print("\nDomain distribution by cluster:")
            for cluster in range(n_clusters):
                cluster_df = self.df[self.df['cluster'] == cluster]
                domain_counts = cluster_df['sender_domain'].value_counts().reset_index()
                domain_counts.columns = ['domain', 'count']
                top_domains = domain_counts.head(3)
                print(f"\nCluster {cluster} top domains:")
                for _, row in top_domains.iterrows():
                    domain_count = row['count']
                    domain_name = row['domain']
                    percentage = domain_count / len(cluster_df) * 100
                    print(f"  {domain_name}: {domain_count} emails ({percentage:.1f}%)")
            return True
        except Exception as e:
            print(f"Error in clustering: {str(e)}")
            return False
    
    def visualize_clusters_2d(self):
        if self.clusters is None or self.text_features is None:
            print("No cluster data available. Run perform_clustering first.")
            return False
        print("\n=== VISUALIZING EMAIL CLUSTERS ===")
        try:
            print("Reducing dimensions with PCA...")
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
                domain_info = ", ".join([f"{d}" for d in top_domains.index])
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
            plt.savefig('email_clusters.png', dpi=300)
            plt.close()
            print("Enhanced visualization saved as 'email_clusters.png'")
            return True
        except Exception as e:
            print(f"Error in cluster visualization: {str(e)}")
            return False
    
    def _calculate_entropy(self, probabilities):
        probabilities = probabilities[probabilities > 0]
        return -np.sum(probabilities * np.log2(probabilities))
    
    def analyze_domain_age(self):
        if self.df is None or 'sender_domain' not in self.df.columns:
            print("No domain data available for WHOIS analysis")
            return
        print("\n=== DOMAIN AGE ANALYSIS ===")
        if self.domain_stats is None:
            print("Running domain analysis first to identify top domains...")
            self.analyze_domains()
        top_domains = self.domain_stats.head(25)['domain'].tolist()
        print(f"Analyzing age for top 25 domains only...")
        self.df['domain_age_days'] = None
        self.df['domain_creation_date'] = None
        self.df['registration_info_available'] = False
        unique_domains = [domain for domain in self.df['sender_domain'].unique() if domain in top_domains]
        print(f"Analyzing age for {len(unique_domains)} unique top domains...")
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
                        print(f"Domain {domain}: {age_days} days old (created: {creation_date.strftime('%Y-%m-%d')})")
                        break
                    else:
                        print(f"Domain {domain}: Creation date not available")
                        domain_age_results[domain] = {'available': False}
                        break
                except (socket.error, Exception) as e:
                    print(f"Error retrieving WHOIS info for {domain}: {str(e)}. Retries left: {retries-1}")
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
            print(f"\nDomain age statistics:")
            print(f"Average domain age: {avg_age:.1f} days ({avg_age/365.25:.1f} years)")
            print(f"Newest domain: {min_age:.1f} days ({min_age/365.25:.1f} years)")
            print(f"Oldest domain: {max_age:.1f} days ({max_age/365.25:.1f} years)")
            suspicious_domains = domains_with_age[domains_with_age['domain_age_days'] < 30]
            if len(suspicious_domains) > 0:
                print(f"\nWARNING: Found {len(suspicious_domains)} emails from recently created domains (<30 days):")
                for domain in suspicious_domains['sender_domain'].unique():
                    count = len(suspicious_domains[suspicious_domains['sender_domain'] == domain])
                    age = suspicious_domains[suspicious_domains['sender_domain'] == domain]['domain_age_days'].iloc[0]
                    print(f"  {domain}: {age:.1f} days old, {count} emails")
    
    def analyze_domain_threats(self, api_key=None):
        if self.df is None or 'sender_domain' not in self.df.columns:
            print("No domain data available for threat analysis")
            return
        # Skip any domain that contains common provider keywords.
        common_keywords = ["yahoo", "hotmail", "gmail", "microsoft", "aol", "outlook", "live", "msn"]
        if api_key is None:
            print("VirusTotal API key required for threat analysis")
            api_key = input("Enter your VirusTotal API key: ").strip()
            if not api_key:
                print("No API key provided. Skipping threat analysis.")
                return
        print("\n=== DOMAIN THREAT ANALYSIS ===")
        if self.domain_stats is None:
            print("Running domain analysis first to identify top domains...")
            self.analyze_domains()
        top_domains = self.domain_stats.head(25)['domain'].tolist()
        print(f"Analyzing threats for top 25 domains only...")
        self.df['vt_positives'] = None
        self.df['vt_total'] = None
        self.df['vt_score'] = None
        self.df['vt_categories'] = None
        unique_domains = [domain for domain in self.df['sender_domain'].unique() if domain in top_domains]
        print(f"Analyzing threats for {len(unique_domains)} unique top domains...")
        domain_threat_results = {}
        client = vt.Client(api_key)
        for domain in unique_domains:
            # Check if the domain contains any common email provider keyword
            if any(keyword in domain.lower() for keyword in common_keywords):
                print(f"Skipping common domain: {domain}")
                continue
            try:
                if domain == 'unknown' or '.' not in domain:
                    continue
                print(f"Querying VirusTotal for {domain}...")
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
                print(f"Domain {domain}: {malicious + suspicious}/{total} detections (Score: {threat_score:.3f})")
                if categories_str:
                    print(f"  Categories: {categories_str}")
            except Exception as e:
                print(f"Error querying VirusTotal for {domain}: {str(e)}")
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
            print(f"\nWARNING: Found {len(high_threat_domains)} emails from potentially malicious domains:")
            for domain in high_threat_domains['sender_domain'].unique():
                domain_df = high_threat_domains[high_threat_domains['sender_domain'] == domain]
                count = len(domain_df)
                score = domain_df['vt_score'].iloc[0]
                positives = domain_df['vt_positives'].iloc[0]
                total = domain_df['vt_total'].iloc[0]
                print(f"  {domain}: {positives}/{total} detections (Score: {score:.3f}), {count} emails")
    
    def setup_nltk(self):
        print("Setting up NLTK resources...")
        try:
            nltk.download('punkt', quiet=True)
            nltk.download('punkt_tab', quiet=True)
            nltk.download('stopwords', quiet=True)
            nltk.download('wordnet', quiet=True)
            nltk.download('averaged_perceptron_tagger', quiet=True)
            return True
        except Exception as e:
            print(f"Error setting up NLTK: {str(e)}")
            return False
    
    def analyze_email_content(self):
        if self.df is None:
            print("No data available for content analysis")
            return
        if 'body' not in self.df.columns:
            print("No email body content found for analysis")
            return
        if not self.setup_nltk():
            return
        print("\n=== EMAIL CONTENT ANALYSIS ===")
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
            r'final notice', r'last chance', r'don\'t miss', r'hurry', r'emergency'
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
        print("Analyzing email content patterns...")
        for index, row in self.df.iterrows():
            body = str(row['body']) if pd.notna(row['body']) else ""
            if not body:
                continue
            tokens = word_tokenize(body.lower())
            stop_words = set(stopwords.words('english'))
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
        print(f"\nContent analysis complete:")
        print(f"Emails with monetary content: {self.df['contains_monetary'].sum()} ({self.df['contains_monetary'].mean()*100:.1f}%)")
        print(f"Emails with urgency indicators: {self.df['contains_urgency'].sum()} ({self.df['contains_urgency'].mean()*100:.1f}%)")
        print(f"Emails with suspicious links: {self.df['contains_suspicious_links'].sum()} ({self.df['contains_suspicious_links'].mean()*100:.1f}%)")
        print(f"Emails with credential requests: {self.df['contains_credential_request'].sum()} ({self.df['contains_credential_request'].mean()*100:.1f}%)")
        print(f"\nIdentified {len(high_risk_emails)} high-risk emails (scam score > 0.5)")
        if not self.df['scam_category'].isna().all():
            category_counts = {}
            for categories in self.df['scam_category'].dropna():
                for category in categories.split(', '):
                    if category in category_counts:
                        category_counts[category] += 1
                    else:
                        category_counts[category] = 1
            print("\nDetected scam categories:")
            for category, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
                print(f"  {category}: {count} emails")
    
    def analyze_urls(self):
        if self.df is None:
            print("No data available for URL analysis")
            return
        if 'body' not in self.df.columns:
            print("No email body content found for URL analysis")
            return
        print("\n=== URL ANALYSIS ===")
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
        print("Extracting and analyzing URLs...")
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
        print(f"\nURL analysis complete:")
        print(f"Emails containing URLs: {len(emails_with_urls)} ({len(emails_with_urls)/len(self.df)*100:.1f}%)")
        print(f"Total unique URLs found: {len(set(all_urls))}")
        print(f"Emails with suspicious URLs: {len(emails_with_suspicious_urls)} ({len(emails_with_suspicious_urls)/len(self.df)*100:.1f}%)")
        if len(all_urls) > 0:
            print("\nTop domains in URLs:")
            domain_counts = Counter([tldextract.extract(url).registered_domain for url in all_urls])
            for domain, count in domain_counts.most_common(10):
                print(f"  {domain}: {count} occurrences")
    
    def calculate_comprehensive_threat_score(self):
        if self.df is None:
            print("No data available for threat scoring")
            return
        print("\n=== COMPREHENSIVE THREAT SCORING ===")
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
            print("Calculating domain age component...")
            max_age = 365 * 10
            self.df['age_score'] = self.df['domain_age_days'].apply(
                lambda x: 1.0 if pd.isna(x) else max(0, 1 - (x / max_age))
            )
            self.df['threat_score'] += weights['domain_age'] * self.df['age_score']
        if 'vt_score' in self.df.columns and not self.df['vt_score'].isna().all():
            print("Calculating VirusTotal component...")
            vt_scores = pd.to_numeric(self.df['vt_score'], errors='coerce').fillna(0)
            self.df['threat_score'] += weights['vt_score'] * vt_scores
        if 'scam_score' in self.df.columns:
            print("Calculating content analysis component...")
            self.df['threat_score'] += weights['content_score'] * self.df['scam_score']
        if 'url_score' in self.df.columns:
            print("Calculating URL analysis component...")
            self.df['threat_score'] += weights['url_score'] * self.df['url_score']
        if 'has_action_phrase' in self.df.columns:
            print("Calculating action phrases component...")
            self.df['threat_score'] += weights['action_phrases'] * self.df['has_action_phrase'].astype(float)
        print("Classifying threat levels...")
        self.df['threat_level'] = self.df['threat_score'].apply(
            lambda score: 'Critical' if score > 0.8 else
                          'High' if score > 0.6 else
                          'Medium' if score > 0.4 else
                          'Low' if score > 0.2 else
                          'Minimal'
        )
        # For the pie chart, use the proper order and explode Critical and High segments.
        ordered_levels = ['Low', 'Critical', 'High', 'Minimal', 'Medium']
        explode = [0, 0.1, 0.1, 0, 0]
        threat_counts = {level: self.df[self.df['threat_level'] == level].shape[0] for level in ordered_levels}
        print("\nThreat level distribution:")
        for level in ordered_levels:
            count = threat_counts.get(level, 0)
            percentage = count / len(self.df) * 100
            print(f"  {level}: {count} emails ({percentage:.1f}%)")
        critical_threats = self.df[self.df['threat_level'] == 'Critical']
        if len(critical_threats) > 0:
            print("\nCRITICAL THREAT DETAILS:")
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
                print("  " + " | ".join(threat_details))
        self._visualize_threat_analysis()
    
    def _visualize_threat_analysis(self):
        if 'threat_level' not in self.df.columns:
            return
        try:
            plt.figure(figsize=(15, 10))
            # Pie chart with ordered threat levels and explode for Critical and High
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
            
            # Bar chart for Average Threat Component Contributions with numeric labels
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
            
            # Domain Age vs. Threat Score scatter
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
            
            # Bar chart for Top Scam Categories with numeric labels
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
            plt.savefig('email_threat_analysis.png', dpi=300)
            plt.close()
            print("\nThreat analysis visualization saved as 'email_threat_analysis.png'")
        except Exception as e:
            print(f"Error creating threat visualizations: {str(e)}")
    
    def generate_report(self, output_path="email_analysis_report.txt"):
        if self.df is None:
            print("No data available for report generation")
            return False
        print(f"\nGenerating analysis report to {output_path}...")
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
                report.append(f"\nUsername pattern analysis:")
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
                    report.append(f"\nRecently created domains (<30 days):")
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
                    report.append(f"\nDomains with significant detections:")
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
        # Enhanced Intelligence Summary & Recommendations
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
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("\n".join(report))
            print(f"Report successfully written to {output_path}")
            return True
        except Exception as e:
            print(f"Error writing report to file: {str(e)}")
            return False

if __name__ == '__main__':
    analyzer = EmailAnalyzer()
    if analyzer.load_file():
         analyzer.analyze_domains()
         analyzer.analyze_emails()
         analyzer.analyze_subject_actions()
         analyzer.extract_text_features()
         analyzer.perform_clustering(n_clusters=4)
         analyzer.visualize_clusters_2d()
         analyzer.analyze_domain_age()
         # Prompt for VT API key.
         analyzer.analyze_domain_threats()
         analyzer.analyze_email_content()
         analyzer.analyze_urls()
         analyzer.calculate_comprehensive_threat_score()
         analyzer.generate_report()
    else:
         print("Failed to load data. Exiting.")
