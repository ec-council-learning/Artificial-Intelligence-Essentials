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

class EmailAnalyzer:
    def __init__(self):
        self.df = None
        self.domain_stats = None
        self.email_stats = None
        self.clusters = None
        self.text_features = None
        self.vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        self.current_date = "2025-03-21 02:33:20"
        self.current_user = "Dandychiggins-4life"
        
        print("Email Analyzer initialized with scikit-learn capabilities.")
    
    def load_file(self, default_path="processed_emails.csv"):
        """Load the processed email file with an option to use a default path"""
        print("\n=== LOADING EMAIL DATA ===")
        
        # First try the default file in the current directory
        if os.path.exists(default_path):
            print(f"Found default file: {default_path}")
            file_path = default_path
        else:
            # If default file doesn't exist, ask user for path
            print(f"Default file {default_path} not found.")
            print("Please enter the full path to your processed email file (.csv):")
            file_path = input().strip('"').strip("'")
        
        if not os.path.exists(file_path):
            print("File not found. Using sample data instead.")
            # Create sample data if file doesn't exist
            self.df = self._create_sample_data()
            print("Created sample data with 100 records.")
            return True
        
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
            
            # Validate the expected columns are present
            required_columns = ['sender_email', 'subject']
            missing_columns = [col for col in required_columns if col not in self.df.columns]
            
            if missing_columns:
                print(f"Warning: Missing required columns: {', '.join(missing_columns)}")
                print("Will attempt to continue with available columns.")
                
                # If sender_email is missing but sender exists, try to use that
                if 'sender_email' in missing_columns and 'sender' in self.df.columns:
                    print("Using 'sender' column as 'sender_email'")
                    self.df['sender_email'] = self.df['sender']
                    missing_columns.remove('sender_email')
                
                # If still missing required columns, use sample data
                if missing_columns:
                    print("Missing critical columns. Using sample data instead.")
                    self.df = self._create_sample_data()
                    print("Created sample data with 100 records.")
                    return True
            
            # Extract domain if not present
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
            print("Using sample data instead.")
            self.df = self._create_sample_data()
            print("Created sample data with 100 records.")
            return True
    
    def _create_sample_data(self):
        """Create sample data for demonstration"""
        print("Creating sample data...")
        
        # Create random domains
        domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 
                  'example.com', 'spam.com', 'scam.net', 'phish.org']
        
        # Create sample data frame
        data = {
            'sender_name': [f'User{i}' for i in range(100)],
            'sender_email': [f'user{i}@{domains[i % len(domains)]}' for i in range(100)],
            'sender_domain': [domains[i % len(domains)] for i in range(100)],
            'recipient_email': ['recipient@example.com' for _ in range(100)],
            'subject': ['Sample Subject ' + ('URGENT! ' if i % 3 == 0 else '') + 
                       ('ACTION REQUIRED: ' if i % 4 == 0 else '') +
                       ('ACT NOW: ' if i % 5 == 0 else '') +
                       ('money' if i % 6 == 0 else 'info') for i in range(100)],
            'body': ['This is a sample email body. ' * (i % 5 + 1) + 
                    ('Please send money' if i % 3 == 0 else 'For your information') for i in range(100)]
        }
        
        return pd.DataFrame(data)
    
    def analyze_domains(self):
        """Analyze email domains"""
        if self.df is None:
            print("No data available for domain analysis")
            return
        
        print("\n=== DOMAIN ANALYSIS ===")
        
        if 'sender_domain' not in self.df.columns:
            print("No sender_domain column found in the dataset")
            # Try to extract domains from sender_email if available
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
        
        # Count domains
        domain_counts = self.df['sender_domain'].value_counts().reset_index()
        domain_counts.columns = ['domain', 'count']
        
        print(f"Found {len(domain_counts)} unique domains")
        
        # Store domain statistics
        self.domain_stats = domain_counts.sort_values('count', ascending=False)
        
        # Display top domains
        print("\nTop 10 sender domains:")
        for i, (_, row) in enumerate(self.domain_stats.head(10).iterrows()):
            print(f"{i+1}. {row['domain']}: {row['count']} emails")
        
        # Calculate domain entropy
        total_emails = len(self.df)
        domain_entropy = self._calculate_entropy(self.domain_stats['count'] / total_emails)
        
        print(f"\nDomain distribution entropy: {domain_entropy:.2f}")
        print(f"Higher entropy (closer to {np.log2(len(self.domain_stats)):.2f}) means more diverse domains")
        print(f"Lower entropy means concentration around fewer domains")
    
    def analyze_emails(self):
        """Analyze sender email addresses"""
        if self.df is None:
            print("No data available for email analysis")
            return
        
        print("\n=== EMAIL ADDRESS ANALYSIS ===")
        
        if 'sender_email' not in self.df.columns:
            print("No sender_email column found in the dataset")
            return
        
        print("Counting email address frequencies...")
        
        # Count email addresses
        email_counts = self.df['sender_email'].value_counts().reset_index()
        email_counts.columns = ['email', 'count']
        
        print(f"Found {len(email_counts)} unique email addresses")
        
        # Store email statistics
        self.email_stats = email_counts.sort_values('count', ascending=False)
        
        # Display top emails
        print("\nTop 10 sender email addresses:")
        for i, (_, row) in enumerate(self.email_stats.head(10).iterrows()):
            print(f"{i+1}. {row['email']}: {row['count']} emails")
        
        # Look for patterns in email addresses
        print("\nAnalyzing email address patterns...")
        
        # Extract usernames from emails
        self.df['username'] = self.df['sender_email'].apply(
            lambda x: str(x).split('@')[0] if '@' in str(x) else str(x)
        )
        
        # Analyze username characteristics
        usernames = self.df['username'].tolist()
        
        # Check for numbers in usernames
        usernames_with_numbers = sum(1 for u in usernames if any(c.isdigit() for c in u))
        percent_with_numbers = usernames_with_numbers / len(usernames) * 100
        print(f"Usernames containing numbers: {usernames_with_numbers} ({percent_with_numbers:.1f}%)")
        
        # Check for underscores
        usernames_with_underscores = sum(1 for u in usernames if '_' in u)
        percent_with_underscores = usernames_with_underscores / len(usernames) * 100
        print(f"Usernames containing underscores: {usernames_with_underscores} ({percent_with_underscores:.1f}%)")
        
        # Check average length
        avg_length = sum(len(u) for u in usernames) / len(usernames)
        print(f"Average username length: {avg_length:.1f} characters")
    
    def analyze_subject_actions(self):
        """Analyze subject lines for action-oriented language"""
        if self.df is None:
            print("No data available for subject analysis")
            return
        
        print("\n=== SUBJECT ACTION ANALYSIS ===")
        
        if 'subject' not in self.df.columns:
            print("No subject column found in the dataset")
            return
        
        print("Analyzing subject lines for action-oriented language...")
        
        # Define action phrases to look for
        action_phrases = [
            'action required', 'act now', 'urgent', 'immediate', 'attention',
            'response needed', 'respond', 'reply', 'click', 'open', 'download',
            'activate', 'verify', 'confirm', 'update', 'validate', 'important',
            'time-sensitive', 'limited time', 'expires', 'deadline', 'last chance',
            'final notice', 'don\'t miss', 'hurry', 'quick', 'asap', 'promptly'
        ]
        
        # Function to check for action phrases in subject
        def contains_action_phrase(subject):
            if not subject or pd.isna(subject):
                return False
            
            subject = str(subject).lower()
            return any(phrase in subject for phrase in action_phrases)
        
        # Count subjects with action phrases
        self.df['has_action_phrase'] = self.df['subject'].apply(contains_action_phrase)
        action_count = self.df['has_action_phrase'].sum()
        action_percentage = action_count / len(self.df) * 100
        
        print(f"\nFound {action_count} emails ({action_percentage:.1f}%) with action-oriented phrases in subjects")
        
        # Count frequency of each action phrase
        phrase_counts = {}
        for phrase in action_phrases:
            count = self.df['subject'].str.lower().str.contains(phrase).sum()
            if count > 0:
                phrase_counts[phrase] = count
        
        # Sort by count and display
        sorted_phrases = sorted(phrase_counts.items(), key=lambda x: x[1], reverse=True)
        
        print("\nTop action phrases found in subject lines:")
        for i, (phrase, count) in enumerate(sorted_phrases[:10]):
            percentage = count / len(self.df) * 100
            print(f"{i+1}. '{phrase}': {count} emails ({percentage:.1f}%)")
    
    def extract_text_features(self):
        """Extract text features using scikit-learn's TF-IDF vectorization"""
        if self.df is None:
            print("No data available for text feature extraction")
            return
        
        print("\n=== TEXT FEATURE EXTRACTION ===")
        
        # Check if we have text columns
        if 'subject' not in self.df.columns:
            print("No subject column found for feature extraction")
            return
        
        # Prepare text for analysis
        print("Preparing text for analysis...")
        texts = []
        
        for _, row in self.df.iterrows():
            parts = []
            
            # Include subject if available
            if 'subject' in self.df.columns and not pd.isna(row['subject']):
                parts.append(str(row['subject']))
            
            # Include body if available (limited length to prevent memory issues)
            if 'body' in self.df.columns and not pd.isna(row['body']):
                parts.append(str(row['body'])[:500])  # Limit to first 500 chars
            
            text = " ".join(parts)
            texts.append(text if text else "empty")
        
        print(f"Prepared {len(texts)} text samples for analysis")
        
        # Apply TF-IDF vectorization
        try:
            print("Applying TF-IDF vectorization...")
            self.text_features = self.vectorizer.fit_transform(texts)
            feature_names = self.vectorizer.get_feature_names_out()
            
            print(f"Successfully extracted {len(feature_names)} text features")
            
            # Get top features
            feature_sum = np.array(self.text_features.sum(axis=0)).flatten()
            top_indices = feature_sum.argsort()[-10:][::-1]
            
            print("\nTop terms across all emails:")
            for idx in top_indices:
                print(f"  {feature_names[idx]}: {feature_sum[idx]:.2f}")
            
            return True
            
        except Exception as e:
            print(f"Error in text feature extraction: {str(e)}")
            return False
    
    def perform_clustering(self, n_clusters=3):
        """Cluster emails based on text content using K-means"""
        if self.text_features is None:
            print("No text features available. Run extract_text_features first.")
            success = self.extract_text_features()
            if not success:
                return False
        
        print(f"\n=== CLUSTERING EMAILS INTO {n_clusters} GROUPS ===")
        
        try:
            # Apply KMeans clustering
            print("Applying K-means clustering...")
            kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
            self.clusters = kmeans.fit_predict(self.text_features)
            
            # Add clusters to dataframe
            self.df['cluster'] = self.clusters
            
            # Display cluster distribution
            cluster_counts = self.df['cluster'].value_counts().sort_index()
            
            print("\nCluster distribution:")
            for cluster, count in cluster_counts.items():
                percentage = count / len(self.df) * 100
                print(f"  Cluster {cluster}: {count} emails ({percentage:.1f}%)")
            
            # Analyze most common words in each cluster
            print("\nMost common words in each cluster:")
            feature_names = self.vectorizer.get_feature_names_out()
            
            # Get cluster centers
            centers = kmeans.cluster_centers_
            
            # Find top terms per cluster
            for cluster in range(n_clusters):
                top_indices = centers[cluster].argsort()[-10:][::-1]
                top_terms = [feature_names[i] for i in top_indices]
                
                print(f"\nCluster {cluster} top terms:")
                for term in top_terms:
                    print(f"  {term}")
            
            # Analyze domains distribution across clusters
            print("\nDomain distribution by cluster:")
            for cluster in range(n_clusters):
                cluster_df = self.df[self.df['cluster'] == cluster]
                
                # Fixed: use proper column names from value_counts result
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
        """Visualize clusters using dimensionality reduction (PCA) with domain annotations"""
        if self.clusters is None or self.text_features is None:
            print("No cluster data available. Run perform_clustering first.")
            return False
        
        print("\n=== VISUALIZING EMAIL CLUSTERS ===")
        
        try:
            # Apply PCA to reduce to 2 dimensions
            print("Reducing dimensions with PCA...")
            pca = PCA(n_components=2, random_state=42)
            reduced_features = pca.fit_transform(self.text_features.toarray())
            
            # Create dataframe for plotting
            plot_df = pd.DataFrame({
                'x': reduced_features[:, 0],
                'y': reduced_features[:, 1],
                'cluster': self.df['cluster'],
                'domain': self.df['sender_domain']
            })
            
            # Create plot with increased size for annotations
            plt.figure(figsize=(14, 10))
            
            # Plot points with distinct colors for each cluster
            colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b', '#e377c2', '#7f7f7f', '#bcbd22', '#17becf']
            
            # Plot points
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
            
            # Get top domains for each cluster for annotation
            cluster_domain_info = {}
            for cluster in sorted(plot_df['cluster'].unique()):
                cluster_df = self.df[self.df['cluster'] == cluster]
                # Get top domains
                top_domains = cluster_df['sender_domain'].value_counts().head(3)
                domain_info = ", ".join([f"{d}" for d in top_domains.index])
                cluster_domain_info[cluster] = domain_info
            
            # Calculate cluster centers for annotation placement
            for cluster in sorted(plot_df['cluster'].unique()):
                cluster_data = plot_df[plot_df['cluster'] == cluster]
                center_x = cluster_data['x'].mean()
                center_y = cluster_data['y'].mean()
                
                # Annotate with domains
                domain_info = cluster_domain_info[cluster]
                plt.annotate(
                    f"Cluster {cluster}:\n{domain_info}", 
                    (center_x, center_y),
                    fontsize=9,
                    bbox=dict(boxstyle="round,pad=0.3", fc="white", alpha=0.8),
                    ha='center', 
                    va='center'
                )
            
            # Removed yellow explanation box completely
            
            plt.title(f'Email Clusters with Domain Information ({self.current_date})', fontsize=14)
            # Updated to keep both labels simple and consistent
            plt.xlabel('Principal Component 1', fontsize=12)
            plt.ylabel('Principal Component 2', fontsize=12)
            plt.legend(fontsize=10)
            plt.grid(alpha=0.3)
            
            # Save figure with better resolution
            plt.tight_layout()
            plt.savefig('email_clusters.png', dpi=300)
            plt.close()
            
            print("Enhanced visualization saved as 'email_clusters.png'")
            return True
            
        except Exception as e:
            print(f"Error in cluster visualization: {str(e)}")
            return False
    
    def _calculate_entropy(self, probabilities):
        """Calculate entropy of a probability distribution"""
        # Filter out zeros to avoid log(0)
        probabilities = probabilities[probabilities > 0]
        return -np.sum(probabilities * np.log2(probabilities))
    
    def generate_report(self, output_path="email_analysis_report.txt"):
        """Generate a text report with analysis findings"""
        if self.df is None:
            print("No data available for report generation")
            return False
        
        print(f"\nGenerating analysis report to {output_path}...")
        
        report = []
        report.append("===== MALICIOUS EMAIL ANALYSIS REPORT =====")
        report.append(f"Generated on: {self.current_date}")
        report.append(f"Generated by: {self.current_user}")
        report.append(f"Total emails analyzed: {len(self.df)}")
        
        # Domain statistics
        if self.domain_stats is not None:
            report.append("\n=== DOMAIN ANALYSIS ===")
            report.append(f"Total unique domains: {len(self.domain_stats)}")
            report.append("\nTop 15 sender domains:")
            
            for i, (_, row) in enumerate(self.domain_stats.head(15).iterrows()):
                report.append(f"{i+1}. {row['domain']}: {row['count']} emails")
            
            # Calculate domain entropy
            total_emails = len(self.df)
            domain_entropy = self._calculate_entropy(self.domain_stats['count'] / total_emails)
            report.append(f"\nDomain distribution entropy: {domain_entropy:.2f}")
            report.append(f"Maximum possible entropy: {np.log2(len(self.domain_stats)):.2f}")
        
        # Email address statistics
        if self.email_stats is not None:
            report.append("\n=== EMAIL ADDRESS ANALYSIS ===")
            report.append(f"Total unique email addresses: {len(self.email_stats)}")
            report.append("\nTop 15 sender email addresses:")
            
            for i, (_, row) in enumerate(self.email_stats.head(15).iterrows()):
                report.append(f"{i+1}. {row['email']}: {row['count']} emails")
            
            # Add username pattern statistics if available
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
        
        # Action phrases in subjects
        if 'has_action_phrase' in self.df.columns:
            action_count = self.df['has_action_phrase'].sum()
            action_percentage = action_count / len(self.df) * 100
            
            report.append("\n=== SUBJECT ACTION ANALYSIS ===")
            report.append(f"Emails with action-oriented phrases: {action_count} ({action_percentage:.1f}%)")
        
        # Clustering results
        if hasattr(self, 'clusters') and self.clusters is not None:
            report.append("\n=== CLUSTERING ANALYSIS ===")
            
            cluster_counts = pd.Series(self.clusters).value_counts().sort_index()
            report.append(f"Number of clusters: {len(cluster_counts)}")
            
            for cluster, count in cluster_counts.items():
                percentage = count / len(self.df) * 100
                report.append(f"Cluster {cluster}: {count} emails ({percentage:.1f}%)")
            
            # Add top terms for each cluster
            if hasattr(self, 'vectorizer'):
                feature_names = self.vectorizer.get_feature_names_out()
                kmeans = KMeans(n_clusters=len(cluster_counts), random_state=42, n_init=10)
                kmeans.fit(self.text_features)
                centers = kmeans.cluster_centers_
                
                report.append("\nCharacteristic terms for each cluster:")
                for cluster in range(len(cluster_counts)):
                    top_indices = centers[cluster].argsort()[-5:][::-1]
                    top_terms = [feature_names[i] for i in top_indices]
                    report.append(f"Cluster {cluster}: {', '.join(top_terms)}")
                
                # Domain distribution by cluster
                report.append("\nDomain distribution by cluster:")
                for cluster in range(len(cluster_counts)):
                    cluster_df = self.df[self.df['cluster'] == cluster]
                    
                    # Get top domains in this cluster
                    domain_counts = cluster_df['sender_domain'].value_counts().reset_index()
                    domain_counts.columns = ['domain', 'count']
                    top_domains = domain_counts.head(3)
                    
                    if not top_domains.empty:
                        report.append(f"\nCluster {cluster} top domains:")
                        for _, row in top_domains.iterrows():
                            domain_count = row['count']
                            domain_name = row['domain']
                            percentage = domain_count / len(cluster_df) * 100
                            report.append(f"  {domain_name}: {domain_count} emails ({percentage:.1f}%)")
        
        # Write report to file
        try:
            with open(output_path, 'w') as f:
                f.write('\n'.join(report))
            print(f"Report generated successfully to {output_path}")
            return True
        except Exception as e:
            print(f"Error writing report: {str(e)}")
            return False

def main():
    print("=== EMAIL DOMAIN & TEXT ANALYZER ===")
    print("This analyzer focuses on malicious email patterns and clustering")
    
    analyzer = EmailAnalyzer()
    
    # Load data
    if not analyzer.load_file():
        print("Failed to load email data. Exiting.")
        return
    
    # Perform domain analysis
    analyzer.analyze_domains()
    
    # Perform email address analysis
    analyzer.analyze_emails()
    
    # Perform subject action analysis
    analyzer.analyze_subject_actions()
    
    # Extract text features and perform clustering
    analyzer.extract_text_features()
    analyzer.perform_clustering(n_clusters=4)  # Try 4 clusters for malicious emails
    
    # Visualize clusters
    try:
        analyzer.visualize_clusters_2d()
    except Exception as e:
        print(f"Could not generate visualization: {str(e)}")
        print("Continuing with analysis...")
    
    # Generate report
    analyzer.generate_report()
    
    print("\nAnalysis complete.")

if __name__ == "__main__":
    main()