#!/usr/bin/env python3
import os
import sys
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.dates import DateFormatter
import datetime
import glob
from sklearn.manifold import TSNE
from sklearn.preprocessing import StandardScaler
import matplotlib.patches as mpatches
from matplotlib.offsetbox import AnchoredText

# Set the style for the plots
plt.style.use('ggplot')
sns.set_palette("viridis")

# Directory paths
anomaly_dir = os.path.expanduser('~/zeek-analysis/detected_anomalies')
vis_dir = os.path.expanduser('~/zeek-analysis/visualizations')

# Create directories if they don't exist
os.makedirs(vis_dir, exist_ok=True)

# Function to load anomaly data
def load_anomaly_data():
    files = glob.glob(os.path.join(anomaly_dir, "anomalies_*.csv"))
    
    if not files:
        print(f"No anomaly files found in {anomaly_dir}")
        return None
    
    print(f"Found {len(files)} anomaly files")
    dfs = []
    
    for file in files:
        try:
            df = pd.read_csv(file)
            dfs.append(df)
        except Exception as e:
            print(f"Error reading {file}: {e}")
    
    if not dfs:
        return None
        
    # Combine all dataframes
    combined_df = pd.concat(dfs, ignore_index=True)
    
    # Convert timestamp to datetime
    if 'timestamp' in combined_df.columns:
        combined_df['timestamp'] = pd.to_datetime(combined_df['timestamp'])
    
    return combined_df

# Function to create time series visualization
def visualize_time_series(df):
    if df is None or len(df) == 0:
        print("No data available for time series visualization")
        return
    
    if 'timestamp' not in df.columns:
        print("Timestamp column required for time series visualization")
        return
    
    # Group by timestamp (hourly bins)
    df['hour'] = df['timestamp'].dt.floor('h')
    hourly_counts = df.groupby('hour').size()
    
    plt.figure(figsize=(12, 6))
    ax = plt.gca()
    
    # Plot with mouseover information
    sc = plt.scatter(hourly_counts.index, hourly_counts.values, 
                    marker='o', s=80, alpha=0.7, c=hourly_counts.values, cmap='viridis')
    
    # Add line
    plt.plot(hourly_counts.index, hourly_counts.values, linestyle='-', alpha=0.6)
    
    # Add informational annotations
    for i, (idx, val) in enumerate(zip(hourly_counts.index, hourly_counts.values)):
        if i % 2 == 0:  # Annotate every other point to avoid clutter
            plt.annotate(f"{val}", 
                        (idx, val), 
                        textcoords="offset points",
                        xytext=(0,10), 
                        ha='center')
    
    # Add explanatory text
    text = ("Spikes indicate time periods with high anomaly activity.\n"
            "Higher values suggest potential attacks or unusual network behavior.")
    at = AnchoredText(text, loc='upper left', frameon=True)
    at.patch.set_boxstyle("round,pad=0.3")
    ax.add_artist(at)
    
    plt.title('Network Anomalies Over Time', fontsize=16)
    plt.xlabel('Time', fontsize=14)
    plt.ylabel('Number of Anomalies', fontsize=14)
    plt.grid(True, alpha=0.3)
    plt.xticks(rotation=45)
    plt.colorbar(sc, label='Number of Anomalies')
    plt.tight_layout()
    
    # Save the plot
    plt.savefig(os.path.join(vis_dir, 'anomalies_over_time.png'), dpi=120)
    print(f"Saved time series visualization to {os.path.join(vis_dir, 'anomalies_over_time.png')}")
    plt.close()

# Function to create protocol distribution visualization
def visualize_protocol_distribution(df):
    if df is None or len(df) == 0 or 'proto' not in df.columns:
        print("No data available for protocol visualization")
        return
    
    # Count protocols
    proto_counts = df['proto'].value_counts()
    
    plt.figure(figsize=(10, 6))
    colors = sns.color_palette("viridis", len(proto_counts))
    bars = plt.bar(proto_counts.index, proto_counts.values, color=colors)
    
    # Add explanatory text
    ax = plt.gca()
    text = ("Shows distribution of protocols in anomalous traffic.\n"
            "High TCP counts often indicate port scans or SYN floods.\n"
            "High UDP may suggest UDP flood attacks.")
    at = AnchoredText(text, loc='upper right', prop=dict(size=10), frameon=True)
    at.patch.set_boxstyle("round,pad=0.3")
    ax.add_artist(at)
    
    plt.title('Protocol Distribution in Anomalies', fontsize=16)
    plt.xlabel('Protocol', fontsize=14)
    plt.ylabel('Count', fontsize=14)
    plt.grid(True, alpha=0.3, axis='y')
    
    # Add count labels on top of bars
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                 f'{int(height)}', ha='center', va='bottom')
    
    plt.tight_layout()
    
    # Save the plot
    plt.savefig(os.path.join(vis_dir, 'protocol_distribution.png'), dpi=120)
    print(f"Saved protocol distribution to {os.path.join(vis_dir, 'protocol_distribution.png')}")
    plt.close()

# Function to create scatter plot of anomaly scores
def visualize_anomaly_scores(df):
    if df is None or len(df) == 0 or 'score' not in df.columns:
        print("No data available for anomaly score visualization")
        return
    
    plt.figure(figsize=(12, 6))
    
    # Sort scores for better visualization
    sorted_scores = sorted(df['score'], reverse=True)
    
    # Use color gradient based on score value
    sc = plt.scatter(range(len(sorted_scores)), sorted_scores, alpha=0.7, 
                    c=sorted_scores, cmap='viridis', s=50)
    
    # Add a line connecting the points
    plt.plot(range(len(sorted_scores)), sorted_scores, alpha=0.3)
    
    # Add explanatory text
    ax = plt.gca()
    text = ("Higher scores indicate more unusual network activity.\n"
            "Scores above 0.8 are highly likely to be attacks or significant anomalies.\n"
            "Steep drop-off indicates clear distinction between normal and abnormal traffic.")
    at = AnchoredText(text, loc='upper right', prop=dict(size=10), frameon=True)
    at.patch.set_boxstyle("round,pad=0.3")
    ax.add_artist(at)
    
    # Highlight threshold regions
    plt.axhline(y=0.8, color='r', linestyle='--', alpha=0.7)
    plt.text(len(sorted_scores)*0.02, 0.82, "High Anomaly Threshold (0.8)", color='r')
    
    plt.title('Anomaly Scores Distribution', fontsize=16)
    plt.xlabel('Anomaly Rank', fontsize=14)
    plt.ylabel('Anomaly Score', fontsize=14)
    plt.grid(True, alpha=0.3)
    plt.colorbar(sc, label='Anomaly Score')
    plt.tight_layout()
    
    # Save the plot
    plt.savefig(os.path.join(vis_dir, 'anomaly_scores.png'), dpi=120)
    print(f"Saved anomaly scores visualization to {os.path.join(vis_dir, 'anomaly_scores.png')}")
    plt.close()

# Function to create 2D projection of anomalies using t-SNE
def visualize_tsne(df):
    if df is None or len(df) < 20:  # t-SNE needs a reasonable number of samples
        print("Not enough data for t-SNE visualization")
        return
    
    # Select numeric features
    numeric_features = ['score', 'orig_bytes', 'resp_bytes', 'duration']
    numeric_features = [f for f in numeric_features if f in df.columns]
    
    if len(numeric_features) < 2:
        print("Not enough numeric features for t-SNE visualization")
        return
    
    # Fill NAs and select data
    X = df[numeric_features].fillna(0).values
    
    # Standardize the data
    X = StandardScaler().fit_transform(X)
    
    # Apply t-SNE
    tsne = TSNE(n_components=2, random_state=42)
    X_tsne = tsne.fit_transform(X)
    
    # Create plot
    plt.figure(figsize=(10, 8))
    
    # Use score for color if available
    scatter = plt.scatter(X_tsne[:, 0], X_tsne[:, 1], c=df['score'], 
                         cmap='viridis', alpha=0.7, s=60)
    
    # Add protocol information if available
    if 'proto' in df.columns:
        # Add protocol labels to some points
        protos = df['proto'].unique()
        for proto in protos:
            indices = df['proto'] == proto
            if sum(indices) > 0:
                # Get mean position of this protocol
                mean_x = np.mean(X_tsne[indices, 0])
                mean_y = np.mean(X_tsne[indices, 1])
                plt.annotate(proto, (mean_x, mean_y), fontsize=12, 
                            ha='center', va='center', 
                            bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="gray", alpha=0.7))
    
    # Add explanatory text
    ax = plt.gca()
    text = ("t-SNE visualization clusters similar network anomalies together.\n"
            "Distinct clusters often represent different attack types or patterns.\n"
            "Color intensity indicates anomaly score (higher = more anomalous).\n"
            "Protocol labels show where different protocols cluster.")
    at = AnchoredText(text, loc='upper right', prop=dict(size=10), frameon=True)
    at.patch.set_boxstyle("round,pad=0.3")
    ax.add_artist(at)
    
    plt.colorbar(scatter, label='Anomaly Score')
    plt.title('t-SNE Projection of Network Anomalies', fontsize=16)
    plt.xlabel('t-SNE Dimension 1', fontsize=14)
    plt.ylabel('t-SNE Dimension 2', fontsize=14)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    
    # Save the plot
    plt.savefig(os.path.join(vis_dir, 'tsne_anomalies.png'), dpi=120)
    print(f"Saved t-SNE visualization to {os.path.join(vis_dir, 'tsne_anomalies.png')}")
    plt.close()

# Main function
def main():
    print("Loading anomaly data...")
    df = load_anomaly_data()
    
    if df is None:
        print("No anomaly data available. Please run the monitor first to collect data.")
        return
    
    print(f"Loaded {len(df)} anomaly records")
    
    # Create visualizations
    print("\nGenerating visualizations...")
    visualize_time_series(df)
    visualize_protocol_distribution(df)
    visualize_anomaly_scores(df)
    visualize_tsne(df)
    
    print(f"\nAll visualizations have been saved to {vis_dir}")

if __name__ == "__main__":
    main()