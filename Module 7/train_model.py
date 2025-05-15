#!/usr/bin/env python3
import os
import pandas as pd
import numpy as np
import joblib
from pyod.models.iforest import IForest
from zat.log_to_dataframe import LogToDataFrame

# Path to Zeek logs directory
log_dir = '/usr/local/zeek/spool/zeek/'

# Output model path
model_path = os.path.expanduser('~/zeek-analysis/models/network_anomaly_model.joblib')

# Create a Zeek log to dataframe converter
log_to_df = LogToDataFrame()

# Function to process a log file
def process_log_file(log_file):
    try:
        df = log_to_df.create_dataframe(log_file)
        return df
    except Exception as e:
        print(f"Error processing {log_file}: {e}")
        return None

# Look for conn.log
conn_log = os.path.join(log_dir, 'conn.log')
if not os.path.exists(conn_log):
    print(f"Could not find {conn_log}")
    exit(1)

# Process conn.log
conn_df = process_log_file(conn_log)
if conn_df is None or len(conn_df) == 0:
    print("No data available in conn.log")
    exit(1)

print(f"Loaded {len(conn_df)} records from conn.log")

# Feature engineering
# Select numeric features
numeric_features = ['duration', 'orig_bytes', 'resp_bytes', 'orig_pkts', 'resp_pkts']

# Process each feature
for feature in numeric_features[:]:  # Use slice copy to avoid modifying during iteration
    if feature in conn_df.columns:
        # Check if the feature contains Timedelta objects
        if pd.api.types.is_timedelta64_dtype(conn_df[feature]):
            print(f"Converting {feature} from Timedelta to float (seconds)")
            # Convert Timedelta to seconds as float
            conn_df[feature] = conn_df[feature].dt.total_seconds()
        
        # Fill NA values
        conn_df[feature] = conn_df[feature].fillna(0)
        
        # Ensure the feature is numeric
        if not pd.api.types.is_numeric_dtype(conn_df[feature]):
            print(f"Warning: Feature {feature} is not numeric, attempting conversion")
            try:
                conn_df[feature] = pd.to_numeric(conn_df[feature], errors='coerce').fillna(0)
            except:
                print(f"Error: Could not convert {feature} to numeric, removing from features list")
                numeric_features.remove(feature)
    else:
        print(f"Warning: Feature {feature} not found in log data")
        numeric_features.remove(feature)

if not numeric_features:
    print("No valid numeric features found in the log data.")
    exit(1)

print(f"Using features: {numeric_features}")

# Select only the features we need for the model
X = conn_df[numeric_features].values

print(f"Training model on {X.shape[0]} samples with {X.shape[1]} features...")

# Initialize and train the model
# Isolation Forest works well for anomaly detection with minimal tuning
model = IForest(contamination=0.05, random_state=42, n_estimators=100)
model.fit(X)

# Create directory for models if it doesn't exist
os.makedirs(os.path.dirname(model_path), exist_ok=True)

# Save the model
joblib.dump({'model': model, 'features': numeric_features}, model_path)
print(f"Model saved to {model_path}")

# Test the model on the training data
scores = model.decision_scores_
labels = model.predict(X)

# Print some statistics
anomaly_count = np.sum(labels == 1)
print(f"Model detected {anomaly_count} potential anomalies in the training data")
print(f"Anomaly rate: {100 * anomaly_count / len(X):.2f}%")

# Optional: Save a sample of potential anomalies for review
anomalies = conn_df.copy()
anomalies['anomaly_score'] = scores
anomalies['is_anomaly'] = labels
anomalies_sample = anomalies[anomalies['is_anomaly'] == 1].sort_values('anomaly_score', ascending=False).head(10)

print("\nTop 10 potential anomalies from training data:")
for idx, row in anomalies_sample.iterrows():
    print(f"  Score: {row['anomaly_score']:.2f}")
    print(f"  Source: {row.get('id.orig_h', 'N/A')} -> Destination: {row.get('id.resp_h', 'N/A')}")
    print(f"  Protocol: {row.get('proto', 'N/A')}")
    print(f"  Duration: {row.get('duration', 0)}")
    print(f"  Bytes: {row.get('orig_bytes', 0)} -> {row.get('resp_bytes', 0)}")
    print()