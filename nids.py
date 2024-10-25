import pandas as pd
import sys
from sklearn.ensemble import IsolationForest

def load_traffic_data(file):
    try:
        return pd.read_csv(file)
    except Exception as e:
        print(f"Error loading traffic data file: {e}")
        return None

def detect_anomalies(df):
    df['timestamp'] = pd.to_datetime(df['timestamp'])

    df['hour'] = df['timestamp'].dt.hour
    df['total_traffic'] = df.groupby('source_ip')['bytes'].transform('sum')
    df['request_count'] = df.groupby('source_ip')['timestamp'].transform('count')

    features = df[['hour', 'port', 'bytes', 'total_traffic', 'request_count']]
    
    model = IsolationForest(contamination=0.1)
    model.fit(features)
    df['anomaly'] = model.predict(features)
    
    anomalies = df[df['anomaly'] == -1]
    if not anomalies.empty:
        print("Anomalous network activities detected:")
        print(anomalies[['timestamp', 'source_ip', 'destination_ip', 'protocol', 'port', 'bytes']])
    else:
        print("No anomalies detected.")

def main():
    if len(sys.argv) < 3 or sys.argv[1] != '--file':
        print("Usage: python nids.py --file <path_to_traffic_file>")
        return

    file = sys.argv[2]
    df = load_traffic_data(file)

    if df is not None:
        print("Analyzing network traffic for anomalies...")
        detect_anomalies(df)

if __name__ == "__main__":
    main()
