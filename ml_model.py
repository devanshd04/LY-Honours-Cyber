"""
Machine Learning Model for Intrusion Detection System
Trains a Random Forest classifier on NSL-KDD dataset
Classifies packets into: normal, DoS, Port scanning, Brute force, Probe, Anomaly
"""

import os
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import pickle
import warnings
warnings.filterwarnings('ignore')

# Dataset files
TRAIN_FILE = "KDDTrain+.txt"
TEST_FILE = "KDDTest+.txt"
MODEL_PATH = "ids_model.pkl"
SCALER_PATH = "ids_scaler.pkl"
ENCODER_PATH = "ids_label_encoder.pkl"

# NSL-KDD column names (41 features + label + difficulty)
COL_NAMES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted",
    "num_root", "num_file_creations", "num_shells", "num_access_files",
    "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty"
]

# Attack type mapping
ATTACK_MAPPING = {
    'normal': 'normal',
    'back': 'DoS',
    'land': 'DoS',
    'neptune': 'DoS',
    'pod': 'DoS',
    'smurf': 'DoS',
    'teardrop': 'DoS',
    'mailbomb': 'DoS',
    'apache2': 'DoS',
    'processtable': 'DoS',
    'udpstorm': 'DoS',
    'worm': 'DoS',
    'ipsweep': 'Port scanning',
    'nmap': 'Port scanning',
    'portsweep': 'Port scanning',
    'satan': 'Port scanning',
    'mscan': 'Port scanning',
    'saint': 'Port scanning',
    'ftp_write': 'Brute force',
    'guess_passwd': 'Brute force',
    'imap': 'Brute force',
    'multihop': 'Brute force',
    'phf': 'Brute force',
    'spy': 'Brute force',
    'warezclient': 'Brute force',
    'warezmaster': 'Brute force',
    'xlock': 'Brute force',
    'xsnoop': 'Brute force',
    'snmpguess': 'Brute force',
    'httptunnel': 'Brute force',
    'sendmail': 'Brute force',
    'named': 'Brute force',
    'snmpgetattack': 'Brute force',
    'xterm': 'Brute force',
    'ps': 'Probe',
    'nmap': 'Probe',
    'saint': 'Probe',
    'mscan': 'Probe',
    'buffer_overflow': 'Anomaly',
    'loadmodule': 'Anomaly',
    'perl': 'Anomaly',
    'rootkit': 'Anomaly',
    'sqlattack': 'Anomaly',
    'xterm': 'Anomaly'
}


def load_nsl_kdd(train_path, test_path):
    """Load NSL-KDD dataset files"""
    print("[1/6] Loading NSL-KDD dataset...")
    train_df = pd.read_csv(train_path, names=COL_NAMES)
    test_df = pd.read_csv(test_path, names=COL_NAMES)
    print(f"  Train: {train_df.shape}, Test: {test_df.shape}")
    return train_df, test_df


def preprocess_data(train_df, test_df):
    """Preprocess data: encode categorical, normalize, map attack types"""
    print("[2/6] Preprocessing data...")
    
    # Drop difficulty column
    train_df = train_df.drop(columns=["difficulty"])
    test_df = test_df.drop(columns=["difficulty"])
    
    # Map attack types to categories
    def map_attack_type(label):
        label_clean = label.rstrip('.')
        return ATTACK_MAPPING.get(label_clean, 'Anomaly')
    
    train_df['attack_type'] = train_df['label'].apply(map_attack_type)
    test_df['attack_type'] = test_df['label'].apply(map_attack_type)
    
    # Encode categorical columns
    cat_cols = ["protocol_type", "service", "flag"]
    encoders = {}
    
    for col in cat_cols:
        le = LabelEncoder()
        train_df[col] = le.fit_transform(train_df[col].astype(str))
        # Handle unseen categories in test
        test_df[col] = test_df[col].map(
            lambda x: le.transform([x])[0] if x in le.classes_ else -1
        )
        encoders[col] = le
    
    # Prepare features and labels
    feature_cols = [col for col in train_df.columns if col not in ['label', 'attack_type']]
    X_train = train_df[feature_cols].values.astype(np.float32)
    X_test = test_df[feature_cols].values.astype(np.float32)
    
    # Encode attack type labels
    label_encoder = LabelEncoder()
    y_train = label_encoder.fit_transform(train_df['attack_type'])
    y_test = label_encoder.transform(test_df['attack_type'])
    
    # Normalize features
    print("[3/6] Normalizing features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    print(f"  Features: {X_train_scaled.shape[1]}")
    print(f"  Classes: {label_encoder.classes_}")
    
    return X_train_scaled, X_test_scaled, y_train, y_test, scaler, label_encoder, feature_cols


def train_model(X_train, X_test, y_train, y_test):
    """Train Random Forest classifier"""
    print("[4/6] Training Random Forest classifier...")
    
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
        verbose=0
    )
    
    model.fit(X_train, y_train)
    
    print("[5/6] Evaluating model...")
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\nAccuracy: {accuracy:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    return model


def save_model_artifacts(model, scaler, label_encoder, feature_cols):
    """Save model, scaler, and label encoder"""
    print("[6/6] Saving model artifacts...")
    
    # Save model
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
    print(f"  ✓ Model saved to {MODEL_PATH}")
    
    # Save scaler
    with open(SCALER_PATH, 'wb') as f:
        pickle.dump(scaler, f)
    print(f"  ✓ Scaler saved to {SCALER_PATH}")
    
    # Save label encoder
    with open(ENCODER_PATH, 'wb') as f:
        pickle.dump(label_encoder, f)
    print(f"  ✓ Label encoder saved to {ENCODER_PATH}")
    
    # Save feature columns for reference
    import json
    with open('ids_feature_columns.json', 'w') as f:
        json.dump(feature_cols, f)
    print(f"  ✓ Feature columns saved to ids_feature_columns.json")


def main():
    """Main training function"""
    # Check if dataset files exist
    for path in [TRAIN_FILE, TEST_FILE]:
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"Missing dataset file: {path}. Place KDDTrain+.txt and KDDTest+.txt in project root."
            )
    
    # Load and preprocess
    train_df, test_df = load_nsl_kdd(TRAIN_FILE, TEST_FILE)
    X_train, X_test, y_train, y_test, scaler, label_encoder, feature_cols = preprocess_data(train_df, test_df)
    
    # Train model
    model = train_model(X_train, X_test, y_train, y_test)
    
    # Save artifacts
    save_model_artifacts(model, scaler, label_encoder, feature_cols)
    
    print("\n" + "="*80)
    print("Training Complete!")
    print("="*80)
    print(f"\nModel files created:")
    print(f"  - {MODEL_PATH}")
    print(f"  - {SCALER_PATH}")
    print(f"  - {ENCODER_PATH}")
    print(f"  - ids_feature_columns.json")
    print("\nYou can now use this model in app_groq.py for real-time classification.")


if __name__ == "__main__":
    main()






