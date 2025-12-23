from flask import Flask, jsonify, request, render_template
try:
    from flask_cors import CORS
    CORS_AVAILABLE = True
except ImportError:
    CORS_AVAILABLE = False
    print("⚠️  flask-cors not installed. CORS enabled via SocketIO only.")
import tensorflow as tf
import numpy as np
import psutil
import datetime
import sqlite3
from ollama_lib import OllamaClient
from scapy.all import sniff, get_if_list, get_if_addr
from scapy.layers.inet import IP, TCP, UDP
import ipaddress
import threading
import requests
import os
import time
import pickle
import json
from collections import deque
from flask_socketio import SocketIO, emit

############################################################
# 🔐 Groq API Key — CHANGE THIS
############################################################
GROQ_API_KEY = "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"
GROQ_HEADERS = {
    "Authorization": f"Bearer {GROQ_API_KEY}",
    "Content-Type": "application/json"
}

############################################################
# Flask + SocketIO (NO EVENTLET)
############################################################
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
if CORS_AVAILABLE:
    CORS(app)  # Enable CORS for all routes
else:
    # Manual CORS headers for /api/alerts
    @app.after_request
    def after_request(response):
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
        return response

# IMPORTANT FIX for macOS WebSocket:
socketio = SocketIO(
    app,
    async_mode="threading",      # <--- FIX
    cors_allowed_origins="*",    # <--- FIX
    logger=False,
    engineio_logger=False
)


# -------- Port Scan Detection Globals --------
port_scan_tracker = {}
PORT_SCAN_THRESHOLD = 20   # number of unique ports scanned quickly


############################################################
# Load ML Model (Random Forest) for Threat Classification
############################################################
ML_MODEL_PATH = "ids_model.pkl"
ML_SCALER_PATH = "ids_scaler.pkl"
ML_ENCODER_PATH = "ids_label_encoder.pkl"
ML_FEATURES_PATH = "ids_feature_columns.json"

ml_model = None
ml_scaler = None
ml_label_encoder = None
ml_feature_columns = None

try:
    with open(ML_MODEL_PATH, "rb") as f:
        ml_model = pickle.load(f)
    print(f"✓ ML model loaded from {ML_MODEL_PATH}")
except Exception as e:
    print(f"⚠️  Failed to load ML model: {e}")
    print("   Run 'python3 ml_model.py' to train the model first.")

try:
    with open(ML_SCALER_PATH, "rb") as f:
        ml_scaler = pickle.load(f)
    print(f"✓ ML scaler loaded from {ML_SCALER_PATH}")
except Exception as e:
    print(f"⚠️  Failed to load ML scaler: {e}")

try:
    with open(ML_ENCODER_PATH, "rb") as f:
        ml_label_encoder = pickle.load(f)
    print(f"✓ ML label encoder loaded from {ML_ENCODER_PATH}")
except Exception as e:
    print(f"⚠️  Failed to load ML label encoder: {e}")

try:
    with open(ML_FEATURES_PATH, "r") as f:
        ml_feature_columns = json.load(f)
    print(f"✓ ML feature columns loaded: {len(ml_feature_columns)} features")
except Exception as e:
    print(f"⚠️  Failed to load feature columns: {e}")

############################################################
# Load Local CNN Model (Legacy)
############################################################
MODEL_PATH = "SecIDS-CNN.h5"
SCALER_PATH = "scaler.pkl"

model = None
scaler = None
N_FEATURES = None

try:
    model = tf.keras.models.load_model(MODEL_PATH)
    print(f"✓ CNN model loaded from {MODEL_PATH}")
except Exception as e:
    print(f"⚠️  Failed to load CNN model: {e}")

try:
    with open(SCALER_PATH, "rb") as f:
        scaler = pickle.load(f)
    N_FEATURES = scaler.mean_.shape[0]
    print(f"✓ CNN scaler loaded from {SCALER_PATH} with {N_FEATURES} features")
except Exception as e:
    print(f"⚠️  Failed to load CNN scaler: {e}")

############################################################
# Database Helpers
############################################################
def get_db_connection():
    conn = sqlite3.connect('system_metrics.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def initialize_database():
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                log TEXT
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT,
                dest_ip TEXT,
                attack_type TEXT,
                severity TEXT,
                confidence REAL,
                protocol TEXT,
                packet_length INTEGER
            );
        """)
        conn.commit()

initialize_database()

############################################################
# Save Logs
############################################################
def save_log(log):
    with get_db_connection() as conn:
        conn.execute(
            "INSERT INTO logs (timestamp, log) VALUES (?, ?)",
            (datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), log)
        )
        conn.commit()

############################################################
# Alert Storage (Thread-safe)
############################################################
alerts_queue = deque(maxlen=1000)  # Store last 1000 alerts
alerts_lock = threading.Lock()

def add_alert(alert_data):
    """Add alert to queue and database"""
    with alerts_lock:
        alerts_queue.append(alert_data)
    
    # Save to database
    try:
        with get_db_connection() as conn:
            conn.execute("""
                INSERT INTO alerts (timestamp, source_ip, dest_ip, attack_type, severity, confidence, protocol, packet_length)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert_data['timestamp'],
                alert_data['source_ip'],
                alert_data['dest_ip'],
                alert_data['attack_type'],
                alert_data['severity'],
                alert_data['confidence'],
                alert_data.get('protocol', 'unknown'),
                alert_data.get('packet_length', 0)
            ))
            conn.commit()
    except Exception as e:
        print(f"Error saving alert to database: {e}")

############################################################
# Network Interface Detection (macOS)
############################################################
def get_network_interface():
    """Get active network interface, default to en0 on macOS"""
    # Try en0 first (common macOS interface)
    if "en0" in get_if_list():
        try:
            addr = get_if_addr("en0")
            if addr:
                print(f"✓ Using network interface: en0 ({addr})")
                return "en0"
        except:
            pass
    
    # Auto-detect active interface
    for iface in get_if_list():
        if iface.startswith("en") or iface.startswith("eth"):
            try:
                addr = get_if_addr(iface)
                if addr and not addr.startswith("127."):
                    print(f"✓ Using network interface: {iface} ({addr})")
                    return iface
            except:
                continue
    
    print("⚠️  Could not detect network interface, using default")
    return None

############################################################
# Enhanced Feature Extraction for ML Model
############################################################
def extract_ml_features_from_packet(packet, prev_packet_time=None):
    """
    Extract comprehensive features from packet for ML classification
    Returns features matching NSL-KDD format
    """
    features = {}
    
    if IP in packet:
        # Basic IP features
        features['src_bytes'] = len(packet[IP].payload) if packet[IP].payload else 0
        features['dst_bytes'] = len(packet)
        features['duration'] = 0  # Will be calculated from time delta
        
        # Protocol encoding (simplified mapping)
        proto_map = {1: 0, 6: 1, 17: 2, 47: 3}  # ICMP, TCP, UDP, GRE
        features['protocol_type'] = proto_map.get(packet[IP].proto, 0)
        
        # TCP/UDP features
        if TCP in packet:
            features['service'] = 0  # Simplified
            features['flag'] = int(packet[TCP].flags)
            features['src_bytes'] = len(packet[TCP].payload) if packet[TCP].payload else 0
        elif UDP in packet:
            features['service'] = 1
            features['flag'] = 0
        else:
            features['service'] = 2
            features['flag'] = 0
        
        # Time-based features
        current_time = time.time()
        if prev_packet_time:
            features['duration'] = current_time - prev_packet_time
        else:
            features['duration'] = 0
        
        # Connection features (simplified)
        features['land'] = 0  # Not a land attack
        features['wrong_fragment'] = 0
        features['urgent'] = 1 if TCP in packet and packet[TCP].flags & 0x20 else 0
        features['hot'] = 0
        features['num_failed_logins'] = 0
        features['logged_in'] = 0
        features['num_compromised'] = 0
        features['root_shell'] = 0
        features['su_attempted'] = 0
        features['num_root'] = 0
        features['num_file_creations'] = 0
        features['num_shells'] = 0
        features['num_access_files'] = 0
        features['num_outbound_cmds'] = 0
        features['is_host_login'] = 0
        features['is_guest_login'] = 0
        
        # Statistical features (simplified - would need packet history)
        features['count'] = 1
        features['srv_count'] = 1
        features['serror_rate'] = 0.0
        features['srv_serror_rate'] = 0.0
        features['rerror_rate'] = 0.0
        features['srv_rerror_rate'] = 0.0
        features['same_srv_rate'] = 1.0
        features['diff_srv_rate'] = 0.0
        features['srv_diff_host_rate'] = 0.0
        features['dst_host_count'] = 1
        features['dst_host_srv_count'] = 1
        features['dst_host_same_srv_rate'] = 1.0
        features['dst_host_diff_srv_rate'] = 0.0
        features['dst_host_same_src_port_rate'] = 1.0
        features['dst_host_srv_diff_host_rate'] = 0.0
        features['dst_host_serror_rate'] = 0.0
        features['dst_host_srv_serror_rate'] = 0.0
        features['dst_host_rerror_rate'] = 0.0
        features['dst_host_srv_rerror_rate'] = 0.0
        
    else:
        # Default values for non-IP packets
        for col in ml_feature_columns if ml_feature_columns else []:
            features[col] = 0.0
    
    # Convert to array in correct order
    if ml_feature_columns:
        feature_array = [features.get(col, 0.0) for col in ml_feature_columns]
        return np.array(feature_array, dtype=np.float32)
    else:
        # Fallback: return basic features
        return np.array([0.0] * 41, dtype=np.float32)

############################################################
# ML Threat Classification
############################################################
def classify_packet(features):
    """
    Classify packet using ML model
    Returns: (attack_type, confidence_score)
    """
    if not ml_model or not ml_scaler or not ml_label_encoder:
        return ("Anomaly", 0.0)
    
    try:
        # Normalize features
        features_scaled = ml_scaler.transform([features])
        
        # Predict
        prediction = ml_model.predict(features_scaled)[0]
        probabilities = ml_model.predict_proba(features_scaled)[0]
        confidence = float(max(probabilities))
        
        # Decode attack type
        attack_type = ml_label_encoder.inverse_transform([prediction])[0]
        
        return (attack_type, confidence)
    except Exception as e:
        print(f"ML classification error: {e}")
        return ("Anomaly", 0.0)

def get_severity(attack_type, confidence):
    """Determine severity based on attack type and confidence"""
    severity_map = {
        "DoS": "HIGH",
        "Brute force": "HIGH",
        "Port scanning": "MEDIUM",
        "Probe": "MEDIUM" if confidence < 0.7 else "HIGH",
        "normal": "LOW",
        "Anomaly": "CRITICAL"
    }
    return severity_map.get(attack_type, "MEDIUM")

############################################################
# Intrusion Detection (CNN - Legacy)
############################################################
def extract_features_from_packet(packet):
    feats = []
    if IP in packet:
        try:
            src_ip_int = int(ipaddress.IPv4Address(packet[IP].src))
            dst_ip_int = int(ipaddress.IPv4Address(packet[IP].dst))
        except:
            src_ip_int = dst_ip_int = 0

        proto = packet[IP].proto
        length = len(packet)

        feats.extend([src_ip_int % 1_000_000, dst_ip_int % 1_000_000, proto, length])

        if TCP in packet:
            feats.extend([
                packet[TCP].sport, packet[TCP].dport,
                int(packet[TCP].flags), 1, 0
            ])
        elif UDP in packet:
            feats.extend([
                packet[UDP].sport, packet[UDP].dport,
                0, 0, 1
            ])
        else:
            feats.extend([0, 0, 0, 0, 0])
    else:
        feats.extend([0] * 9)

    if N_FEATURES:
        if len(feats) < N_FEATURES:
            feats.extend([0] * (N_FEATURES - len(feats)))
        else:
            feats = feats[:N_FEATURES]

    return np.array(feats, dtype=np.float32)


def analyze_packet_with_cnn(packet_features):
    if not model or not scaler or not N_FEATURES:
        return "model_unavailable"

    try:
        X = scaler.transform([packet_features])
        X = X.reshape(1, -1, 1)
        prob = model.predict(X, verbose=0)[0][0]
        return "suspicious" if prob > 0.5 else "normal"
    except Exception as e:
        print(f"Prediction error: {e}")
        return "error"


# Global variable to track last packet time
last_packet_time = {}
packet_time_lock = threading.Lock()

def process_packet_for_ids(packet):
    """Process packet: extract features, classify, and create alert if threat detected"""
    global last_packet_time
    
    try:
        if IP not in packet:
            return
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        packet_length = len(packet)
        

                # ------------ Port Scan Detection (Rule-Based) ------------
        if TCP in packet:
            key = src_ip
            dport = packet[TCP].dport

            if key not in port_scan_tracker:
                port_scan_tracker[key] = set()

            port_scan_tracker[key].add(dport)

            if len(port_scan_tracker[key]) > PORT_SCAN_THRESHOLD:
                alert = {
                    "timestamp": datetime.datetime.now().isoformat(),
                    "source_ip": src_ip,
                    "dest_ip": dst_ip,
                    "attack_type": "Port Scan",
                    "severity": "HIGH",
                    "confidence": 99.0,
                    "protocol": "TCP",
                    "packet_length": packet_length
                }

                add_alert(alert)
                socketio.emit("intrusion_alert", alert)

                print(f"🚨 HIGH Alert: Port Scan detected from {src_ip}!")
                return
        # -----------------------------------------------------------


        # Get time delta
        current_time = time.time()
        prev_time = None
        with packet_time_lock:
            prev_time = last_packet_time.get(src_ip)
            last_packet_time[src_ip] = current_time
        
        # Extract ML features
        ml_features = extract_ml_features_from_packet(packet, prev_time)
        
        # Classify using ML model
        attack_type, confidence = classify_packet(ml_features)
        
        # Only create alert for non-normal traffic or high confidence threats
        if attack_type != "normal" and confidence > 0.6:
            severity = get_severity(attack_type, confidence)
            
            # Create alert object
            alert = {
                "timestamp": datetime.datetime.now().isoformat(),
                "source_ip": src_ip,
                "dest_ip": dst_ip,
                "attack_type": attack_type,
                "severity": severity,
                "confidence": round(confidence * 100, 2),
                "protocol": "TCP" if TCP in packet else ("UDP" if UDP in packet else "Other"),
                "packet_length": packet_length
            }
            
            # Add to alerts queue
            add_alert(alert)
            
            # Emit via SocketIO
            socketio.emit("intrusion_alert", alert)
            
            # Log
            msg = f"🚨 {severity} Alert: {attack_type} from {src_ip} (confidence: {confidence:.2%})"
            save_log(msg)
            print(msg)
            
    except Exception as e:
        # Silently handle errors to avoid flooding logs
        pass

def packet_sniffer_thread(interface=None):
    """Background thread for packet sniffing"""
    try:
        if interface:
            print(f"🔍 Starting packet capture on interface: {interface}")
            sniff(iface=interface, prn=process_packet_for_ids, store=False)


        else:
            print("🔍 Starting packet capture on default interface")
            sniff(prn=process_packet_for_ids, store=False)
    except Exception as e:
        print(f"⚠️  Packet sniffing error: {e}")
        print("   Note: Packet sniffing may require sudo privileges on macOS")

############################################################
# System Info API
############################################################
@app.route('/system-info')
def system_info():
    cpu = psutil.cpu_percent()
    cpu_freq = psutil.cpu_freq().current if psutil.cpu_freq() else "N/A"
    cores = psutil.cpu_count(logical=False)
    mem_total = psutil.virtual_memory().total
    disk_total = psutil.disk_usage("/").total
    battery = psutil.sensors_battery()
    power = battery.percent if battery else "N/A"

    return jsonify({
        "cpu_usage": cpu,
        "cpu_frequency": cpu_freq,
        "cpu_cores": cores,
        "memory_total": mem_total,
        "disk_total": disk_total,
        "power_usage": power,
        "gpu_usage": "N/A",
        "gpu_memory_used": "N/A",
        "gpu_memory_total": "N/A"
    })

############################################################
# Realtime Metrics
############################################################
def send_system_metrics():
    while True:
        socketio.emit("update_metrics", {
            "cpu_usage": psutil.cpu_percent(),
            "memory_usage": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent
        })
        time.sleep(5)

############################################################
# Chat with Groq
############################################################
@app.route('/chat', methods=['POST'])
def chat():
    msg = request.json.get("message", "")
    if not msg:
        return jsonify({"response": "Please provide a message."}), 400
    
    cpu = psutil.cpu_percent()
    mem = psutil.virtual_memory().percent

    # Try multiple Groq model names in order of preference (updated Dec 2024)
    # Using currently available models from Groq API
    models_to_try = [
        "llama-3.3-70b-versatile",      # Currently working model (Dec 2024)
        "llama-3.1-70b-versatile",      # Fallback option
        "llama-3.1-8b-instruct",        # Fallback option
        "llama-3-70b-8192",             # Fallback option
        "llama-3-8b-8192"               # Fallback option
    ]
    
    payload = {
        "messages": [
            {"role": "system", "content": "You are a cybersecurity SIEM assistant. Analyze logs and threats."},
            {"role": "user", "content": f"{msg}\nSystem: CPU={cpu}%, RAM={mem}%"}
        ],
        "temperature": 0.7,
        "max_tokens": 1024
    }

    last_error = None
    for model_name in models_to_try:
        try:
            payload["model"] = model_name
            r = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers=GROQ_HEADERS,
                json=payload,
                timeout=30
            )
            
            # Check if request was successful
            if r.status_code == 200:
                data = r.json()
                if "choices" in data and len(data["choices"]) > 0:
                    reply = data["choices"][0]["message"]["content"]
                    save_log(f"User: {msg} | AI: {reply}")
                    return jsonify({"response": reply})
                else:
                    last_error = "Invalid response format from Groq API"
                    continue
            elif r.status_code == 404:
                # Model not found, try next model
                last_error = f"Model {model_name} not found (404)"
                continue
            elif r.status_code == 401:
                # Authentication error - don't try other models
                error_data = r.json() if r.content else {}
                error_msg = error_data.get("error", {}).get("message", "Invalid API key")
                save_log(f"AI auth error: {error_msg}")
                return jsonify({"response": f"Authentication error: {error_msg}. Please check your Groq API key."})
            else:
                # Other error, try next model
                try:
                    error_data = r.json()
                    last_error = error_data.get("error", {}).get("message", f"HTTP {r.status_code}")
                except:
                    last_error = f"HTTP {r.status_code}"
                continue
                
        except requests.exceptions.Timeout:
            last_error = "Request timeout"
            continue
        except requests.exceptions.ConnectionError as e:
            last_error = f"Connection error: {str(e)}"
            continue
        except Exception as e:
            last_error = f"Error: {str(e)}"
            continue
    
    # If all models failed, return helpful error message
    if "Invalid API key" in str(last_error) or "401" in str(last_error):
        reply = "Authentication failed. Please check your Groq API key in app_groq.py"
    elif "404" in str(last_error):
        reply = "Groq API endpoint or models not found. The API may have changed. Please check Groq documentation."
    else:
        reply = f"Unable to connect to Groq API. Last error: {last_error}. Please check your internet connection and API key."
    
    save_log(f"User: {msg} | AI Error: {reply}")
    return jsonify({"response": reply})

############################################################
# API Endpoint: Get Alerts
############################################################
@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get latest alerts with optional limit"""
    limit = request.args.get('limit', default=100, type=int)
    
    with alerts_lock:
        # Get latest alerts from queue
        alerts_list = list(alerts_queue)[-limit:]
        alerts_list.reverse()  # Most recent first
    
    # Format for JSON response
    alerts_json = []
    for alert in alerts_list:
        alerts_json.append({
            "timestamp": alert.get("timestamp", ""),
            "source_ip": alert.get("source_ip", ""),
            "dest_ip": alert.get("dest_ip", ""),
            "attack_type": alert.get("attack_type", ""),
            "severity": alert.get("severity", ""),
            "confidence": alert.get("confidence", 0.0),
            "protocol": alert.get("protocol", ""),
            "packet_length": alert.get("packet_length", 0)
        })
    
    return jsonify({
        "alerts": alerts_json,
        "count": len(alerts_json),
        "total": len(alerts_queue)
    })

############################################################
# Intrusion Detection Test Endpoint
############################################################
@app.route('/test-alert', methods=['POST'])
def test_alert():
    """Test endpoint to trigger an intrusion alert"""
    test_alert_data = {
        "timestamp": datetime.datetime.now().isoformat(),
        "source_ip": "192.168.1.100",
        "dest_ip": "10.0.0.1",
        "attack_type": "DoS",
        "severity": "HIGH",
        "confidence": 95.5,
        "protocol": "TCP",
        "packet_length": 1500
    }
    add_alert(test_alert_data)
    socketio.emit("intrusion_alert", test_alert_data)
    return jsonify({"status": "Test alert sent", "alert": test_alert_data})

############################################################
# Test Groq API Connection
############################################################
@app.route('/test-groq', methods=['GET'])
def test_groq():
    """Test endpoint to check Groq API connection"""
    test_payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [
            {"role": "user", "content": "Say hello"}
        ],
        "max_tokens": 10
    }
    
    try:
        r = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers=GROQ_HEADERS,
            json=test_payload,
            timeout=10
        )
        
        return jsonify({
            "status_code": r.status_code,
            "response": r.text[:500],
            "headers_sent": {
                "Authorization": "Bearer " + GROQ_API_KEY[:10] + "...",
                "Content-Type": GROQ_HEADERS["Content-Type"]
            },
            "endpoint": "https://api.groq.com/openai/v1/chat/completions"
        })
    except Exception as e:
        return jsonify({
            "error": str(e),
            "endpoint": "https://api.groq.com/openai/v1/chat/completions"
        }), 500

############################################################
# Socket Events
############################################################
@socketio.on("connect")
def client_connect():
    print("Client connected")
    socketio.start_background_task(send_system_metrics)

############################################################
# Home Page
############################################################
@app.route('/')
def home():
    return render_template("index.html")

############################################################
# Start Server
############################################################
if __name__ == "__main__":
    # Start packet sniffing in background thread
    if ml_model and ml_scaler:
        interface = get_network_interface()
        try:
            sniff_thread = threading.Thread(
                target=packet_sniffer_thread,
                args=(interface,),
                daemon=True
            )
            sniff_thread.start()
            print("🔍 Packet capture thread started")
        except Exception as e:
            print(f"⚠️  Packet sniffing thread failed: {e}")
            print("   Note: Packet sniffing may require sudo privileges on macOS")
    else:
        print("⚠️  ML model not loaded. Packet sniffing disabled.")
        print("   Run 'python3 ml_model.py' to train the model first.")

    print("🚀 Server running at: http://127.0.0.1:5000")
    print("📊 Dashboard: http://127.0.0.1:5000")
    print("🔔 Alerts API: http://127.0.0.1:5000/api/alerts")

    socketio.run(
        app,
        host="127.0.0.1",     # Keep localhost for macOS
        port=5000,
        debug=False
    )
