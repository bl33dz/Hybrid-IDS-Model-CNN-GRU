import json
import time
import tensorflow as tf
import numpy as np
import csv
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from tensorflow.keras.preprocessing.sequence import pad_sequences
from urllib.parse import unquote
import pickle

model = tf.keras.models.load_model("../models/cnn_gru_model.keras")

with open("../models/tokenizer.pkl", "rb") as f:
    tokenizer = pickle.load(f)

MAX_LEN = 64
output_csv = '../data/results.csv'
alerted_flows = {}
flow_last_http = {}
ALERT_EXPIRY = 300
seen_entries = set()

TOTAL_SURICATA_ALERT = 0
TOTAL_MACHINE_ALERT = 0
TOTAL_BENIGN = 0

def preprocess(text):
    tokens = text.lower()
    seq = tokenizer.texts_to_sequences([tokens])
    padded = pad_sequences(seq, maxlen=MAX_LEN, padding='post')
    return padded

def classify(text):
    x = preprocess(text)
    pred = model.predict(x, verbose=0)[0][0]
    label = "ATTACK" if pred > 0.7 else "BENIGN"
    return label, float(pred)

def cleanup_expired():
    now = time.time()
    expired = [fid for fid, ts in alerted_flows.items() if now - ts > ALERT_EXPIRY]
    for fid in expired:
        alerted_flows.pop(fid, None)
        flow_last_http.pop(fid, None)

class EveHandler(FileSystemEventHandler):
    def __init__(self, file_path):
        self.file_path = file_path
        self._file = open(file_path, "r")
        self._file.seek(0, 2)

    def on_modified(self, event):
        global TOTAL_BENIGN
        global TOTAL_SURICATA_ALERT
        global TOTAL_MACHINE_ALERT


        if event.src_path != self.file_path:
            return
        cleanup_expired()
        for line in self._file:
            try:
                data = json.loads(line)
                etype = data.get("event_type")

                if etype == "http":
                    flow_id = data.get("flow_id")
                    tx_id = data.get("tx_id")
                    http_data = data.get("http", {})
                    url = http_data.get("url", "").strip()
                    if url and flow_id not in alerted_flows and (flow_id, tx_id, url) not in seen_entries:
                        seen_entries.add((flow_id, tx_id, url))
                        label, score = classify(unquote(url))
                        if label == "ATTACK":
                            TOTAL_MACHINE_ALERT += 1
                        else:
                            TOTAL_BENIGN += 1
                        with open(output_csv, mode='a', newline='') as f:
                            writer = csv.writer(f)
                            writer.writerow([url, label, f"{score:.2f}"])
                        print(f"[{label}] {url} ({score:.2f})")

                elif etype == "alert":
                    flow_id = data.get("flow_id")
                    tx_id = data.get("tx_id")
                    http_data = data.get("http", {})
                    url = http_data.get("url", "").strip()
                    if url and (flow_id, tx_id, url) not in seen_entries:
                        seen_entries.add((flow_id, tx_id, url))
                        alerted_flows[flow_id] = time.time()
                        with open(output_csv, mode='a', newline='') as f:
                            writer = csv.writer(f)
                            writer.writerow([url, "ATTACK", "1.00"])
                        print(f"[ATTACK] {url} (1.00)")
                        TOTAL_SURICATA_ALERT += 1

                print(f"BENIGN: {TOTAL_BENIGN}")
                print(f"SURICATA: {TOTAL_SURICATA_ALERT}")
                print(f"MACHINE: {TOTAL_MACHINE_ALERT}")

            except Exception as e:
                print("Error parsing line:", e)

path_to_eve = "/var/log/suricata/eve.json"
observer = Observer()
event_handler = EveHandler(path_to_eve)
observer.schedule(event_handler, path=path_to_eve, recursive=False)
observer.start()

print(f"Monitoring Suricata HTTP logs from {path_to_eve}...")
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    observer.stop()
observer.join()
