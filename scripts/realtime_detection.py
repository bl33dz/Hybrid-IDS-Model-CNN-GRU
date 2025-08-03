import json
import time
import tensorflow as tf
import numpy as np
import csv
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from urllib.parse import unquote

model = tf.keras.models.load_model("../models/cnn_gru_model.keras")

import pickle
with open("../models/tokenizer.pkl", "rb") as f:
    tokenizer = pickle.load(f)

MAX_LEN = 64
output_csv = '../data/results.csv'

def preprocess(text):
    tokens = text.lower()
    seq = tokenizer.texts_to_sequences([tokens])
    padded = pad_sequences(seq, maxlen=MAX_LEN, padding='post')
    return padded

def classify(text):
    x = preprocess(text)
    pred = model.predict(x)[0][0]
    label = "ATTACK" if pred > 0.7 else "BENIGN"
    return label, float(pred)

class EveHandler(FileSystemEventHandler):
    def __init__(self, file_path):
        self.file_path = file_path
        self._file = open(file_path, "r")
        self._file.seek(0, 2)

    def on_modified(self, event):
        if event.src_path != self.file_path:
            return
        for line in self._file:
            try:
                data = json.loads(line)
                if data.get("event_type") == "http":
                    http = data.get("http", {})
                    url = http.get("url", "")
                    query = url.strip()
    
                    label, score = classify(unquote(query))
    
                    with open(output_csv, mode='a', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow([
                            query,
                            label,
                            f"{score:.2f}"
                        ])
    
                    print(f"[{label}] {query} ({score:.2f})")
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

