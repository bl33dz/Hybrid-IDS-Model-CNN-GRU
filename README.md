# Hybrid IDS: Suricata + CNN-GRU

A hybrid Intrusion Detection System (IDS) that combines Suricata network monitoring with a CNN-GRU deep learning model for real-time SQL injection detection.

## Overview

This project implements a two-stage intrusion detection system:
1. **Suricata**: Network traffic monitoring and initial filtering
2. **CNN-GRU Model**: Deep learning-based SQL injection detection using Convolutional Neural Networks and Gated Recurrent Units

The system monitors HTTP traffic in real-time and classifies requests as either benign or malicious SQL injection attempts.

## Project Structure

```
├── data/                          # Dataset files
│   ├── Train_augmented.csv       # Training data
│   ├── Validation_augmented.csv  # Validation data
│   ├── Test_augmented.csv        # Test data
│   ├── benign_uri_100.csv        # Sample benign URIs
│   └── sqlmap_uri_100.csv        # Sample malicious URIs
├── models/                        # Trained models
│   ├── cnn_gru_model.keras       # Trained CNN-GRU model
│   └── tokenizer.pkl             # Text tokenizer
├── scripts/                       # Python scripts
│   ├── sqli-detect-cnn-gru.ipynb # Model training notebook
│   ├── realtime_detection.py     # Real-time detection script
│   └── simulate_attack.py        # Attack simulation script
└── README.md
```

## Prerequisites

### System Requirements
- Python 3.11
- Suricata IDS
- Docker (for web application container)

### Python Dependencies
```bash
pip install tensorflow pandas numpy scikit-learn matplotlib seaborn requests watchdog
```

### Suricata Installation
```bash
# Ubuntu/Debian
sudo apt-get install suricata

# CentOS/RHEL
sudo yum install suricata

# Arch Linux
sudo pacman -S suricata
```

## Setup Instructions

### 1. Model Building

The CNN-GRU model is built using the Jupyter notebook:

```bash
cd scripts
jupyter notebook sqli-detect-cnn-gru.ipynb
```

The notebook includes:
- Data preprocessing and augmentation
- CNN-GRU model architecture
- Model training and validation
- Performance evaluation
- Model and tokenizer saving

### 2. Web Application Setup

For attack simulation, you need a web application that can handle HTTP requests. You can use any web server or container:

```bash
# Example: Using a simple Python HTTP server
python -m http.server 8080

# Or using Docker with a web application
docker run -d -p 8080:80 nginx
```

### 3. Suricata Configuration

Ensure Suricata is configured to monitor the appropriate network interface:

```bash
# Check available interfaces
ip addr show

# Configure Suricata to monitor your interface
sudo suricata -i docker0 -c /etc/suricata/suricata.yaml
```

## Usage

### Real-time Detection

1. **Start Suricata monitoring**:
```bash
sudo suricata -i docker0 -c /etc/suricata/suricata.yaml
```

2. **Run the real-time detection script**:
```bash
cd scripts
python realtime_detection.py
```

The script will:
- Monitor Suricata's eve.json log file
- Process HTTP requests in real-time
- Classify requests using the CNN-GRU model
- Output results to `results.csv`

### Attack Simulation

To test the system with simulated attacks:

1. **Start your web application** (e.g., on port 8080)

2. **Run the attack simulation**:
```bash
cd scripts
python simulate_attack.py
```

The simulation script will:
- Send both benign and malicious requests to your web application
- Use data from `data/benign_uri_100.csv` and `data/sqlmap_uri_100.csv`
- Send requests with a 1-second delay between each request

## Model Architecture

The CNN-GRU model combines:
- **Embedding Layer**: Converts text tokens to dense vectors
- **Convolutional Layers**: Extract local features from the text
- **MaxPooling**: Reduces dimensionality
- **GRU Layer**: Captures sequential dependencies
- **Dense Layer**: Final classification


## Monitoring and Logs

- **Suricata logs**: `/var/log/suricata/`
- **Detection results**: `data/results.csv`
- **Model predictions**: Real-time console output