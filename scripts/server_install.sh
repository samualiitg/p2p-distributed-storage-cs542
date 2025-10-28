#!/usr/bin/env bash
sudo apt update
sudo apt install -y python3 python3-pip
python3 -m pip install --user cryptography
sudo ufw allow 4444/udp
nohup python3 src/s.py > server_log.log 2>&1 &
echo "Server installed and running in background (logs -> server_log.log)"
