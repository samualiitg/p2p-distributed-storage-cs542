#!/usr/bin/env bash
sudo apt update
sudo apt install -y python3 python3-pip fuse
python3 -m pip install --user cryptography fusepy
nohup python3 src/c.py > client_log.log 2>&1 &
echo "Client installed and running in background (logs -> client_log.log)"
