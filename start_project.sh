#!/bin/bash

echo "[*] Starting Metasploit with msgrpc..."

# Démarrage de Metasploit en arrière-plan (sans gnome-terminal)
msfconsole -q -x "load msgrpc ServerHost=127.0.0.1 Pass=msf" > /dev/null 2>&1 &

# Attendre quelques secondes que le service démarre
sleep 6

# Vérification si le port RPC est ouvert
if ss -lnt | grep -q 55552; then
    echo "[✔] msgrpc is RUNNING on 127.0.0.1:55552"
else
    echo "[✖] msgrpc FAILED to start"
    echo "[!] Please check Metasploit installation"
    exit 1
fi

echo "[*] Activating Python virtual environment..."
source venv/bin/activate

echo "[*] Installing Python dependencies..."
pip install -r requirements.txt >/dev/null 2>&1

echo "[*] Starting Flask application..."
python3 apppp.py

