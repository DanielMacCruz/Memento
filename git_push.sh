#!/bin/bash
# Update GitHub with latest changes for Base Station and Field Laptop features

echo "[*] Adding all files..."
git add .

echo "[*] Committing changes..."
git commit -m "Implement Dual-Server Architecture (Base Station + Field Laptop)"

echo "[*] Pushing to origin..."
git push

echo "[+] Done!"
