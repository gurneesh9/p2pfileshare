Three steps: grant port 443 permission, create a systemd service, start it.

1. Move the binary and grant low-port permission

Port 443 requires root or a capability. setcap is cleaner than running as root:


sudo mv ~/p2pshare-relay /usr/local/bin/
sudo setcap CAP_NET_BIND_SERVICE=+eip /usr/local/bin/p2pshare-relay
2. Create a systemd service


sudo tee /etc/systemd/system/p2pshare-relay.service > /dev/null <<'EOF'
[Unit]
Description=p2pshare relay server
After=network.target

[Service]
ExecStart=/usr/local/bin/p2pshare-relay
Restart=always
RestartSec=5
Environment=RUST_LOG=info
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
3. Enable and start


sudo systemctl daemon-reload
sudo systemctl enable p2pshare-relay
sudo systemctl start p2pshare-relay
4. Verify it's up


sudo systemctl status p2pshare-relay
# Should show: Active: active (running)

sudo journalctl -u p2pshare-relay -f
# Should show: p2pshare relay listening on 0.0.0.0:443
Then from your Mac:


nc -zv 34.68.99.198 443
# Connection to 34.68.99.198 port 443 [tcp] succeeded!
That's it — the relay is live and will auto-restart on crash or reboot.