git clone https://github.com/mrzetrixyt-525/Rain-Cloud-Free-VPS-Manager

cd vms

cp Rain-Cloud-Free-VPS-Manager vms


apt install python3-pip -y

mkdir -p ~/.config/pip && echo -e "[global]\nbreak-system-packages = true" > ~/.config/pip/pip.conf

pip install -r requirements.txt

bash scripts/run-forever.sh

sudo nano /etc/systemd/system/rgbot.service

[Unit]
Description=rgBot Discord Bot
After=network.target

[Service]
User=root
WorkingDirectory=/root
ExecStart=/usr/bin/python3 /root/vm.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target

sudo systemctl daemon-reload
sudo systemctl restart unixbot
