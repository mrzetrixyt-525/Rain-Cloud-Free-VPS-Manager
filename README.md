git clone https://github.com/mrzetrixyt-525/Rain-Cloud-Free-VPS-Manager

cp -r Rain-Cloud-Free-VPS-Manager vms

rm -r Rain-Cloud-Free-VPS-Manager

cd vms

apt install python3-pip -y

mkdir -p ~/.config/pip && echo -e "[global]\nbreak-system-packages = true" > ~/.config/pip/pip.conf

pip install -r requirements.txt

bash scripts/run-forever.sh

python3 vm.py

sudo nano /etc/systemd/system/rgbot.service
``
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
``
sudo systemctl daemon-reload
sudo systemctl restart unixbot
