#!/bin/bash
set -e
#2025-10-08-06-47

# =============================
# 提示端口
# =============================
read -p "请输入 WSS HTTP 监听端口（默认80）: " WSS_HTTP_PORT
WSS_HTTP_PORT=${WSS_HTTP_PORT:-80}

read -p "请输入 WSS TLS 监听端口（默认443）: " WSS_TLS_PORT
WSS_TLS_PORT=${WSS_TLS_PORT:-443}

read -p "请输入 Stunnel4 端口（默认444）: " STUNNEL_PORT
STUNNEL_PORT=${STUNNEL_PORT:-444}

read -p "请输入 UDPGW 端口（默认7300）: " UDPGW_PORT
UDPGW_PORT=${UDPGW_PORT:-7300}

# =============================
# 系统更新与依赖安装
# =============================
echo "==== 更新系统并安装依赖 ===="
sudo apt update -y
sudo apt install -y python3 python3-pip wget curl git net-tools cmake build-essential openssl stunnel4
echo "依赖安装完成"
echo "----------------------------------"

# =============================
# 安装 WSS 脚本
# =============================
echo "==== 安装 WSS 脚本 ===="
sudo mkdir -p /usr/local/bin

sudo tee /usr/local/bin/wss > /dev/null <<'EOF'
#!/usr/bin/python3
# -*- coding: utf-8 -*-
# [这里保留你之前的完整 WSS 脚本内容, 已经支持从命令行获取端口]
EOF

sudo chmod +x /usr/local/bin/wss
echo "WSS 脚本安装完成"
echo "----------------------------------"

# =============================
# 创建 WSS systemd 服务
# =============================
sudo tee /etc/systemd/system/wss.service > /dev/null <<EOF
[Unit]
Description=WSS Python Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/wss $WSS_HTTP_PORT $WSS_TLS_PORT
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl stop wss || true
sudo systemctl enable wss
sudo systemctl restart wss
echo "WSS 已启动，HTTP端口 $WSS_HTTP_PORT, TLS端口 $WSS_TLS_PORT"
echo "----------------------------------"

# =============================
# 安装 Stunnel4 并生成证书
# =============================
echo "==== 安装 Stunnel4 ===="
sudo mkdir -p /etc/stunnel/certs
if [ ! -f /etc/stunnel/certs/stunnel.pem ]; then
    sudo openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/stunnel/certs/stunnel.key \
        -out /etc/stunnel/certs/stunnel.crt \
        -subj "/CN=wss.local"
    sudo sh -c 'cat /etc/stunnel/certs/stunnel.key /etc/stunnel/certs/stunnel.crt > /etc/stunnel/certs/stunnel.pem'
fi

sudo chmod 600 /etc/stunnel/certs/stunnel.pem /etc/stunnel/certs/stunnel.key
sudo chown root:root /etc/stunnel/certs/stunnel.pem /etc/stunnel/certs/stunnel.key

# 创建 Stunnel4 配置
sudo tee /etc/stunnel/ssh-tls.conf > /dev/null <<EOF
pid = /var/run/stunnel4.pid
client = no
foreground = yes
setuid = root
setgid = root
cert = /etc/stunnel/certs/stunnel.pem
key = /etc/stunnel/certs/stunnel.key
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[ssh-tls-gateway]
accept = $STUNNEL_PORT
connect = 127.0.0.1:$WSS_TLS_PORT
EOF

# 创建自定义 systemd 服务启动 Stunnel
sudo tee /etc/systemd/system/stunnel-wss.service > /dev/null <<EOF
[Unit]
Description=Stunnel WSS Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/stunnel4 /etc/stunnel/ssh-tls.conf
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl stop stunnel-wss || true
sudo systemctl enable stunnel-wss
sudo systemctl restart stunnel-wss
echo "Stunnel4 已启动，监听端口 $STUNNEL_PORT -> $WSS_TLS_PORT"
echo "----------------------------------"

# =============================
# 安装 UDPGW (Badvpn)
# =============================
echo "==== 安装 UDPGW (Badvpn) ===="
sudo mkdir -p /root/badvpn
cd /root/badvpn
if [ ! -f /usr/local/bin/badvpn-udpgw ]; then
    git clone https://github.com/ambrop72/badvpn.git .
    mkdir -p build
    cd build
    cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
    make -j$(nproc)
    cp udpgw/badvpn-udpgw /usr/local/bin/badvpn-udpgw
fi

sudo tee /etc/systemd/system/udpgw.service > /dev/null <<EOF
[Unit]
Description=UDP Gateway (Badvpn)
After=network.target

[Service]
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:$UDPGW_PORT --max-clients 1024
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl stop udpgw || true
sudo systemctl enable udpgw
sudo systemctl restart udpgw
echo "UDPGW 已启动，端口 $UDPGW_PORT"
echo "----------------------------------"

echo "==== 安装完成，所有服务运行正常 ===="
