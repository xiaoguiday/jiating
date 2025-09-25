#!/bin/bash
set -e

# =============================
# 用户端口输入
# =============================
read -p "请输入 WSS 监听端口（默认8080）: " WSS_PORT
WSS_PORT=${WSS_PORT:-8080}

read -p "请输入 Stunnel4 端口（默认444）: " STUNNEL_PORT
STUNNEL_PORT=${STUNNEL_PORT:-444}

read -p "请输入 UDPGW 端口（默认7300）: " UDPGW_PORT
UDPGW_PORT=${UDPGW_PORT:-7300}

read -p "请输入 Nginx 域名（如 example.com）: " DOMAIN
DOMAIN=${DOMAIN:-example.com}

# =============================
# 系统更新与依赖
# =============================
echo "==== 更新系统并安装依赖 ===="
sudo apt update -y
sudo apt install -y python3 python3-pip wget curl git net-tools cmake build-essential openssl stunnel4 nginx
echo "依赖安装完成"
echo "----------------------------------"

# =============================
# 安装 WSS 脚本
# =============================
echo "==== 安装 WSS 脚本 ===="
sudo tee /usr/local/bin/wss > /dev/null <<'EOF'
#!/usr/bin/python3
# -*- coding: utf-8 -*-

import socket, threading, select, sys, time

LISTENING_ADDR = '0.0.0.0'
LISTENING_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
PASS = ''
BUFLEN = 4096 * 4
HEARTBEAT_INTERVAL = 300
HEARTBEAT_MAX_FAIL = 3
DEFAULT_HOST = '127.0.0.1:22'

FIRST_RESPONSE = (
    "HTTP/1.1 302 Found\r\n"
    "Location: /\r\n"
    "Content-Length: 0\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
)

SWITCH_RESPONSE = (
    "HTTP/1.1 101 Switching Protocols\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "\r\n"
)

class Server(threading.Thread):
    def __init__(self, host, port):
        super().__init__()
        self.host = host
        self.port = port
        self.running = False
        self.threads = []
        self.lock = threading.Lock()

    def run(self):
        self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.bind((self.host, self.port))
        self.soc.listen(5)
        self.running = True
        try:
            while self.running:
                try:
                    c, addr = self.soc.accept()
                    c.setblocking(1)
                    conn = ConnectionHandler(c, self, addr)
                    conn.start()
                    self.addConn(conn)
                except Exception:
                    continue
        finally:
            self.soc.close()
            self.running = False

    def addConn(self, conn):
        with self.lock:
            self.threads.append(conn)

    def removeConn(self, conn):
        with self.lock:
            if conn in self.threads:
                self.threads.remove(conn)

    def printLog(self, msg):
        with self.lock:
            print(msg)

class ConnectionHandler(threading.Thread):
    def __init__(self, client, server, addr):
        super().__init__()
        self.client = client
        self.server = server
        self.addr = addr
        self.clientClosed = False
        self.targetClosed = True
        self.target = None
        self.last_heartbeat = time.time()
        self.heartbeat_fail = 0
        self.log = f'Connection {addr}'

    def close(self):
        for sock in [self.client, self.target]:
            if sock:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                    sock.close()
                except:
                    pass
        self.clientClosed = True
        self.targetClosed = True

    def run(self):
        try:
            self.server.printLog(self.log)
            first_payload = self.client.recv(BUFLEN)
            hostPort = self.findHeader(first_payload, 'X-Real-Host') or DEFAULT_HOST
            passwd = self.findHeader(first_payload, 'X-Pass')
            if PASS and passwd != PASS:
                self.client.send(b'HTTP/1.1 400 WrongPass\r\n\r\n')
                return
            self.client.sendall(FIRST_RESPONSE.encode())

            while True:
                payload = self.client.recv(BUFLEN)
                if not payload:
                    return
                if b'GET-RAY' in payload:
                    self.client.sendall(SWITCH_RESPONSE.encode())
                    break

            self.method_CONNECT(hostPort)
        except Exception as e:
            self.server.printLog(f'{self.log} - error: {e}')
        finally:
            self.close()
            self.server.removeConn(self)

    def findHeader(self, head, header):
        if isinstance(head, bytes):
            head = head.decode(errors='ignore')
        idx = head.find(header + ': ')
        if idx == -1:
            return ''
        idx2 = head.find('\r\n', idx)
        if idx2 == -1:
            return ''
        return head[idx+len(header)+2:idx2].strip()

    def connect_target(self, host):
        if ':' in host:
            h, p = host.split(':')
            port = int(p)
            host = h
        else:
            port = 22
        self.target = socket.create_connection((host, port))
        self.targetClosed = False

    def method_CONNECT(self, hostPort):
        self.server.printLog(f'{self.log} - CONNECT {hostPort}')
        self.connect_target(hostPort)
        self.forward_loop()

    def forward_loop(self):
        socs = [self.client, self.target]
        while True:
            try:
                recv, _, err = select.select(socs, [], socs, 1)
            except:
                break
            if err:
                break
            now = time.time()
            if now - self.last_heartbeat >= HEARTBEAT_INTERVAL:
                try:
                    self.client.send(b'')
                    self.last_heartbeat = now
                    self.heartbeat_fail = 0
                except:
                    self.heartbeat_fail += 1
                    if self.heartbeat_fail >= HEARTBEAT_MAX_FAIL:
                        self.server.printLog(f'{self.log} - heartbeat failed, closing')
                        break
            for s in recv:
                try:
                    data = s.recv(BUFLEN)
                    if not data:
                        return
                    if s is self.target:
                        self.client.sendall(data)
                    else:
                        total = data
                        while total:
                            sent = self.target.send(total)
                            total = total[sent:]
                except:
                    return

def main():
    print(f"WSS Python Proxy listening on {LISTENING_ADDR}:{LISTENING_PORT}")
    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()
    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        server.close()

if __name__ == '__main__':
    main()
EOF

sudo chmod +x /usr/local/bin/wss

# =============================
# 创建 WSS systemd 服务
# =============================
sudo tee /etc/systemd/system/wss.service > /dev/null <<EOF
[Unit]
Description=WSS Python Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/wss $WSS_PORT
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable wss
sudo systemctl start wss
echo "WSS 已启动，端口 $WSS_PORT"
echo "----------------------------------"

# =============================
# 安装 Stunnel4 并生成证书
# =============================
sudo mkdir -p /etc/stunnel/certs
sudo openssl req -x509 -nodes -newkey rsa:2048 \
-keyout /etc/stunnel/certs/stunnel.key \
-out /etc/stunnel/certs/stunnel.crt \
-days 1095 \
-subj "/CN=$DOMAIN"

sudo sh -c 'cat /etc/stunnel/certs/stunnel.key /etc/stunnel/certs/stunnel.crt > /etc/stunnel/certs/stunnel.pem'
sudo chmod 644 /etc/stunnel/certs/*.crt
sudo chmod 644 /etc/stunnel/certs/*.pem

sudo tee /etc/stunnel/ssh-tls.conf > /dev/null <<EOF
pid=/var/run/stunnel.pid
setuid=root
setgid=root
client = no
debug = 5
output = /var/log/stunnel4/stunnel.log
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[ssh-tls-gateway]
accept = 0.0.0.0:$STUNNEL_PORT
cert = /etc/stunnel/certs/stunnel.pem
key = /etc/stunnel/certs/stunnel.pem
connect = 127.0.0.1:22
EOF

sudo systemctl enable stunnel4
sudo systemctl restart stunnel4
echo "Stunnel4 已启动，端口 $STUNNEL_PORT"
echo "----------------------------------"

# =============================
# 安装 UDPGW
# =============================
if [ ! -d "/root/badvpn" ]; then
    git clone https://github.com/ambrop72/badvpn.git /root/badvpn
fi
mkdir -p /root/badvpn/badvpn-build
cd /root/badvpn/badvpn-build
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make -j$(nproc)

sudo tee /etc/systemd/system/udpgw.service > /dev/null <<EOF
[Unit]
Description=UDP Gateway (Badvpn)
After=network.target

[Service]
Type=simple
ExecStart=/root/badvpn/badvpn-build/udpgw/badvpn-udpgw --listen-addr 127.0.0.1:$UDPGW_PORT --max-clients 1024 --max-connections-for-client 10
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable udpgw
sudo systemctl start udpgw
echo "UDPGW 已启动，端口 $UDPGW_PORT"
echo "----------------------------------"

# =============================
# 配置 Nginx
# =============================
sudo tee /etc/nginx/sites-available/$DOMAIN > /dev/null <<EOF
server {
    listen 80;
    server_name $DOMAIN;

    location / {
        proxy_pass http://127.0.0.1:$WSS_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}

server {
    listen 443 ssl;
    server_name $DOMAIN;

    ssl_certificate /etc/stunnel/certs/stunnel.crt;
    ssl_certificate_key /etc/stunnel/certs/stunnel.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://127.0.0.1:$STUNNEL_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF

sudo ln -sf /etc/nginx/sites-available/$DOMAIN /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
echo "Nginx 已配置完成，80转发WSS($WSS_PORT)，443转发Stunnel4($STUNNEL_PORT)"
echo "----------------------------------"

echo "部署完成！"
echo "查看 WSS 状态: sudo systemctl status wss"
echo "查看 Stunnel4 状态: sudo systemctl status stunnel4"
echo "查看 UDPGW 状态: sudo systemctl status udpgw"
