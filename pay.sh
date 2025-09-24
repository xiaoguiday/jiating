#!/bin/bash
set -e

# =============================
# 提示端口
# =============================
read -p "请输入 WSS 监听端口（默认80）: " WSS_PORT
WSS_PORT=${WSS_PORT:-80}

read -p "请输入 Stunnel4 端口（默认443）: " STUNNEL_PORT
STUNNEL_PORT=${STUNNEL_PORT:-443}

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
sudo tee /usr/local/bin/wss > /dev/null <<'EOF'
#!/usr/bin/python3
# -*- coding: utf-8 -*-

import socket, threading, select, sys, time

LISTENING_ADDR = '0.0.0.0'
LISTENING_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 80
PASS = ''
BUFLEN = 4096 * 4
HEARTBEAT_INTERVAL = 300  # 300秒心跳触发
HEARTBEAT_MAX_FAIL = 3    # 连续3次失败才断开
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
        self.running = False
        self.host = host
        self.port = port
        self.threads = []
        self.threadsLock = threading.Lock()
        self.logLock = threading.Lock()

    def run(self):
        self.soc = socket.socket(socket.AF_INET)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.settimeout(2)
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
                except socket.timeout:
                    continue
        finally:
            self.running = False
            self.soc.close()

    def printLog(self, log):
        with self.logLock:
            print(log)

    def addConn(self, conn):
        with self.threadsLock:
            if self.running:
                self.threads.append(conn)

    def removeConn(self, conn):
        with self.threadsLock:
            if conn in self.threads:
                self.threads.remove(conn)

    def close(self):
        self.running = False
        with self.threadsLock:
            for c in list(self.threads):
                c.close()


class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        super().__init__()
        self.clientClosed = False
        self.targetClosed = True
        self.client = socClient
        self.server = server
        self.addr = addr
        self.log = 'Connection: ' + str(addr)
        self.last_active = time.time()
        self.last_heartbeat = time.time()
        self.heartbeat_fail_count = 0
        self.target = None

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

            # === 第一段握手 ===
            first_payload = self.client.recv(BUFLEN)
            hostPort = self.findHeader(first_payload, 'X-Real-Host') or DEFAULT_HOST
            passwd = self.findHeader(first_payload, 'X-Pass')
            if PASS and passwd != PASS:
                self.client.send(b'HTTP/1.1 400 WrongPass!\r\n\r\n')
                return
            self.client.sendall(FIRST_RESPONSE.encode())

            # === 第二段握手 ===
            second_payload = self.client.recv(BUFLEN)
            if b'GET-RAY' not in second_payload:
                self.server.printLog(f'{self.log} - invalid second handshake')
                return
            self.client.sendall(SWITCH_RESPONSE.encode())

            # === 连接目标并开始数据转发 ===
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
        soc_family, soc_type, proto, _, address = socket.getaddrinfo(host, port)[0]
        self.target = socket.socket(soc_family, soc_type, proto)
        self.target.connect(address)
        self.targetClosed = False

    def method_CONNECT(self, hostPort):
        self.server.printLog(f'{self.log} - CONNECT {hostPort}')
        self.connect_target(hostPort)
        self.doCONNECT()

    def doCONNECT(self):
        socs = [self.client, self.target]

        while True:
            try:
                recv, _, err = select.select(socs, [], socs, 1)
            except:
                break
            if err:
                break

            now = time.time()

            # 心跳逻辑：300秒发一次空包
            if now - self.last_heartbeat >= HEARTBEAT_INTERVAL:
                try:
                    self.client.send(b'')
                    self.last_heartbeat = now
                    self.heartbeat_fail_count = 0
                except:
                    self.heartbeat_fail_count += 1
                    if self.heartbeat_fail_count >= HEARTBEAT_MAX_FAIL:
                        self.server.printLog(f'{self.log} - heartbeat failed {HEARTBEAT_MAX_FAIL} times, closing')
                        break

            for s in recv:
                try:
                    data = s.recv(BUFLEN)
                    if not data:
                        self.server.printLog(f'{self.log} - peer closed, closing')
                        return
                    self.last_active = now
                    if s is self.target:
                        self.client.sendall(data)
                    else:
                        total = data
                        while total:
                            sent = self.target.send(total)
                            total = total[sent:]
                except Exception:
                    self.server.printLog(f'{self.log} - forwarding error, closing')
                    return


def main():
    print("\n:-------PythonProxy WSS Multi-handshake + Heartbeat-------:\n")
    print(f"Listening addr: {LISTENING_ADDR}, port: {LISTENING_PORT}\n")
    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()
    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        print('Stopping...')
        server.close()


if __name__ == '__main__':
    main()

EOF

sudo chmod +x /usr/local/bin/wss
echo "WSS 脚本安装完成"
echo "----------------------------------"

# 创建 systemd 服务
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
echo "==== 安装 Stunnel4 ===="
sudo mkdir -p /etc/stunnel/certs
sudo openssl req -x509 -nodes -newkey rsa:2048 \
-keyout /etc/stunnel/certs/stunnel.key \
-out /etc/stunnel/certs/stunnel.crt \
-days 1095 \
-subj "/CN=example.com"
sudo sh -c 'cat /etc/stunnel/certs/stunnel.key /etc/stunnel/certs/stunnel.crt > /etc/stunnel/certs/stunnel.pem'
sudo chmod 644 /etc/stunnel/certs/*.crt
sudo chmod 644 /etc/stunnel/certs/*.pem

# Stunnel 配置
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
echo "Stunnel4 安装完成，端口 $STUNNEL_PORT"
echo "----------------------------------"

# =============================
# 安装 UDPGW
# =============================
echo "==== 安装 UDPGW ===="
if [ -d "/root/badvpn" ]; then
    echo "/root/badvpn 已存在，跳过克隆"
else
    git clone https://github.com/ambrop72/badvpn.git /root/badvpn
fi
mkdir -p /root/badvpn/badvpn-build
cd /root/badvpn/badvpn-build
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make -j$(nproc)

# 创建 systemd 服务（修正绑定地址为 127.0.0.1）
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
echo "UDPGW 已安装并启动，端口: $UDPGW_PORT"
echo "----------------------------------"

echo "所有组件安装完成!"
echo "查看 WSS 状态: sudo systemctl status wss"
echo "查看 Stunnel4 状态: sudo systemctl status stunnel4"
echo "查看 UDPGW 状态: sudo systemctl status udpgw"
