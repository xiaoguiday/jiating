#!/bin/bash
set -e

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
sudo tee /usr/local/bin/wss > /dev/null <<'EOF'
#!/usr/bin/python3
# -*- coding: utf-8 -*-

import asyncio
import socket
import ssl
import re
import time

# ================= 配置 =================
LISTEN_ADDR = '0.0.0.0'
HTTP_PORT = 80
TLS_PORT = 443
DEFAULT_TARGET = ('127.0.0.1', 22)  # 转发目标
BUFFER_SIZE = 65536
TIMEOUT = 300
CERT_FILE = '/etc/stunnel/certs/stunnel.pem'
KEY_FILE = '/etc/stunnel/certs/stunnel.key'
HEARTBEAT_INTERVAL = 5  # 秒
PASS = ''  # 如需要密码，可填

# 响应内容
FIRST_RESPONSE = b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK'
SWITCH_RESPONSE = b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n'
FORBIDDEN_RESPONSE = b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n'

# 活动连接管理
ACTIVE_CONNS = {}

# ---------------- TCP 优化 ----------------
def set_socket_options(writer: asyncio.StreamWriter):
    sock = writer.get_extra_info('socket')
    if sock:
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        except Exception:
            pass

# ---------------- 读取 HTTP Header ----------------
async def read_until_headers(reader: asyncio.StreamReader, initial_chunk: bytes = b''):
    data = bytearray(initial_chunk)
    while True:
        if b'\r\n\r\n' in data:
            headers, rest = data.split(b'\r\n\r\n', 1)
            return bytes(headers), bytes(rest)
        chunk = await reader.read(4096)
        if not chunk:
            return bytes(data), b''
        data.extend(chunk)
        if len(data) > 64 * 1024:
            return bytes(data), b''

# ---------------- 双向转发 ----------------
async def pipe(src_reader: asyncio.StreamReader, dst_writer: asyncio.StreamWriter, conn_id):
    try:
        while True:
            buf = await src_reader.read(BUFFER_SIZE)
            if not buf:
                break
            dst_writer.write(buf)
            await dst_writer.drain()
            ACTIVE_CONNS[conn_id]['last_active'] = time.time()
    except Exception:
        pass
    finally:
        try:
            dst_writer.close()
            await dst_writer.wait_closed()
        except Exception:
            pass

# ---------------- 处理客户端 ----------------
async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, tls=False):
    peer = writer.get_extra_info('peername')
    conn_id = f"{peer}-{time.time()}"
    ACTIVE_CONNS[conn_id] = {'writer': writer, 'last_active': time.time()}
    set_socket_options(writer)
    print(f"[+] Connection from {peer} {'(TLS)' if tls else ''}")

    try:
        while True:  # 循环处理多次 payload
            first_chunk = await reader.read(4096)
            if not first_chunk:
                break

            headers_bytes, rest = await read_until_headers(reader, first_chunk)
            headers_text = headers_bytes.decode(errors='ignore')

            # 解析 X-Real-Host、X-Pass、User-Agent
            host_header = ''
            passwd_header = ''
            for line in headers_text.split('\r\n'):
                if line.lower().startswith('x-real-host:'):
                    host_header = line.split(':', 1)[1].strip()
                if line.lower().startswith('x-pass:'):
                    passwd_header = line.split(':', 1)[1].strip()

            if PASS and passwd_header != PASS:
                writer.write(b'HTTP/1.1 400 WrongPass!\r\n\r\n')
                await writer.drain()
                break

            ua_match = re.search(r'User-Agent:\s*(.+)', headers_text, re.IGNORECASE)
            ua_value = ua_match.group(1).strip() if ua_match else ""

            # ---------------- 处理 UA ----------------
            if "26.4.0" in ua_value:
                # 建立双向转发
                writer.write(SWITCH_RESPONSE)
                await writer.drain()

                # 解析目标
                if host_header:
                    if ':' in host_header:
                        host, port = host_header.split(':', 1)
                        target = (host.strip(), int(port.strip()))
                    else:
                        target = (host_header.strip(), 22)
                else:
                    target = DEFAULT_TARGET

                # 连接目标
                try:
                    target_reader, target_writer = await asyncio.open_connection(*target)
                    set_socket_options(target_writer)
                except Exception as e:
                    print(f"[!] Failed to connect target {target}: {e}")
                    writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    await writer.drain()
                    break

                # 如果有剩余数据，先发给目标
                if rest:
                    target_writer.write(rest)
                    await target_writer.drain()

                # 双向转发
                t1 = asyncio.create_task(pipe(reader, target_writer, conn_id))
                t2 = asyncio.create_task(pipe(target_reader, writer, conn_id))
                done, pending = await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
                for p in pending:
                    p.cancel()
                    try:
                        await p
                    except:
                        pass
                break  # 转发后退出循环，连接交给 pipe 管理

            elif "1.0" in ua_value:
                # 返回 200 OK，保持连接，等待下一个 payload
                writer.write(FIRST_RESPONSE)
                await writer.drain()
                # 如果有剩余数据，丢弃即可
                continue
            else:
                writer.write(FORBIDDEN_RESPONSE)
                await writer.drain()
                break

    except Exception as e:
        print(f"[!] Connection error {peer}: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except:
            pass
        ACTIVE_CONNS.pop(conn_id, None)
        print(f"[-] Connection {peer} closed")

# ---------------- 心跳机制 ----------------
async def heartbeat():
    while True:
        await asyncio.sleep(HEARTBEAT_INTERVAL)
        now = time.time()
        for conn_id, info in list(ACTIVE_CONNS.items()):
            writer = info['writer']
            last = info['last_active']
            if now - last >= HEARTBEAT_INTERVAL:
                try:
                    writer.write(b'')
                    await writer.drain()
                except:
                    ACTIVE_CONNS.pop(conn_id, None)

# ---------------- 启动服务 ----------------
async def main():
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(CERT_FILE, KEY_FILE)

    tls_server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, tls=True),
        LISTEN_ADDR,
        TLS_PORT,
        ssl=ssl_ctx
    )

    http_server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, tls=False),
        LISTEN_ADDR,
        HTTP_PORT
    )

    print(f"[+] Listening on {LISTEN_ADDR}:{HTTP_PORT} (HTTP payload)")
    print(f"[+] Listening on {LISTEN_ADDR}:{TLS_PORT} (TLS)")

    async with tls_server, http_server:
        await asyncio.gather(
            tls_server.serve_forever(),
            http_server.serve_forever(),
            heartbeat()
        )


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped manually.")
    except Exception as e:
        print(f"[!] Fatal error: {e}")

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
sudo systemctl enable wss
sudo systemctl start wss
echo "WSS 已启动，HTTP端口 $WSS_HTTP_PORT, TLS端口 $WSS_TLS_PORT"
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
