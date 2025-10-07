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
apt update -y
apt install -y python3 python3-pip wget curl git net-tools cmake build-essential openssl stunnel4
echo "依赖安装完成"
echo "----------------------------------"

# 安装 uvloop（WSS 脚本依赖）
echo "==== 安装 WSS Python 依赖（uvloop） ===="
pip3 install --upgrade pip
pip3 install uvloop
echo "uvloop 安装完成"
echo "----------------------------------"

# =============================
# 安装 WSS 脚本
# =============================
echo "==== 安装 WSS 脚本 ===="
cat > /usr/local/bin/wss <<'PYEOF'
#!/usr/bin/python3
# -*- coding: utf-8 -*-

import asyncio
import socket
import ssl
import re
import time
import sys

# --- uvloop 加速（若已安装） ---
try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    print("[*] uvloop enabled")
except Exception:
    print("[*] uvloop not available, using default asyncio loop")

# ================= 配置 =================
LISTEN_ADDR = '0.0.0.0'
DEFAULT_TARGET = ('127.0.0.1', 22)
BUFFER_SIZE = 64 * 1024
TIMEOUT = 300
IDLE_TIMEOUT = 60
WRITE_BACKPRESSURE = 512 * 1024
CERT_FILE = '/etc/stunnel/certs/stunnel.pem'
KEY_FILE = '/etc/stunnel/certs/stunnel.key'
PASS = ''
HEARTBEAT_INTERVAL = 5  # 秒

FIRST_RESPONSE = b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK'
SWITCH_RESPONSE = b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n'
FORBIDDEN_RESPONSE = b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n'

ACTIVE_CONNS = {}

# ---------------- TCP 优化 ----------------
def set_socket_options(writer: asyncio.StreamWriter):
    sock = writer.get_extra_info('socket')
    if sock:
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            for opt in ('TCP_KEEPIDLE', 'TCP_KEEPINTVL', 'TCP_KEEPCNT'):
                if hasattr(socket, opt):
                    try:
                        sock.setsockopt(socket.IPPROTO_TCP, getattr(socket, opt), 30)
                    except:
                        pass
        except Exception:
            pass

# ---------------- HTTP Header ----------------
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
        if len(data) > 128 * 1024:
            return bytes(data), b''

# ---------------- 双向转发 ----------------
async def pipe(src_reader: asyncio.StreamReader, dst_writer: asyncio.StreamWriter, conn_key: str):
    try:
        while True:
            chunk = await src_reader.read(BUFFER_SIZE)
            if not chunk:
                break
            try:
                dst_writer.write(chunk)
            except:
                break
            transport = getattr(dst_writer, 'transport', None)
            try:
                if transport and transport.get_write_buffer_size() > WRITE_BACKPRESSURE:
                    await dst_writer.drain()
            except:
                break
            if conn_key in ACTIVE_CONNS:
                ACTIVE_CONNS[conn_key]['last_active'] = time.time()
    except asyncio.CancelledError:
        pass
    except Exception:
        pass
    finally:
        try:
            dst_writer.close()
            await dst_writer.wait_closed()
        except:
            pass

# ---------------- 处理客户端 ----------------
async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, tls=False):
    peer = writer.get_extra_info('peername')
    conn_key = f"{peer}-{time.time()}"
    ACTIVE_CONNS[conn_key] = {'writer': writer, 'last_active': time.time()}
    set_socket_options(writer)
    print(f"[+] Connection from {peer} {'(TLS)' if tls else ''}")

    forwarding_started = False
    target_reader = target_writer = None
    pipe_tasks = []

    try:
        while True:  # 循环支持多次 payload
            initial = await asyncio.wait_for(reader.read(64 * 1024), timeout=TIMEOUT)
            if not initial:
                break

            headers_bytes, rest = await read_until_headers(reader, initial)
            headers_text = headers_bytes.decode(errors='ignore')

            host_header = ''
            passwd_header = ''
            for line in headers_text.split('\r\n'):
                l = line.strip()
                if not l:
                    continue
                if l.lower().startswith('x-real-host:'):
                    host_header = l.split(':', 1)[1].strip()
                elif l.lower().startswith('x-pass:'):
                    passwd_header = l.split(':', 1)[1].strip()

            if PASS and passwd_header != PASS:
                try:
                    writer.write(b'HTTP/1.1 400 WrongPass!\r\n\r\n')
                    await writer.drain()
                except:
                    pass
                return

            ua_match = re.search(r'User-Agent:\s*(.+)', headers_text, re.IGNORECASE)
            ua_value = ua_match.group(1).strip() if ua_match else ""

            if "26.4.0" in ua_value:
                try:
                    writer.write(SWITCH_RESPONSE)
                    await writer.drain()
                except Exception as e:
                    print(f"[!] Failed to send SWITCH_RESPONSE to {peer}: {e}")
                    return
                forwarding_started = True

                if host_header:
                    if ':' in host_header:
                        host, port = host_header.split(':', 1)
                        try:
                            target = (host.strip(), int(port.strip()))
                        except:
                            target = DEFAULT_TARGET
                    else:
                        target = (host_header.strip(), 22)
                else:
                    target = DEFAULT_TARGET

                try:
                    target_reader, target_writer = await asyncio.open_connection(*target)
                    set_socket_options(target_writer)
                except Exception as e:
                    print(f"[!] Failed to connect target {target}: {e}")
                    try:
                        writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                        await writer.drain()
                    except:
                        pass
                    return

                if rest:
                    try:
                        target_writer.write(rest)
                        transport = getattr(target_writer, 'transport', None)
                        if transport and transport.get_write_buffer_size() > WRITE_BACKPRESSURE:
                            await target_writer.drain()
                    except:
                        pass

                t1 = asyncio.create_task(pipe(reader, target_writer, conn_key))
                t2 = asyncio.create_task(pipe(target_reader, writer, conn_key))
                pipe_tasks = [t1, t2]

                done, pending = await asyncio.wait(pipe_tasks, return_when=asyncio.FIRST_COMPLETED)
                for p in pending:
                    p.cancel()
                    try:
                        await p
                    except:
                        pass
                break  # 转发后退出循环

            elif "1.0" in ua_value:
                try:
                    writer.write(FIRST_RESPONSE)
                    await writer.drain()
                except:
                    pass
                continue  # 等待下一个 payload
            else:
                try:
                    writer.write(FORBIDDEN_RESPONSE)
                    await writer.drain()
                except:
                    pass
                return

    except asyncio.TimeoutError:
        print(f"[!] initial read timeout from {peer}")
    except Exception as e:
        print(f"[!] Connection error {peer}: {e}")
    finally:
        for t in pipe_tasks:
            if not t.done():
                t.cancel()
                try:
                    await t
                except:
                    pass
        try:
            writer.close()
            await writer.wait_closed()
        except:
            pass
        try:
            if target_writer:
                target_writer.close()
                await target_writer.wait_closed()
        except:
            pass
        ACTIVE_CONNS.pop(conn_key, None)
        print(f"[-] Closed {peer}")

# ---------------- 心跳 ----------------
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

# ---------------- 端口处理 ----------------
HTTP_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 80
TLS_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 443

try:
    if sys.stdin.isatty():
        inp = input(f"请输入 WSS HTTP 监听端口（默认{HTTP_PORT}）: ")
        if inp.strip():
            HTTP_PORT = int(inp.strip())
        inp = input(f"请输入 WSS TLS 监听端口（默认{TLS_PORT}）: ")
        if inp.strip():
            TLS_PORT = int(inp.strip())
except Exception:
    pass

# ---------------- 启动服务 ----------------
async def main():
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

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

    gc_task = asyncio.create_task(heartbeat())

    async with tls_server, http_server:
        await asyncio.gather(
            tls_server.serve_forever(),
            http_server.serve_forever(),
            gc_task
        )

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped manually.")
    except Exception as e:
        print(f"[!] Fatal error: {e}")
PYEOF

chmod +x /usr/local/bin/wss
echo "WSS 脚本安装完成"
echo "----------------------------------"

# =============================
# 创建 WSS systemd 服务
# =============================
cat > /etc/systemd/system/wss.service <<'SVC'
[Unit]
Description=WSS Python Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/wss '"$WSS_HTTP_PORT"' '"$WSS_TLS_PORT"'
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
SVC

# Ensure systemd picks up unit and start service
systemctl daemon-reload
systemctl enable wss
systemctl restart wss
echo "WSS 已启动，HTTP端口 $WSS_HTTP_PORT, TLS端口 $WSS_TLS_PORT"
echo "----------------------------------"

# =============================
# 安装 Stunnel4 并生成证书
# =============================
echo "==== 安装 Stunnel4 ===="
mkdir -p /etc/stunnel/certs
openssl req -x509 -nodes -newkey rsa:2048 \
-keyout /etc/stunnel/certs/stunnel.key \
-out /etc/stunnel/certs/stunnel.crt \
-days 1095 \
-subj "/CN=example.com"
sh -c 'cat /etc/stunnel/certs/stunnel.key /etc/stunnel/certs/stunnel.crt > /etc/stunnel/certs/stunnel.pem'
chmod 644 /etc/stunnel/certs/*.crt
chmod 644 /etc/stunnel/certs/*.pem

cat > /etc/stunnel/ssh-tls.conf <<'STUNCFG'
pid=/var/run/stunnel.pid
setuid=root
setgid=root
client = no
debug = 5
output = /var/log/stunnel4/stunnel.log
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[ssh-tls-gateway]
accept = 0.0.0.0:__STUNNEL_PORT__
cert = /etc/stunnel/certs/stunnel.pem
key = /etc/stunnel/certs/stunnel.pem
connect = 127.0.0.1:22
STUNCFG

# Replace placeholder with actual port
sed -i "s/__STUNNEL_PORT__/${STUNNEL_PORT}/g" /etc/stunnel/ssh-tls.conf

systemctl enable stunnel4
systemctl restart stunnel4
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

cat > /etc/systemd/system/udpgw.service <<'UDPSVC'
[Unit]
Description=UDP Gateway (Badvpn)
After=network.target

[Service]
Type=simple
ExecStart=/root/badvpn/badvpn-build/udpgw/badvpn-udpgw --listen-addr 127.0.0.1:__UDPGW_PORT__ --max-clients 1024 --max-connections-for-client 10
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
UDPSVC

sed -i "s/__UDPGW_PORT__/${UDPGW_PORT}/g" /etc/systemd/system/udpgw.service

systemctl daemon-reload
systemctl enable udpgw
systemctl restart udpgw
echo "UDPGW 已安装并启动，端口: $UDPGW_PORT"
echo "----------------------------------"

echo "所有组件安装完成!"
echo "查看 WSS 状态: sudo systemctl status wss"
echo "查看 Stunnel4 状态: sudo systemctl status stunnel4"
echo "查看 UDPGW 状态: sudo systemctl status udpgw"
