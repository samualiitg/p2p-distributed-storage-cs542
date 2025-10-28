# s.py (updated with secure peer replication + heartbeat + metadata sync)
import time
import socket
import shutil
import os
import threading
import json
import base64
import traceback

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet

from replication_handler import ReplicationHandler

# ---------- Helpers ----------
def port_finder():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('',0))
    port_no = s.getsockname()[1]
    s.close()
    return port_no

def read_peers():
    if os.path.exists("peers.json"):
        try:
            with open("peers.json","r") as f:
                return json.load(f)
        except:
            return []
    return []

def read_metadata():
    if os.path.exists("metadata.json"):
        with open("metadata.json","r") as f:
            return json.load(f)
    return {}

def write_metadata(meta):
    with open("metadata.json","w") as f:
        json.dump(meta, f, indent=2)

# ---------- RSA key generation ----------
RSA_KEY_PATH = "server_rsa_priv.pem"
def ensure_rsa_keys():
    if os.path.exists(RSA_KEY_PATH):
        with open(RSA_KEY_PATH, "rb") as f:
            priv = serialization.load_pem_private_key(f.read(), password=None)
        pub = priv.public_key()
        return priv, pub
    else:
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(RSA_KEY_PATH, "wb") as f:
            f.write(pem)
        pub = priv.public_key()
        return priv, pub

PRIV_KEY, PUB_KEY = ensure_rsa_keys()
PUB_PEM = PUB_KEY.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

# ---------- Server state ----------
peers = read_peers()
replication_handler = ReplicationHandler(peers, PRIV_KEY, PUB_PEM)

# ---------- Service function ----------
def service(client_ip,my_new_port):
    """
    Handle TCP connections from both clients (they send KEYEX then encrypted payloads)
    and peers (PEER_HELLO/KEYEX or encrypted payloads).
    """
    sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock1.bind(('', my_new_port))
    except Exception as e:
        print("Bind error:", e)
        return
    sock1.listen()
    print(f"TCP server listening on {my_new_port} ...")
    while True:
        conn, addr = sock1.accept()
        threading.Thread(target=handle_connection, args=(conn, addr), daemon=True).start()

def handle_connection(conn, addr):
    print("Connection from", addr)
    client_dir = f"client_storage_{addr[0].replace('.', '_')}"
    if not os.path.exists(client_dir):
        os.makedirs(client_dir, exist_ok=True)

    try:
        raw = conn.recv(65536)
        if not raw:
            conn.close()
            return
        try:
            j = json.loads(raw.decode('utf-8'))
        except Exception:
            conn.close()
            return

        ph = replication_handler.handle_incoming_peer_message(j, conn)
        if ph.get("handled") and not ph.get("decrypted"):
            while True:
                raw2 = conn.recv(65536)
                if not raw2:
                    break
                try:
                    j2 = json.loads(raw2.decode('utf-8'))
                except:
                    break
                ph2 = replication_handler.handle_incoming_peer_message(j2, conn)
                if ph2.get("decrypted"):
                    ph = ph2
                    break
            if not ph:
                conn.close()
                return

        if ph and ph.get("decrypted"):
            request = ph.get("decrypted")
            fernet_for_peer = ph.get("fernet")
            source_is_peer = True
        else:
            if j.get("command") == "KEYEX":
                enc_key_b64 = j.get("key")
                enc_key = base64.b64decode(enc_key_b64.encode('utf-8'))
                try:
                    symmetric_key = PRIV_KEY.decrypt(
                        enc_key,
                        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                     algorithm=hashes.SHA256(),
                                     label=None)
                    )
                except Exception as e:
                    print("Failed client KEYEX:", e)
                    conn.close()
                    return
                fernet_for_peer = Fernet(symmetric_key)
                while True:
                    enc_raw = conn.recv(65536)
                    if not enc_raw:
                        break
                    try:
                        wrapper = json.loads(enc_raw.decode('utf-8'))
                        token = wrapper.get('payload').encode('utf-8')
                        plain = fernet_for_peer.decrypt(token)
                        request = json.loads(plain.decode('utf-8'))
                        break
                    except Exception as e:
                        print("Failed decrypt client payload:", e)
                        break
                source_is_peer = False
            else:
                conn.close()
                return

        while request:
            response = {}
            cmd = request.get("command")
            if cmd == "LS":
                path = request.get('path','')
                full_path = os.path.join(client_dir, path.strip('/'))
                if os.path.isdir(full_path):
                    files = os.listdir(full_path)
                    response = {'status':'success','files':files}
                else:
                    response = {'status':'error','message':'Directory not found'}

            elif cmd == "GETATTR":
                path = request.get('path','')
                full_path = os.path.join(client_dir, path.strip('/'))
                if os.path.exists(full_path):
                    stats = os.stat(full_path)
                    response = {'status':'success',
                                'st_mode':stats.st_mode,'st_nlink':stats.st_nlink,
                                'st_size':stats.st_size,'st_ctime':stats.st_ctime,
                                'st_mtime':stats.st_mtime,'st_atime':stats.st_atime}
                else:
                    response = {'status':'error','message':'File or directory not found'}

            elif cmd == "CREATE":
                path = request.get('path','')
                full_path = os.path.join(client_dir, path.strip('/'))
                try:
                    parent = os.path.dirname(full_path)
                    if parent and not os.path.exists(parent):
                        os.makedirs(parent, exist_ok=True)
                    fd = os.open(full_path, os.O_CREAT | os.O_WRONLY, 0o666)
                    os.close(fd)
                    response = {'status':'success'}
                except Exception as e:
                    response = {'status':'error','message':str(e)}

            elif cmd == "WRITE":
                path = request.get('path','')
                offset = request.get('offset', 0)
                data_hex = request.get('data_hex','')
                data_bytes = bytes.fromhex(data_hex)
                full_path = os.path.join(client_dir, path.strip('/'))
                try:
                    parent = os.path.dirname(full_path)
                    if parent and not os.path.exists(parent):
                        os.makedirs(parent, exist_ok=True)
                    with open(full_path, 'r+b' if os.path.exists(full_path) else 'wb') as f:
                        f.seek(offset)
                        f.write(data_bytes)
                    response = {'status':'success','bytes_written':len(data_bytes)}
                    meta = read_metadata()
                    host_ip = socket.gethostbyname(socket.gethostname())
                    entry = meta.get(path, {"replicas":[],"size":os.path.getsize(full_path)})
                    entry["size"] = os.path.getsize(full_path)
                    if host_ip not in entry["replicas"]:
                        entry["replicas"].append(host_ip)
                    meta[path] = entry
                    write_metadata(meta)
                    for p in peers:
                        try:
                            msg = {"command":"REPLICA_WRITE","path": path, "data_hex": data_hex}
                            replication_handler.send_encrypted_to_peer(p['host'], p['port'], msg)
                        except Exception:
                            pass
                    for p in peers:
                        try:
                            replication_handler.send_encrypted_to_peer(p['host'], p['port'], {"command":"SYNC_METADATA","metadata": meta})
                        except Exception:
                            pass
                except Exception as e:
                    response = {'status':'error','message':str(e)}

            elif cmd == "REPLICA_WRITE":
                path = request.get('path','')
                data_hex = request.get('data_hex','')
                full_path = os.path.join(client_dir, path.strip('/'))
                try:
                    parent = os.path.dirname(full_path)
                    if parent and not os.path.exists(parent):
                        os.makedirs(parent, exist_ok=True)
                    with open(full_path,'wb') as f:
                        f.write(bytes.fromhex(data_hex))
                    meta = read_metadata()
                    host_ip = socket.gethostbyname(socket.gethostname())
                    entry = meta.get(path, {"replicas":[],"size":os.path.getsize(full_path)})
                    if host_ip not in entry["replicas"]:
                        entry["replicas"].append(host_ip)
                    entry["size"] = os.path.getsize(full_path)
                    meta[path] = entry
                    write_metadata(meta)
                    response = {'status':'success'}
                except Exception as e:
                    response = {'status':'error','message':str(e)}

            elif cmd == "SYNC_METADATA":
                incoming = request.get('metadata',{})
                if isinstance(incoming, dict):
                    local = read_metadata()
                    for k,v in incoming.items():
                        local[k] = v
                    write_metadata(local)
                    response = {'status':'success'}
                else:
                    response = {'status':'error','message':'invalid metadata'}

            elif cmd == "GET_METADATA":
                response = {'status':'success','metadata': read_metadata()}

            elif cmd == "READ":
                path = request.get('path','')
                offset = request.get('offset',0)
                size = request.get('size',0)
                full_path = os.path.join(client_dir, path.strip('/'))
                try:
                    with open(full_path,'rb') as f:
                        f.seek(offset)
                        data = f.read(size)
                    response = {'status':'success','data': data.hex()}
                except Exception as e:
                    response = {'status':'error','message':str(e)}

            else:
                response = {'status':'error','message':'Unknown command'}

            try:
                if fernet_for_peer:
                    token = fernet_for_peer.encrypt(json.dumps(response).encode('utf-8'))
                    conn.sendall(json.dumps({'payload': token.decode('utf-8')}).encode('utf-8'))
                else:
                    conn.sendall(json.dumps(response).encode('utf-8'))
            except Exception as e:
                print("Failed to send response:", e)
                break

            try:
                raw_next = conn.recv(65536)
                if not raw_next:
                    break
                jnext = json.loads(raw_next.decode('utf-8'))
                if 'payload' in jnext and fernet_for_peer:
                    token = jnext['payload'].encode('utf-8')
                    plain = fernet_for_peer.decrypt(token)
                    request = json.loads(plain.decode('utf-8'))
                else:
                    request = jnext
            except Exception:
                break

    except Exception as e:
        print("Connection handling error:", e)
        traceback.print_exc()
    finally:
        conn.close()
        print("Connection closed:", addr)

# ---------- UDP discovery server ----------
def main_process():
    total_disk_space, used_space, avail_space = shutil.disk_usage('/')
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    HOST = ''
    DEFAULT_PORT_FOR_BROADCAST = 4444
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        sock.bind((HOST, DEFAULT_PORT_FOR_BROADCAST))
        print(f"UDP discovery listening on port {DEFAULT_PORT_FOR_BROADCAST}")
    except Exception as e:
        print("UDP bind error:", e)
        sock.close()
        return
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            try:
                request = json.loads(data.decode('utf-8'))
            except:
                continue
            if request.get('service') != 'storage':
                continue
            client_ip, client_port = addr[0], addr[1]
            requested_space = request.get('size_needed', 0)
            avail_gb = round(avail_space / (1024**3), 2)
            if avail_gb > requested_space:
                my_new_port = port_finder()
                reply = {'flag':'Green', 'new_port':my_new_port, 'pubkey': PUB_PEM}
                sock.sendto(json.dumps(reply).encode('utf-8'), (client_ip, client_port))
                th = threading.Thread(target=service, args=(client_ip,my_new_port), daemon=True)
                th.start()
        except Exception as e:
            print("UDP loop error:", e)
            traceback.print_exc()

if __name__ == "__main__":
    main_process()
