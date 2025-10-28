# replication_handler.py
import socket
import json
import time
import threading
import base64
import traceback

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet

class ReplicationHandler:
    """
    Manage peer key exchanges, per-peer Fernet objects, replication and heartbeat.
    peers: list of {"host":..,"port":..}
    rsa_priv: server private key (cryptography object)
    rsa_pub_pem: server public key PEM string
    my_host: optional hostname/ip of this server (string)
    """
    def __init__(self, peers, rsa_priv, rsa_pub_pem, my_host=None, heartbeat_interval=5, heartbeat_fail_threshold=3):
        self.peers = peers[:]  # list of dicts
        self.rsa_priv = rsa_priv
        self.rsa_pub_pem = rsa_pub_pem
        self.my_host = my_host or socket.gethostbyname(socket.gethostname())
        self.peer_fernet = {}  # key: (host,port) -> Fernet symmetric key (bytes)
        self.peer_pub = {}     # key: (host,port) -> peer public key PEM (str)
        self.peer_status = {}  # key: (host,port) -> {"alive":bool, "fail_count":int}
        self.heartbeat_interval = heartbeat_interval
        self.heartbeat_fail_threshold = heartbeat_fail_threshold
        self.lock = threading.Lock()
        # start heartbeat thread
        t = threading.Thread(target=self._heartbeat_loop, daemon=True)
        t.start()
        # attempt initial key exchanges
        self._initial_key_exchange_all()

    def _initial_key_exchange_all(self):
        for p in self.peers:
            host, port = p['host'], p['port']
            self.peer_status[(host,port)] = {"alive": False, "fail_count": 0}
            try:
                self.perform_key_exchange(host, port)
            except Exception:
                # best effort; will be retried in heartbeat
                pass

    def perform_key_exchange(self, host, port, timeout=3):
        """
        Perform pairwise handshake:
        1) Connect to peer TCP
        2) Send: {"command":"PEER_HELLO","pubkey":<our_pub_pem>,"host":<my_host>}
        3) Expect reply: {"command":"PEER_HELLO_REPLY","pubkey":<their_pub_pem>}
        4) Generate symmetric key, encrypt with their pubkey and send {"command":"PEER_KEYEX","key":<b64>}
        5) On success both sides will keep the symmetric key for encrypted channel.
        """
        addr = (host, port)
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(timeout)
        conn.connect(addr)
        # send hello
        hello = {"command":"PEER_HELLO","pubkey": self.rsa_pub_pem, "host": self.my_host}
        conn.sendall(json.dumps(hello).encode('utf-8'))
        data = conn.recv(8192)
        if not data:
            conn.close()
            raise RuntimeError("No response from peer during hello")
        reply = json.loads(data.decode('utf-8'))
        if reply.get("command") != "PEER_HELLO_REPLY" or "pubkey" not in reply:
            conn.close()
            raise RuntimeError("Bad hello reply")
        peer_pub_pem = reply["pubkey"]
        # store peer pub
        with self.lock:
            self.peer_pub[(host,port)] = peer_pub_pem
        # create symmetric key and send encrypted with peer public key
        sym = Fernet.generate_key()
        peer_pub = serialization.load_pem_public_key(peer_pub_pem.encode('utf-8'))
        enc = peer_pub.encrypt(
            sym,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        enc_b64 = base64.b64encode(enc).decode('utf-8')
        keyex = {"command":"PEER_KEYEX", "key": enc_b64}
        conn.sendall(json.dumps(keyex).encode('utf-8'))
        # read ack
        ack = conn.recv(8192)
        if not ack:
            conn.close()
            raise RuntimeError("No ACK after KEYEX")
        ackj = json.loads(ack.decode('utf-8'))
        if ackj.get("status") != "OK":
            conn.close()
            raise RuntimeError("Peer KEYEX failed: " + str(ackj))
        # store Fernet
        with self.lock:
            self.peer_fernet[(host,port)] = Fernet(sym)
            self.peer_status[(host,port)] = {"alive": True, "fail_count": 0}
        conn.close()
        return True

    def handle_incoming_peer_message(self, raw_json, conn_sock):
        """
        Called by server when it accepts a TCP connection and gets JSON from peer.
        Handles: PEER_HELLO, PEER_KEYEX, PING, REPLICA_WRITE, SYNC_METADATA
        """
        try:
            cmd = raw_json.get("command")
            if cmd == "PEER_HELLO":
                # store peer pub key, respond with our pub key
                peer_pub = raw_json.get("pubkey")
                # reply with our pubkey
                reply = {"command":"PEER_HELLO_REPLY","pubkey": self.rsa_pub_pem}
                conn_sock.sendall(json.dumps(reply).encode('utf-8'))
                return {"handled": True}

            elif cmd == "PEER_KEYEX":
                enc_b64 = raw_json.get("key")
                enc = base64.b64decode(enc_b64.encode('utf-8'))
                sym = self.rsa_priv.decrypt(
                    enc,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
                peer_addr = conn_sock.getpeername()[:2]
                with self.lock:
                    self.peer_fernet[peer_addr] = Fernet(sym)
                    self.peer_status[peer_addr] = {"alive": True, "fail_count": 0}
                conn_sock.sendall(json.dumps({"status":"OK"}).encode('utf-8'))
                return {"handled": True}

            elif cmd == "PING":
                conn_sock.sendall(json.dumps({"command":"PONG"}).encode('utf-8'))
                return {"handled": True}

            elif 'payload' in raw_json:
                peer_addr = conn_sock.getpeername()[:2]
                f = None
                with self.lock:
                    f = self.peer_fernet.get(peer_addr)
                if f is None:
                    host = peer_addr[0]
                    candidate = None
                    with self.lock:
                        for (h,p),fn in self.peer_fernet.items():
                            if h == host:
                                candidate = fn
                                break
                    f = candidate
                if f is None:
                    return {"handled": False, "error": "No symmetric key for peer"}
                try:
                    token = raw_json['payload'].encode('utf-8')
                    plain = f.decrypt(token)
                    subreq = json.loads(plain.decode('utf-8'))
                    return {"handled": False, "decrypted": subreq, "fernet": f}
                except Exception as e:
                    return {"handled": False, "error": str(e)}

            else:
                return {"handled": False}

        except Exception as e:
            traceback.print_exc()
            return {"handled": False, "error": str(e)}

    def send_encrypted_to_peer(self, host, port, message_json, timeout=5):
        """
        Uses existing stored Fernet to encrypt 'message_json' and send to peer.
        message_json is a dict which will be serialized and encrypted.
        """
        addr = (host, port)
        with self.lock:
            f = self.peer_fernet.get(addr)
        if f is None:
            try:
                self.perform_key_exchange(host, port)
                with self.lock:
                    f = self.peer_fernet.get(addr)
            except Exception:
                return {"status":"error","message":"No key and exchange failed"}

        token = f.encrypt(json.dumps(message_json).encode('utf-8'))
        wrapper = {"payload": token.decode('utf-8')}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect(addr)
            s.sendall(json.dumps(wrapper).encode('utf-8'))
            try:
                resp_raw = s.recv(65536)
                if not resp_raw:
                    s.close()
                    return {"status":"ok","note":"no response body"}
                try:
                    resp = json.loads(resp_raw.decode('utf-8'))
                    if 'payload' in resp:
                        with self.lock:
                            ff = self.peer_fernet.get(addr)
                        try:
                            plain = ff.decrypt(resp['payload'].encode('utf-8'))
                            ans = json.loads(plain.decode('utf-8'))
                            s.close()
                            return {"status":"ok","response": ans}
                        except Exception:
                            s.close()
                            return {"status":"ok","response_raw": resp}
                    else:
                        s.close()
                        return {"status":"ok","response_raw": resp}
                except Exception:
                    s.close()
                    return {"status":"ok","note":"unparseable response"}
            except socket.timeout:
                s.close()
                return {"status":"ok","note":"no response (timeout)"}
        except Exception as e:
            return {"status":"error","message": str(e)}

    def _heartbeat_loop(self):
        while True:
            for p in self.peers:
                addr = (p['host'], p['port'])
                try:
                    self.perform_key_exchange(p['host'], p['port'])
                    with self.lock:
                        self.peer_status[addr] = {"alive": True, "fail_count": 0}
                except Exception:
                    with self.lock:
                        st = self.peer_status.get(addr, {"alive": False, "fail_count": 0})
                        st['fail_count'] = st.get('fail_count',0) + 1
                        if st['fail_count'] >= self.heartbeat_fail_threshold:
                            st['alive'] = False
                        self.peer_status[addr] = st
                time.sleep(0.1)
            time.sleep(self.heartbeat_interval)
