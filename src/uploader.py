# uploader.py - small CLI to test handshake + create+write (no FUSE)
import socket, json, base64, sys
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet

def discover_and_upload(filename="test_upload.txt", content=b"Hello secure world\n"):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(('',0))
    sock.sendto(json.dumps({'service':'storage','size_needed':1}).encode(), ('255.255.255.255',4444))
    sock.settimeout(5)
    try:
        data, addr = sock.recvfrom(4096)
        reply = json.loads(data.decode())
        if reply.get('flag')=='Green':
            host = addr[0]; port = reply.get('new_port')
            pub = reply.get('pubkey')
            sym = Fernet.generate_key()
            pubkey = serialization.load_pem_public_key(pub.encode())
            enc = pubkey.encrypt(sym, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
            enc_b64 = base64.b64encode(enc).decode()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host,port))
            s.sendall(json.dumps({'command':'KEYEX','key':enc_b64}).encode())
            f = Fernet(sym)
            req = {'command':'CREATE','path':filename}
            s.sendall(json.dumps({'payload':f.encrypt(json.dumps(req).encode()).decode()}).encode())
            resp = s.recv(65536)
            print("create resp =>", f.decrypt(json.loads(resp.decode())['payload'].encode()).decode())
            data_hex = content.hex()
            req2 = {'command':'WRITE','path':filename,'offset':0,'data_hex':data_hex}
            s.sendall(json.dumps({'payload':f.encrypt(json.dumps(req2).encode()).decode()}).encode())
            resp = s.recv(65536)
            print("write resp =>", f.decrypt(json.loads(resp.decode())['payload'].encode()).decode())
            s.close()
    except Exception as e:
        print("No server found or error:", e)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        fname = sys.argv[1]
    else:
        fname = "test_upload.txt"
    discover_and_upload(filename=fname)
