# c.py (client)
import socket
import os
import time
import json
import base64
import fuse
import errno

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# FUSE class to forward ops to server over encrypted channel
class FuseClient(fuse.Operations):
    def __init__(self, server_ip, server_port, fernet):
        self.server_ip = server_ip
        self.server_port = server_port
        self.fernet = fernet
        self.connection = self.connect_to_server()

    def connect_to_server(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.server_ip, self.server_port))
            return sock
        except Exception as e:
            print(f"Connection error: {e}")
            return None

    def _send_command(self, command, **kwargs):
        if not self.connection:
            return {'status':'error','message':'No connection'}
        request = {'command': command, **kwargs}
        plain = json.dumps(request).encode('utf-8')
        token = self.fernet.encrypt(plain)
        wrapper = json.dumps({'payload': token.decode('utf-8')})
        try:
            self.connection.sendall(wrapper.encode('utf-8'))
            response_raw = self.connection.recv(65536)
            response_json = json.loads(response_raw.decode('utf-8'))
            token2 = response_json.get('payload').encode('utf-8')
            resp_plain = self.fernet.decrypt(token2)
            return json.loads(resp_plain.decode('utf-8'))
        except Exception as e:
            print("Network / encryption error:", e)
            return {'status':'error','message':str(e)}

    # FUSE methods (readdir, getattr, read, write, create, etc.)
    def readdir(self, path, fh):
        response = self._send_command('LS', path=path)
        if response.get('status') == 'success':
            for item in ['.', '..'] + response.get('files',[]):
                yield item
        else:
            raise fuse.FuseOSError(errno.EIO)

    def getattr(self, path, fh=None):
        response = self._send_command('GETATTR', path=path)
        if response.get('status') == 'success':
            st = {}
            st["st_nlink"] = response.get('st_nlink',0)
            st["st_mode"] = response.get('st_mode', 0)
            st["st_size"] = response.get('st_size', 0)
            st["st_ctime"] = response.get('st_ctime', 0)
            st["st_mtime"] = response.get('st_mtime', 0)
            st["st_atime"] = response.get('st_atime', 0)
            return st
        else:
            raise fuse.FuseOSError(errno.ENOENT)

    def statfs(self,path):
        return {
            'f_bsize' : 4096,
            'f_frsize' : 4096,
            'f_blocks' : 1024*1024,
            'f_bfree' : 1024*1024,
            'f_bavail' : 1024*1024,
            'f_files' : 1000000,
            'f_ffree' : 1000000,
            'f_favail' : 1000000,
            'f_namemax' : 255,
        }

    def truncate(self,path,length,fh=None):
        response = self._send_command('TRUNCATE',path=path,length=length)
        if response.get('status') == 'success':
            return 0
        raise fuse.FuseOSError(errno.EIO)

    def open(self, path, flags):
        response = self._send_command('OPEN',path=path,flags=flags)
        if(response.get('status') == 'success'):
            return 0
        elif response.get('message') == 'file or directory not found':
            raise fuse.FuseOSError(errno.ENOENT)
        elif response.get('message') == 'Permission denied':
            raise fuse.FuseOSError(errno.EACCES)
        else:
            raise fuse.FuseOSError(errno.EIO)

    def read(self, path, size, offset, fh):
        total_data = []
        bytes_to_read = size
        current_offset = offset
        max_chunk_size = 1024
        while bytes_to_read > 0:
            chunk_size = min(bytes_to_read, max_chunk_size)
            response = self._send_command('READ',path=path, size=chunk_size, offset=current_offset)
            if response.get('status') == 'success':
                data_hex = response.get('data')
                if not data_hex:
                    break
                chunk_data = bytes.fromhex(data_hex)
                total_data.append(chunk_data)
                bytes_to_read -= len(chunk_data)
                current_offset += len(chunk_data)
                if len(chunk_data) < max_chunk_size:
                    break
            else:
                raise fuse.FuseOSError(errno.EIO)
        return b"".join(total_data)

    def rename(self,old,new,flags=0):
        response = self._send_command('RENAME',old_path=old,new_path=new)
        if response.get('status') == 'success':
            return 0
        elif (response.get('message') == 'Permission denied'):
            raise fuse.FuseOSError(errno.EACCES)
        else:
            raise fuse.FuseOSError(errno.EIO)

    def write(self, path, data, offset, fh):
        chunk_size = 512
        total_written = 0
        for i in range(0,len(data),chunk_size):
            data_hex = data[i:i+chunk_size].hex()
            response = self._send_command('WRITE', path=path, offset=offset+total_written, data_hex=data_hex)
            if response.get('status') == 'success':
                total_written += response.get('bytes_written',0)
            else:
                raise fuse.FuseOSError(errno.EIO)
        return total_written

    def create(self, path, mode, fi=None):
        response = self._send_command('CREATE', path=path)
        if response.get('status') == 'success':
            return 0
        raise fuse.FuseOSError(errno.EIO)

    def release(self, path, fh):
        response = self._send_command('RELEASE', path=path)
        if response.get('status') == 'success'):
            return 0
        raise fuse.FuseOSError(errno.EIO)

    def unlink(self, path):
        response = self._send_command('UNLINK', path=path)
        if response.get('status') == 'success'):
            return 0
        raise fuse.FuseOSError(errno.EIO)

    def mkdir(self, path, mode):
        response = self._send_command('MKDIR', path=path)
        if response.get('status') == 'success'):
            return 0
        raise fuse.FuseOSError(errno.EIO)

    def rmdir(self, path):
        response = self._send_command('RMDIR', path=path)
        if response.get('status') == 'success'):
            return 0
        raise fuse.FuseOSError(errno.EIO)


def start_client():
    DEFAULT_PORT_FOR_BROADCAST = 4444
    storage_size = 5 # GB
    request = {'service' : 'storage','size_needed' : storage_size}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(('', 0))
    sock.sendto(f"{json.dumps(request)}".encode('utf-8'), ('255.255.255.255', DEFAULT_PORT_FOR_BROADCAST))
    print("\nRequest sent. Waiting for a reply...")
    
    sock.settimeout(10.0)
    server_ip = None
    server_port = 0
    server_pubkey_pem = None

    try:
        data, addr = sock.recvfrom(4096)
        reply = json.loads(data.decode('utf-8'))
        print(f"Got reply from {addr[0]}:{addr[1]} \n")
        if reply.get('flag') == "Green":
            server_ip = addr[0]
            server_port = reply.get('new_port')
            server_pubkey_pem = reply.get('pubkey')
    except socket.timeout:
        print("\nNo Device found!!! Program terminated.\n")
        return

    sock.close()

    if server_ip:
        sym = Fernet.generate_key()
        pub = serialization.load_pem_public_key(server_pubkey_pem.encode('utf-8'))
        enc_key = pub.encrypt(
            sym,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(),
                         label=None)
        )
        enc_key_b64 = base64.b64encode(enc_key).decode('utf-8')

        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            tcp.connect((server_ip, server_port))
            handshake = {'command':'KEYEX','key':enc_key_b64}
            tcp.sendall(json.dumps(handshake).encode('utf-8'))
            mount_point = "p2p_storage"
            if not os.path.exists(mount_point):
                os.makedirs(mount_point)
            print(f"Mounting FUSE filesystem at {mount_point}...")
            fuse.FUSE(FuseClient(server_ip, server_port, Fernet(sym)), mount_point, nothreads=True, foreground=True)
        except Exception as e:
            print("TCP connect error:", e)
            return

if __name__ == "__main__":
    start_client()
