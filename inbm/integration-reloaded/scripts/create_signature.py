import hashlib
import sys
from binascii import hexlify

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

file_name = package_name = password = None
num_params = len(sys.argv)
if num_params < 3:
    print('Invalid number of params')
    exit(1)
else:
    file_name = sys.argv[1]
    package_name = sys.argv[2]
    if num_params == 4:
        password = sys.argv[3].encode('utf-8')

with open(package_name, 'rb') as package:
    checksum = hashlib.sha384(package.read()).hexdigest()

with open(file_name, 'rb') as f:
    priv_key = load_pem_private_key(f.read(), password=password, backend=default_backend())

signature = priv_key.sign(checksum.encode('utf-8'), padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA384())

print((hexlify(signature)).decode('utf-8', errors='strict'))
