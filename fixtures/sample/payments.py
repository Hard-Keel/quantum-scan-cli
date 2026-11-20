# Sample code with planted weak and quantum-vulnerable crypto, for testing the scanner.
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

signing_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
session_key = ec.generate_private_key(ec.SECP256R1())
shared = session_key.exchange(ec.ECDH(), peer_public_key)
fingerprint = hashlib.md5(card_number.encode()).hexdigest()
cipher = Cipher(algorithms.AES(key), modes.ECB())
