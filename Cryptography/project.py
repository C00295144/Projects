from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, dsa, ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import time
import os

# RSA Key Generation
rsa_sizes = {
    "80-bit security (RSA 1024)": 1024,
    "112-bit security (RSA 2048)": 2048,
    "128-bit security (RSA 3072)": 3072,
    "192-bit security (RSA 7680)": 7680,
    "256-bit security (RSA 15360)": 15360,
}

for label, key_size in rsa_sizes.items():
    count = []

    for _ in range(10):
        start = time.perf_counter()
        private_key = rsa.generate_private_key(
            public_exponent = 65537,
            key_size = key_size
        )
        public_key = private_key.public_key()
        end = time.perf_counter()

        count.append((end - start) * 1000)

    average = sum(count[1:]) / (len(count) - 1)
    print (f"RSA-{label} average generation: {average:.4f} ms")

# DSA Key Generation
dsa_sizes = {
    "80-bit security (DSA 1024)": 1024,
    "112-bit security (DSA 2048)": 2048,
    "128-bit security (DSA 3072)": 3072,
}

for label, key_size in dsa_sizes.items():
    count = []

    for _ in range(10):
        before = time.perf_counter()
        private_key = dsa.generate_private_key(key_size)
        public_key = private_key.public_key()
        after = time.perf_counter()

        count.append((after - before) * 1000)

    average = sum(count[1:]) / (len(count) - 1)
    print (f"DSA-{label} average generation: {average:.4f} ms")

# ECC Key Generation
ecc_sizes = {
    "112-bit security (ECC)": ec.SECP224R1(),
    "128-bit security (ECC)": ec.SECP256R1(),
    "192-bit security (ECC)": ec.SECP384R1(),
    "256-bit security (ECC)": ec.SECP521R1(),
}

for label, key_size in ecc_sizes.items():
    count = []

    for _ in range(10):
        before = time.perf_counter()
        private_key = ec.generate_private_key(key_size)
        public_key = private_key.public_key()
        after = time.perf_counter()

        count.append((after - before) * 1000)

    average = sum(count[1:]) / (len(count) - 1)
    print (f"ECC-{label} average generation: {average:.4f} ms")

# AES Encryption
aes_sizes = {
    "128-bit security (AES)": 128,
    "192-bit security (AES)": 192,
    "256-bit security (AES)": 256,
}

text = os.urandom(10 * 1024)

padding_length = 16 - (len(text) % 16)
padded_text = text + bytes([padding_length]) * padding_length

for label, key_size in aes_sizes.items():
    count = []

    key_bytes = os.urandom(key_size // 8)

    for i in range(10):
        iv = os.urandom(16)
        aes_cipher = Cipher(
            algorithms.AES(key_bytes),
            modes.CBC(iv),
            backend = default_backend()
        )
        aes_encryptor = aes_cipher.encryptor()

        before = time.perf_counter()
        ciphertext = aes_encryptor.update(padded_text) + aes_encryptor.finalize()
        after = time.perf_counter()

        count.append((after - before) * 1000)

    average = sum(count[1:]) / (len(count) - 1)
    print (f"AES-{label} average encryption: {average:.4f} ms")

# ChaCha20 Encryption
text = os.urandom(10 * 1024)

key = os.urandom(32)
nonce = os.urandom(16)

count = []

for i in range(10):
    chacha20_cipher = Cipher(
        algorithms.ChaCha20(key, nonce),
        mode = None,
        backend = default_backend()
    )
    chacha20_encryptor = chacha20_cipher.encryptor()

    before = time.perf_counter()
    ciphertext = chacha20_encryptor.update(text) + chacha20_encryptor.finalize()
    after = time.perf_counter()

    count.append((after - before) * 1000)

average = sum(count[1:]) / (len(count) - 1)
print (f"ChaCha20 average encryption: {average:.4f} ms")

# RSA Encryption
rsa_sizes = {
    "80-bit security (RSA 1024)": 1024,
    "112-bit security (RSA 2048)": 2048,
    "128-bit security (RSA 3072)": 3072,
    "192-bit security (RSA 7680)": 7680,
    "256-bit security (RSA 15360)": 15360,
}

def split_message(message, chunk_size):
    return [message[i:i+chunk_size] for i in range(0, len(message), chunk_size)]

def encrypt_message(public_key, message, chunk_size):
    encrypt_chunks = []
    for chunk in split_message(message, chunk_size):
        encrypt_chunks.append(
            public_key.encrypt(
                chunk,
                padding.OAEP(
                    mgf = padding.MGF1(algorithm = hashes.SHA256()),
                    algorithm = hashes.SHA256(),
                    label = None
                )
            )
        )
    return encrypt_chunks

text = os.urandom(10 * 1024)

for label, key_size in rsa_sizes.items():
    count = []

    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = key_size
    )
    public_key = private_key.public_key()

    chunk_size = key_size // 8 - 66

    for _ in range(10):
        before = time.perf_counter()
        ciphertext = encrypt_message(public_key, text, chunk_size)
        after = time.perf_counter()
        
        count.append((after - before) * 1000)

    average = sum(count[1:]) / (len(count) - 1)
    print (f"RSA-{label} average encryption: {average:.4f} ms")

# AES Decryption
aes_sizes = {
    "128-bit security (AES)": 128,
    "192-bit security (AES)": 192,
    "256-bit security (AES)": 256,
}

text = os.urandom(10 * 1024)

padding_length = 16 - (len(text) % 16)
padded_text = text + bytes([padding_length]) * padding_length

for label, key_size in aes_sizes.items():
    count = []

    key_bytes = os.urandom(key_size // 8)

    iv = os.urandom(16)
    aes_cipher = Cipher(
        algorithms.AES(key_bytes),
        modes.CBC(iv),
        backend = default_backend()
    )
    aes_encryptor = aes_cipher.encryptor()
    ciphertext = aes_encryptor.update(padded_text) + aes_encryptor.finalize()

    for i in range(10):
        dec_cipher = Cipher(
            algorithms.AES(key_bytes),
            modes.CBC(iv),
            backend = default_backend()
        )
        aes_decryptor = dec_cipher.decryptor()

        before = time.perf_counter()
        decrypted = aes_decryptor.update(ciphertext) + aes_decryptor.finalize()
        after = time.perf_counter()

        count.append((after - before) * 1000)

    average = sum(count[1:]) / (len(count) - 1)
    print (f"AES-{label} average decryption: {average:.4f} ms")

# ChaCha20 Decryption
text = os.urandom(10 * 1024)

key = os.urandom(32)
nonce = os.urandom(16)

chacha20_cipher = Cipher(
    algorithms.ChaCha20(key, nonce),
    mode = None,
    backend = default_backend()
    )
chacha20_encryptor = chacha20_cipher.encryptor()
ciphertext = chacha20_encryptor.update(text)

count = []

for i in range(10):
    dec_cipher = Cipher(
        algorithms.ChaCha20(key, nonce),
        mode = None,
        backend = default_backend()
    )
    chacha20_decryptor = dec_cipher.decryptor()

    before = time.perf_counter()
    decrypted = chacha20_decryptor.update(ciphertext)
    after = time.perf_counter()

    count.append((after - before) * 1000)

average = sum(count[1:]) / (len(count) - 1)
print (f"ChaCha20 average decryption: {average:.4f} ms")

# RSA Decryption
rsa_sizes = {
    "80-bit security (RSA 1024)": 1024,
    "112-bit security (RSA 2048)": 2048,
    "128-bit security (RSA 3072)": 3072,
    "192-bit security (RSA 7680)": 7680,
    "256-bit security (RSA 15360)": 15360,
}

def decrypt_message(private_key, encrypted_chunks):
    decrypted_chunks = []
    for chunk in encrypted_chunks:
        decrypted_chunks.append(
            private_key.decrypt(
                chunk,
                padding.OAEP(
                    mgf = padding.MGF1(algorithm = hashes.SHA256()),
                    algorithm = hashes.SHA256(),
                    label = None
                )
            )
        )
    return b"".join(decrypted_chunks)

text = os.urandom(10 * 1024)

for label, key_size in rsa_sizes.items():
    count = []

    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = key_size
    )
    public_key = private_key.public_key()

    chunk_size = key_size // 8 - 66

    ciphertext_chunks = encrypt_message(public_key, text, chunk_size)

    for _ in range(10):
        before = time.perf_counter()
        decrypted = decrypt_message(private_key, ciphertext_chunks)
        after = time.perf_counter()

        count.append((after - before) * 1000)

    average = sum(count[1:]) / (len(count) - 1)
    print (f"RSA-{label} average decryption: {average:.4f} ms")

# RSA Digital Signing
message = os.urandom(10 * 1024)

rsa_sizes = {
    "80-bit security (RSA 1024)": 1024,
    "112-bit security (RSA 2048)": 2048,
    "128-bit security (RSA 3072)": 3072,
    "192-bit security (RSA 7680)": 7680,
    "256-bit security (RSA 15360)": 15360,
}

def average_time(count):
    return sum(count[1:]) / (len(count) - 1)

for label, size in rsa_sizes.items():
    count = []

    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = size
    )

    for _ in range(10):
        before = time.perf_counter()
        digital_signature = private_key.sign(
            message,
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length = padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        after = time.perf_counter()
        
        count.append((after - before) * 1000)

    average = average_time(count)
    print(f"RSA-{label} average digital signing: {average:.4f} ms")

# DSA Digital Signing
message = os.urandom(10 * 1024)

dsa_sizes = {
    "80-bit security (DSA 1024)": 1024,
    "112-bit security (DSA 2048)": 2048,
    "128-bit security (DSA 3072)": 3072,
}

def average_time(count):
    return sum(count[1:]) / (len(count) - 1)

for label, size in dsa_sizes.items():
    count = []

    private_key = dsa.generate_private_key(size)

    for _ in range(10):
        before = time.perf_counter()
        digital_signature = private_key.sign(
            message,
            hashes.SHA256()
        )
        after = time.perf_counter()

        count.append((after - before) * 1000)

    average = average_time(count)
    print(f"DSA-{label} average digital signing: {average:.4f} ms")

# ECC Digital Signing
message = os.urandom(10 * 1024)

ecc_sizes = {
    "112-bit security (ECC)": ec.SECP224R1(),
    "128-bit security (ECC)": ec.SECP256R1(),
    "192-bit security (ECC)": ec.SECP384R1(),
    "256-bit security (ECC)": ec.SECP521R1(),
}

def average_time(count):
    return sum(count[1:]) / (len(count) - 1)

for label, size in ecc_sizes.items():
    count = []

    private_key = ec.generate_private_key(size)

    for _ in range(10):
        before = time.perf_counter()
        digital_signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
        )
        after = time.perf_counter()

        count.append((after - before) * 1000)

    average = average_time(count)
    print (f"ECC-{label} average digital signing: {average:.4f} ms")

# RSA Verification
message = os.urandom(10 * 1024)

rsa_sizes = {
    "80-bit security (RSA 1024)": 1024,
    "112-bit security (RSA 2048)": 2048,
    "128-bit security (RSA 3072)": 3072,
    "192-bit security (RSA 7680)": 7680,
    "256-bit security (RSA 15360)": 15360,
}

def average_time(count):
    return sum(count[1:]) / (len(count) - 1)

for label, size in rsa_sizes.items():
    count = []

    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = size
    )
    public_key = private_key.public_key()

    digital_signature = private_key.sign(
        message,
        padding.PSS(
            mgf = padding.MGF1(hashes.SHA256()),
            salt_length = padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    for _ in range(10):
        before = time.perf_counter()
        public_key.verify(
            digital_signature,
            message,
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length = padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        after = time.perf_counter()

        count.append((after - before) * 1000)
    
    average = average_time(count)
    print (f"RSA-{label} average verification: {average:.4f} ms")

# DSA Verification
message = os.urandom(10 * 1024)

dsa_sizes = {
    "80-bit security (DSA 1024)": 1024,
    "112-bit security (DSA 2048)": 2048,
    "128-bit security (DSA 3072)": 3072,
}

def average_time(count):
    return sum(count[1:]) / (len(count) - 1)

for label, size in dsa_sizes.items():
    count = []

    private_key = dsa.generate_private_key(size)
    public_key = private_key.public_key()

    digital_signature = private_key.sign(
        message,
        hashes.SHA256()
    )

    for _ in range(10):
        before = time.perf_counter()
        public_key.verify(
            digital_signature,
            message,
            hashes.SHA256()
        )
        after = time.perf_counter()

        count.append((after - before) * 1000)

    average = average_time(count)
    print(f"DSA-{label} average verification: {average:.4f} ms")

# ECC Verification
message = os.urandom(10 * 1024)

ecc_sizes = {
    "112-bit security (ECC)": ec.SECP224R1(),
    "128-bit security (ECC)": ec.SECP256R1(),
    "192-bit security (ECC)": ec.SECP384R1(),
    "256-bit security (ECC)": ec.SECP521R1(),
}

def average_time(count):
    return sum(count[1:]) / (len(count) - 1)

for label, size in ecc_sizes.items():
    count = []

    private_key = ec.generate_private_key(size)
    public_key = private_key.public_key()

    digital_signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )

    for _ in range(10):
        before = time.perf_counter()
        public_key.verify(
            digital_signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        after = time.perf_counter()

        count.append((after - before) * 1000)

    average = average_time(count)
    print (f"ECC-{label} average verification: {average:.4f} ms")