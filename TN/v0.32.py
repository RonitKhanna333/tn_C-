from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.Cipher import AES as AES_SIV
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
import os
import stat
import json
import ctypes
from ctypes import wintypes
import tempfile
import shutil
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import cpu_count
from functools import partial
import time
import psutil
from tqdm import tqdm
import secrets
import logging
import boto3
import base64
import hashlib

# Constants
CHUNK_SIZE = 2 * 1024 * 1024
MIN_SHARES = 3

# Define BCRYPT_OAEP_PADDING_INFO for OAEP padding
class BCRYPT_OAEP_PADDING_INFO(ctypes.Structure):
    _fields_ = [
        ("pszAlgId", wintypes.LPCWSTR),  # Hash algorithm (e.g., "SHA1")
        ("pbLabel", ctypes.c_void_p),    # Optional label (NULL if not used)
        ("cbLabel", wintypes.DWORD),     # Length of the label (0 if no label)
    ]

# Configure logging
logging.basicConfig(
    filename='encryption.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def memory_safe_process_count():
    """Calculate safe number of processes based on available memory."""
    available_mem = psutil.virtual_memory().available / (1024 ** 3)
    cpu_cores = cpu_count()
    return max(1, min(cpu_cores, int(available_mem)))

def generate_ephemeral_key():
    """Generate ephemeral keys with secure memory handling."""
    logging.info("Generating ephemeral keys")
    master_key = bytearray(secrets.token_bytes(32))
    master_mv = memoryview(master_key)
    
    content_key = bytearray(HKDF(master_mv, 32, salt=b"content-salt", hashmod=SHA256, context=b"file-content-encryption"))
    filename_key = bytearray(HKDF(master_mv, 32, salt=b"filename-salt", hashmod=SHA256, context=b"filename-encryption"))
    metadata_key = bytearray(HKDF(master_mv, 32, salt=b"metadata-salt", hashmod=SHA256, context=b"metadata-encryption"))

    part1 = bytes(master_mv[:16])
    part2 = bytes(master_mv[16:])
    shares_part1 = Shamir.split(3, 5, part1)
    shares_part2 = Shamir.split(3, 5, part2)
    
    zero_out_key(master_key)
    
    key_shares = [(idx, share1, share2) for (idx, share1), (_, share2) in zip(shares_part1, shares_part2)]
    
    return content_key, filename_key, metadata_key, key_shares

def zero_out_key(key):
    """Securely wipe keys from memory."""
    if isinstance(key, (bytearray, bytes)):
        ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(key)), 0, len(key))
    del key
    import gc; gc.collect()

def encrypt_key_shares(key_shares, rsa_key_path, key_shares_dir):
    """Encrypt key shares with RSA."""
    logging.info("Encrypting key shares with RSA")
    with open(rsa_key_path, "rb") as f:
        rsa_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    
    os.makedirs(key_shares_dir, mode=0o700, exist_ok=True)
    
    for idx, share_part1, share_part2 in key_shares:
        encrypted_share_part1 = cipher_rsa.encrypt(share_part1)
        encrypted_share_part2 = cipher_rsa.encrypt(share_part2)
        
        for part, data in [("part1", encrypted_share_part1), ("part2", encrypted_share_part2)]:
            share_path = os.path.join(key_shares_dir, f"key_share_{idx}_{part}.bin")
            with open(share_path, "wb") as f:
                f.write(data)
            os.chmod(share_path, 0o600)

def delete_one_key_share(key_shares_dir):
    """Delete the key share with the highest index."""
    existing_shares = [f for f in os.listdir(key_shares_dir) if f.startswith("key_share_") and f.endswith("_part1.bin")]
    if not existing_shares:
        return
    max_idx = max(int(f.split('_')[2]) for f in existing_shares)
    for part in ["part1", "part2"]:
        share_path = os.path.join(key_shares_dir, f"key_share_{max_idx}_{part}.bin")
        if os.path.exists(share_path):
            os.remove(share_path)

def decrypt_key_shares(rsa_private_key_path, key_shares_dir):
    """Decrypt and combine key shares with tampering detection."""
    logging.info("Decrypting key shares")
    with open(rsa_private_key_path, "rb") as f:
        rsa_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    
    key_shares_part1 = []
    key_shares_part2 = []
    
    for idx in range(1, 6):
        part1_path = os.path.join(key_shares_dir, f"key_share_{idx}_part1.bin")
        part2_path = os.path.join(key_shares_dir, f"key_share_{idx}_part2.bin")
        
        if os.path.exists(part1_path) and os.path.exists(part2_path):
            try:
                with open(part1_path, "rb") as f:
                    decrypted_share_part1 = cipher_rsa.decrypt(f.read())
                with open(part2_path, "rb") as f:
                    decrypted_share_part2 = cipher_rsa.decrypt(f.read())
                
                key_shares_part1.append((idx, decrypted_share_part1))
                key_shares_part2.append((idx, decrypted_share_part2))
            except ValueError as e:
                logging.warning("Failed to decrypt key share %d - possible tampering: %s", idx, str(e))
                delete_one_key_share(key_shares_dir)
                remaining_shares = len([f for f in os.listdir(key_shares_dir) if f.startswith("key_share_") and f.endswith("_part1.bin")])
                if remaining_shares < MIN_SHARES:
                    logging.critical("Insufficient key shares remaining. Data is now unrecoverable.")
                    raise RuntimeError("Insufficient key shares remaining after tampering detection.")
                else:
                    logging.info("Deleted one key share. %d shares remaining.", remaining_shares)
                raise RuntimeError(f"Failed to decrypt key share {idx}.")
    
    if len(key_shares_part1) < MIN_SHARES or len(key_shares_part2) < MIN_SHARES:
        raise ValueError("Insufficient shares for recovery")
    
    part1 = Shamir.combine(key_shares_part1[:MIN_SHARES])
    part2 = Shamir.combine(key_shares_part2[:MIN_SHARES])
    master_key = bytearray(part1 + part2)
    master_mv = memoryview(master_key)
    
    content_key = bytearray(HKDF(master_mv, 32, salt=b"content-salt", hashmod=SHA256, context=b"file-content-encryption"))
    filename_key = bytearray(HKDF(master_mv, 32, salt=b"filename-salt", hashmod=SHA256, context=b"filename-encryption"))
    metadata_key = bytearray(HKDF(master_mv, 32, salt=b"metadata-salt", hashmod=SHA256, context=b"metadata-encryption"))
    
    zero_out_key(master_key)
    return content_key, filename_key, metadata_key

def encrypt_filename(filename_key, filename):
    """Encrypt filenames using AES-SIV."""
    cipher = AES_SIV.new(filename_key, AES_SIV.MODE_SIV)
    ciphertext, tag = cipher.encrypt_and_digest(filename.encode('utf-8'))
    return (ciphertext + tag).hex()

def encrypt_metadata(metadata, metadata_key, encrypted_folder):
    """Encrypt metadata with AES-GCM."""
    metadata_bytes = json.dumps(metadata).encode('utf-8')
    iv = secrets.token_bytes(12)
    cipher_aes = AES.new(metadata_key, AES.MODE_GCM, nonce=iv)
    encrypted_metadata, tag = cipher_aes.encrypt_and_digest(metadata_bytes)
    
    metadata_path = os.path.join(encrypted_folder, "metadata.enc")
    with open(metadata_path, "wb") as f:
        f.write(iv + encrypted_metadata + tag)
    os.chmod(metadata_path, 0o600)

def decrypt_metadata(metadata_key, encrypted_folder):
    """Decrypt metadata with AES-GCM."""
    metadata_path = os.path.join(encrypted_folder, "metadata.enc")
    with open(metadata_path, "rb") as f:
        data = f.read()
    
    iv = data[:12]
    ciphertext = data[12:-16]
    tag = data[-16:]
    
    cipher_aes = AES.new(metadata_key, AES.MODE_GCM, nonce=iv)
    try:
        return json.loads(cipher_aes.decrypt_and_verify(ciphertext, tag).decode())
    except ValueError as e:
        logging.error("Metadata decryption failed: %s", str(e))
        raise RuntimeError("Metadata integrity check failed")

def encrypt_file(file_path, encrypted_file_path, content_key):
    """Encrypt file using AES-GCM with progress bar."""
    logging.info("Encrypting file: %s", file_path)
    iv = secrets.token_bytes(12)
    cipher_aes = AES.new(content_key, AES.MODE_GCM, nonce=iv)
    
    try:
        file_size = os.path.getsize(file_path)
        with open(file_path, "rb") as f_in, open(encrypted_file_path, "wb") as f_out:
            f_out.write(iv)
            
            with tqdm(total=file_size, unit='B', unit_scale=True, desc=f"Encrypting {os.path.basename(file_path)}") as pbar:
                while chunk := f_in.read(CHUNK_SIZE):
                    encrypted_chunk = cipher_aes.encrypt(chunk)
                    f_out.write(encrypted_chunk)
                    pbar.update(len(chunk))
                
                f_out.write(cipher_aes.digest())
        os.chmod(encrypted_file_path, 0o600)
                
    except Exception as e:
        logging.error("Error encrypting %s: %s", file_path, str(e))
        if os.path.exists(encrypted_file_path):
            os.remove(encrypted_file_path)
        raise
    finally:
        logging.info("Finished encrypting file: %s", file_path)

def encrypt_file_wrapper(args):
    """Parallel processing wrapper for encryption."""
    file_path, encrypted_file_path, content_key = args
    key_copy = bytearray(content_key)
    try:
        encrypt_file(file_path, encrypted_file_path, key_copy)
    finally:
        zero_out_key(key_copy)

def encrypt_folder_parallel(folder_path, encrypted_folder, rsa_public_key_path, key_shares_dir):
    """Parallel folder encryption with logging."""
    start_time = time.time()
    logging.info("Starting encryption of folder: %s to %s", folder_path, encrypted_folder)
    content_key, filename_key, metadata_key, key_shares = generate_ephemeral_key()
    os.makedirs(encrypted_folder, mode=0o700, exist_ok=True)
    
    metadata = {}
    files_to_encrypt = []
    real_folder_path = os.path.realpath(folder_path)

    for root, _, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            real_file_path = os.path.realpath(file_path)
            if not real_file_path.startswith(real_folder_path):
                continue
            relative_path = os.path.relpath(file_path, folder_path)
            stat_info = os.stat(file_path)
            encrypted_name = encrypt_filename(filename_key, file_path)
            short_name = hashlib.sha256(encrypted_name.encode()).hexdigest()
            encrypted_file_path = os.path.join(encrypted_folder, short_name)
            metadata[short_name] = {
                'relative_path': relative_path,
                'st_mtime': stat_info.st_mtime,
                'st_atime': stat_info.st_atime,
                'st_mode': stat_info.st_mode,
                'original_encrypted_name': encrypted_name
            }
            files_to_encrypt.append((file_path, encrypted_file_path, memoryview(content_key)))

    with ThreadPoolExecutor(max_workers=memory_safe_process_count()) as executor:
        list(tqdm(executor.map(encrypt_file_wrapper, files_to_encrypt), total=len(files_to_encrypt), desc="Encrypting files"))
    
    encrypt_metadata(metadata, metadata_key, encrypted_folder)
    encrypt_key_shares(key_shares, rsa_public_key_path, key_shares_dir)
    
    for key in [content_key, filename_key, metadata_key]:
        if key is not None:
            zero_out_key(key)
    logging.info("Encryption completed in %.2f seconds", time.time() - start_time)

def encrypt_folder_parallel_tpm(folder_path, encrypted_folder, tpm_key_handles, key_shares_dir):
    """Parallel folder encryption using TPM for key share encryption."""
    start_time = time.time()
    logging.info("Starting TPM-based encryption of folder: %s to %s", folder_path, encrypted_folder)
    content_key, filename_key, metadata_key, key_shares = generate_ephemeral_key()
    os.makedirs(encrypted_folder, mode=0o700, exist_ok=True)
    
    metadata = {}
    files_to_encrypt = []
    real_folder_path = os.path.realpath(folder_path)

    for root, _, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            real_file_path = os.path.realpath(file_path)
            if not real_file_path.startswith(real_folder_path):
                continue
            relative_path = os.path.relpath(file_path, folder_path)
            stat_info = os.stat(file_path)
            encrypted_name = encrypt_filename(filename_key, file_path)
            short_name = hashlib.sha256(encrypted_name.encode()).hexdigest()
            encrypted_file_path = os.path.join(encrypted_folder, short_name)
            metadata[short_name] = {
                'relative_path': relative_path,
                'st_mtime': stat_info.st_mtime,
                'st_atime': stat_info.st_atime,
                'st_mode': stat_info.st_mode,
                'original_encrypted_name': encrypted_name
            }
            files_to_encrypt.append((file_path, encrypted_file_path, memoryview(content_key)))

    with ThreadPoolExecutor(max_workers=memory_safe_process_count()) as executor:
        list(tqdm(executor.map(encrypt_file_wrapper, files_to_encrypt), total=len(files_to_encrypt), desc="Encrypting files"))
    
    encrypt_metadata(metadata, metadata_key, encrypted_folder)
    tpm_encrypt_key_shares(key_shares, tpm_key_handles, key_shares_dir)
    
    for key in [content_key, filename_key, metadata_key]:
        if key is not None:
            zero_out_key(key)
    logging.info("TPM-based encryption completed in %.2f seconds", time.time() - start_time)

def decrypt_file_batch(encrypted_files_batch, decrypted_files_batch, content_key):
    """Optimized batch decryption with tampering detection and progress bar."""
    key_copy = bytearray(content_key)
    try:
        for encrypted_file, decrypted_file in zip(encrypted_files_batch, decrypted_files_batch):
            logging.info("Decrypting file: %s", encrypted_file)
            try:
                file_size = os.path.getsize(encrypted_file) - 12 - 16
                with open(encrypted_file, "rb") as f_in:
                    iv = f_in.read(12)
                    cipher_aes = AES.new(key_copy, AES.MODE_GCM, nonce=iv)
                    
                    with open(decrypted_file, "wb") as f_out, tqdm(total=file_size, unit='B', unit_scale=True, desc=f"Decrypting {os.path.basename(encrypted_file)}") as pbar:
                        bytes_processed = 0
                        while bytes_processed < file_size:
                            chunk_size = min(
                                CHUNK_SIZE,
                                file_size - bytes_processed,
                                max(1024*1024, int(psutil.virtual_memory().available * 0.1))
                            )
                            chunk = f_in.read(chunk_size)
                            decrypted = cipher_aes.decrypt(chunk)
                            f_out.write(decrypted)
                            bytes_processed += len(chunk)
                            pbar.update(len(chunk))
                            del decrypted
                        
                        tag = f_in.read(16)
                        cipher_aes.verify(tag)
                
                src_stat = os.stat(encrypted_file)
                os.utime(decrypted_file, (src_stat.st_atime, src_stat.st_mtime))
                logging.info("Finished decrypting file: %s", encrypted_file)
                
            except ValueError as e:
                if "MAC check failed" in str(e):
                    logging.error("Tampering detected in %s. Deleting encrypted file.", encrypted_file)
                    os.remove(encrypted_file)
                else:
                    logging.error("Decryption error in %s: %s", encrypted_file, str(e))
                    if os.path.exists(decrypted_file):
                        os.remove(decrypted_file)
                raise
            except Exception as e:
                logging.error("Error decrypting %s: %s", encrypted_file, str(e))
                if os.path.exists(decrypted_file):
                    os.remove(decrypted_file)
                raise
    finally:
        zero_out_key(key_copy)

def decrypt_folder(encrypted_folder, decrypted_folder, key_shares_dir, rsa_private_key_path):
    """High-performance folder decryption with security mechanisms."""
    start_time = time.time()
    logging.info("Starting decryption of folder: %s to %s", encrypted_folder, decrypted_folder)
    content_key, filename_key, metadata_key = None, None, None
    
    try:
        content_key, filename_key, metadata_key = decrypt_key_shares(rsa_private_key_path, key_shares_dir)
        try:
            metadata = decrypt_metadata(metadata_key, encrypted_folder)
        except RuntimeError as e:
            logging.error("Metadata decryption failed: %s", str(e))
            print("🚨 Warning: Incorrect key or tampered metadata detected.")
            raise
        
        file_list = []
        total_size = 0
        for short_name, info in metadata.items():
            src = os.path.join(encrypted_folder, short_name)
            dst = os.path.join(decrypted_folder, info['relative_path'])
            if not os.path.exists(src):
                logging.warning("Encrypted file missing: %s", src)
                continue
            file_size = os.path.getsize(src)
            file_list.append((src, dst, file_size))
            total_size += file_size
        
        os.makedirs(decrypted_folder, mode=0o700, exist_ok=True)
        dirs_to_create = {os.path.dirname(dst) for _, dst, _ in file_list}
        for d in dirs_to_create:
            os.makedirs(d, exist_ok=True)
        
        num_workers = memory_safe_process_count()
        batch_size = max(1, min(10, int(total_size / (1024*1024*500))))
        
        print(f"🔧 Using {num_workers} workers with adaptive batch sizing")
        
        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            current_batch = []
            current_batch_size = 0
            for src, dst, size in sorted(file_list, key=lambda x: x[2]):
                if current_batch_size + size > 1024*1024*500:
                    encrypted_batch = [i[0] for i in current_batch]
                    decrypted_batch = [i[1] for i in current_batch]
                    executor.submit(decrypt_file_batch, encrypted_batch, decrypted_batch, memoryview(content_key))
                    current_batch = []
                    current_batch_size = 0
                current_batch.append((src, dst, size))
                current_batch_size += size
            
            if current_batch:
                encrypted_batch = [i[0] for i in current_batch]
                decrypted_batch = [i[1] for i in current_batch]
                executor.submit(decrypt_file_batch, encrypted_batch, decrypted_batch, memoryview(content_key))
        
        missing = [dst for _, dst, _ in file_list if not os.path.exists(dst)]
        if missing:
            logging.error("Missing %d files after decryption", len(missing))
            raise RuntimeError(f"Missing {len(missing)} files after decryption")
        
        for short_name, info in metadata.items():
            dst = os.path.join(decrypted_folder, info['relative_path'])
            if os.path.exists(dst):
                try:
                    os.chmod(dst, info['st_mode'] & 0o777)
                except Exception as e:
                    logging.warning("Couldn’t set permissions for %s: %s", dst, str(e))
                    print(f"⚠️ Couldn’t set permissions for {dst}: {str(e)}")
                
    except Exception as e:
        logging.error("Decryption failed: %s", str(e))
        raise
    finally:
        for key in [content_key, filename_key, metadata_key]:
            if key is not None:
                zero_out_key(key)
        logging.info("Decryption completed in %.2f seconds", time.time() - start_time)
        logging.info("Processed %d files, total size %.2f MB", len(file_list), total_size / 1024 / 1024)

def decrypt_folder_tpm(encrypted_folder, decrypted_folder, key_shares_dir, tpm_key_handles):
    """Folder decryption using TPM to decrypt key shares."""
    start_time = time.time()
    logging.info("Starting TPM-based decryption of folder: %s to %s", encrypted_folder, decrypted_folder)
    content_key, filename_key, metadata_key = None, None, None
    file_list = []  # Initialize outside try block
    total_size = 0  # Initialize outside try block
    
    try:
        content_key, filename_key, metadata_key = tpm_decrypt_key_shares(tpm_key_handles, key_shares_dir)
        metadata = decrypt_metadata(metadata_key, encrypted_folder)

        for short_name, info in metadata.items():
            src = os.path.join(encrypted_folder, short_name)
            dst = os.path.join(decrypted_folder, info['relative_path'])
            if not os.path.exists(src):
                logging.warning("Encrypted file missing: %s", src)
                continue
            file_size = os.path.getsize(src)
            file_list.append((src, dst, file_size))
            total_size += file_size
        
        os.makedirs(decrypted_folder, mode=0o700, exist_ok=True)
        dirs_to_create = {os.path.dirname(dst) for _, dst, _ in file_list}
        for d in dirs_to_create:
            os.makedirs(d, exist_ok=True)
        
        num_workers = memory_safe_process_count()
        print(f"🔧 Using {num_workers} workers with adaptive batch sizing")
        
        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            current_batch = []
            current_batch_size = 0
            for src, dst, size in sorted(file_list, key=lambda x: x[2]):
                if current_batch_size + size > 1024*1024*500:
                    encrypted_batch = [i[0] for i in current_batch]
                    decrypted_batch = [i[1] for i in current_batch]
                    executor.submit(decrypt_file_batch, encrypted_batch, decrypted_batch, memoryview(content_key))
                    current_batch = []
                    current_batch_size = 0
                current_batch.append((src, dst, size))
                current_batch_size += size
            
            if current_batch:
                encrypted_batch = [i[0] for i in current_batch]
                decrypted_batch = [i[1] for i in current_batch]
                executor.submit(decrypt_file_batch, encrypted_batch, decrypted_batch, memoryview(content_key))
        
        missing = [dst for _, dst, _ in file_list if not os.path.exists(dst)]
        if missing:
            logging.error("Missing %d files after decryption", len(missing))
            raise RuntimeError(f"Missing {len(missing)} files after decryption")
        
        for short_name, info in metadata.items():
            dst = os.path.join(decrypted_folder, info['relative_path'])
            if os.path.exists(dst):
                try:
                    os.chmod(dst, info['st_mode'] & 0o777)
                except Exception as e:
                    logging.warning("Couldn’t set permissions for %s: %s", dst, str(e))
                    print(f"⚠️ Couldn’t set permissions for {dst}: {str(e)}")
                
    except Exception as e:
        logging.error("TPM-based decryption failed: %s", str(e))
        raise
    finally:
        for key in [content_key, filename_key, metadata_key]:
            if key is not None:
                zero_out_key(key)
        logging.info("TPM-based decryption completed in %.2f seconds", time.time() - start_time)
        logging.info("Processed %d files, total size %.2f MB", len(file_list), total_size / 1024 / 1024)

def generate_rsa_keys(private_key_path, public_key_path):
    """Generate RSA keys with secure permissions."""
    logging.info("Generating RSA keys")
    key_dir = os.path.dirname(private_key_path)
    os.makedirs(key_dir, mode=0o700, exist_ok=True)
    
    key = RSA.generate(4096)
    with open(private_key_path, "wb") as f:
        f.write(key.export_key(pkcs=8))
    os.chmod(private_key_path, 0o600)
    
    with open(public_key_path, "wb") as f:
        f.write(key.publickey().export_key())
    os.chmod(public_key_path, 0o644)

def store_rsa_keys_in_aws_secret_manager(key_dir, secret_name, region_name="us-east-1"):
    """Store RSA private key from key_dir into AWS Secrets Manager."""
    private_key_path = os.path.join(key_dir, "private.pem")
    if not os.path.exists(private_key_path):
        print("Private key file not found in the provided key directory.")
        return
    with open(private_key_path, "r") as f:
        private_key_data = f.read()
    client = boto3.client('secretsmanager', region_name=region_name)
    try:
        client.create_secret(
            Name=secret_name,
            SecretString=private_key_data,
            Description="RSA Private Key for Echelon X encryption"
        )
        print(f"Successfully stored RSA private key as secret '{secret_name}' in AWS Secrets Manager.")
    except client.exceptions.ResourceExistsException:
        client.update_secret(
            SecretId=secret_name,
            SecretString=private_key_data
        )
        print(f"Successfully updated RSA private key as secret '{secret_name}' in AWS Secrets Manager.")

def store_key_shares_in_aws_secret_manager(key_shares_dir, secret_name, region_name="us-east-1"):
    """Store RSA key shares from key_shares_dir into AWS Secrets Manager."""
    key_shares_dict = {}
    for filename in os.listdir(key_shares_dir):
        if filename.startswith("key_share_") and filename.endswith("_part1.bin"):
            idx = filename.split('_')[2]
            part1_path = os.path.join(key_shares_dir, f"key_share_{idx}_part1.bin")
            part2_path = os.path.join(key_shares_dir, f"key_share_{idx}_part2.bin")
            if os.path.exists(part1_path) and os.path.exists(part2_path):
                with open(part1_path, "rb") as f:
                    part1_data = f.read()
                with open(part2_path, "rb") as f:
                    part2_data = f.read()
                key_shares_dict[idx] = {
                    "part1": base64.b64encode(part1_data).decode("utf-8"),
                    "part2": base64.b64encode(part2_data).decode("utf-8")
                }
    if not key_shares_dict:
        print("No key shares found in the provided key shares directory.")
        return
    secret_value = json.dumps(key_shares_dict)
    client = boto3.client('secretsmanager', region_name=region_name)
    try:
        client.create_secret(
            Name=secret_name,
            SecretString=secret_value,
            Description="RSA Key Shares for Echelon X encryption"
        )
        print(f"Successfully stored RSA key shares as secret '{secret_name}' in AWS Secrets Manager.")
    except client.exceptions.ResourceExistsException:
        client.update_secret(
            SecretId=secret_name,
            SecretString=secret_value
        )
        print(f"Successfully updated RSA key shares as secret '{secret_name}' in AWS Secrets Manager.")

def retrieve_rsa_key_from_aws(secret_name, region_name, key_dir):
    """Retrieve RSA private key from AWS Secrets Manager."""
    try:
        client = boto3.client('secretsmanager', region_name=region_name)
        response = client.get_secret_value(SecretId=secret_name)
        private_key_data = response['SecretString']
        
        os.makedirs(key_dir, mode=0o700, exist_ok=True)
        private_key_path = os.path.join(key_dir, "private.pem")
        
        with open(private_key_path, "w") as f:
            f.write(private_key_data)
        os.chmod(private_key_path, 0o600)
        
        print(f"✅ RSA private key retrieved from AWS and saved to {private_key_path}")
        return private_key_path
    except Exception as e:
        logging.error("AWS RSA key retrieval failed: %s", str(e))
        raise RuntimeError(f"AWS key retrieval failed: {str(e)}")

def retrieve_key_shares_from_aws(secret_name, region_name, key_shares_dir):
    """Retrieve key shares from AWS Secrets Manager."""
    try:
        client = boto3.client('secretsmanager', region_name=region_name)
        response = client.get_secret_value(SecretId=secret_name)
        secret_data = json.loads(response['SecretString'])
        
        os.makedirs(key_shares_dir, mode=0o700, exist_ok=True)
        
        for idx, parts in secret_data.items():
            part1 = base64.b64decode(parts['part1'])
            part2 = base64.b64decode(parts['part2'])
            
            part1_path = os.path.join(key_shares_dir, f"key_share_{idx}_part1.bin")
            part2_path = os.path.join(key_shares_dir, f"key_share_{idx}_part2.bin")
            
            with open(part1_path, "wb") as f:
                f.write(part1)
            with open(part2_path, "wb") as f:
                f.write(part2)
            
            os.chmod(part1_path, 0o600)
            os.chmod(part2_path, 0o600)
        
        print(f"✅ Key shares retrieved from AWS and saved to {key_shares_dir}")
        return key_shares_dir
    except Exception as e:
        logging.error("AWS key shares retrieval failed: %s", str(e))
        raise RuntimeError(f"AWS shares retrieval failed: {str(e)}")

def delete_local_keys(key_dir):
    """Securely delete all local keys and key shares."""
    try:
        private_path = os.path.join(key_dir, "private.pem")
        if os.path.exists(private_path):
            os.remove(private_path)
        
        public_path = os.path.join(key_dir, "public.pem")
        if os.path.exists(public_path):
            os.remove(public_path)
        
        shares_dir = os.path.join(key_dir, "key_shares")
        if os.path.exists(shares_dir):
            shutil.rmtree(shares_dir)
        
        print(f"🧹 Successfully deleted all keys in {key_dir}")
        logging.info("Local keys deleted from %s", key_dir)
    except Exception as e:
        logging.error("Key deletion failed: %s", str(e))
        raise RuntimeError(f"Key deletion failed: {str(e)}")

### TPM Integration Functions ###

def generate_tpm_rsa_key():
    """Open an existing TPM RSA key or create a new one if it doesn't exist, with decrypt usage."""
    ncrypt = ctypes.windll.ncrypt
    NCRYPT_PROV_HANDLE = ctypes.c_void_p
    NCRYPT_KEY_HANDLE = ctypes.c_void_p
    
    # Open the TPM provider
    hProvider = NCRYPT_PROV_HANDLE()
    provider_name = "Microsoft Platform Crypto Provider"
    provider_name_w = ctypes.create_unicode_buffer(provider_name)
    
    status = ncrypt.NCryptOpenStorageProvider(ctypes.byref(hProvider), provider_name_w, 0)
    if status != 0:
        raise Exception(f"NCryptOpenStorageProvider failed with error code: {status}")
    
    # Define key name and handle
    hKey = NCRYPT_KEY_HANDLE()
    key_name = "TPM_RSA_KEY"
    key_name_w = ctypes.create_unicode_buffer(key_name)
    
    # Try to open existing key
    status = ncrypt.NCryptOpenKey(hProvider, ctypes.byref(hKey), key_name_w, 0, 0)
    if status == 0:
        print("Using existing TPM RSA Key.")
        logging.info("Using existing TPM RSA Key.")
        return hProvider, hKey
    elif status == 0x8009000D:  # NTE_NO_KEY
        # Create a new key
        algorithm = "RSA"
        algorithm_w = ctypes.create_unicode_buffer(algorithm)
        status = ncrypt.NCryptCreatePersistedKey(hProvider, ctypes.byref(hKey), algorithm_w, key_name_w, 0, 0)
        if status != 0:
            raise Exception(f"NCryptCreatePersistedKey failed with error code: {status}")
        
        # Set key length to 2048 bits
        key_length = wintypes.DWORD(2048)
        status = ncrypt.NCryptSetProperty(hKey, "Length", ctypes.cast(ctypes.byref(key_length), ctypes.c_void_p), ctypes.sizeof(key_length), 0)
        if status != 0:
            raise Exception(f"NCryptSetProperty (Length) failed with error code: {status}")
        
        # Set key usage to allow decryption
        key_usage = wintypes.DWORD(0x00000001)  # NCRYPT_ALLOW_DECRYPT_FLAG = 1
        status = ncrypt.NCryptSetProperty(hKey, "KeyUsage", ctypes.cast(ctypes.byref(key_usage), ctypes.c_void_p), ctypes.sizeof(key_usage), 0)
        if status != 0:
            raise Exception(f"NCryptSetProperty (KeyUsage) failed with error code: {status}")
        
        # Finalize the key
        status = ncrypt.NCryptFinalizeKey(hKey, 0)
        if status != 0:
            raise Exception(f"NCryptFinalizeKey failed with error code: {status}")
        
        print("TPM RSA Key Created Successfully using TPM with decrypt usage.")
        logging.info("TPM RSA Key Created Successfully using TPM with decrypt usage.")
        return hProvider, hKey
    else:
        raise Exception(f"NCryptOpenKey failed with error code: {status}")

def tpm_encrypt_with_key(hKey, data):
    """Encrypt data using the TPM RSA key with OAEP padding."""
    ncrypt = ctypes.windll.ncrypt
    if not hKey.value:
        raise Exception("Invalid hKey: Handle is NULL")
    
    print(f"Encrypting data of size {len(data)} bytes with hKey={hKey.value}")
    
    # Set up OAEP padding with SHA1
    padding_info = BCRYPT_OAEP_PADDING_INFO()
    padding_info.pszAlgId = u"SHA1"
    padding_info.pbLabel = None
    padding_info.cbLabel = 0
    
    # Prepare input buffer
    input_buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    pcbResult = wintypes.DWORD(0)
    
    # First call: Determine the size of the encrypted data
    status = ncrypt.NCryptEncrypt(
        hKey,
        input_buffer,
        len(data),
        ctypes.byref(padding_info),
        None,
        0,
        ctypes.byref(pcbResult),
        4  # NCRYPT_PAD_OAEP_FLAG
    )
    if status != 0:
        raise Exception(f"NCryptEncrypt (size determination) failed with error code: {status}")
    
    # Allocate output buffer and encrypt
    buffer_size = pcbResult.value
    output_buffer = (ctypes.c_ubyte * buffer_size)()
    pcbResult = wintypes.DWORD(buffer_size)
    
    status = ncrypt.NCryptEncrypt(
        hKey,
        input_buffer,
        len(data),
        ctypes.byref(padding_info),
        output_buffer,
        buffer_size,
        ctypes.byref(pcbResult),
        4  # NCRYPT_PAD_OAEP_FLAG
    )
    if status != 0:
        raise Exception(f"NCryptEncrypt failed with error code: {status}")
    
    encrypted_data = bytes(output_buffer[:pcbResult.value])
    return encrypted_data

def tpm_decrypt_with_key(hKey, encrypted_data):
    """Decrypt data using the TPM RSA key with OAEP padding."""
    ncrypt = ctypes.windll.ncrypt
    if not hKey.value:
        raise Exception("Invalid hKey: Handle is NULL")
    
    # Set up OAEP padding with SHA1
    padding_info = BCRYPT_OAEP_PADDING_INFO()
    padding_info.pszAlgId = u"SHA1"
    padding_info.pbLabel = None
    padding_info.cbLabel = 0
    
    input_buffer = (ctypes.c_ubyte * len(encrypted_data)).from_buffer_copy(encrypted_data)
    pcbResult = wintypes.DWORD(0)
    
    # First call: Determine the size of the decrypted data
    status = ncrypt.NCryptDecrypt(
        hKey,
        input_buffer,
        len(encrypted_data),
        ctypes.byref(padding_info),
        None,
        0,
        ctypes.byref(pcbResult),
        4  # NCRYPT_PAD_OAEP_FLAG
    )
    if status != 0:
        raise Exception(f"NCryptDecrypt (size determination) failed with error code: {status}")
    
    # Allocate output buffer and decrypt
    buffer_size = pcbResult.value
    output_buffer = (ctypes.c_ubyte * buffer_size)()
    pcbResult = wintypes.DWORD(buffer_size)
    
    status = ncrypt.NCryptDecrypt(
        hKey,
        input_buffer,
        len(encrypted_data),
        ctypes.byref(padding_info),
        output_buffer,
        buffer_size,
        ctypes.byref(pcbResult),
        4  # NCRYPT_PAD_OAEP_FLAG
    )
    if status != 0:
        raise Exception(f"NCryptDecrypt failed with error code: {status}")
    
    decrypted_data = bytes(output_buffer[:pcbResult.value])
    return decrypted_data

def tpm_encrypt_key_shares(key_shares, tpm_key_handles, key_shares_dir):
    """Encrypt key shares using TPM RSA key."""
    logging.info("Encrypting key shares with TPM RSA key")
    hProvider, hKey = tpm_key_handles
    os.makedirs(key_shares_dir, mode=0o700, exist_ok=True)
    
    for idx, share_part1, share_part2 in key_shares:
        encrypted_share_part1 = tpm_encrypt_with_key(hKey, share_part1)
        encrypted_share_part2 = tpm_encrypt_with_key(hKey, share_part2)
        
        for part, data in [("part1", encrypted_share_part1), ("part2", encrypted_share_part2)]:
            share_path = os.path.join(key_shares_dir, f"key_share_{idx}_{part}.bin")
            with open(share_path, "wb") as f:
                f.write(data)
            os.chmod(share_path, 0o600)

def tpm_decrypt_key_shares(tpm_key_handles, key_shares_dir):
    """Decrypt key shares using TPM RSA key."""
    logging.info("Decrypting key shares using TPM")
    hProvider, hKey = tpm_key_handles
    key_shares_part1 = []
    key_shares_part2 = []
    
    for idx in range(1, 6):
        part1_path = os.path.join(key_shares_dir, f"key_share_{idx}_part1.bin")
        part2_path = os.path.join(key_shares_dir, f"key_share_{idx}_part2.bin")
        
        if os.path.exists(part1_path) and os.path.exists(part2_path):
            try:
                with open(part1_path, "rb") as f:
                    encrypted_share_part1 = f.read()
                with open(part2_path, "rb") as f:
                    encrypted_share_part2 = f.read()
                
                decrypted_share_part1 = tpm_decrypt_with_key(hKey, encrypted_share_part1)
                decrypted_share_part2 = tpm_decrypt_with_key(hKey, encrypted_share_part2)
                
                key_shares_part1.append((idx, decrypted_share_part1))
                key_shares_part2.append((idx, decrypted_share_part2))
            except Exception as e:
                logging.warning(f"Failed to decrypt key share {idx} using TPM: {str(e)}")
                delete_one_key_share(key_shares_dir)
                remaining_shares = len([f for f in os.listdir(key_shares_dir) if f.startswith("key_share_") and f.endswith("_part1.bin")])
                if remaining_shares < MIN_SHARES:
                    logging.critical("Insufficient key shares remaining after TPM decryption failure.")
                    raise RuntimeError("Insufficient key shares remaining after TPM decryption failure.")
                else:
                    logging.info("Deleted one key share. %d shares remaining.", remaining_shares)
                raise RuntimeError(f"Failed to decrypt key share {idx} using TPM: {str(e)}")
    
    if len(key_shares_part1) < MIN_SHARES or len(key_shares_part2) < MIN_SHARES:
        raise ValueError("Insufficient shares for recovery")
    
    part1 = Shamir.combine(key_shares_part1[:MIN_SHARES])
    part2 = Shamir.combine(key_shares_part2[:MIN_SHARES])
    master_key = bytearray(part1 + part2)
    master_mv = memoryview(master_key)
    
    content_key = bytearray(HKDF(master_mv, 32, salt=b"content-salt", hashmod=SHA256, context=b"file-content-encryption"))
    filename_key = bytearray(HKDF(master_mv, 32, salt=b"filename-salt", hashmod=SHA256, context=b"filename-encryption"))
    metadata_key = bytearray(HKDF(master_mv, 32, salt=b"metadata-salt", hashmod=SHA256, context=b"metadata-encryption"))
    
    zero_out_key(master_key)
    return content_key, filename_key, metadata_key

### Hybrid Approach: TPM + AWS Cloud Backup ###

def hybrid_encrypt_key_shares(key_shares, tpm_key_handles, local_key_shares_dir, aws_secret_name, region_name="us-east-1"):
    """Encrypt key shares using TPM and then back them up to AWS Secrets Manager."""
    tpm_encrypt_key_shares(key_shares, tpm_key_handles, local_key_shares_dir)
    store_key_shares_in_aws_secret_manager(local_key_shares_dir, aws_secret_name, region_name)
    print("Hybrid encryption of key shares completed: TPM secured locally and backed up to AWS.")

def hybrid_decrypt_key_shares(tpm_key_handles, local_key_shares_dir, aws_secret_name, region_name="us-east-1"):
    """Decrypt key shares using TPM. If local decryption fails, retrieve shares from AWS and try again."""
    try:
        return tpm_decrypt_key_shares(tpm_key_handles, local_key_shares_dir)
    except Exception as e:
        print("Local TPM decryption failed, attempting AWS retrieval...")
        retrieve_key_shares_from_aws(aws_secret_name, region_name, local_key_shares_dir)
        return tpm_decrypt_key_shares(tpm_key_handles, local_key_shares_dir)

def encrypt_folder_parallel_hybrid(folder_path, encrypted_folder, tpm_key_handles, local_key_shares_dir, aws_secret_name, region_name="us-east-1"):
    """Parallel folder encryption using hybrid approach: TPM for local protection and AWS backup."""
    start_time = time.time()
    logging.info("Starting hybrid encryption of folder: %s to %s", folder_path, encrypted_folder)
    content_key, filename_key, metadata_key, key_shares = generate_ephemeral_key()
    os.makedirs(encrypted_folder, mode=0o700, exist_ok=True)
    
    metadata = {}
    files_to_encrypt = []
    real_folder_path = os.path.realpath(folder_path)

    for root, _, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            real_file_path = os.path.realpath(file_path)
            if not real_file_path.startswith(real_folder_path):
                continue
            relative_path = os.path.relpath(file_path, folder_path)
            stat_info = os.stat(file_path)
            encrypted_name = encrypt_filename(filename_key, file_path)
            short_name = hashlib.sha256(encrypted_name.encode()).hexdigest()
            encrypted_file_path = os.path.join(encrypted_folder, short_name)
            metadata[short_name] = {
                'relative_path': relative_path,
                'st_mtime': stat_info.st_mtime,
                'st_atime': stat_info.st_atime,
                'st_mode': stat_info.st_mode,
                'original_encrypted_name': encrypted_name
            }
            files_to_encrypt.append((file_path, encrypted_file_path, memoryview(content_key)))

    with ThreadPoolExecutor(max_workers=memory_safe_process_count()) as executor:
        list(tqdm(executor.map(encrypt_file_wrapper, files_to_encrypt), total=len(files_to_encrypt), desc="Encrypting files"))
    
    encrypt_metadata(metadata, metadata_key, encrypted_folder)
    hybrid_encrypt_key_shares(key_shares, tpm_key_handles, local_key_shares_dir, aws_secret_name, region_name)
    
    for key in [content_key, filename_key, metadata_key]:
        if key is not None:
            zero_out_key(key)
    logging.info("Hybrid encryption completed in %.2f seconds", time.time() - start_time)

def decrypt_folder_hybrid(encrypted_folder, decrypted_folder, local_key_shares_dir, aws_secret_name, tpm_key_handles, region_name="us-east-1"):
    """Folder decryption using the hybrid approach."""
    start_time = time.time()
    logging.info("Starting hybrid decryption of folder: %s to %s", encrypted_folder, decrypted_folder)
    content_key, filename_key, metadata_key = hybrid_decrypt_key_shares(tpm_key_handles, local_key_shares_dir, aws_secret_name, region_name)
    try:
        metadata = decrypt_metadata(metadata_key, encrypted_folder)
    except RuntimeError as e:
        logging.error("Metadata decryption failed: %s", str(e))
        print("🚨 Warning: Incorrect key or tampered metadata detected.")
        raise

    file_list = []
    total_size = 0
    for short_name, info in metadata.items():
        src = os.path.join(encrypted_folder, short_name)
        dst = os.path.join(decrypted_folder, info['relative_path'])
        if not os.path.exists(src):
            logging.warning("Encrypted file missing: %s", src)
            continue
        file_size = os.path.getsize(src)
        file_list.append((src, dst, file_size))
        total_size += file_size
    
    os.makedirs(decrypted_folder, mode=0o700, exist_ok=True)
    dirs_to_create = {os.path.dirname(dst) for _, dst, _ in file_list}
    for d in dirs_to_create:
        os.makedirs(d, exist_ok=True)
    
    num_workers = memory_safe_process_count()
    print(f"🔧 Using {num_workers} workers with adaptive batch sizing")
    
    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        current_batch = []
        current_batch_size = 0
        for src, dst, size in sorted(file_list, key=lambda x: x[2]):
            if current_batch_size + size > 1024*1024*500:
                encrypted_batch = [i[0] for i in current_batch]
                decrypted_batch = [i[1] for i in current_batch]
                executor.submit(decrypt_file_batch, encrypted_batch, decrypted_batch, memoryview(content_key))
                current_batch = []
                current_batch_size = 0
            current_batch.append((src, dst, size))
            current_batch_size += size
        
        if current_batch:
            encrypted_batch = [i[0] for i in current_batch]
            decrypted_batch = [i[1] for i in current_batch]
            executor.submit(decrypt_file_batch, encrypted_batch, decrypted_batch, memoryview(content_key))
    
    missing = [dst for _, dst, _ in file_list if not os.path.exists(dst)]
    if missing:
        logging.error("Missing %d files after decryption", len(missing))
        raise RuntimeError(f"Missing {len(missing)} files after decryption")
    
    for short_name, info in metadata.items():
        dst = os.path.join(decrypted_folder, info['relative_path'])
        if os.path.exists(dst):
            try:
                os.chmod(dst, info['st_mode'] & 0o777)
            except Exception as e:
                logging.warning("Couldn’t set permissions for %s: %s", dst, str(e))
                print(f"⚠️ Couldn’t set permissions for {dst}: {str(e)}")
    for key in [content_key, filename_key, metadata_key]:
        if key is not None:
            zero_out_key(key)
    logging.info("Hybrid decryption completed in %.2f seconds", time.time() - start_time)
    logging.info("Processed %d files, total size %.2f MB", len(file_list), total_size / 1024 / 1024)

def display_menu():
    """Display interactive menu."""
    print("\n=== Echelon X Pre-Release Build ===")
    print("1.  Encrypt folder")
    print("2.  Decrypt with local keys")
    print("3.  Generate RSA keys")
    print("4.  Store RSA key in AWS")
    print("5.  Store shares in AWS")
    print("6.  Get RSA key from AWS")
    print("7.  Get shares from AWS")
    print("8.  Delete local keys")
    print("9.  Decrypt using AWS keys")
    print("10. Exit")
    print("11. Encrypt folder with TPM")
    print("12. Decrypt with TPM keys")
    print("13. Encrypt folder with Hybrid TPM+AWS")
    print("14. Decrypt folder with Hybrid TPM+AWS")
    return input("Enter choice (1-14): ").strip()

if __name__ == '__main__':
    while True:
        choice = display_menu()
        
        if choice == '1':
            start_time = time.time()
            src = input("Folder to encrypt: ").strip()
            dest = input("Encrypted output folder: ").strip()
            key_dir = input("Key storage directory: ").strip()
            generate_rsa_keys(
                os.path.join(key_dir, "private.pem"),
                os.path.join(key_dir, "public.pem")
            )
            encrypt_folder_parallel(
                src, dest,
                os.path.join(key_dir, "public.pem"),
                os.path.join(key_dir, "key_shares")
            )
            print(f"🕒 Encryption completed in {time.time() - start_time:.2f} seconds")
        
        elif choice == '2':
            start_time = time.time()
            src = input("Encrypted folder: ").strip()
            dest = input("Decryption output folder: ").strip()
            key_dir = input("Key directory: ").strip()
            decrypt_folder(
                src, dest,
                os.path.join(key_dir, "key_shares"),
                os.path.join(key_dir, "private.pem")
            )
            print(f"🕒 Decryption completed in {time.time() - start_time:.2f} seconds")
        
        elif choice == '3':
            key_dir = input("Key output directory: ").strip()
            generate_rsa_keys(
                os.path.join(key_dir, "private.pem"),
                os.path.join(key_dir, "public.pem")
            )
        
        elif choice == '4':
            key_dir = input("Key directory (where private.pem is located): ").strip()
            secret_name = input("Enter AWS Secret Name for RSA key: ").strip()
            region = input("Enter AWS Region (default us-east-1): ").strip()
            if not region:
                region = "us-east-1"
            store_rsa_keys_in_aws_secret_manager(key_dir, secret_name, region)
        
        elif choice == '5':
            key_shares_dir = input("Key shares directory: ").strip()
            secret_name = input("Enter AWS Secret Name for key shares: ").strip()
            region = input("Enter AWS Region (default us-east-1): ").strip()
            if not region:
                region = "us-east-1"
            store_key_shares_in_aws_secret_manager(key_shares_dir, secret_name, region)
        
        elif choice == '6':
            key_dir = input("Key output directory: ").strip()
            secret_name = input("AWS secret name for RSA key: ").strip()
            region = input("AWS region (default us-east-1): ").strip() or "us-east-1"
            retrieve_rsa_key_from_aws(secret_name, region, key_dir)
        
        elif choice == '7':
            key_dir = input("Key shares directory: ").strip()
            secret_name = input("AWS secret name for shares: ").strip()
            region = input("AWS region (default us-east-1): ").strip() or "us-east-1"
            retrieve_key_shares_from_aws(secret_name, region, os.path.join(key_dir, "key_shares"))
        
        elif choice == '8':
            key_dir = input("Key directory to clean: ").strip()
            delete_local_keys(key_dir)
        
        elif choice == '9':
            start_time = time.time()
            src = input("Encrypted folder: ").strip()
            dest = input("Decrypted output folder: ").strip()
            temp_key_dir = input("Temporary key directory: ").strip()
            key_secret = input("AWS secret name for RSA key: ").strip()
            shares_secret = input("AWS secret name for shares: ").strip()
            region = input("AWS region (default us-east-1): ").strip() or "us-east-1"
            
            try:
                retrieve_rsa_key_from_aws(key_secret, region, temp_key_dir)
                retrieve_key_shares_from_aws(
                    shares_secret, region,
                    os.path.join(temp_key_dir, "key_shares")
                )
                
                decrypt_folder(
                    src, dest,
                    os.path.join(temp_key_dir, "key_shares"),
                    os.path.join(temp_key_dir, "private.pem")
                )
                
                delete_local_keys(temp_key_dir)
                print(f"🕒 AWS decryption completed in {time.time() - start_time:.2f} seconds")
            
            except Exception as e:
                print(f"❌ Decryption failed: {str(e)}")
                if os.path.exists(temp_key_dir):
                    delete_local_keys(temp_key_dir)
        
        elif choice == '10':
            print("🚪 Exiting securely!")
            break
        
        elif choice == '11':
            start_time = time.time()
            src = input("Folder to encrypt: ").strip()
            dest = input("Encrypted output folder: ").strip()
            key_dir = input("Key storage directory for TPM key shares: ").strip()
            tpm_key_handles = generate_tpm_rsa_key()  # Use existing key or create new if not exists
            encrypt_folder_parallel_tpm(
                src, dest,
                tpm_key_handles,
                os.path.join(key_dir, "key_shares")
            )
            print(f"🕒 TPM-based encryption completed in {time.time() - start_time:.2f} seconds")
        
        elif choice == '12':
            start_time = time.time()
            src = input("Encrypted folder: ").strip()
            dest = input("Decrypted output folder: ").strip()
            key_dir = input("Key shares directory for TPM key shares: ").strip()
            tpm_key_handles = generate_tpm_rsa_key()  # Use existing key
            decrypt_folder_tpm(
                src, dest,
                os.path.join(key_dir, "key_shares"),
                tpm_key_handles
            )
            print(f"🕒 TPM-based decryption completed in {time.time() - start_time:.2f} seconds")
        
        elif choice == '13':
            start_time = time.time()
            src = input("Folder to encrypt: ").strip()
            dest = input("Encrypted output folder: ").strip()
            key_dir = input("Local key shares directory for Hybrid mode: ").strip()
            aws_secret = input("AWS secret name for key shares backup: ").strip()
            region = input("AWS region (default us-east-1): ").strip() or "us-east-1"
            tpm_key_handles = generate_tpm_rsa_key()  # Use existing key or create new if not exists
            encrypt_folder_parallel_hybrid(
                src, dest,
                tpm_key_handles,
                os.path.join(key_dir, "key_shares"),
                aws_secret,
                region
            )
            print(f"🕒 Hybrid (TPM+AWS) encryption completed in {time.time() - start_time:.2f} seconds")
        
        elif choice == '14':
            start_time = time.time()
            src = input("Encrypted folder: ").strip()
            dest = input("Decrypted output folder: ").strip()
            key_dir = input("Local key shares directory for Hybrid mode: ").strip()
            aws_secret = input("AWS secret name for key shares backup: ").strip()
            region = input("AWS region (default us-east-1): ").strip() or "us-east-1"
            tpm_key_handles = generate_tpm_rsa_key()  # Use existing key
            decrypt_folder_hybrid(
                src, dest,
                os.path.join(key_dir, "key_shares"),
                aws_secret,
                tpm_key_handles,
                region
            )
            print(f"🕒 Hybrid (TPM+AWS) decryption completed in {time.time() - start_time:.2f} seconds")
        
        else:
            print("❌ Invalid choice")