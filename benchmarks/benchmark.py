import time
import csv

from aes.aes import (aes_encrypt_with_round_keys,aes_decrypt_with_round_keys)
from aes.key_schedule import (key_expansion,get_round_keys)
# Keys for AES-128, AES-192 and AES-256
KEYS = {"AES-128": bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f"),
    "AES-192": bytes.fromhex("000102030405060708090a0b0c0d0e0f"
        "1011121314151617"),
    "AES-256": bytes.fromhex("000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f")
}
# Data sizes required by the laboratory
SIZES_MB = [1]
# Each experiment must be repeated at least 3 times
REPETITIONS = 3
BLOCK_SIZE = 16

def encrypt_data(data, round_keys):
    """Encrypt all 16-byte blocks in data."""
    ciphertext = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i + BLOCK_SIZE]
        encrypted_block = aes_encrypt_with_round_keys(block,round_keys)
        ciphertext.extend(encrypted_block)
    return bytes(ciphertext)

def decrypt_data(data, round_keys):
    """Decrypt all 16-byte blocks in data."""
    plaintext = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i + BLOCK_SIZE]
        decrypted_block = aes_decrypt_with_round_keys(block,round_keys)
        plaintext.extend(decrypted_block)
    return bytes(plaintext)

def run_benchmark():
    results = []
    for aes_version, key in KEYS.items():
        print(f"\n===== {aes_version} =====")
        # Key expansion is performed once per AES version
        key_schedule = key_expansion(key)
        round_keys = get_round_keys(key_schedule)
        for size_mb in SIZES_MB:
            print(f"\nData size: {size_mb} MB")
            # 1 MB = 1024 * 1024 bytes
            data = bytes(size_mb * 1024 * 1024)
            for run in range(1, REPETITIONS + 1):
                print(f"Run {run}/{REPETITIONS}")
                # Encryption benchmark
                start = time.perf_counter()
                ciphertext = encrypt_data(data,round_keys)
                encryption_time = time.perf_counter() - start
                encryption_throughput = (size_mb / encryption_time)
                # Decryption benchmark
                start = time.perf_counter()
                recovered = decrypt_data(ciphertext,round_keys)
                decryption_time = time.perf_counter() - start
                decryption_throughput = (size_mb / decryption_time)
                # Verify correctness
                if recovered != data:
                    raise ValueError("Decryption did not recover original data")
                print(f"Encrypt: {encryption_time:.4f} s "
                    f"({encryption_throughput:.4f} MB/s)")
                print(f"Decrypt: {decryption_time:.4f} s "
                    f"({decryption_throughput:.4f} MB/s)")
                results.append([aes_version,size_mb,run,encryption_time,decryption_time,
                                encryption_throughput,decryption_throughput])
    # Save results to CSV
    with open("benchmark_results.csv","w",newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["AES Version","Data Size (MB)","Run","Encryption Time (s)",
                         "Decryption Time (s)","Encryption Throughput (MB/s)","Decryption Throughput (MB/s)"])
        writer.writerows(results)
    print("\nBenchmark completed.")
    print("Results saved in benchmark_results.csv")

if __name__ == "__main__":
    run_benchmark()