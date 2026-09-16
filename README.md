# AES Implementation Laboratory

This project implements the Advanced Encryption Standard (AES) from scratch in Python.

The implementation supports:

- AES-128
- AES-192
- AES-256

No cryptographic library is used for the AES core implementation.

---

## Project Structure

```text
AES_lab/
├── aes/
│   ├── __init__.py
│   ├── aes.py
│   ├── aes_tables.py
│   ├── key_schedule.py
│   └── transformations.py
│
├── tests/
│   ├── __init__.py
│   ├── test_aes.py
│   ├── test_key_schedule.py
│   └── test_transformations.py
│
├── benchmarks/
│   ├── __init__.py
│   └── benchmark.py
│
├── README.md
└── benchmark_results.csv
```

---

## AES Components

The implementation includes the main AES transformations:

- SubBytes
- InvSubBytes
- ShiftRows
- InvShiftRows
- MixColumns
- InvMixColumns
- AddRoundKey
- Key Expansion
- Encryption
- Decryption

AES always operates on 128-bit blocks.

The supported key sizes and number of rounds are:

| AES Version | Key Size | Number of Rounds |
|---|---:|---:|
| AES-128 | 128 bits | 10 |
| AES-192 | 192 bits | 12 |
| AES-256 | 256 bits | 14 |

---

## Implementation

### `aes_tables.py`

Contains the AES constants used by the implementation:

- S-Box
- Inverse S-Box
- Round Constants (Rcon)
- MixColumns constants

### `transformations.py`

Contains the AES transformations and finite-field operations.

The `gf_mult()` function performs byte multiplication in `GF(2^8)` using the AES irreducible polynomial.

It also contains functions to convert between a 16-byte block and the AES 4x4 State matrix.

### `key_schedule.py`

Implements the AES key expansion algorithm.

The original key is expanded into round keys depending on the selected AES version:

- AES-128: 11 round keys
- AES-192: 13 round keys
- AES-256: 15 round keys

### `aes.py`

Contains the complete AES encryption and decryption procedures.

Encryption applies:

1. Initial AddRoundKey
2. Main AES rounds
3. Final AES round without MixColumns

Decryption applies the inverse transformations using the round keys in reverse order.

---

## Validation

The implementation was validated with recognized AES test vectors for AES-128, AES-192, and AES-256.

Test plaintext:

```text
00112233445566778899aabbccddeeff
```

Expected results:

| AES Version | Expected Ciphertext |
|---|---|
| AES-128 | `69c4e0d86a7b0430d8cdb78070b4c55a` |
| AES-192 | `dda97ca4864cdfe06eaf70a0ec0d7191` |
| AES-256 | `8ea2b7ca516745bfeafc49904b496089` |

All three encryption tests matched the expected ciphertexts.

Decryption was also verified by checking that:

```text
Decrypt(Encrypt(plaintext)) = plaintext
```

for AES-128, AES-192, and AES-256.

---

## Automated Tests

The test suite checks:

- AES-128 encryption and decryption
- AES-192 encryption and decryption
- AES-256 encryption and decryption
- Key expansion for the three key sizes
- Finite-field multiplication
- State conversion
- SubBytes / InvSubBytes
- ShiftRows / InvShiftRows
- MixColumns / InvMixColumns

Run all tests from the project root:

```bash
python3 -m unittest discover -s tests -v
```

Current result:

```text
Ran 11 tests

OK
```

---

## Benchmark

The benchmark evaluates the performance of:

- AES-128
- AES-192
- AES-256

using different input sizes:

- 1 MB
- 10 MB
- 100 MB

Both encryption and decryption are measured.

Each experiment is repeated three times.

The benchmark records:

- Encryption time
- Decryption time
- Encryption throughput in MB/s
- Decryption throughput in MB/s

Run the benchmark with:

```bash
python3 -m benchmarks.benchmark
```

The benchmark results are stored in:

```text
benchmark_results.csv
```

---

## Notes

The AES implementation is written completely in Python for educational purposes.

The objective is to understand the internal operations of AES, including finite-field arithmetic, transformations, key expansion, encryption, and decryption.

The implementation is not intended to replace optimized cryptographic libraries for production systems.
