import unittest

from aes.aes import aes_encrypt, aes_decrypt


class TestAES(unittest.TestCase):
    def setUp(self):
        self.plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    def test_aes_128(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        expected_ciphertext = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        ciphertext = aes_encrypt(self.plaintext,key)
        recovered = aes_decrypt(ciphertext,key)
        self.assertEqual(ciphertext,expected_ciphertext)
        self.assertEqual(recovered,self.plaintext)

    def test_aes_192(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f"
            "1011121314151617")
        expected_ciphertext = bytes.fromhex("dda97ca4864cdfe06eaf70a0ec0d7191")
        ciphertext = aes_encrypt(self.plaintext,key)
        recovered = aes_decrypt(ciphertext,key)
        self.assertEqual(ciphertext,expected_ciphertext)
        self.assertEqual(recovered,self.plaintext)

    def test_aes_256(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f")
        expected_ciphertext = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
        ciphertext = aes_encrypt(self.plaintext,key)
        recovered = aes_decrypt(ciphertext,key)
        self.assertEqual(ciphertext,expected_ciphertext)
        self.assertEqual(recovered,self.plaintext)
if __name__ == "__main__":
    unittest.main()