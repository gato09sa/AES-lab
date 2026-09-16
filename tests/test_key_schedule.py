import unittest

from aes.key_schedule import (
    key_expansion,
    get_round_keys
)

class TestKeySchedule(unittest.TestCase):

    def test_aes_128_key_schedule(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        schedule = key_expansion(key)
        round_keys = get_round_keys(schedule)
        self.assertEqual(len(schedule), 44)
        self.assertEqual(len(round_keys), 11)

    def test_aes_192_key_schedule(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f"
            "1011121314151617")
        schedule = key_expansion(key)
        round_keys = get_round_keys(schedule)
        self.assertEqual(len(schedule), 52)
        self.assertEqual(len(round_keys), 13)

    def test_aes_256_key_schedule(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f")
        schedule = key_expansion(key)
        round_keys = get_round_keys(schedule)
        self.assertEqual(len(schedule), 60)
        self.assertEqual(len(round_keys), 15)

if __name__ == "__main__":
    unittest.main()