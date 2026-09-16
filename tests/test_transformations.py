import unittest

from aes.transformations import (
    bytes_to_state,
    state_to_bytes,
    sub_bytes,
    inv_sub_bytes,
    shift_rows,
    inv_shift_rows,
    mix_columns,
    inv_mix_columns,
    gf_mult
)

class TestTransformations(unittest.TestCase):
    def setUp(self):
        self.data = bytes.fromhex("00112233445566778899aabbccddeeff")

    def test_state_conversion(self):
        state = bytes_to_state(self.data)
        recovered = state_to_bytes(state)
        self.assertEqual(recovered, self.data)

    def test_gf_mult(self):
        # Examples from the AES lecture
        self.assertEqual(gf_mult(0x25, 0x02), 0x4A)
        self.assertEqual(gf_mult(0x25, 0x03), 0x6F)

    def test_sub_bytes_inverse(self):
        state = bytes_to_state(self.data)
        sub_bytes(state)
        inv_sub_bytes(state)
        recovered = state_to_bytes(state)
        self.assertEqual(recovered, self.data)

    def test_shift_rows_inverse(self):
        state = bytes_to_state(self.data)
        shift_rows(state)
        inv_shift_rows(state)
        recovered = state_to_bytes(state)
        self.assertEqual(recovered, self.data)
        
    def test_mix_columns_inverse(self):
        state = bytes_to_state(self.data)
        mix_columns(state)
        inv_mix_columns(state)
        recovered = state_to_bytes(state)
        self.assertEqual(recovered, self.data)

if __name__ == "__main__":
    unittest.main()