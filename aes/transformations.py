from .aes_tables import S_BOX, INV_S_BOX

# Functions to convert between a 4x4 matrix and a 16-byte array.
def bytes_to_state(data): 
    """Convert a 16-byte array into a 4x4 matrix."""
    return [[data[i + 4 * j] for j in range(4)] for i in range(4)]

def state_to_bytes(state):
    """Convert a 4x4 matrix into a 16-byte array."""
    return bytes([state[i][j] for j in range(4) for i in range(4)])

# AES functions     
def sub_bytes(state):
    """Apply the S-Box to each byte of the state."""
    for row in range(4):
        for col in range(4):
            state[row][col] = S_BOX[state[row][col]]
    return state
# ShiftRows function shifts the rows of the state to the left. 
# The first row is not shifted, the second row is shifted by 1, 
# the third row by 2, and the fourth row by 3.
def shift_rows(state):
    """Shift the rows of the state to the left."""
    for row in range(1, 4):
        state[row] = state[row][row:] + state[row][:row]
    return state

def gf_mult(a, b):
    """Multiply two bytes in GF(2^8) using the AES polynomial."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit_set:
            a ^= 0x1B #AES polynomial x^8 + x^4 + x^3 + x + 1
        b >>= 1
    return p

def mix_columns(state):
    """Mix the columns of the state using the AES polynomial."""
    for col in range(4):
        a = state[0][col]
        b = state[1][col]
        c = state[2][col]
        d = state[3][col]
        state[0][col] = gf_mult(a, 2) ^ gf_mult(b, 3) ^ c ^ d
        state[1][col] = a ^ gf_mult(b, 2) ^ gf_mult(c, 3) ^ d
        state[2][col] = a ^ b ^ gf_mult(c, 2) ^ gf_mult(d, 3)
        state[3][col] = gf_mult(a, 3) ^ b ^ c ^ gf_mult(d, 2)
    return state

def add_round_key(state, round_key):
    """XOR the state with the round key."""
    for row in range(4):
        for col in range(4):
            state[row][col] ^= round_key[row][col]
    return state

def inv_sub_bytes(state):
    """Apply the inverse S-Box to each byte of the state."""
    for row in range(4):
        for col in range(4):
            state[row][col] = INV_S_BOX[state[row][col]]
    return state

def inv_shift_rows(state):
    """Shift the rows of the state to the right (inverse of ShiftRows)."""
    for row in range(1, 4):
        state[row] = state[row][-row:] + state[row][:-row]
    return state

def inv_mix_columns(state):
    """Inverse MixColumns transformation."""
    for col in range(4):
        a = state[0][col]
        b = state[1][col]
        c = state[2][col]
        d = state[3][col]
        state[0][col] = gf_mult(a, 0x0e) ^ gf_mult(b, 0x0b) ^ gf_mult(c, 0x0d) ^ gf_mult(d, 0x09)
        state[1][col] = gf_mult(a, 0x09) ^ gf_mult(b, 0x0e) ^ gf_mult(c, 0x0b) ^ gf_mult(d, 0x0d)
        state[2][col] = gf_mult(a, 0x0d) ^ gf_mult(b, 0x09) ^ gf_mult(c, 0x0e) ^ gf_mult(d, 0x0b)
        state[3][col] = gf_mult(a, 0x0b) ^ gf_mult(b, 0x0d) ^ gf_mult(c, 0x09) ^ gf_mult(d, 0x0e)
    return state