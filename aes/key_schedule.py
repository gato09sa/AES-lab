from .aes_tables import S_BOX, RCON

def rot_word(word):
    """Rotate a 4-byte word one position to the left."""
    return [word[1], word[2], word[3], word[0]]
def sub_word(word):
    """Apply the AES S-Box to each byte of a 4-byte word."""
    result = []
    for byte in word:
        result.append(S_BOX[byte])
    return result

def key_expansion(key):
    """Expand AES-128, AES-192, or AES-256 key."""
    # Number of words in the original key
    Nk = len(key) // 4
    if Nk == 4:
        Nr = 10       # AES-128
    elif Nk == 6:
        Nr = 12       # AES-192
    elif Nk == 8:
        Nr = 14       # AES-256
    else:
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    # AES always uses 4 words per round key
    total_words = 4 * (Nr + 1)
    key_schedule = []
    # Divide the original key into words
    for i in range(0, len(key), 4):
        word = [
            key[i],
            key[i + 1],
            key[i + 2],
            key[i + 3]
        ]
        key_schedule.append(word)
    # Generate the remaining words
    for i in range(Nk, total_words):
        temp = key_schedule[i - 1].copy()
        # Special transformation every Nk words
        if i % Nk == 0:
            temp = rot_word(temp)
            temp = sub_word(temp)
            rcon_index = (i // Nk) - 1
            temp[0] ^= RCON[rcon_index]
        # AES-256 has one additional SubWord operation
        elif Nk == 8 and i % Nk == 4:
            temp = sub_word(temp)
        new_word = []
        for j in range(4):
            new_byte = key_schedule[i - Nk][j] ^ temp[j]
            new_word.append(new_byte)
        key_schedule.append(new_word)
    return key_schedule

def get_round_keys(key_schedule):
    """Convert expanded words into 128-bit round keys."""
    round_keys = []
    # Every 4 words form one round key
    number_of_round_keys = len(key_schedule) // 4
    for i in range(number_of_round_keys):
        w0 = key_schedule[4 * i]
        w1 = key_schedule[4 * i + 1]
        w2 = key_schedule[4 * i + 2]
        w3 = key_schedule[4 * i + 3]
        round_key = [
            [w0[0], w1[0], w2[0], w3[0]],
            [w0[1], w1[1], w2[1], w3[1]],
            [w0[2], w1[2], w2[2], w3[2]],
            [w0[3], w1[3], w2[3], w3[3]]
        ]
        round_keys.append(round_key)
    return round_keys