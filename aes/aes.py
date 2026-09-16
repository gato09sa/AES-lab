from .transformations import (
    bytes_to_state,
    state_to_bytes,
    sub_bytes,
    shift_rows,
    mix_columns,
    add_round_key, 
    inv_sub_bytes,
    inv_shift_rows,
    inv_mix_columns
)

from .key_schedule import (
    get_round_keys,
    key_expansion
)

def aes_encrypt(plaintext, key):
    """Encrypt one 16-byte block using AES."""
    state = bytes_to_state(plaintext)
    # Generate the round keys
    key_schedule = key_expansion(key)
    round_keys = get_round_keys(key_schedule)
    # Number of AES rounds
    Nr = len(round_keys) - 1
    # Initial AddRoundKey
    state = add_round_key(state, round_keys[0])
    # Main rounds
    for round_num in range(1, Nr):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(
            state,round_keys[round_num])
    # Final round without MixColumns
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(
        state,round_keys[Nr])
    return state_to_bytes(state)

def aes_decrypt(ciphertext, key):
    """Decrypt one 16-byte block using AES."""
    state = bytes_to_state(ciphertext)
    # Generate the round keys
    key_schedule = key_expansion(key)
    round_keys = get_round_keys(key_schedule)
    # Number of AES rounds
    Nr = len(round_keys) - 1
    # Start with the last round key
    state = add_round_key(
        state,round_keys[Nr])
    # Main inverse rounds
    for round_num in range(Nr - 1, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state,round_keys[round_num])
        state = inv_mix_columns(state)
    # Final inverse round
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state,round_keys[0])
    return state_to_bytes(state)

def aes_encrypt_with_round_keys(plaintext, round_keys):
    """Encrypt one 16-byte block using precomputed round keys."""

    state = bytes_to_state(plaintext)
    Nr = len(round_keys) - 1

    # Initial AddRoundKey
    state = add_round_key(state, round_keys[0])

    # Main rounds
    for round_num in range(1, Nr):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[round_num])

    # Final round without MixColumns
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[Nr])

    return state_to_bytes(state)


def aes_decrypt_with_round_keys(ciphertext, round_keys):
    """Decrypt one 16-byte block using precomputed round keys."""

    state = bytes_to_state(ciphertext)
    Nr = len(round_keys) - 1

    # Start with the last round key
    state = add_round_key(state, round_keys[Nr])

    # Main inverse rounds
    for round_num in range(Nr - 1, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[round_num])
        state = inv_mix_columns(state)

    # Final inverse round
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])

    return state_to_bytes(state)