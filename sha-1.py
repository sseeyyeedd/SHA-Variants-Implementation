import struct
from typing import List, Tuple
from utils import left_rotate


def sha1_pad_message(message: bytes) -> bytes:
    """
    Pad the message according to SHA-0 specifications:
    - Append a single '1' bit
    - Append 0 bits until length ≡ 448 (mod 512)
    - Append 64-bit representation of original length
    """
    message_len = len(message) * 8  # length in bits
    message = bytearray(message)
    message.append(0x80)  # append single '1' bit (plus 7 '0' bits)
    
    # Pad with zeros until message length ≡ 448 (mod 512)
    while (len(message) * 8) % 512 != 448:
        message.append(0x00)
        
    # Append original length as 64-bit big-endian
    message.extend(struct.pack('>Q', message_len))
    return bytes(message)

def sha1_expand_block(block: bytes) -> List[int]:
    """
    Expand 16 32-bit words into 80 32-bit words according to SHA-1 algorithm.
    """
    words = list(struct.unpack('>16L', block))
    
    for i in range(16, 80):
        # SHA-0 expansion (no rotation)
        word = ROTL(words[i-3] ^ words[i-8] ^ words[i-14] ^ words[i-16])
        words.append(word & 0xffffffff)
    
    return words

def sha1_process_block(block: bytes, state: Tuple[int, ...]) -> Tuple[int, ...]:
    """
    Process a single 512-bit block according to SHA-1 algorithm.
    """
    # Constants
    K = [
        0x5A827999,  # rounds 0-19
        0x6ED9EBA1,  # rounds 20-39
        0x8F1BBCDC,  # rounds 40-59
        0xCA62C1D6   # rounds 60-79
    ]
    
    # Initialize working variables
    a, b, c, d, e = state
    
    # Expand block into 80 words
    W = sha1_expand_block(block)
    
    # Main loop
    for t in range(80):
        if t < 20:
            f = (b & c) | ((~b) & d)
            k = K[0]
        elif t < 40:
            f = b ^ c ^ d
            k = K[1]
        elif t < 60:
            f = (b & c) | (b & d) | (c & d)
            k = K[2]
        else:
            f = b ^ c ^ d
            k = K[3]
        
        temp = (left_rotate(a, 5) + f + e + k + W[t]) & 0xffffffff
        e = d
        d = c
        c = left_rotate(b, 30)
        b = a
        a = temp
    
    # Update state
    state = (
        (state[0] + a) & 0xffffffff,
        (state[1] + b) & 0xffffffff,
        (state[2] + c) & 0xffffffff,
        (state[3] + d) & 0xffffffff,
        (state[4] + e) & 0xffffffff
    )
    
    return state

def sha1(message: bytes) -> bytes:
    """
    Compute SHA-1 hash of a message.
    """
    # Initial state
    state = (
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0
    )
    
    # Pad message
    padded_message = sha1_pad_message(message)
    
    # Process message in 512-bit blocks
    for i in range(0, len(padded_message), 64):
        block = padded_message[i:i+64]
        state = sha1_process_block(block, state)
    
    # Produce final hash value
    return struct.pack('>5L', *state)
