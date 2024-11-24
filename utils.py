def left_rotate(n: int, b: int) -> int:
    """Left rotate a 32-bit integer by b bits."""
    return ((n << b) | (n >> (32 - b))) & 0xffffffff


def right_rotate(value, shift):
    """Right rotate a 32-bit integer value by shift bits."""
    return (value >> shift) | (value << (32 - shift)) & 0xFFFFFFFF
