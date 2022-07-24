"""
Curve25519 is a montgomery curve defined by:
y**2 = x**3 + A * x**2 + x  mod p
where p = 2**255-19 and A = 486662
-> y²=(x³+486662x²+x)mod(2²⁵⁵−19)
"""
p = 2 ** 255 - 19
A24 = 121665
base_point = 9


# Defined here https://tools.ietf.org/html/rfc7748
def cswap(swap, x_2, x_3):
    dummy = swap * ((x_2 - x_3) % p)
    x_2 = x_2 - dummy
    x_2 %= p
    x_3 = x_3 + dummy
    x_3 %= p
    return x_2, x_3


# Based on https://tools.ietf.org/html/rfc7748
def x25519(k, u):
    """
    Start at x=u. Find point k times x-point.
    Equivalent of calculating u to the power of k.
    """
    x_1 = u
    x_2 = 1
    z_2 = 0
    x_3 = u
    z_3 = 1
    swap = 0

    for t in reversed(range(255)):
        k_t = (k >> t) & 1
        swap ^= k_t
        x_2, x_3 = cswap(swap, x_2, x_3)
        z_2, z_3 = cswap(swap, z_2, z_3)
        swap = k_t

        a = (x_2 + z_2) % p
        aa = (a * a) % p
        b = (x_2 - z_2) % p
        bb = (b * b) % p
        e = (aa - bb) % p
        c = (x_3 + z_3) % p
        d = (x_3 - z_3) % p
        da = (d * a) % p
        cb = (c * b) % p
        x_3 = (((da + cb) % p)**2) % p
        z_3 = (x_1 * (((da - cb) % p)**2) % p) % p
        x_2 = (aa * bb) % p
        z_2 = (e * ((aa + (A24 * e) % p) % p)) % p

    x_2, x_3 = cswap(swap, x_2, x_3)
    z_2, z_3 = cswap(swap, z_2, z_3)

    return (x_2 * pow(z_2, p - 2, p)) % p


def decode_little_endian(b):
    return sum([b[i] << 8*i for i in range(32)])


def decode_scalar_25519(k):
    """Turn scalar into int value"""
    k_list = [(b) for b in k]
    k_list[0] &= 248
    k_list[31] &= 127
    k_list[31] |= 64
    return decode_little_endian(k_list)


def decode_u_coordinate(u):
    """Turn s into int value"""
    if len(u) != 32:
        raise ValueError('Invalid Curve25519 scalar (len=%d)' % len(u))
    t = sum((ord(u[i])) << (8 * i) for i in range(31))
    t += (((ord(u[31])) & 0x7f) << 248)
    return t    


def pack(n):
    """Turns value into string"""
    return ''.join([chr((n >> (8 * i)) & 255) for i in range(32)])


def clamp(n):
    n &= ~7
    n &= ~(128 << 8 * 31)
    n |= 64 << 8 * 31
    return n


# Return nP
def multscalar(k, u):
    """Calculate Shared Key"""
    # Private key gets decoded value and clamped
    k = clamp(decode_scalar_25519(k))
    # Public key of partner gets turned into int value
    u = decode_u_coordinate(u)
    return pack(x25519(k, u))


def base_point_mult(k):
    """Calculate Public Key"""
    # Private key gets decoded and clamped
    k = clamp(decode_scalar_25519(k))
    # Start at x=9 (Base point). Find point n times x-point. Gets turned into bytes.
    return pack(x25519(k, base_point))
