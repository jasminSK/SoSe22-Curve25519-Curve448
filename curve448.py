import os
import binascii

p = 2 ** 448 - 2 ** 224 - 1
A24 = 39081                                                                 # A24 = (156326 - 2) / 4    
base_point = 5

# Defined here https://tools.ietf.org/html/rfc7748
def cswap(swap, x_2, x_3):
    dummy = swap * ((x_2 - x_3) % p)
    x_2 = x_2 - dummy
    x_2 %= p
    x_3 = x_3 + dummy
    x_3 %= p
    return x_2, x_3

# Defined here https://tools.ietf.org/html/rfc7748
def X448(k, u):
    x_1 = u
    x_2 = 1
    z_2 = 0
    x_3 = u
    z_3 = 1
    swap = 0

    for t in reversed(range(448)):                                             
        k_t = (k >> t) & 1                                                  # k_1 is either 0 or 1
        swap ^= k_t                                                         # bitwise XOR with swap = 0
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


def decode_little_endian(b):                                                # stores bits from lsb to msb
    return sum([b[i] << 8*i for i in range(56)])                            # u[0] + 256*u[1] + 256^2*u[2] + ... + 256^(n-1)*u[n-1]


def decode_scalar448(k):                                                    # tbd: what the function does
  k_list = [(b) for b in k]                                                 
  k_list[0] &= 252                                                          # changes the last two bits to 0
  k_list[55] |= 128                                                         # changes the first bit to 1
  return decode_little_endian(k_list)


def decode_u_coordinate(s):
    if len(s) != 56:
        raise ValueError('Invalid Curve448 scalar (len=%d)' % len(s))
    return sum(ord(s[i]) << (8 * i) for i in range(56))

def pack(n):                                                                # turns value into string
    return ''.join([chr((n >> (8 * i)) & 255) for i in range(56)])

def clamp(n):
    n &= ~3                                                                 # changes last 2 bits to 0
    n |= 128 << 8 * 55                                                      # changes first bit to 1
    return n


# Return nP
def multscalar(n, p):                                                       # tbd: maybe align parameters with x25519
    n = clamp(decode_scalar448(n))
    p = decode_u_coordinate(p)
    return pack(X448(n, p))

# Start at x=5. Find point n times x-point
def base_point_mult(n):
    n = clamp(decode_scalar448(n))
    return pack(X448(n, base_point))
