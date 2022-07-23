# X448
import os
import binascii

P = 2 ** 448 - 2 ** 224 - 1
A24 = 39081

# Defined here https://tools.ietf.org/html/rfc7748
def cswap(swap, x_2, x_3):
    dummy = swap * ((x_2 - x_3) % P)
    x_2 = x_2 - dummy
    x_2 %= P
    x_3 = x_3 + dummy
    x_3 %= P
    return (x_2, x_3)

# Defined here https://tools.ietf.org/html/rfc7748
def X448(k, u):
    x_1 = u
    x_2 = 1
    z_2 = 0
    x_3 = u
    z_3 = 1
    swap = 0

    for t in reversed(range(448)):
        k_t = (k >> t) & 1
        swap ^= k_t
        x_2, x_3 = cswap(swap, x_2, x_3)
        z_2, z_3 = cswap(swap, z_2, z_3)
        swap = k_t

        A = (x_2 + z_2) % P
        #A %= P

        AA = A * A
        AA %= P

        B = x_2 - z_2
        B %= P

        BB = B * B
        BB %= P

        E = AA - BB
        E %= P

        C = x_3 + z_3
        C %= P

        D = x_3 - z_3
        D %= P

        DA = D * A
        DA %= P

        CB = C * B
        CB %= P

        x_3 = ((DA + CB) % P)**2
        x_3 %= P

        z_3 = x_1 * (((DA - CB) % P)**2) % P
        z_3 %= P

        x_2 = AA * BB
        x_2 %= P

        z_2 = E * ((AA + (A24 * E) % P) % P)
        z_2 %= P

    x_2, x_3 = cswap(swap, x_2, x_3)
    z_2, z_3 = cswap(swap, z_2, z_3)

    return (x_2 * pow(z_2, P - 2, P)) % P


def decodeScalar448(k):
  k_list = [(b) for b in k]
  k_list[0] &= 252
  k_list[55] |= 128
  return decodeLittleEndian(k_list)

def decodeLittleEndian(b):
    return sum([b[i] << 8*i for i in range( 56 )])


# 
def unpack2(s):
    if len(s) != 56:
        raise ValueError('Invalid Curve448 scalar (len=%d)' % len(s))
    return sum(ord(s[i]) << (8 * i) for i in range(56))

# encodeUCoordinate
def pack(n): 
    return ''.join([chr((n >> (8 * i)) & 255) for i in range(56)])

def clamp(n):
    n &= ~3
    n |= 128 << 8 * 55
    return n


# Return nP
def multscalar(n, p):
    n = clamp(decodeScalar448(n))
    p = unpack2(p)
    return pack(X448(n, p))

# Start at x=5. Find point n times x-point
def base_point_mult(n):
    n = clamp(decodeScalar448(n))
    return pack(X448(n, 5))

