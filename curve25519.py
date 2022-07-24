"""
Curve25519 is a Montgomery curve defined by:
y**2 = x**3 + A * x**2 + x  mod p
where p = 2**255-19, A = 486662
-> y²=(x³+486662x²+x)mod(2²⁵⁵−19)
"""
A = 486662
p = 2 ** 255 - 19

# def point_add(first_point, second_point):
#    """
#    Point addition on montgomery curve
#    :return: x and y coordinates of resulting point
#    """
#    (x1, y1) = first_point
#    (x2, y2) = second_point
#    lambda_val = ((y2 - y1) / (x2 - x1)) % p
#    x3 = (lambda_val ** 2 - x1 - x2 - A) % p
#    y3 = ((2 * x1 + x2 + A) * lambda_val - lambda_val ** 3 - y1) % p
#    return x3, y3


# def point_double(point):
#    """
#    Point doubling on montgomery curve
#    :return: x and y coordinate of resulting point
#    """
#    (x1, y1) = point
#    lambda_val = ((3 * x1 ** 2) + (2 * A * x1 + 1)) / (2 * y1)
#    x3 = (lambda_val ** 2 - x1 - x1 - A) % p
#    y3 = ((2 * x1 + x1 + A) * lambda_val - lambda_val ** 3 - y1) % p
#    return x3, y3


def point_add(point_n, point_m, point_diff):
    """Given the projection of two points and their difference, return their sum"""
    (xn, zn) = point_n
    (xm, zm) = point_m
    (x_diff, z_diff) = point_diff
    x = (z_diff << 2) * (xm * xn - zm * zn) ** 2
    z = (x_diff << 2) * (xm * zn - zm * xn) ** 2
    return x % p, z % p


def point_double(point_n):
    """Double a point provided in projective coordinates"""
    (xn, zn) = point_n
    xn2 = xn ** 2
    zn2 = zn ** 2
    x = (xn2 - zn2) ** 2
    xzn = xn * zn
    z = 4 * xzn * (xn2 + A * xzn + zn2)
    return x % p, z % p


def const_time_swap(a, b, swap):
    """Swap two values in constant time"""
    index = int(swap) * 2
    temp = (a, b, b, a)
    return temp[index:index+2]


def raw_curve25519(base, n):
    """Raise the point base to the power n"""
    zero = (1, 0)
    one = (base, 1)
    mP, m1P = zero, one

    for i in reversed(range(256)):
        bit = bool(n & (1 << i))
        mP, m1P = const_time_swap(mP, m1P, bit)
        mP, m1P = point_double(mP), point_add(mP, m1P, one)
        mP, m1P = const_time_swap(mP, m1P, bit)

    x, z = mP
    inv_z = pow(z, p - 2, p)
    return (x * inv_z) % p


def unpack_number(s):
    """Unpack 32 bytes to a 256 bit value"""
    if len(s) != 32:
        raise ValueError('Curve25519 values must be 32 bytes')
    return int.from_bytes(s, "little")


def pack_number(n):
    """Pack a value into 32 bytes"""
    return n.to_bytes(32, "little")


def fix_secret(n):
    """Mask a value to be an acceptable exponent"""
    n &= ~7
    n &= ~(128 << 8 * 31)
    n |= 64 << 8 * 31
    return n


def curve25519(base_point_raw, secret_raw):
    """Raise the base point to a given power"""
    base_point = unpack_number(base_point_raw)
    secret = fix_secret(unpack_number(secret_raw))
    return pack_number(raw_curve25519(base_point, secret))


def curve25519_base(secret_raw):
    """Raise the generator point to a given power"""
    secret = fix_secret(unpack_number(secret_raw))
    return pack_number(raw_curve25519(9, secret))
