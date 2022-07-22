"""
Curve25519 is a Montgomery curve defined by:
y**2 = x**3 + A * x**2 + x  mod p
where p = 2**255-19 and A = 486662
-> y²=(x³+486662x²+x)mod(2²⁵⁵−19)
"""
A = 486662
p = 2 ** 255 - 19


def point_add(first_point, second_point):
    """
    Point addition on montgomery curve
    :return: x and y coordinates of resulting point
    """
    (x1, y1) = first_point
    (x2, y2) = second_point
    lambda_val = ((y2 - y1) / (x2 - x1)) % p
    x3 = (lambda_val ** 2 - x1 - x2 - A) % p
    y3 = ((2 * x1 + x2 + A) * lambda_val - lambda_val ** 3 - y1) % p
    return x3, y3


def point_double(point):
    """
    Point doubling on montgomery curve
    :return: x and y coordinate of resulting point
    """
    (x1, y1) = point
    lambda_val = ((3 * x1 ** 2) + (2 * A * x1 + 1)) / (2 * y1)
    x3 = (lambda_val ** 2 - x1 - x1 - A) % p
    y3 = ((2 * x1 + x1 + A) * lambda_val - lambda_val ** 3 - y1) % p
    return x3, y3


# Couldn't figure this one out yet. Something to do with ladder?
def _const_time_swap(a, b, swap):
    """Swap two values in constant time"""
    index = int(swap) * 2
    temp = (a, b, b, a)
    return temp[index:index+2]


# Couldn't figure this one out yet. Something to do with ladder?
def _raw_curve25519(base, n):
    """Raise the point base to the power n"""
    zero = (1, 0)
    one = (base, 1)
    mP, m1P = zero, one

    for i in reversed(range(256)):
        bit = bool(n & (1 << i))
        mP, m1P = _const_time_swap(mP, m1P, bit)
        mP, m1P = point_double(mP), point_add(mP, m1P)
        mP, m1P = _const_time_swap(mP, m1P, bit)

    x, z = mP
    inv_z = pow(z, p - 2, p)
    return (x * inv_z) % p


def bytes_to_bit(value):
    """
    Turns 32 bytes into a 256 bit value
    """
    # Don't know what the little does yet
    # Didn't include length check yet
    return int.from_bytes(value, "little")


def value_to_byte(value):
    """
    Turns value into 32 bytes
    """
    return value.to_bytes(32, "little")


# Don't why this is used yet
def _fix_secret(n):
    """Mask a value to be an acceptable exponent"""
    n &= ~7
    n &= ~(128 << 8 * 31)
    n |= 64 << 8 * 31
    return n


class X25519PublicKey:
    def __init__(self, x):
        # random chosen value x? or maybe is a from PrivateKey class
        self.x = x

    @classmethod
    def from_public_bytes(cls, data):
        return cls(bytes_to_bit(data))

    def public_bytes(self):
        """
        :return: public key as a 32 byte value
        """
        return value_to_byte(self.x)


class X25519PrivateKey:
    def __init__(self, a):
        # Random chosen value = private key
        self.a = a

    @classmethod
    def from_private_bytes(cls, data):
        # cls is similar do self, don't know what it does
        return cls(_fix_secret(bytes_to_bit(data)))

    def private_bytes(self):
        """
        :return: private key as a 32 byte value
        """
        return value_to_byte(self.a)

    def public_key(self):
        """
        :return: public key as 32 byte value
        """
        # Generator point is 9?
        # Calculates 9^a on montgomery curve
        return value_to_byte(_raw_curve25519(9, self.a))

    def exchange(self, peer_public_key):
        # checks if key is instance of class, rest is unclear to me
        if isinstance(peer_public_key, bytes):
            peer_public_key = X25519PublicKey.from_public_bytes(peer_public_key)
        # public_key^a, calculates shared key? Maybe our implementation could be less complicated.
        return value_to_byte(_raw_curve25519(peer_public_key.x, self.a))
