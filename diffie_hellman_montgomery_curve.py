import curve25519
import os
import binascii
import curve448


class MontgomeryCurve:
    def __init__(self, p, a, bits, bytes, base_point):
        self.p = p
        self.a = a
        self.bits = bits
        self.bytes = bytes
        self.base_point = base_point

    @staticmethod
    def const_time_swap(a, b, swap):
        """Swap two values in constant time"""
        index = int(swap) * 2
        temp = (a, b, b, a)
        return temp[index:index + 2]

    def point_add(self, point_p, point_q, point_diff_p_q):
        """Given the projection of two points and their difference, return their sum"""
        (xp, zp) = point_p
        (xq, zq) = point_q
        (x_diff, z_diff) = point_diff_p_q
        a = xp + zp
        b = xq - zq
        b = a * b
        a = xp - zp
        c = xq + zq
        c = c * a
        d = b + c
        d = d ** 2
        e = b - c
        e = e ** 2
        x = z_diff * d
        z = x_diff * e
        return x % self.p, z % self.p

    def point_double(self, point_p):
        """Double a point provided in projective coordinates"""
        (xp, zp) = point_p
        a = (xp + zp) ** 2
        b = (xp - zp) ** 2
        # resulting x coordinate
        x = a * b

        a = a - b
        c = ((self.a + 2) // 4) * a
        c = c + b
        # resulting z coordinate
        z = a * c
        return x % self.p, z % self.p

    def curve(self, scalar, base):
        """Raise the point base to the power of the scalar"""
        zero = (1, 0)
        one = (base, 1)
        p_1, p_2 = zero, one

        for i in reversed(range(self.bits)):
            bit = bool(scalar & (1 << i))
            p_1, p_2 = self.const_time_swap(p_1, p_2, bit)
            p_1, p_2 = self.point_double(p_1), self.point_add(p_1, p_2, one)
            p_1, p_2 = self.const_time_swap(p_1, p_2, bit)

        x, z = p_1
        inv_z = pow(z, self.p - 2, self.p)
        return (x * inv_z) % self.p

    def decode_little_endian(self, b):  # stores bits from lsb to msb
        return sum([b[i] << 8 * i for i in range(self.bytes)])  # u[0] + 256*u[1] + 256^2*u[2] + ... + 256^(n-1)*u[n-1]

    def decode_scalar(self, k):  # tbd: what the function does
        k_list = [(b) for b in k]

        if self.bytes == 56:
            k_list[0] &= 252  # changes the last two bits to 0
            k_list[55] |= 128  # changes the first bit to 1

        if self.bytes == 32:
            k_list[0] &= 248
            k_list[31] &= 127
            k_list[31] |= 64
        return self.decode_little_endian(k_list)

    def decode_u_coordinate(self, s):
        if len(s) != self.bytes:
            raise ValueError('Invalid Curve scalar (len=%d)' % len(s))

        if self.bytes == 56:
            return sum(ord(s[i]) << (8 * i) for i in range(56))

        if self.bytes == 32:
            t = sum((ord(s[i])) << (8 * i) for i in range(31))
            t += (((ord(s[31])) & 0x7f) << 248)
            return t

    def pack(self, n):  # turns value into string
        return ''.join([chr((n >> (8 * i)) & 255) for i in range(self.bytes)])

    def clamp(self, n):
        if self.bytes == 56:
            n &= ~3  # changes last 2 bits to 0
            n |= 128 << 8 * 55  # changes first bit to 1
        if self.bytes == 32:
            n &= ~7
            n &= ~(128 << 8 * 31)
            n |= 64 << 8 * 31
        return n

    # Return nP
    def multscalar(self, n, p):  # tbd: maybe align parameters with x25519
        """Calculate Shared Key"""
        # Private key gets decoded value and clamped
        n = self.clamp(self.decode_scalar(n))
        # Public key of partner gets turned into int value
        p = self.decode_u_coordinate(p)
        return self.pack(self.curve(n, p))

    # Start at x=5. Find point n times x-point
    def base_point_mult(self, n):
        """Calculate Public Key"""
        # Private key gets decoded and clamped
        n = self.clamp(self.decode_scalar(n))
        # Start at x=Base point. Find point n times x-point. Gets turned into bytes.
        return self.pack(self.curve(n, self.base_point))


if __name__ == "__main__":
    print("\n\nCurve25519 standard")
    # Random value a and b are created -> Alice and Bobs private keys
    a = os.urandom(32)
    b = os.urandom(32)

    # Public keys are created by raising base point to the power of private key
    a_pub = curve25519.base_point_mult(a)
    b_pub = curve25519.base_point_mult(b)

    # Shared keys are created by raising private key to the power of public key of partner
    k_ab = curve25519.multscalar(a, b_pub)
    k_ba = curve25519.multscalar(b, a_pub)

    # Outputs
    # hexlify to represent the binary numbers in hexadecimal numbers
    # encode is used to turn string into byte representation
    print("Bob private:\t", binascii.hexlify(a))
    print("Alice private:\t", binascii.hexlify(b))

    print("\nBob public:\t", binascii.hexlify(b_pub.encode()))
    print("Alice public:\t", binascii.hexlify(a_pub.encode()))

    print("\nBob shared:\t", binascii.hexlify(k_ba.encode()))
    print("Alice shared:\t", binascii.hexlify(k_ab.encode()))

    P = 2 ** 255 - 19
    A = 486662
    bits1 = 256
    bytes1 = 32
    base_point = 9
    curve_25519 = MontgomeryCurve(P, A, bits1, bytes1, base_point)
    print("\n\nCurve25519 class")
    # Public keys are created by raising base point to the power of private key
    a_pub = curve_25519.base_point_mult(a)
    b_pub = curve_25519.base_point_mult(b)

    # Shared keys are created by raising private key to the power of public key of partner
    k_ab = curve_25519.multscalar(a, b_pub)
    k_ba = curve_25519.multscalar(b, a_pub)

    # Outputs
    # hexlify to represent the binary numbers in hexadecimal numbers
    # encode is used to turn string into byte representation
    print("Bob private:\t", binascii.hexlify(a))
    print("Alice private:\t", binascii.hexlify(b))

    print("\nBob public:\t", binascii.hexlify(b_pub.encode()))
    print("Alice public:\t", binascii.hexlify(a_pub.encode()))

    print("\nBob shared:\t", binascii.hexlify(k_ba.encode()))
    print("Alice shared:\t", binascii.hexlify(k_ab.encode()))

    print("\n\nCurve448 Standard")
    # random a and b are created
    a = os.urandom(56)
    b = os.urandom(56)

    # public key = a or b multiplied by the base point
    a_pub = curve448.base_point_mult(a)
    b_pub = curve448.base_point_mult(b)

    # common value is a or b multiplied by the other public key (b_pub for a and vice versa)
    k_ab = curve448.multscalar(a, b_pub)
    k_ba = curve448.multscalar(b, a_pub)

    # Outputs
    # hexlify to represent the binary numbers in hexadecimal numbers
    print("Bob private:\t", binascii.hexlify(a))
    print("Alice private:\t", binascii.hexlify(b))

    print("\n\nBob public:\t", binascii.hexlify(b_pub.encode()))
    print("Alice public:\t", binascii.hexlify(a_pub.encode()))

    print("\n\nBob shared:\t", binascii.hexlify(k_ba.encode()))
    print("Alice shared:\t", binascii.hexlify(k_ab.encode()))

    P = 2 ** 448 - 2 ** 224 - 1
    A = 156326
    bits2 = 449
    bytes2 = 56
    base_point = 5
    curve_448 = MontgomeryCurve(P, A, bits2, bytes2, base_point)
    print("\n\nCurve448 class")
    # Public keys are created by raising base point to the power of private key
    a_pub = curve_448.base_point_mult(a)
    b_pub = curve_448.base_point_mult(b)

    # Shared keys are created by raising private key to the power of public key of partner
    k_ab = curve_448.multscalar(a, b_pub)
    k_ba = curve_448.multscalar(b, a_pub)

    # Outputs
    # hexlify to represent the binary numbers in hexadecimal numbers
    # encode is used to turn string into byte representation
    print("Bob private:\t", binascii.hexlify(a))
    print("Alice private:\t", binascii.hexlify(b))

    print("\nBob public:\t", binascii.hexlify(b_pub.encode()))
    print("Alice public:\t", binascii.hexlify(a_pub.encode()))

    print("\nBob shared:\t", binascii.hexlify(k_ba.encode()))
    print("Alice shared:\t", binascii.hexlify(k_ab.encode()))
    
