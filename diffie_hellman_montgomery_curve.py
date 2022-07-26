class MontgomeryCurve:
    def __init__(self, p, a, bits, bytes, base_point):
        self.p = p
        self.a = a
        self.bits = bits
        self.bytes = bytes
        self.base_point = base_point

    @staticmethod
    def const_time_swap(p_1, p_2, swap):
        """Swap two points in constant time"""
        index = int(swap) * 2
        temp = (p_1, p_2, p_2, p_1)
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

    def decode_scalar(self, k):
        """Decode scalar"""
        k_list = [(b) for b in k]

        if self.bytes == 56:
            k_list[0] &= 252  # changes the last two bits to 0
            k_list[55] |= 128  # changes the first bit to 1

        if self.bytes == 32:
            k_list[0] &= 248
            k_list[31] &= 127
            k_list[31] |= 64
        return self.decode_little_endian(k_list)

    def decode_x_coordinate(self, s):
        """Decode x coordinate"""
        if len(s) != self.bytes:
            raise ValueError('Invalid Curve scalar (len=%d)' % len(s))

        if self.bytes == 56:
            return sum(ord(s[i]) << (8 * i) for i in range(56))

        if self.bytes == 32:
            t = sum((ord(s[i])) << (8 * i) for i in range(31))
            t += (((ord(s[31])) & 0x7f) << 248)
            return t

    def pack(self, n):
        return ''.join([chr((n >> (8 * i)) & 255) for i in range(self.bytes)])

    def multscalar(self, n, p):
        """Calculate Shared Key"""
        n = self.decode_scalar(n)  # Private key gets decoded
        p = self.decode_x_coordinate(p)  # Public key of partner gets decoded
        return self.pack(self.curve(n, p))  # Return nP

    def base_point_mult(self, n):
        """Calculate Public Key"""
        n = self.decode_scalar(n)  # Private key gets decoded
        # Start at x = Base point. Find point n times x-point. Gets turned into bytes.
        return self.pack(self.curve(n, self.base_point))
