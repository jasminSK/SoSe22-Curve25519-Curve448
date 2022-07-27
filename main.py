import os
import binascii
from diffie_hellman_montgomery_curve import MontgomeryCurve

"""This part features the diffie-hellman key exchange on curve25519"""
# Setup for curve25519
p = 2 ** 255 - 19  # Prime number
a = 486662  # A
bits_1 = 256
bytes_1 = 32
base_point = 9

# Curve gets created
curve_25519 = MontgomeryCurve(p, a, bits_1, bytes_1, base_point)

# Random value a and b are created -> Alice and Bobs private keys
a = os.urandom(32)
b = os.urandom(32)

# Public keys are created by raising base point to the power of private key
a_pub = curve_25519.base_point_mult(a)
b_pub = curve_25519.base_point_mult(b)

# Shared keys are created by raising public key of partner to the power of private key
k_ab = curve_25519.multscalar(a, b_pub)
k_ba = curve_25519.multscalar(b, a_pub)

# Outputs
# hexlify to represent the binary numbers in hexadecimal numbers
# encode is used to turn string into byte representation
print("\n\nValues for Curve25519:")
print("\nBob private:\t", binascii.hexlify(a))
print("Alice private:\t", binascii.hexlify(b))

print("\nBob public:\t", binascii.hexlify(b_pub.encode()))
print("Alice public:\t", binascii.hexlify(a_pub.encode()))

print("\nBob shared:\t", binascii.hexlify(k_ba.encode()))
print("Alice shared:\t", binascii.hexlify(k_ab.encode()))


"""This part features the diffie hellman key exchange on curve448"""
# Setup for curve448
p = 2 ** 448 - 2 ** 224 - 1  # Prime number
a = 156326  # A
bits_2 = 448
bytes_2 = 56
base_point = 5

# Curve gets created
curve_448 = MontgomeryCurve(p, a, bits_2, bytes_2, base_point)

# random a and b are created -> Alice and Bobs private keys
a = os.urandom(56)
b = os.urandom(56)

# Public keys are created by raising base point to the power of private key
a_pub = curve_448.base_point_mult(a)
b_pub = curve_448.base_point_mult(b)

# Shared keys are created by raising public key of partner to the power of private key
k_ab = curve_448.multscalar(a, b_pub)
k_ba = curve_448.multscalar(b, a_pub)

# Outputs
# hexlify to represent the binary numbers in hexadecimal numbers
# encode is used to turn strings into byte representation
print("\n\nValues for Curve448:")
print("\nBob private:\t", binascii.hexlify(a))
print("Alice private:\t", binascii.hexlify(b))

print("\nBob public:\t", binascii.hexlify(b_pub.encode()))
print("Alice public:\t", binascii.hexlify(a_pub.encode()))

print("\nBob shared:\t", binascii.hexlify(k_ba.encode()))
print("Alice shared:\t", binascii.hexlify(k_ab.encode()))
