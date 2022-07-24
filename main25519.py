import os
import binascii
from curve25519 import base_point_mult, multscalar


"""
Curve25519 is a Montgomery Curve
Following code shows Diffie-Hellman Key Exchange using Curve25519
"""

# Random value a and b are created -> Alice and Bobs private keys
a = os.urandom(32)
b = os.urandom(32)

# Public keys are created by raising base point to the power of private key
a_pub = base_point_mult(a)
b_pub = base_point_mult(b)


# Shared keys are created by raising private key to the power of public key of partner
k_ab = multscalar(a, b_pub)
k_ba = multscalar(b, a_pub)

# Outputs
# hexlify to represent the binary numbers in hexadecimal numbers
# encode is used to turn string into byte representation
print("Bob private:\t", binascii.hexlify(a))
print("Alice private:\t", binascii.hexlify(b))

print("\nBob public:\t", binascii.hexlify(b_pub.encode()))
print("Alice public:\t", binascii.hexlify(a_pub.encode()))

print("\nBob shared:\t", binascii.hexlify(k_ba.encode()))
print("Alice shared:\t", binascii.hexlify(k_ab.encode()))
