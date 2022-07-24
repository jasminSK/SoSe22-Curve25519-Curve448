import os
import binascii
import curve25519

"""
Curve25519 is a montgomery curve defined by: 
y**2 = x**3 + A * x**2 + x  mod p
where p = 2**255-19 and A = 486662
-> y²=(x³+486662x²+x)mod(2²⁵⁵−19)

Following code shows Diffie-Hellman Key Exchange using Curve25519
"""

# Random value a and b are created -> Alice and Bobs private keys
a = os.urandom(32)
b = os.urandom(32)

# Public keys are created by raising base point to the power of private key
a_pub = curve25519.curve25519_base(a)
b_pub = curve25519.curve25519_base(b)

# Shared keys are created by raising private key to the power of public key of partner
k_ab = curve25519.curve25519(b_pub, a)
k_ba = curve25519.curve25519(a_pub, b)

# Outputs
# hexlify to represent the binary numbers in hexadecimal numbers
print("Bob private:\t", binascii.hexlify(a))
print("Alice private:\t", binascii.hexlify(b))

print("\nBob public:\t", binascii.hexlify(b_pub))
print("Alice public:\t", binascii.hexlify(a_pub))

print("\nBob shared:\t", binascii.hexlify(k_ba))
print("Alice shared:\t", binascii.hexlify(k_ab))
