import os
import binascii
from curve448 import base_point_mult, multscalar 

# random a and b are created
a = os.urandom(56)
b = os.urandom(56)

# public key = a or b multiplied by the base point
a_pub = base_point_mult(a)
b_pub = base_point_mult(b)

# common value is a or b multiplied by the other public key (b_pub for a and vice versa)
k_ab = multscalar(a, b_pub)
k_ba = multscalar(b, a_pub)

# Outputs
# hexlify to represent the binary numbers in hexadecimal numbers
print ("Bob private:\t",binascii.hexlify(a))
print ("Alice private:\t",binascii.hexlify(b))

print ("\n\nBob public:\t",binascii.hexlify(b_pub.encode()))
print ("Alice public:\t",binascii.hexlify(a_pub.encode()))

print ("\n\nBob shared:\t",binascii.hexlify(k_ba.encode()))
print ("Alice shared:\t",binascii.hexlify(k_ab.encode()))
