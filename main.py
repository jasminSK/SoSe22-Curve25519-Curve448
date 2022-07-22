import curve25519
import os


if __name__ == "__main__":
    # Doesn't work yet

    # Random values for Alice and Bob (secret)
    a = os.urandom(32)
    b = os.urandom(32)

    # Private Key Class of Alice and Bob, enables all functionalities for key exchange
    a_priv = curve25519.X25519PrivateKey(a)
    b_priv = curve25519.X25519PrivateKey(b)

    # Private Keys of Alice and Bob, used to compute shared key
    a_priv_key = a_priv.public_key()
    b_priv_key = b_priv.public_key()

    # Public Keys of Alice and Bob, used to compute shared key
    a_pub_key = a_priv.public_key()
    b_pub_key = b_priv.public_key()

    # Key exchange

    # Bob and Alice calculate shared key
    Alice_shared_key = a_priv.exchange(b_pub_key)
    Bob_shared_key = b_priv.exchange(a_pub_key)

    print(Alice_shared_key)
    print(Bob_shared_key)
