## Decisions and primitives

tau parameter : **128**

This is so that all output values of functions will be of 256 bits / 32 bytes
which is still plenty at this point, and will result in a 256 bits shared key.

group G of order prime q with 256 bit q -> **secp256r1 / NIST P256**

This is the secp curve that has a generator order of 256 bits, and respects the OPAQUE spec.

* Hash function H that gives 256 bit output -> **sha3-256**

Since this protocol is still at a draft stage, and has not defined the exact primitives to be used.
I may as well use a modern standard hash function.

* Hash function H' that returns a hash as a curve point -> **`P256_XMD:SHA-256_SSWU_RO_` for secp256r1**

Since a rust module implementing the hash_to_curve draft exists, I may as well use it.

The following Domain Separation Tag was used in the hash_to_curve protocol : **"P256_XMD:SHA-256_SSWU_RO_OPAQUE"**

* PRF function f -> **HMAC(sha3-256)**

Since the sha3-256 primitive is already used, we may as well use it for our PRF function,
thus, hmac(sha3-256)

For the PRF function f and hash function H, multiple inputs are non-padded, but separated with the ascii character "|"
(ascii code 124)

Since the password is used directly for encryption/decryption of data, and not directly compared to a database entry,
the use of a password grade hash function is unnecessary, since the bruteforce-resistance of the data brought by the 
aead encrypted blob sent to the client, which will slow down the bruteforce process significantly.

The AEAD scheme used is xchacha20, this is because the standard is modern and satisfies the random key robustness requirement
for the OPAQUE protocol. 
Due to the use of xchacha20 as the AEAD algorithm, 
the nonce will need to be transmitted to the client along with the ciphertext and tag

Since the library used for elliptic curve operations does not directly support the verification
that a point belongs to the generator group, we must check manually that the point multiplied by the
order of the generator is equal to the point at infinity.

Due to another restriction of the library (we can only use scalars modulo the generator order), 
we must multiply the point by generator order minus 1, and then add the original point.

All numerical values that are serialised are serialised in little endian representation.
The choice is purely arbitrary, and the advantage of being able to properly read a number stored into too large a buffer
is appreciated.

All random scalar generation uses a chacha20 prng with a secure random seed obtained from the device RNG source.
Every time a scalar in Zq is required, it's obtained by requesting 256 bits from the prng

All points are serialised in compressed form (x coordinate, and a sign byte)


