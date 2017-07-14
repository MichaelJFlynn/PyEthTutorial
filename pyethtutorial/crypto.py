import hashlib
import sha3 

## Ethereum uses the keccak-256 hash algorithm
def keccak256(s):
    k = sha3.keccak_256()
    k.update(s)
    return k.digest()

