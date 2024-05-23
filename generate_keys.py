import struct
from fastecdsa.curve import P224
from fastecdsa.point import Point
from fastecdsa.util import mod_sqrt
import hashlib
import base64

def build_hashed_keys(modem_id, index, msg_id, bit):

    # counter for valid keys
    valid_key_counter = 0

    # Constants

    PUB_KEY_LEN = 28  # Length of the public key

    # Initialize the public key array
    public_key = [0] * PUB_KEY_LEN

    # Set magic values and other parameters
    public_key[0] = 0xBA
    public_key[1] = 0xBE
    public_key[2:6] = list(struct.pack(">I", index))  # Convert to big-endian format
    public_key[6:10] = list(struct.pack(">I", msg_id))
    public_key[10:14] = list(struct.pack(">I", modem_id))
    public_key[27] = bit

    public_key, valid_key_counter = find_valid_pubkey(public_key)

    # Prepare the formatted string
    public_key_hex_str = ' '.join(f'{byte:02x}' for byte in public_key)
    log_message = f"pub key to use ({valid_key_counter}. try): {public_key_hex_str}"
    #print(log_message) 


    # Convert the list of integers to bytes
    public_key_bytes = bytes(public_key)

    # Hash the byte representation of the public key
    hashed_key_bytes = hashlib.sha256(public_key_bytes).digest()  # Note .digest() instead of .hexdigest()

    # Convert the hash to a base64-encoded string
    hashed_key_base64 = base64.b64encode(hashed_key_bytes).decode()


    #print(hashed_key_base64)
    return hashed_key_base64



def find_valid_pubkey(public_key):
    valid_key_counter = 0
    while not is_valid_pubkey(public_key):
        #print(' '.join(f'{byte:02x}' for byte in public_key))
        # Update part of the public key with the current counter value in big-endian format
        packed_counter = struct.pack(">I", valid_key_counter)
        public_key[14:18] = packed_counter
        valid_key_counter += 1
    return public_key, valid_key_counter


def is_valid_pubkey(pub_key_compressed):
    with_sign_byte = bytearray(29)

    # Array to hold the uncompressed public key.
    pub_key_uncompressed = bytearray(128)

    # Set the first byte to 0x02 to indicate a compressed key with even y-coordinate.
    with_sign_byte[0] = 0x02

    # Copy the compressed public key into 'with_sign_byte', starting from the second byte.
    with_sign_byte[1:29] = pub_key_compressed[:28]


    decompressed_key = decompress_public_key(with_sign_byte, P224)

    #print(decompressed_key)

    # Validate the decompressed public key
    if decompressed_key:
        # Pass the point coordinates as a tuple to is_point_on_curve
        if P224.is_point_on_curve((decompressed_key.x, decompressed_key.y)):
            return 1
    return 0



def decompress_public_key(compressed_key, curve):
    # Extract the prefix byte and x-coordinate
    prefix = compressed_key[0]
    x = int.from_bytes(compressed_key[1:], 'big')

    # Ensure x is within the field
    x = x % curve.p

    # Compute alpha (y^2) = x^3 + ax + b mod p
    alpha = (pow(x, 3, curve.p) + (curve.a * x % curve.p) + curve.b) % curve.p

    # Check if alpha is a square in Fp
    # If alpha^((p - 1) / 2) % p == 1, then alpha is a square (quadratic residue)
    is_square = pow(alpha, (curve.p - 1) // 2, curve.p) == 1

    if not is_square:
        # Handle the non-square case without terminating
        #print("Alpha is not a square in Fp. No square root can be found.")
        # You could either return None or continue with a default value or alternative operation
        return None

    # If alpha is a square, find the square root(s)
    y0, y1 = mod_sqrt(alpha, curve.p)

    # Select the correct y-coordinate based on the prefix
    if (prefix == 0x02 and y0 % 2 == 0) or (prefix == 0x03 and y0 % 2 == 1):
        y = y0
    else:
        y = y1

    # Return the decompressed Point
    return Point(x, y, curve)



def get_both_public_keys(modem_id, index, msg_id):
    # Generate public key for current_bit = 0
    public_key1 = build_hashed_keys(modem_id, index, msg_id, 0)
    # Generate public key for current_bit = 1
    public_key2 = build_hashed_keys(modem_id, index, msg_id, 1)
    return public_key1, public_key2