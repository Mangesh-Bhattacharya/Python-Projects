import hashlib
import os
import time
import ecdsa


def create_wallet():
    private_key = os.urandom(32)
    private_key_hex = private_key.hex()

    # Generate public key
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    public_key = sk.get_verifying_key().to_string().hex()

    print(f"Private Key: {private_key_hex}")
    print(f"Public Key: {public_key}")

    return private_key_hex, public_key


def mine(block_number, transactions, previous_hash, prefix_zeros):
    prefix_str = '0' * prefix_zeros
    nonce = 0
    while True:
        block_data = f"{block_number}{transactions}{previous_hash}{nonce}".encode()
        block_hash = hashlib.sha256(block_data).hexdigest()

        if block_hash.startswith(prefix_str):
            print(f"Mining successful with nonce: {nonce}")
            print(f"Hash: {block_hash}")
            return block_hash
        nonce += 1

# Class to represent a token
class Token:
    def __init__(self, name, symbol, total_supply):
        self.name = name
        self.symbol = symbol
        self.total_supply = total_supply

    def __repr__(self):
        return f"Token({self.name}, {self.symbol}, {self.total_supply})"

# Function to create a token
def create_token(name, symbol, total_supply):
    return Token(name, symbol, total_supply)


# Main function to tie everything together
if __name__ == "__main__":
    print("Creating Wallet...")
    private_key, public_key = create_wallet()

    print("\nMining...")
    block_number = 1
    transactions = f"{public_key} pays someone 1 MTK"
    previous_hash = "0" * 64  # Simplified previous hash
    prefix_zeros = 4  # Difficulty
    start_time = time.time()
    print("Mining...")
    mine(block_number, transactions, previous_hash, prefix_zeros)
    print(f"Mining took {time.time() - start_time:.2f} seconds")

    print("\nGenerating Token...")
    token = create_token("MyToken", "MTK", 1000000)
    print(token)
