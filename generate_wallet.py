from web3.auto import w3

def generate_polygon_wallet():
    account = w3.eth.account.create()
    private_key = account.key.hex()
    address = account.address
    return private_key, address

if __name__ == '__main__':
    private_key, address = generate_polygon_wallet()
    print(f"Private Key: {private_key}")
    print(f"Address: {address}")

