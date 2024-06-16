import sys
from hashlib import sha256

def str_to_sha256(x: str) -> str:
    return sha256(x.encode('utf-8')).hexdigest()

def print_data_sha256(data: str) -> str:
    print(str_to_sha256(data))

def print_data_sha256_stripped(data: str) -> str:
    print(str_to_sha256(data.strip()))

def main():
    with open(sys.argv[1], 'r') as file:
        data = file.read()

    print_data_sha256(data)

if __name__ == '__main__':
    main()
