import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def get_input(keyfile, ivfile, new_file_path, file_md5, len_encrypted_data):
    firstarg = input("Enter 8-byte firstarg: ").encode('utf-8')[:8]
    firstarg = firstarg.ljust(8, b'\x00')

    secondarg = input("Enter secondarg to be hashed (MD5): ")
    secondarg_hashed = hashlib.md5(secondarg.encode('utf-8')).digest()

    is_check_system = int(
        input("Enter 4-byte IsCheckSystem (0 or 1): ")).to_bytes(4, byteorder='little')
    if is_check_system == b'\x01\x00\x00\x00':
        mac_address_str = input(
            "Enter 6-byte MAC address in format '11:22:33:44:55:66': ")
        mac_address = bytes.fromhex(mac_address_str.replace(':', ''))[:6]
        mac_address = mac_address.ljust(6, b'\x00')

        computer_name = input(
            "Enter 32-byte wchar ComputerName: ").encode('utf-16le')[:64]
        computer_name = computer_name.ljust(64, b'\x00')
    else:
        mac_address = b'\x00' * 6
        computer_name = b'\x00' * 64

    encrypted_file_path = input(
        "Enter 260-byte wchar EncryptedFilePath: ")[:520]
    if encrypted_file_path == "":
        encrypted_file_path = os.path.basename(new_file_path)
    else:
        encrypted_file_path = encrypted_file_path + \
            "\\" + os.path.basename(new_file_path)
    encrypted_file_path = encrypted_file_path.encode(
        'utf-16le').ljust(520, b'\x00')

    flag_delete = int(input("Enter 4-byte FlagDelete (0 or 1): ")
                      ).to_bytes(4, byteorder='little')
    terminate_process = int(input(
        "Enter 4-byte TerminateProcess (0 or 1): ")).to_bytes(4, byteorder='little')

    return {
        'firstarg': firstarg,
        'secondarg_hashed': secondarg_hashed,
        'mac_address': mac_address,
        'computer_name': computer_name,
        'is_check_system': is_check_system,
        'encrypted_file_path': encrypted_file_path,
        'size_file_enc': len_encrypted_data.to_bytes(4, byteorder='little'),
        'key': keyfile,
        'iv': ivfile,
        'hashfile': file_md5,
        'flag_delete': flag_delete,
        'terminate_process': terminate_process
    }


def encrypt_aes_cfb(keyconfig, ivconfig, packed_data):
    cipher = Cipher(algorithms.AES(keyconfig), modes.CFB(ivconfig))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(packed_data) + encryptor.finalize()
    return encrypted_data


def encrypt_file(file_path, keyfile, ivfile, extra_bytes):
    with open(file_path, 'rb') as f:
        file_data = f.read()

    file_md5 = hashlib.md5(file_data).digest()

    print("\nMD5 Hash of File:")
    print(format_bytes(file_md5))
    print("\nKeyfile (16-byte random key):")
    print(format_bytes(keyfile))
    print("\nIVfile (16-byte IV):")
    print(format_bytes(ivfile))
    encrypted_data = extra_bytes+encrypt_aes_cfb(keyfile, ivfile, file_data)
    print("\nEncrypted Data (Hex Format):")
    print(format_bytes(encrypted_data))
    print(f"Size of encrypted data: {len(encrypted_data)} bytes")

    new_file_path = f"{os.path.splitext(file_path)[0]}.dat"

    with open(new_file_path, 'wb') as f:
        f.write(encrypted_data)

    return new_file_path, file_md5, len(encrypted_data)


def pack_data(data):
    packed_data = (
        data['firstarg'] +                # 8 byte
        data['secondarg_hashed'] +        # 16 byte
        data['mac_address'] +             # 6 byte
        data['computer_name'] +           # 64 byte
        data['is_check_system'] +         # 4 byte
        data['encrypted_file_path'] +     # 520 byte
        data['size_file_enc'] +           # 4 byte
        data['key'] +                     # 16 byte
        data['iv'] +                      # 16 byte
        data['hashfile'] +                # 16 byte
        data['flag_delete'] +             # 4 byte
        data['terminate_process']         # 4 byte
    )
    return packed_data


def format_bytes(byte_data):
    formatted = []
    for i in range(0, len(byte_data), 16):
        line = ', '.join(f'0x{byte:02x}' for byte in byte_data[i:i+16])
        formatted.append(line)
    return '\n'.join(formatted)


def guid_to_byte_array(guid):
    # Remove dashes from the GUID and convert it to a byte array
    hex_string = guid.replace('-', '')
    return bytes.fromhex(hex_string)


def main():
    keyfile = os.urandom(16)
    ivfile = os.urandom(16)

    guid = input("Enter GUID (leave blank to use a random IV): ")

    if guid:
        guid_bytes = guid_to_byte_array(guid)
        ivfile = hashlib.md5(guid_bytes).digest()
        print(f"\nGUID provided. Using MD5 hash of GUID as IV:")
        print(format_bytes(ivfile))
        extra_bytes = os.urandom(4)

    else:
        print(f"\nNo GUID provided. Using a random IV:")
        print(format_bytes(ivfile))
        extra_bytes = b'\x00' * 4

    file_path = input("\nEnter the path of the file to encrypt: ")
    new_file_path, file_md5, len_encrypted_data = encrypt_file(
        file_path, keyfile, ivfile, extra_bytes)

    data = get_input(keyfile, ivfile, new_file_path,
                     file_md5, len_encrypted_data)
    packed_data = pack_data(data)

    keyconfig = os.urandom(16)
    ivconfig = os.urandom(16)
    encrypted_data = encrypt_aes_cfb(keyconfig, ivconfig, packed_data)

    print("\nPacked Data (Hex Format):")
    print(format_bytes(packed_data))
    print(f"Size of packed data: {len(packed_data)} bytes")

    print("\nEncrypted Packed Data (Hex Format):")
    print(format_bytes(encrypted_data))
    print(f"Size of encrypted packed data: {len(encrypted_data)} bytes")

    # Hash MD5 of encrypted packed data
    encrypted_data_md5 = hashlib.md5(encrypted_data).digest()
    print("\nMD5 Hash of Encrypted Packed Data:")
    print(format_bytes(encrypted_data_md5))

    print("\nKeyConfig (16-byte random key):")
    print(format_bytes(keyconfig))
    print("\nIVConfig (16-byte random IV):")
    print(format_bytes(ivconfig))


if __name__ == "__main__":
    main()
