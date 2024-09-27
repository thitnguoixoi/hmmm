def patch_dll(input_file, output_file):
    # Đọc file DLL gốc
    with open(input_file, 'rb') as f:
        data = bytearray(f.read())

    # Ghi đè dữ liệu vào các offset nhất định
    # 678 byte 0xaa vào offset 0x2A80
    data[0x2A80:0x2A80 + 678] = bytes([0xAA] * 678)
    # 16 byte 0xbb vào offset 0x2D28
    data[0x2D28:0x2D28 + 16] = bytes([0xBB] * 16)
    # 16 byte 0xdd vào offset 0x2D30
    data[0x2D30:0x2D30 + 16] = bytes([0xDD] * 16)
    # 16 byte 0xcc vào offset 0x2D40
    data[0x2D40:0x2D40 + 16] = bytes([0xCC] * 16)
    # 16 byte 0xee vào offset 0x2D50
    data[0x2D50:0x2D50 + 16] = bytes([0xEE] * 16)

    # Ghi dữ liệu đã sửa vào file mới
    with open(output_file, 'wb') as f:
        f.write(data)


# Ví dụ sử dụng
input_dll = 'Dll1.dll'   # Thay bằng tên file DLL gốc
output_dll = 'patched.dll'  # Tên file DLL sau khi được ghi đè
patch_dll(input_dll, output_dll)
