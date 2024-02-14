import binascii

output = "0x5825b1c0 0x170 0x565ffd85 0x1 0x4e 0x26 0x1 0x2 0x5660096c 0x5825b1c0 0x5825b340 0x7b425448 0x5f796877 0x5f643164 0x34735f31 0x745f3376 0x665f3368 0x5f67346c 0x745f6e30 0x355f3368 0x6b633474 0x7d213f 0x79f13000 0xf7f183fc 0x56602f8c 0xffd0ec58 0x56600441 0x1 0xffd0ed04 0xffd0ed0c"
arr_hex = output.split()

# Get all the bytes and then reverse them as they are all in Little Endian
def convert_big_endian(byte_num: int) -> int:
    move_first = (byte_num << 24) & 0xff000000  # shift left 24 bits
    move_last = ((byte_num >> 24) & 0x000000ff)    # shift right 24 bits
    move_second = ((byte_num << 8) & 0x00ff0000)  # shift left 8 bits
    move_third = ((byte_num >> 8) & 0x0000ff00) # shift right 8 bits
    result = move_first | move_second | move_third | move_last  # combine hexa values with OR
    return result

for i in range(len(arr_hex)):
    hex_val = convert_big_endian(int(arr_hex[i], 16))
    print(hex(hex_val))
