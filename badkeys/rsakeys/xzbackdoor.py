def xzbackdoor(n, e=0):
    byte_len = (n.bit_length() + 7) // 8
    nb = n.to_bytes(byte_len, byteorder="big")
    # if upper bit is set, ASN1 encodes with leading zero byte
    if nb[0] & 0x80:
        nb = b"\x00" + nb

    a = int.from_bytes(nb[0:4], byteorder="little", signed=False)
    b = int.from_bytes(nb[4:8], byteorder="little", signed=False)
    c = int.from_bytes(nb[8:16], byteorder="little", signed=False)
    res = 0xFFFFFFFFFFFFFFFF & (a * b + c)
    if res <= 3:
        return {"detected": True}
    return False
