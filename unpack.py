import struct
import zlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher


class data(object):
    def __init__(self, file_name) -> None:
        self.handle = open(file_name, "rb")

    def unpack(self, parse: str, length: int):
        return struct.unpack(parse, self.handle.read(length))

    def ignore(self, length: int):
        return self.handle.read(length)


encblob_list = []
entry_list = []


def process_data():
    d = data("./archive")
    # magic_str = d.unpack("8s", 8)
    # print(magic_str[0].decode())
    fentry_len = d.unpack("I", 4)
    # print(f"total entries num: { fentry_len[0] }")
    for _ in range(fentry_len[0]):
        file_name_len = d.unpack("I", 4)[0]
        s = d.unpack(f"{file_name_len}s", file_name_len)[0]
        entry_list.append(s.decode())
        d.ignore(48)
        res = d.unpack("I", 4)[0]
        # print(res)
        enc_data = d.unpack(f"{res}s", res)[0]
        encblob_list.append(enc_data)


ivlist = []
keylist = []
dict_map_list = []


def process_key():
    k = data("./kerstore")
    # magic_str = k.unpack("8s", 8)
    # print(magic_str[0].decode())
    fentry_len = k.unpack("I", 4)
    # print(f"total entries num: { fentry_len[0] }")
    for _ in range(fentry_len[0]):
        k.ignore(16)
        key_tuple = list(k.unpack("32c", 32))
        key_tuple.reverse()
        iv = b"".join(key_tuple[0:16])
        key = b"".join(key_tuple[16:])
        ivlist.append(iv)
        keylist.append(key)
        # print(f"iv is {iv}")
        # print(f"key is {key}")
        dictmap_len = k.unpack("I", 4)[0]
        # print(dictmap_len)
        dict = {}
        for _ in range(dictmap_len):
            a = k.unpack("I", 4)[0]
            b = k.unpack("I", 4)[0]
            dict[a] = b
        dict_map_list.append(dict)


def dec():
    for i in range(16):
        print(f"decrypting {entry_list[i]}")
        blob = encblob_list[i]
        # print(blob)
        tmp_blob = {}
        for _, b in dict_map_list[i].items():
            tmp_blob[b] = blob[b * 128 : b * 128 + 128]
        original_enc_blob = []
        for j in range(len(tmp_blob)):
            original_enc_blob.append(tmp_blob[j])
        # print(b"".join(original_enc_blob))
        original_enc_blob = b"".join(original_enc_blob)
        cipher = Cipher(
            algorithms.AES(keylist[i]), modes.CBC(ivlist[i]), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        zlib_hash = decryptor.update(original_enc_blob)+decryptor.finalize()
        original_bytes = zlib.decompress(zlib_hash)
        print(original_bytes.decode())

        # break


if __name__ == "__main__":
    process_data()
    process_key()
    # print(encblob_list)
    dec()
    # print(ivlist)
    # print(keylist)
