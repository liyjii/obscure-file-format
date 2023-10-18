import os as osi
import uuid as uuidi
import zlib as zlibi
import struct as structi
import random as randomi
import pathlib as pathlibi
import pathlib
import argparse as argparsei
import cryptography.hazmat.backends as backendsi
import cryptography.hazmat.primitives.ciphers as ciphersi
from cryptography.hazmat.primitives.ciphers import algorithms, modes

data1 = 16
data2 = 16
backend = backendsi.default_backend()


class aesenc_class:
    def __init__(self):
        self.randomstr1 = osi.urandom(data1)
        self.randomstr2 = osi.urandom(data2)
        self.cipher = ciphersi.Cipher(
            algorithms.AES(self.randomstr2),
            modes.CBC(self.randomstr1),
            backend=backend,
        )

    def __str__(self):
        return f"[{self.randomstr1.hex()}|{self.randomstr2.hex()}]"

    def hash_bytes(self, bytes: "bytes"):
        res = self.cipher.encryptor()
        return res.update(bytes) + res.finalize()

    def rev_key_bytes(self):
        tmp = list((self.randomstr1 + self.randomstr2))
        tmp.reverse()
        return bytes(tmp)


def padding_bytes(param_bytes: "bytes", param_int: "int"):
    tmp = param_int - (len(param_bytes) % param_int)
    return param_bytes + bytes(([tmp] * tmp))


class enc_class:
    len_128 = 128
    len_16 = 16

    def __init__(
        self,
        file_ins: "file_class",
    ):
        self.file_ins = file_ins
        self.aesenc = aesenc_class()
        self.dict_map: dict[int, int] = {}

    def __str__(self):
        return f"[{self.file_ins.uuid}|{self.aesenc}]"

    def serilize(self):
        if not self.dict_map:
            raise RuntimeError("Serializing key before data...")
        res_bytes = self.file_ins.uuid.bytes
        res_bytes += self.aesenc.rev_key_bytes()
        res_bytes += structi.pack(
            "I",
            len(self.dict_map),
        )
        for (
            key,
            value,
        ) in self.dict_map.items():
            res_bytes += structi.pack(
                "2I",
                key,
                value,
            )
        return res_bytes

    def get_bytes(self):
        with self.file_ins.file_name_path.open("rb") as f:
            file_bytes = f.read()
        zlib_bytes = padding_bytes(zlibi.compress(file_bytes), 16)
        hash_bytes = padding_bytes(self.aesenc.hash_bytes(zlib_bytes), 128)
        hash_len = len(hash_bytes) // 128
        random_range = list(range(hash_len))
        randomi.shuffle(random_range)
        for (
            a,
            random,
        ) in zip(
            list(range(hash_len)),
            random_range,
        ):
            self.dict_map[a] = random
        hash_step_by_128 = [
            hash_bytes[(i * 128) : ((i + 1) * 128)] for i in range(hash_len)
        ]
        res = bytes([])
        for i in range(hash_len):
            res += hash_step_by_128[self.dict_map[i]]
        return res


class file_class:
    def __init__(
        self,
        path_name: "pathlib.Path",
    ):
        self.ifile_name = path_name
        self.iuuid = uuidi.uuid4()
        self.istat = path_name.stat()

    def __str__(self):
        return f"[{self.iuuid}|{self.ifile_name}]"

    @property
    def uuid(self):
        return self.iuuid

    @property
    def file_name_path(self):
        return self.ifile_name

    @property
    def file_name(self):
        return str(self.ifile_name)

    @property
    def st_size(self):
        return self.istat.st_size

    @property
    def st_mode(self):
        return self.istat.st_mode

    @property
    def st_atime(self):
        return self.istat.st_atime

    @property
    def st_mtime(self):
        return self.istat.st_mtime

    @property
    def st_ctime(self):
        return self.istat.st_ctime

    def get_file_bytes(self):
        c_file_name = self.file_name.encode() + bytes([0])
        res_bytes = structi.pack("I", len(c_file_name))
        res_bytes += c_file_name
        res_bytes += self.uuid.bytes
        res_bytes += structi.pack(
            "2I",
            self.st_size,
            self.st_mode,
        )
        res_bytes += structi.pack(
            "3d",
            self.st_atime,
            self.st_mtime,
            self.st_ctime,
        )
        return res_bytes


class process_engine:
    magic_bytes = bytes([76, 48, 76, 75, 83, 84, 82, 0])

    def __init__(self):
        self.enc_list: list[enc_class] = []

    def doing(
        self,
        file_ins: "file_class",
    ):
        enc_ins = enc_class(file_ins)
        print(enc_ins)
        self.enc_list.append(enc_ins)
        return enc_ins

    def write_to_keystore(
        self,
        path: "pathlib.Path",
    ):
        keystore_bytes = process_engine.magic_bytes
        keystore_bytes += structi.pack(
            "I",
            len(self.enc_list),
        )
        for item in self.enc_list:
            keystore_bytes += item.serilize()
        path.joinpath("keystore").write_bytes(keystore_bytes)


class factory_class:
    magic_bytes = bytes([76, 48, 76, 65, 82, 67, 72, 0])
    size_limit = 1024 * 1024

    def __init__(self):
        self.fentry_info_list: list[tuple[file_class, enc_class]] = []
        self.engine = process_engine()

    def process(
        self,
        file_name: "pathlib.Path",
    ):
        file_ins = file_class(file_name)
        print(file_ins)
        if file_ins.st_size > factory_class.size_limit:
            raise RuntimeError(
                f"{file_ins.file_name_path} size too big ({factory_class.size_limit})!"
            )
        serialize_ins = self.engine.doing(file_ins)
        self.fentry_info_list.append((file_ins, serialize_ins))

    def write_to_archive(
        self,
        path: "pathlib.Path",
    ):
        archive_bytes = factory_class.magic_bytes
        archive_bytes += structi.pack(
            "I",
            len(self.fentry_info_list),
        )
        for (
            file_ins,
            enc_ins,
        ) in self.fentry_info_list:
            print(f"adding {file_ins.file_name_path}...")
            archive_bytes += file_ins.get_file_bytes()
            res_bytes = enc_ins.get_bytes()
            archive_bytes += structi.pack(
                "I",
                len(res_bytes),
            )
            archive_bytes += res_bytes
        path.joinpath("archive").write_bytes(archive_bytes)
        self.engine.write_to_keystore(path)


class filter_file_class:
    def __init__(
        self,
        dec_path: "pathlib.Path",
    ):
        self.item = pathlibi.Path(dec_path)

    def filter_file(self, is_recur: "bool"):
        all_items = list(self.item.glob("*"))
        if is_recur:
            all_items = list(self.item.rglob("*"))
        return list(
            filter(
                (lambda file: file.is_file()),
                all_items,
            )
        )


def parse_argi():
    parser = argparsei.ArgumentParser(description="")
    parser.add_argument("d")
    parser.add_argument("o")
    return parser.parse_args()


def main():
    namespace = parse_argi()
    print(namespace)
    factory_ins = factory_class()
    print(factory_ins)
    filter_file_ins = filter_file_class(namespace.d)
    print(filter_file_ins)
    o_filepath = pathlibi.Path(namespace.o)
    print(o_filepath)
    for file in filter_file_ins.filter_file(True):
        factory_ins.process(file)
    o_filepath.mkdir(
        parents=True,
        exist_ok=True,
    )
    factory_ins.write_to_archive(o_filepath)


if __name__ == "__main__":
    main()
