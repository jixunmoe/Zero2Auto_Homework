from pefile import PE
from sys import argv
from arc4 import ARC4
import struct


def extract_resource_by_id(pe: PE, resource_id: int) -> bytearray:
    for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for resource in res_type.directory.entries:
            if resource.struct.Id == resource_id:
                for res_lang in resource.directory.entries:
                    offset = res_lang.data.struct.OffsetToData
                    size = res_lang.data.struct.Size
                    return bytearray(pe.get_data(offset, size))
    return None


def extract_stage1_to_stage_2(input_file: bytes) -> bytes:
    pe = PE(data=input_file)
    data = bytes(extract_resource_by_id(pe, 101))
    (size_div_10, rc4_key) = struct.unpack("<8xI15sx", data[0:0x1c])
    payload_size = size_div_10 * 10
    rc4 = ARC4(rc4_key)
    return rc4.decrypt(data[0x1c:0x1c + payload_size])


def main(input_path, output_path):
    with open(input_path, 'rb') as f:
        input_file = f.read()
    stage2 = extract_stage1_to_stage_2(input_file)
    with open(output_path, 'wb') as f:
        f.write(stage2)


if __name__ == '__main__':
    main(argv[1], argv[2])
