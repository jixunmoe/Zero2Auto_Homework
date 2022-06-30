from pefile import PE
from sys import argv
import requests


def get_rdata(pe: PE) -> bytes:
    for section in pe.sections:
        if b'.rdata' in section.Name:
            return section.get_data()
    return b''


def iter_null_term_str(data: bytes):
    temp = bytearray()
    for b in data:
        if b == 0:
            if len(temp) > 0:
                yield bytes(temp)
                temp.clear()
        else:
            temp.append(b)


def rol_u8_4(value: int) -> int:
    return ((value << 4) | (value >> 4)) & 0xff


def ror_u8_4(value: int) -> int:
    return rol_u8_4(value)


def decrypt_str(src: bytes, xor_key: int) -> bytes:
    result = bytearray()
    for b in src:
        result.append(rol_u8_4(b) ^ xor_key)
    return bytes(result)


def naive_decode_string_to_url(s: bytes) -> str:
    '''
    attempt to decode a given string buffer to url start with "http".
    '''
    xor_key = rol_u8_4(s[0]) ^ b'h'[0]
    if decrypt_str(s[0:4], xor_key) == b'http':
        return decrypt_str(s, xor_key).decode(encoding='ascii')
    return ''


def fetch_remote_content(url: str) -> bytes:
    resp = requests.get(url, headers={
        'User-Agent': 'cruloader'
    })
    if resp.status_code == 200:
        return resp.content
    return b''


def extract_payload_from_url(url: str) -> bytes:
    next_url = fetch_remote_content(url)
    if next_url == b'':
        return b''
    next_url = next_url.decode('utf-8')
    payload_image = fetch_remote_content(next_url)
    pos = payload_image.find(b'redaolurc')
    if pos == -1:
        return b''
    payload = bytearray(payload_image[pos + 9:])
    return bytes(map(lambda x: x ^ 0x61, payload))


def extract_stage2_to_stage_3(input_exe: bytes) -> bytes:
    pe = PE(data=input_exe)
    rdata = get_rdata(pe)

    for s in iter_null_term_str(rdata):
        if len(s) > 4 and len(s) < 255:
            url = naive_decode_string_to_url(s)
            if url == '':
                continue
            payload = extract_payload_from_url(url)
            if payload != b'':
                return payload

    return b''


def main(input_path, output_path):
    with open(input_path, 'rb') as f:
        input_file = f.read()
    stage3 = extract_stage2_to_stage_3(input_file)
    with open(output_path, 'wb') as f:
        f.write(stage3)


if __name__ == '__main__':
    main(argv[1], argv[2])
