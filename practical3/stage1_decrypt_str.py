# String Decryptor for Stage 1 loader.
#
# Executable SHA256:
#   a0ac02a1e6c908b90173e86c3e321f2bab082ed45236503a21eb7d984de10611

table = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890./='
table += table


def decrypt_string(src: str) -> str:
    result = ''
    for c in src:
        if c in table:
            result += table[table.find(c) + 13]
        else:
            result += c
    return result


print(decrypt_string("I9egh1/n//b3"))  # VirtualAlloc
