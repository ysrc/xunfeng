
import string, re


def encode_name(name, type, scope = None):
    """
    Perform first and second level encoding of name as specified in RFC 1001 (Section 4)
    """
    if name == '*':
        name = name + '\0' * 15
    elif len(name) > 15:
        name = name[:15] + chr(type)
    else:
        name = string.ljust(name, 15) + chr(type)

    def _do_first_level_encoding(m):
        s = ord(m.group(0))
        return string.uppercase[s >> 4] + string.uppercase[s & 0x0f]

    encoded_name = chr(len(name) * 2) + re.sub('.', _do_first_level_encoding, name)
    if scope:
        encoded_scope = ''
        for s in string.split(scope, '.'):
            encoded_scope = encoded_scope + chr(len(s)) + s
        return encoded_name + encoded_scope + '\0'
    else:
        return encoded_name + '\0'


def decode_name(name):
    name_length = ord(name[0])
    assert name_length == 32

    def _do_first_level_decoding(m):
        s = m.group(0)
        return chr(((ord(s[0]) - ord('A')) << 4) | (ord(s[1]) - ord('A')))

    decoded_name = re.sub('..', _do_first_level_decoding, name[1:33])
    if name[33] == '\0':
        return 34, decoded_name, ''
    else:
        decoded_domain = ''
        offset = 34
        while 1:
            domain_length = ord(name[offset])
            if domain_length == 0:
                break
            decoded_domain = '.' + name[offset:offset + domain_length]
            offset = offset + domain_length
        return offset + 1, decoded_name, decoded_domain
