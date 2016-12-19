
import types, hmac, binascii, struct, random
from utils.pyDes import des

try:
    import hashlib
    hashlib.new('md4')

    def MD4(): return hashlib.new('md4')
except ( ImportError, ValueError ):
    from utils.md4 import MD4

try:
    import hashlib
    def MD5(s): return hashlib.md5(s)
except ImportError:
    import md5
    def MD5(s): return md5.new(s)

################
# NTLMv2 Methods
################

# The following constants are defined in accordance to [MS-NLMP]: 2.2.2.5

NTLM_NegotiateUnicode                =  0x00000001
NTLM_NegotiateOEM                    =  0x00000002
NTLM_RequestTarget                   =  0x00000004
NTLM_Unknown9                        =  0x00000008
NTLM_NegotiateSign                   =  0x00000010
NTLM_NegotiateSeal                   =  0x00000020
NTLM_NegotiateDatagram               =  0x00000040
NTLM_NegotiateLanManagerKey          =  0x00000080
NTLM_Unknown8                        =  0x00000100
NTLM_NegotiateNTLM                   =  0x00000200
NTLM_NegotiateNTOnly                 =  0x00000400
NTLM_Anonymous                       =  0x00000800
NTLM_NegotiateOemDomainSupplied      =  0x00001000
NTLM_NegotiateOemWorkstationSupplied =  0x00002000
NTLM_Unknown6                        =  0x00004000
NTLM_NegotiateAlwaysSign             =  0x00008000
NTLM_TargetTypeDomain                =  0x00010000
NTLM_TargetTypeServer                =  0x00020000
NTLM_TargetTypeShare                 =  0x00040000
NTLM_NegotiateExtendedSecurity       =  0x00080000
NTLM_NegotiateIdentify               =  0x00100000
NTLM_Unknown5                        =  0x00200000
NTLM_RequestNonNTSessionKey          =  0x00400000
NTLM_NegotiateTargetInfo             =  0x00800000
NTLM_Unknown4                        =  0x01000000
NTLM_NegotiateVersion                =  0x02000000
NTLM_Unknown3                        =  0x04000000
NTLM_Unknown2                        =  0x08000000
NTLM_Unknown1                        =  0x10000000
NTLM_Negotiate128                    =  0x20000000
NTLM_NegotiateKeyExchange            =  0x40000000
NTLM_Negotiate56                     =  0x80000000

NTLM_FLAGS = NTLM_NegotiateUnicode | \
             NTLM_RequestTarget | \
             NTLM_NegotiateNTLM | \
             NTLM_NegotiateAlwaysSign | \
             NTLM_NegotiateExtendedSecurity | \
             NTLM_NegotiateTargetInfo | \
             NTLM_NegotiateVersion | \
             NTLM_Negotiate128 | \
             NTLM_NegotiateKeyExchange | \
             NTLM_Negotiate56

def generateNegotiateMessage():
    """
    References:
    ===========
    - [MS-NLMP]: 2.2.1.1
    """
    s = struct.pack('<8sII8s8s8s',
                    'NTLMSSP\0', 0x01, NTLM_FLAGS,
                    '\0' * 8,  # Domain
                    '\0' * 8,  # Workstation
                    '\x06\x00\x72\x17\x00\x00\x00\x0F')  # Version [MS-NLMP]: 2.2.2.10
    return s


def generateAuthenticateMessage(challenge_flags, nt_response, lm_response, session_key, user, domain = 'WORKGROUP', workstation = 'LOCALHOST'):
    """
    References:
    ===========
    - [MS-NLMP]: 2.2.1.3
    """
    FORMAT = '<8sIHHIHHIHHIHHIHHIHHII'
    FORMAT_SIZE = struct.calcsize(FORMAT)

    lm_response_length = len(lm_response)
    lm_response_offset = FORMAT_SIZE
    nt_response_length = len(nt_response)
    nt_response_offset = lm_response_offset + lm_response_length
    domain_unicode = domain.encode('UTF-16LE')
    domain_length = len(domain_unicode)
    domain_offset = nt_response_offset + nt_response_length

    padding = ''
    if domain_offset % 2 != 0:
        padding = '\0'
        domain_offset += 1

    user_unicode = user.encode('UTF-16LE')
    user_length = len(user_unicode)
    user_offset = domain_offset + domain_length
    workstation_unicode = workstation.encode('UTF-16LE')
    workstation_length = len(workstation_unicode)
    workstation_offset = user_offset + user_length
    session_key_length = len(session_key)
    session_key_offset = workstation_offset + workstation_length

    auth_flags = challenge_flags
    auth_flags &= ~NTLM_NegotiateVersion

    s = struct.pack(FORMAT,
                    'NTLMSSP\0', 0x03,
                    lm_response_length, lm_response_length, lm_response_offset,
                    nt_response_length, nt_response_length, nt_response_offset,
                    domain_length, domain_length, domain_offset,
                    user_length, user_length, user_offset,
                    workstation_length, workstation_length, workstation_offset,
                    session_key_length, session_key_length, session_key_offset,
                    auth_flags)

    return s + lm_response + nt_response + padding + domain_unicode + user_unicode + workstation_unicode + session_key


def decodeChallengeMessage(ntlm_data):
    """
    References:
    ===========
    - [MS-NLMP]: 2.2.1.2
    - [MS-NLMP]: 2.2.2.1 (AV_PAIR)
    """
    FORMAT = '<8sIHHII8s8sHHI'
    FORMAT_SIZE = struct.calcsize(FORMAT)

    signature, message_type, \
    targetname_len, targetname_maxlen, targetname_offset, \
    flags, challenge, _, \
    targetinfo_len, targetinfo_maxlen, targetinfo_offset, \
        = struct.unpack(FORMAT, ntlm_data[:FORMAT_SIZE])

    assert signature == 'NTLMSSP\0'
    assert message_type == 0x02

    return challenge, flags, ntlm_data[targetinfo_offset:targetinfo_offset+targetinfo_len]


def generateChallengeResponseV2(password, user, server_challenge, server_info, domain = '', client_challenge = None):
    client_timestamp = '\0' * 8

    if not client_challenge:
        client_challenge = ''
        for i in range(0, 8):
            client_challenge += chr(random.getrandbits(8))
    assert len(client_challenge) == 8

    d = MD4()
    d.update(password.encode('UTF-16LE'))
    ntlm_hash = d.digest()   # The NT password hash
    response_key = hmac.new(ntlm_hash, (user.upper() + domain).encode('UTF-16LE')).digest()  # The NTLMv2 password hash. In [MS-NLMP], this is the result of NTOWFv2 and LMOWFv2 functions
    temp = '\x01\x01' + '\0'*6 + client_timestamp + client_challenge + '\0'*4 + server_info
    ntproofstr = hmac.new(response_key, server_challenge + temp).digest()

    nt_challenge_response = ntproofstr + temp
    lm_challenge_response = hmac.new(response_key, server_challenge + client_challenge).digest() + client_challenge
    session_key = hmac.new(response_key, ntproofstr).digest()

    return nt_challenge_response, lm_challenge_response, session_key


################
# NTLMv1 Methods
################

def expandDesKey(key):
    """Expand the key from a 7-byte password key into a 8-byte DES key"""
    s = chr(((ord(key[0]) >> 1) & 0x7f) << 1)
    s = s + chr(((ord(key[0]) & 0x01) << 6 | ((ord(key[1]) >> 2) & 0x3f)) << 1)
    s = s + chr(((ord(key[1]) & 0x03) << 5 | ((ord(key[2]) >> 3) & 0x1f)) << 1)
    s = s + chr(((ord(key[2]) & 0x07) << 4 | ((ord(key[3]) >> 4) & 0x0f)) << 1)
    s = s + chr(((ord(key[3]) & 0x0f) << 3 | ((ord(key[4]) >> 5) & 0x07)) << 1)
    s = s + chr(((ord(key[4]) & 0x1f) << 2 | ((ord(key[5]) >> 6) & 0x03)) << 1)
    s = s + chr(((ord(key[5]) & 0x3f) << 1 | ((ord(key[6]) >> 7) & 0x01)) << 1)
    s = s + chr((ord(key[6]) & 0x7f) << 1)
    return s


def DESL(K, D):
    """
    References:
    ===========
    - http://ubiqx.org/cifs/SMB.html (2.8.3.4)
    - [MS-NLMP]: Section 6
    """
    d1 = des(expandDesKey(K[0:7]))
    d2 = des(expandDesKey(K[7:14]))
    d3 = des(expandDesKey(K[14:16] + '\0' * 5))
    return d1.encrypt(D) + d2.encrypt(D) + d3.encrypt(D)


def generateChallengeResponseV1(password, server_challenge, has_extended_security = False, client_challenge = None):
    """
    Generate a NTLMv1 response

    @param password: User password string
    @param server_challange: A 8-byte challenge string sent from the server
    @param has_extended_security: A boolean value indicating whether NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY flag is enabled in the NTLM negFlag
    @param client_challenge: A 8-byte string representing client challenge. If None, it will be generated randomly if needed by the response generation
    @return: a tuple of ( NT challenge response string, LM challenge response string )

    References:
    ===========
    - http://ubiqx.org/cifs/SMB.html (2.8.3.3 and 2.8.3.4)
    - [MS-NLMP]: 3.3.1
    """
    _password = (password.upper() + '\0' * 14)[:14]
    d1 = des(expandDesKey(_password[:7]))
    d2 = des(expandDesKey(_password[7:]))
    lm_response_key = d1.encrypt("KGS!@#$%") + d2.encrypt("KGS!@#$%")  # LM password hash. In [MS-NLMP], this is the result of LMOWFv1 function

    d = MD4()
    d.update(password.encode('UTF-16LE'))
    nt_response_key = d.digest()   # In [MS-NLMP], this is the result of NTOWFv1 function

    if has_extended_security:
        if not client_challenge:
            client_challenge = ''
            for i in range(0, 8):
                client_challenge += chr(random.getrandbits(8))

        assert len(client_challenge) == 8

        lm_challenge_response = client_challenge + '\0'*16
        nt_challenge_response = DESL(nt_response_key, MD5(server_challenge + client_challenge).digest()[0:8])
    else:
        nt_challenge_response = DESL(nt_response_key, server_challenge)   # The result after DESL is the NT response
        lm_challenge_response = DESL(lm_response_key, server_challenge)   # The result after DESL is the LM response

    d = MD4()
    d.update(nt_response_key)
    session_key = d.digest()

    return nt_challenge_response, lm_challenge_response, session_key
