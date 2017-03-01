
import os, sys, struct, types, logging, binascii, time
from StringIO import StringIO
from smb_constants import *


# Set to True if you want to enable support for extended security. Required for Windows Vista and later
SUPPORT_EXTENDED_SECURITY = True

# Set to True if you want to enable SMB2 protocol.
SUPPORT_SMB2 = True

# Supported dialects
DIALECTS = [ ]
for i, ( name, dialect ) in enumerate([ ( 'NT_LAN_MANAGER_DIALECT', 'NT LM 0.12' ), ]):
    DIALECTS.append(dialect)
    globals()[name] = i

DIALECTS2 = [ ]
for i, ( name, dialect ) in enumerate([ ( 'SMB2_DIALECT', 'SMB 2.002' ) ]):
    DIALECTS2.append(dialect)
    globals()[name] = i + len(DIALECTS)


class UnsupportedFeature(Exception):
    """
    Raised when an supported feature is present/required in the protocol but is not
    currently supported by pysmb
    """
    pass


class ProtocolError(Exception):

    def __init__(self, message, data_buf = None, smb_message = None):
        self.message = message
        self.data_buf = data_buf
        self.smb_message = smb_message

    def __str__(self):
        b = StringIO()
        b.write(self.message + os.linesep)
        if self.smb_message:
            b.write('=' * 20 + ' SMB Message ' + '=' * 20 + os.linesep)
            b.write(str(self.smb_message))

        if self.data_buf:
            b.write('=' * 20 + ' SMB Data Packet (hex) ' + '=' * 20 + os.linesep)
            b.write(binascii.hexlify(self.data_buf))
            b.write(os.linesep)

        return b.getvalue()

class SMB2ProtocolHeaderError(ProtocolError):

    def __init__(self):
        ProtocolError.__init__(self, "Packet header belongs to SMB2")

class OperationFailure(Exception):

    def __init__(self, message, smb_messages):
        self.args = [ message ]
        self.message = message
        self.smb_messages = smb_messages

    def __str__(self):
        b = StringIO()
        b.write(self.message + os.linesep)

        for idx, m in enumerate(self.smb_messages):
            b.write('=' * 20 + ' SMB Message %d ' % idx + '=' * 20 + os.linesep)
            b.write('SMB Header:' + os.linesep)
            b.write('-----------' + os.linesep)
            b.write(str(m))
            b.write('SMB Data Packet (hex):' + os.linesep)
            b.write('----------------------' + os.linesep)
            b.write(binascii.hexlify(m.raw_data))
            b.write(os.linesep)

        return b.getvalue()


class SMBError:

    def __init__(self):
        self.reset()

    def reset(self):
        self.internal_value = 0L
        self.is_ntstatus = True

    def __str__(self):
        if self.is_ntstatus:
            return 'NTSTATUS=0x%08X' % self.internal_value
        else:
            return 'ErrorClass=0x%02X ErrorCode=0x%04X' % ( self.internal_value >> 24, self.internal_value & 0xFFFF )

    @property
    def hasError(self):
        return self.internal_value != 0


class SMBMessage:

    HEADER_STRUCT_FORMAT = "<4sBIBHHQxxHHHHB"
    HEADER_STRUCT_SIZE = struct.calcsize(HEADER_STRUCT_FORMAT)

    log = logging.getLogger('SMB.SMBMessage')
    protocol = 1

    def __init__(self, payload = None):
        self.reset()
        if payload:
            self.payload = payload
            self.payload.initMessage(self)

    def __str__(self):
        b = StringIO()
        b.write('Command: 0x%02X (%s) %s' % ( self.command, SMB_COMMAND_NAMES.get(self.command, '<unknown>'), os.linesep ))
        b.write('Status: %s %s' % ( str(self.status), os.linesep ))
        b.write('Flags: 0x%02X %s' % ( self.flags, os.linesep ))
        b.write('Flags2: 0x%04X %s' % ( self.flags2, os.linesep ))
        b.write('PID: %d %s' % ( self.pid, os.linesep ))
        b.write('UID: %d %s' % ( self.uid, os.linesep ))
        b.write('MID: %d %s' % ( self.mid, os.linesep ))
        b.write('TID: %d %s' % ( self.tid, os.linesep ))
        b.write('Security: 0x%016X %s' % ( self.security, os.linesep ))
        b.write('Parameters: %d bytes %s%s %s' % ( len(self.parameters_data), os.linesep, binascii.hexlify(self.parameters_data), os.linesep ))
        b.write('Data: %d bytes %s%s %s' % ( len(self.data), os.linesep, binascii.hexlify(self.data), os.linesep ))
        return b.getvalue()

    def reset(self):
        self.raw_data = ''
        self.command = 0
        self.status = SMBError()
        self.flags = 0
        self.flags2 = 0
        self.pid = 0
        self.tid = 0
        self.uid = 0
        self.mid = 0
        self.security = 0L
        self.parameters_data = ''
        self.data = ''
        self.payload = None

    @property
    def isReply(self):
        return bool(self.flags & SMB_FLAGS_REPLY)

    @property
    def hasExtendedSecurity(self):
        return bool(self.flags2 & SMB_FLAGS2_EXTENDED_SECURITY)

    def encode(self):
        """
        Encode this SMB message into a series of bytes suitable to be embedded with a NetBIOS session message.
        AssertionError will be raised if this SMB message has not been initialized with a Payload instance

        @return: a string containing the encoded SMB message
        """
        assert self.payload

        self.pid = os.getpid()
        self.payload.prepare(self)

        parameters_len = len(self.parameters_data)
        assert parameters_len % 2 == 0

        headers_data = struct.pack(self.HEADER_STRUCT_FORMAT,
                                   '\xFFSMB', self.command, self.status.internal_value, self.flags,
                                   self.flags2, (self.pid >> 16) & 0xFFFF, self.security, self.tid,
                                   self.pid & 0xFFFF, self.uid, self.mid, int(parameters_len / 2))
        return headers_data + self.parameters_data + struct.pack('<H', len(self.data)) + self.data

    def decode(self, buf):
        """
        Decodes the SMB message in buf.
        All fields of the SMBMessage object will be reset to default values before decoding.
        On errors, do not assume that the fields will be reinstated back to what they are before
        this method is invoked.

        @param buf: data containing one complete SMB message
        @type buf: string
        @return: a positive integer indicating the number of bytes used in buf to decode this SMB message
        @raise ProtocolError: raised when decoding fails
        """
        buf_len = len(buf)
        if buf_len < self.HEADER_STRUCT_SIZE:
            # We need at least 32 bytes (header) + 1 byte (parameter count)
            raise ProtocolError('Not enough data to decode SMB header', buf)

        self.reset()

        protocol, self.command, status, self.flags, \
        self.flags2, pid_high, self.security, self.tid, \
        pid_low, self.uid, self.mid, params_count = struct.unpack(self.HEADER_STRUCT_FORMAT, buf[:self.HEADER_STRUCT_SIZE])

        if protocol == '\xFESMB':
            raise SMB2ProtocolHeaderError()
        if protocol != '\xFFSMB':
            raise ProtocolError('Invalid 4-byte protocol field', buf)

        self.pid = (pid_high << 16) | pid_low
        self.status.internal_value = status
        self.status.is_ntstatus = bool(self.flags2 & SMB_FLAGS2_NT_STATUS)

        offset = self.HEADER_STRUCT_SIZE
        if buf_len < params_count * 2 + 2:
            # Not enough data in buf to decode up to body length
            raise ProtocolError('Not enough data. Parameters list decoding failed', buf)

        datalen_offset = offset + params_count*2
        body_len = struct.unpack('<H', buf[datalen_offset:datalen_offset+2])[0]
        if body_len > 0 and buf_len < (datalen_offset + 2 + body_len):
            # Not enough data in buf to decode body
            raise ProtocolError('Not enough data. Body decoding failed', buf)

        self.parameters_data = buf[offset:datalen_offset]

        if body_len > 0:
            self.data = buf[datalen_offset+2:datalen_offset+2+body_len]

        self.raw_data = buf
        self._decodePayload()

        return self.HEADER_STRUCT_SIZE + params_count * 2 + 2 + body_len

    def _decodePayload(self):
        if self.command == SMB_COM_READ_ANDX:
            self.payload = ComReadAndxResponse()
        elif self.command == SMB_COM_WRITE_ANDX:
            self.payload = ComWriteAndxResponse()
        elif self.command == SMB_COM_TRANSACTION:
            self.payload = ComTransactionResponse()
        elif self.command == SMB_COM_TRANSACTION2:
            self.payload = ComTransaction2Response()
        elif self.command == SMB_COM_OPEN_ANDX:
            self.payload = ComOpenAndxResponse()
        elif self.command == SMB_COM_NT_CREATE_ANDX:
            self.payload = ComNTCreateAndxResponse()
        elif self.command == SMB_COM_TREE_CONNECT_ANDX:
            self.payload = ComTreeConnectAndxResponse()
        elif self.command == SMB_COM_ECHO:
            self.payload = ComEchoResponse()
        elif self.command == SMB_COM_SESSION_SETUP_ANDX:
            self.payload = ComSessionSetupAndxResponse()
        elif self.command == SMB_COM_NEGOTIATE:
            self.payload = ComNegotiateResponse()

        if self.payload:
            self.payload.decode(self)


class Payload:

    DEFAULT_ANDX_PARAM_HEADER = '\xFF\x00\x00\x00'
    DEFAULT_ANDX_PARAM_SIZE = 4

    def initMessage(self, message):
        # SMB_FLAGS2_UNICODE must always be enabled. Without this, almost all the Payload subclasses will need to be
        # rewritten to check for OEM/Unicode strings which will be tedious. Fortunately, almost all tested CIFS services
        # support SMB_FLAGS2_UNICODE by default.
        assert message.payload == self
        message.flags =  SMB_FLAGS_CASE_INSENSITIVE | SMB_FLAGS_CANONICALIZED_PATHS
        message.flags2 = SMB_FLAGS2_UNICODE | SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_LONG_NAMES | SMB_FLAGS2_EAS

        if SUPPORT_EXTENDED_SECURITY:
            message.flags2 |= SMB_FLAGS2_EXTENDED_SECURITY | SMB_FLAGS2_SMB_SECURITY_SIGNATURE

    def prepare(self, message):
        raise NotImplementedError

    def decode(self, message):
        raise NotImplementedError


class ComNegotiateRequest(Payload):
    """
    References:
    ===========
    - [MS-CIFS]: 2.2.4.52.1
    - [MS-SMB]: 2.2.4.5.1
    """

    def initMessage(self, message):
        Payload.initMessage(self, message)
        message.command = SMB_COM_NEGOTIATE

    def prepare(self, message):
        assert message.payload == self
        message.parameters_data = ''
        if SUPPORT_SMB2:
            message.data = ''.join(map(lambda s: '\x02'+s+'\x00', DIALECTS + DIALECTS2))
        else:
            message.data = ''.join(map(lambda s: '\x02'+s+'\x00', DIALECTS))


class ComNegotiateResponse(Payload):
    """
    Contains information on the SMB_COM_NEGOTIATE response from server

    After calling the decode method, each instance will contain the following attributes,
    - security_mode (integer)
    - max_mpx_count (integer)
    - max_number_vcs (integer)
    - max_buffer_size (long)
    - max_raw_size (long)
    - session_key (long)
    - capabilities (long)
    - system_time (long)
    - server_time_zone (integer)
    - challenge_length (integer)

    If the underlying SMB message's flag2 does not have SMB_FLAGS2_EXTENDED_SECURITY bit enabled,
    then the instance will have the following additional attributes,
    - challenge (string)
    - domain (unicode)

    If the underlying SMB message's flags2 has SMB_FLAGS2_EXTENDED_SECURITY bit enabled,
    then the instance will have the following additional attributes,
    - server_guid (string)
    - security_blob (string)

    References:
    ===========
    - [MS-SMB]: 2.2.4.5.2.1
    - [MS-CIFS]: 2.2.4.52.2
    """

    PAYLOAD_STRUCT_FORMAT = '<HBHHIIIIQHB'
    PAYLOAD_STRUCT_SIZE = struct.calcsize(PAYLOAD_STRUCT_FORMAT)

    def decode(self, message):
        assert message.command == SMB_COM_NEGOTIATE

        if not message.isReply:
            raise ProtocolError('Not a SMB_COM_NEGOTIATE reply', message.raw_data, message)

        self.security_mode, self.max_mpx_count, self.max_number_vcs, self.max_buffer_size, \
        self.max_raw_size, self.session_key, self.capabilities, self.system_time, self.server_time_zone, \
        self.challenge_length = ( 0, ) * 10

        data_len = len(message.parameters_data)
        if data_len < 2:
            raise ProtocolError('Not enough data to decode SMB_COM_NEGOTIATE dialect_index field', message.raw_data, message)

        self.dialect_index = struct.unpack('<H', message.parameters_data[:2])[0]
        if self.dialect_index == NT_LAN_MANAGER_DIALECT:
            if data_len != (0x11 * 2):
                raise ProtocolError('NT LAN Manager dialect selected in SMB_COM_NEGOTIATE but parameters bytes count (%d) does not meet specs' % data_len,
                                    message.raw_data, message)
            else:
                _, self.security_mode, self.max_mpx_count, self.max_number_vcs, self.max_buffer_size, \
                self.max_raw_size, self.session_key, self.capabilities, self.system_time, self.server_time_zone, \
                self.challenge_length = struct.unpack(self.PAYLOAD_STRUCT_FORMAT, message.parameters_data[:self.PAYLOAD_STRUCT_SIZE])
        elif self.dialect_index == 0xFFFF:
            raise ProtocolError('Server does not support any of the pysmb dialects. Please email pysmb to add in support for your OS',
                                message.raw_data, message)
        else:
            raise ProtocolError('Unknown dialect index (0x%04X)' % self.dialect_index, message.raw_data, message)

        data_len = len(message.data)
        if not message.hasExtendedSecurity:
            self.challenge, self.domain = '', ''
            if self.challenge_length > 0:
                if data_len >= self.challenge_length:
                    self.challenge = message.data[:self.challenge_length]

                    s = ''
                    offset = self.challenge_length
                    while offset < data_len:
                        _s = message.data[offset:offset+2]
                        if _s == '\0\0':
                            self.domain = s.decode('UTF-16LE')
                            break
                        else:
                            s += _s
                            offset += 2
                else:
                    raise ProtocolError('Not enough data to decode SMB_COM_NEGOTIATE (without security extensions) Challenge field', message.raw_data, message)
        else:
            if data_len < 16:
                raise ProtocolError('Not enough data to decode SMB_COM_NEGOTIATE (with security extensions) ServerGUID field', message.raw_data, message)

            self.server_guid = message.data[:16]
            self.security_blob = message.data[16:]

    @property
    def supportsExtendedSecurity(self):
        return bool(self.capabilities & CAP_EXTENDED_SECURITY)


class ComSessionSetupAndxRequest__WithSecurityExtension(Payload):
    """
    References:
    ===========
    - [MS-SMB]: 2.2.4.6.1
    """

    PAYLOAD_STRUCT_FORMAT = '<HHHIHII'

    def __init__(self, session_key, security_blob):
        self.session_key = session_key
        self.security_blob = security_blob

    def initMessage(self, message):
        Payload.initMessage(self, message)
        message.command = SMB_COM_SESSION_SETUP_ANDX

    def prepare(self, message):
        assert message.hasExtendedSecurity

        message.flags2 |= SMB_FLAGS2_UNICODE

        cap = CAP_UNICODE | CAP_STATUS32 | CAP_EXTENDED_SECURITY | CAP_NT_SMBS

        message.parameters_data = \
            self.DEFAULT_ANDX_PARAM_HEADER + \
            struct.pack(self.PAYLOAD_STRUCT_FORMAT,
                        16644, 10, 1, self.session_key, len(self.security_blob), 0, cap)

        message.data = self.security_blob
        if (SMBMessage.HEADER_STRUCT_SIZE + len(message.parameters_data) + len(message.data)) % 2 != 0:
            message.data = message.data + '\0'
        message.data = message.data + '\0' * 4


class ComSessionSetupAndxRequest__NoSecurityExtension(Payload):
    """
    References:
    ===========
    - [MS-CIFS]: 2.2.4.53.1
    """

    PAYLOAD_STRUCT_FORMAT = '<HHHIHHII'

    def __init__(self, session_key, username, password, is_unicode, domain):
        self.username = username
        self.session_key = session_key
        self.password = password
        self.is_unicode = is_unicode
        self.domain = domain

    def initMessage(self, message):
        Payload.initMessage(self, message)
        message.command = SMB_COM_SESSION_SETUP_ANDX

    def prepare(self, message):
        if self.is_unicode:
            message.flags2 |= SMB_FLAGS2_UNICODE
        else:
            message.flags2 &= (~SMB_FLAGS2_UNICODE & 0xFFFF)

        password_len = len(self.password)
        message.parameters_data = \
            self.DEFAULT_ANDX_PARAM_HEADER + \
            struct.pack(self.PAYLOAD_STRUCT_FORMAT,
                        16644, 10, 0, self.session_key,
                        (not self.is_unicode and password_len) or 0,
                        (self.is_unicode and password_len) or 0,
                        0,
                        CAP_UNICODE | CAP_LARGE_FILES | CAP_STATUS32)

        est_offset = SMBMessage.HEADER_STRUCT_SIZE + len(message.parameters_data)  # To check if data until SMB paramaters are aligned to a 16-bit boundary

        message.data = self.password
        if (est_offset + len(message.data)) % 2 != 0 and message.flags2 & SMB_FLAGS2_UNICODE:
            message.data = message.data + '\0'

        if message.flags2 & SMB_FLAGS2_UNICODE:
            message.data = message.data + self.username.encode('UTF-16LE') + '\0'
        else:
            message.data = message.data + str(self.username) + '\0'

        if (est_offset + len(message.data)) % 2 != 0 and message.flags2 & SMB_FLAGS2_UNICODE:
            message.data = message.data + '\0'

        if message.flags2 & SMB_FLAGS2_UNICODE:
            message.data = message.data + self.domain.encode('UTF-16LE') + '\0\0' + 'pysmb'.encode('UTF-16LE') + '\0\0'
        else:
            message.data = message.data + self.domain + '\0pysmb\0'


class ComSessionSetupAndxResponse(Payload):
    """
    Contains information on the SMB_COM_SESSION_SETUP_ANDX response from server

    If the underlying SMB message's flags2 does not have SMB_FLAGS2_EXTENDED_SECURITY bit enabled,
    then the instance will have the following attributes,
    - action

    If the underlying SMB message's flags2 has SMB_FLAGS2_EXTENDED_SECURITY bit enabled
    and the message status is STATUS_MORE_PROCESSING_REQUIRED or equals to 0x00 (no error),
    then the instance will have the following attributes,
    - action
    - securityblob

    If the underlying SMB message's flags2 has SMB_FLAGS2_EXTENDED_SECURITY bit enabled but
    the message status is not STATUS_MORE_PROCESSING_REQUIRED

    References:
    ===========
    - [MS-SMB]: 2.2.4.6.2
    - [MS-CIFS]: 2.2.4.53.2
    """

    NOSECURE_PARAMETER_STRUCT_FORMAT = '<BBHH'
    NOSECURE_PARAMETER_STRUCT_SIZE = struct.calcsize(NOSECURE_PARAMETER_STRUCT_FORMAT)

    SECURE_PARAMETER_STRUCT_FORMAT = '<BBHHH'
    SECURE_PARAMETER_STRUCT_SIZE = struct.calcsize(SECURE_PARAMETER_STRUCT_FORMAT)

    def decode(self, message):
        assert message.command == SMB_COM_SESSION_SETUP_ANDX
        if not message.hasExtendedSecurity:
            if not message.status.hasError:
                if len(message.parameters_data) < self.NOSECURE_PARAMETER_STRUCT_SIZE:
                    raise ProtocolError('Not enough data to decode SMB_COM_SESSION_SETUP_ANDX (no security extensions) parameters', message.raw_data, message)

                _, _, _, self.action = struct.unpack(self.NOSECURE_PARAMETER_STRUCT_FORMAT, message.parameters_data[:self.NOSECURE_PARAMETER_STRUCT_SIZE])
        else:
            if not message.status.hasError or message.status.internal_value == 0xc0000016:   # STATUS_MORE_PROCESSING_REQUIRED
                if len(message.parameters_data) < self.SECURE_PARAMETER_STRUCT_SIZE:
                    raise ProtocolError('Not enough data to decode SMB_COM_SESSION_SETUP_ANDX (with security extensions) parameters', message.raw_data, message)

                _, _, _, self.action, blob_length = struct.unpack(self.SECURE_PARAMETER_STRUCT_FORMAT, message.parameters_data[:self.SECURE_PARAMETER_STRUCT_SIZE])
                if len(message.data) < blob_length:
                    raise ProtocolError('Not enough data to decode SMB_COM_SESSION_SETUP_ANDX (with security extensions) security blob', message.raw_data, message)

                self.security_blob = message.data[:blob_length]


class ComTreeConnectAndxRequest(Payload):
    """
    References:
    ===========
    - [MS-CIFS]: 2.2.4.55.1
    - [MS-SMB]: 2.2.4.7.1
    """

    PAYLOAD_STRUCT_FORMAT = '<HH'
    PAYLOAD_STRUCT_SIZE = struct.calcsize(PAYLOAD_STRUCT_FORMAT)

    def __init__(self, path, service, password = ''):
        self.path = path
        self.service = service
        self.password = password + '\0'

    def initMessage(self, message):
        Payload.initMessage(self, message)
        message.command = SMB_COM_TREE_CONNECT_ANDX

    def prepare(self, message):
        password_len = len(self.password)
        message.parameters_data = \
            self.DEFAULT_ANDX_PARAM_HEADER + \
            struct.pack(self.PAYLOAD_STRUCT_FORMAT,
                        0x08 | \
                            ((message.hasExtendedSecurity and 0x0004) or 0x00) | \
                            ((message.tid and message.tid != 0xFFFF and 0x0001) or 0x00),  # Disconnect tid, if message.tid must be non-zero
                        password_len)

        padding = ''
        if password_len % 2 == 0:
            padding = '\0'

        # Note that service field is never encoded in UTF-16LE. [MS-CIFS]: 2.2.1.1
        message.data = self.password + padding + self.path.encode('UTF-16LE') + '\0\0' + self.service + '\0'


class ComTreeConnectAndxResponse(Payload):
    """
    Contains information about the SMB_COM_TREE_CONNECT_ANDX response from the server.

    If the message has no errors, each instance contains the following attributes:
    - optional_support

    References:
    ===========
    - [MS-CIFS]: 2.2.4.55.2
    """

    PAYLOAD_STRUCT_FORMAT = '<BBHH'
    PAYLOAD_STRUCT_SIZE = struct.calcsize(PAYLOAD_STRUCT_FORMAT)

    def decode(self, message):
        assert message.command == SMB_COM_TREE_CONNECT_ANDX

        if not message.status.hasError:
            if len(message.parameters_data) < self.PAYLOAD_STRUCT_SIZE:
                raise ProtocolError('Not enough data to decode SMB_COM_TREE_CONNECT_ANDX parameters', message.raw_data, message)

            _, _, _, self.optional_support = struct.unpack(self.PAYLOAD_STRUCT_FORMAT, message.parameters_data[:self.PAYLOAD_STRUCT_SIZE])


class ComNTCreateAndxRequest(Payload):
    """
    References:
    ===========
    - [MS-CIFS]: 2.2.4.64.1
    - [MS-SMB]: 2.2.4.9.1
    """

    PAYLOAD_STRUCT_FORMAT = '<BHIIIQIIIIIB'
    PAYLOAD_STRUCT_SIZE = struct.calcsize(PAYLOAD_STRUCT_FORMAT)

    def __init__(self, filename, flags = 0, root_fid = 0, access_mask = 0, allocation_size = 0L, ext_attr = 0,
                 share_access = 0, create_disp = 0, create_options = 0, impersonation = 0, security_flags = 0):
        self.filename = (filename + '\0').encode('UTF-16LE')
        self.flags = flags
        self.root_fid = root_fid
        self.access_mask = access_mask
        self.allocation_size = allocation_size
        self.ext_attr = ext_attr
        self.share_access = share_access
        self.create_disp = create_disp
        self.create_options = create_options
        self.impersonation = impersonation
        self.security_flags = security_flags

    def initMessage(self, message):
        Payload.initMessage(self, message)
        message.command = SMB_COM_NT_CREATE_ANDX

    def prepare(self, message):
        filename_len = len(self.filename)

        message.parameters_data = \
            self.DEFAULT_ANDX_PARAM_HEADER + \
            struct.pack(self.PAYLOAD_STRUCT_FORMAT,
                        0x00,                  # reserved
                        filename_len,          # NameLength
                        self.flags,            # Flags
                        self.root_fid,         # RootDirectoryFID
                        self.access_mask,      # DesiredAccess
                        self.allocation_size,  # AllocationSize
                        self.ext_attr,         # ExtFileAttributes
                        self.share_access,     # ShareAccess
                        self.create_disp,      # CreateDisposition
                        self.create_options,   # CreateOptions
                        self.impersonation,    # ImpersonationLevel
                        self.security_flags)   # SecurityFlags

        padding = ''
        if (message.HEADER_STRUCT_SIZE + len(message.parameters_data)) % 2 != 0:
            padding = '\0'

        message.data = padding + self.filename


class ComNTCreateAndxResponse(Payload):
    """
    Contains (partial) information about the SMB_COM_NT_CREATE_ANDX response from the server.

    Each instance contains the following attributes after decoding:
    - oplock_level
    - fid

    References:
    ===========
    - [MS-CIFS]: 2.2.4.64.2
    """
    PAYLOAD_STRUCT_FORMAT = '<BBHBH'
    PAYLOAD_STRUCT_SIZE = struct.calcsize(PAYLOAD_STRUCT_FORMAT)

    def decode(self, message):
        assert message.command == SMB_COM_NT_CREATE_ANDX

        if not message.status.hasError:
            if len(message.parameters_data) < self.PAYLOAD_STRUCT_SIZE:
                raise ProtocolError('Not enough data to decode SMB_COM_NT_CREATE_ANDX parameters', message.raw_data, message)

            _, _, _, self.oplock_level, self.fid = struct.unpack(self.PAYLOAD_STRUCT_FORMAT, message.parameters_data[:self.PAYLOAD_STRUCT_SIZE])


class ComTransactionRequest(Payload):
    """
    References:
    ===========
    - [MS-CIFS]: 2.2.4.33.1
    """

    PAYLOAD_STRUCT_FORMAT = '<HHHHBBHIHHHHHH'
    PAYLOAD_STRUCT_SIZE = struct.calcsize(PAYLOAD_STRUCT_FORMAT)

    def __init__(self, max_params_count, max_data_count, max_setup_count,
                 total_params_count = 0, total_data_count = 0,
                 params_bytes = '', data_bytes = '', setup_bytes = '',
                 flags = 0, timeout = 0, name = "\\PIPE\\"):
        self.total_params_count = total_params_count or len(params_bytes)
        self.total_data_count = total_data_count or len(data_bytes)
        self.max_params_count = max_params_count
        self.max_data_count = max_data_count
        self.max_setup_count = max_setup_count
        self.flags = flags
        self.timeout = timeout
        self.params_bytes = params_bytes
        self.data_bytes = data_bytes
        self.setup_bytes = setup_bytes
        self.name = name

    def initMessage(self, message):
        Payload.initMessage(self, message)
        message.command = SMB_COM_TRANSACTION

    def prepare(self, message):
        name = (self.name + '\0').encode('UTF-16LE')
        name_len = len(name)
        setup_bytes_len = len(self.setup_bytes)
        params_bytes_len = len(self.params_bytes)
        data_bytes_len = len(self.data_bytes)

        padding0 = ''
        offset = message.HEADER_STRUCT_SIZE + self.PAYLOAD_STRUCT_SIZE + setup_bytes_len + 2 # constant 2 is for the ByteCount field in the SMB header (i.e. field which indicates number of data bytes after the SMB parameters)
        if offset % 2 != 0:
            padding0 = '\0'
            offset += 1

        offset += name_len  # For the name field
        padding1 = ''
        if offset % 4 != 0:
            padding1 = '\0'*(4-offset%4)
            offset += (4-offset%4)

        if params_bytes_len > 0:
            params_bytes_offset = offset
            offset += params_bytes_len
        else:
            params_bytes_offset = 0

        padding2 = ''
        if offset % 4 != 0:
            padding2 = '\0'*(4-offset%4)
            offset += (4-offset%4)

        if data_bytes_len > 0:
            data_bytes_offset = offset
        else:
            data_bytes_offset = 0

        message.parameters_data = \
            struct.pack(self.PAYLOAD_STRUCT_FORMAT,
                        self.total_params_count,
                        self.total_data_count,
                        self.max_params_count,
                        self.max_data_count,
                        self.max_setup_count,
                        0x00,           # Reserved1. Must be 0x00
                        self.flags,
                        self.timeout,
                        0x0000,         # Reserved2. Must be 0x0000
                        params_bytes_len,
                        params_bytes_offset,
                        data_bytes_len,
                        data_bytes_offset,
                        int(setup_bytes_len / 2)) + \
            self.setup_bytes

        message.data = padding0 + name + padding1 + self.params_bytes + padding2 + self.data_bytes


class ComTransactionResponse(Payload):
    """
    Contains information about a SMB_COM_TRANSACTION response from the server

    After decoding, each instance contains the following attributes:
    - total_params_count (integer)
    - total_data_count (integer)
    - setup_bytes (string)
    - data_bytes (string)
    - params_bytes (string)

    References:
    ===========
    - [MS-CIFS]: 2.2.4.33.2
    """

    PAYLOAD_STRUCT_FORMAT = '<HHHHHHHHHH'
    PAYLOAD_STRUCT_SIZE = struct.calcsize(PAYLOAD_STRUCT_FORMAT)

    def decode(self, message):
        assert message.command == SMB_COM_TRANSACTION

        if not message.status.hasError:
            if len(message.parameters_data) < self.PAYLOAD_STRUCT_SIZE:
                raise ProtocolError('Not enough data to decode SMB_COM_TRANSACTION parameters', message.raw_data, message)

            self.total_params_count, self.total_data_count, _, \
            params_bytes_len, params_bytes_offset, params_bytes_displ, \
            data_bytes_len, data_bytes_offset, data_bytes_displ, \
            setup_count = struct.unpack(self.PAYLOAD_STRUCT_FORMAT, message.parameters_data[:self.PAYLOAD_STRUCT_SIZE])

            if setup_count > 0:
                setup_bytes_len = setup_count * 2

                if len(message.parameters_data) < self.PAYLOAD_STRUCT_SIZE + setup_bytes_len:
                    raise ProtocolError('Not enough data to decode SMB_COM_TRANSACTION parameters', message.raw_data, message)

                self.setup_bytes = message.parameters_data[self.PAYLOAD_STRUCT_SIZE:self.PAYLOAD_STRUCT_SIZE+setup_bytes_len]
            else:
                self.setup_bytes = ''

            offset = message.HEADER_STRUCT_SIZE + self.PAYLOAD_STRUCT_SIZE + setup_count * 2 + 2 # constant 2 is for the ByteCount field in the SMB header (i.e. field which indicates number of data bytes after the SMB parameters)

            if params_bytes_len > 0:
                self.params_bytes = message.data[params_bytes_offset-offset:params_bytes_offset-offset+params_bytes_len]
            else:
                self.params_bytes = ''

            if data_bytes_len > 0:
                self.data_bytes = message.data[data_bytes_offset-offset:data_bytes_offset-offset+data_bytes_len]
            else:
                self.data_bytes = ''


class ComTransaction2Request(Payload):
    """
    References:
    ===========
    - [MS-CIFS]: 2.2.4.46.1
    """

    PAYLOAD_STRUCT_FORMAT = 'HHHHBBHIHHHHHH'
    PAYLOAD_STRUCT_SIZE = struct.calcsize(PAYLOAD_STRUCT_FORMAT)

    def __init__(self, max_params_count, max_data_count, max_setup_count,
                 total_params_count = 0, total_data_count = 0,
                 params_bytes = '', data_bytes = '', setup_bytes = '',
                 flags = 0, timeout = 0):
        self.total_params_count = total_params_count or len(params_bytes)
        self.total_data_count = total_data_count or len(data_bytes)
        self.max_params_count = max_params_count
        self.max_data_count = max_data_count
        self.max_setup_count = max_setup_count
        self.flags = flags
        self.timeout = timeout
        self.params_bytes = params_bytes
        self.data_bytes = data_bytes
        self.setup_bytes = setup_bytes

    def initMessage(self, message):
        Payload.initMessage(self, message)
        message.command = SMB_COM_TRANSACTION2

    def prepare(self, message):
        setup_bytes_len = len(self.setup_bytes)
        params_bytes_len = len(self.params_bytes)
        data_bytes_len = len(self.data_bytes)
        name = '\0\0'

        padding0 = ''
        offset = message.HEADER_STRUCT_SIZE + self.PAYLOAD_STRUCT_SIZE + setup_bytes_len + 2 # constant 2 is for the ByteCount field in the SMB header (i.e. field which indicates number of data bytes after the SMB parameters)
        if offset % 2 != 0:
            padding0 = '\0'
            offset += 1

        offset += 2  # For the name field
        padding1 = ''
        if offset % 4 != 0:
            padding1 = '\0'*(4-offset%4)

        if params_bytes_len > 0:
            params_bytes_offset = offset
            offset += params_bytes_len
        else:
            params_bytes_offset = 0

        padding2 = ''
        if offset % 4 != 0:
            padding2 = '\0'*(4-offset%4)

        if data_bytes_len > 0:
            data_bytes_offset = offset
        else:
            data_bytes_offset = 0

        message.parameters_data = \
            struct.pack(self.PAYLOAD_STRUCT_FORMAT,
                        self.total_params_count,
                        self.total_data_count,
                        self.max_params_count,
                        self.max_data_count,
                        self.max_setup_count,
                        0x00,           # Reserved1. Must be 0x00
                        self.flags,
                        self.timeout,
                        0x0000,         # Reserved2. Must be 0x0000
                        params_bytes_len,
                        params_bytes_offset,
                        data_bytes_len,
                        data_bytes_offset,
                        int(setup_bytes_len / 2)) + \
            self.setup_bytes

        message.data = padding0 + name + padding1 + self.params_bytes + padding2 + self.data_bytes


class ComTransaction2Response(Payload):
    """
    Contains information about a SMB_COM_TRANSACTION2 response from the server

    After decoding, each instance contains the following attributes:
    - total_params_count (integer)
    - total_data_count (integer)
    - setup_bytes (string)
    - data_bytes (string)
    - params_bytes (string)

    References:
    ===========
    - [MS-CIFS]: 2.2.4.46.2
    """

    PAYLOAD_STRUCT_FORMAT = '<HHHHHHHHHBB'
    PAYLOAD_STRUCT_SIZE = struct.calcsize(PAYLOAD_STRUCT_FORMAT)

    def decode(self, message):
        assert message.command == SMB_COM_TRANSACTION2

        if not message.status.hasError:
            if len(message.parameters_data) < self.PAYLOAD_STRUCT_SIZE:
                raise ProtocolError('Not enough data to decode SMB_COM_TRANSACTION2 parameters', message.raw_data, message)

            self.total_params_count, self.total_data_count, _, \
            params_bytes_len, params_bytes_offset, params_bytes_displ, \
            data_bytes_len, data_bytes_offset, data_bytes_displ, \
            setup_count, _ = struct.unpack(self.PAYLOAD_STRUCT_FORMAT, message.parameters_data[:self.PAYLOAD_STRUCT_SIZE])

            if setup_count > 0:
                setup_bytes_len = setup_count * 2

                if len(message.parameters_data) < self.PAYLOAD_STRUCT_SIZE + setup_bytes_len:
                    raise ProtocolError('Not enough data to decode SMB_COM_TRANSACTION parameters', message.raw_data, message)

                self.setup_bytes = message.parameters_data[self.PAYLOAD_STRUCT_SIZE:self.PAYLOAD_STRUCT_SIZE+setup_bytes_len]
            else:
                self.setup_bytes = ''

            offset = message.HEADER_STRUCT_SIZE + self.PAYLOAD_STRUCT_SIZE + setup_count * 2 + 2 # constant 2 is for the ByteCount field in the SMB header (i.e. field which indicates number of data bytes after the SMB parameters)

            if params_bytes_len > 0:
                self.params_bytes = message.data[params_bytes_offset-offset:params_bytes_offset-offset+params_bytes_len]
            else:
                self.params_bytes = ''

            if data_bytes_len > 0:
                self.data_bytes = message.data[data_bytes_offset-offset:data_bytes_offset-offset+data_bytes_len]
            else:
                self.data_bytes = ''


class ComCloseRequest(Payload):
    """
    References:
    ===========
    - [MS-CIFS]: 2.2.4.5.1
    """

    PAYLOAD_STRUCT_FORMAT = '<HI'
    PAYLOAD_STRUCT_SIZE = struct.calcsize(PAYLOAD_STRUCT_FORMAT)

    def __init__(self, fid, last_modified_time = 0xFFFFFFFF):
        self.fid = fid
        self.last_modified_time = last_modified_time

    def initMessage(self, message):
        Payload.initMessage(self, message)
        message.command = SMB_COM_CLOSE

    def prepare(self, message):
        message.parameters_data = struct.pack(self.PAYLOAD_STRUCT_FORMAT, self.fid, self.last_modified_time)
        message.data = ''


class ComOpenAndxRequest(Payload):
    """
    References:
    ===========
    - [MS-CIFS]: 2.2.4.41.1
    """

    PAYLOAD_STRUCT_FORMAT = '<HHHHIHIII'
    PAYLOAD_STRUCT_SIZE = struct.calcsize(PAYLOAD_STRUCT_FORMAT)

    def __init__(self, filename, access_mode, open_mode, flags = 0x0000, search_attributes = 0, file_attributes = 0, create_time = 0, timeout = 0):
        """
        @param create_time: Epoch time value to indicate the time of creation for this file. If zero, we will automatically assign the current time
        @type create_time: int
        @param timeout: Number of milliseconds to wait for blocked open request before failing
        @type timeout: int
        """
        self.filename = filename
        self.access_mode = access_mode
        self.open_mode = open_mode
        self.flags = flags
        self.search_attributes = search_attributes
        self.file_attributes = file_attributes
        self.create_time = create_time or int(time.time())
        self.timeout = timeout

    def initMessage(self, message):
        Payload.initMessage(self, message)
        message.command = SMB_COM_OPEN_ANDX

    def prepare(self, message):
        message.parameters_data = \
            self.DEFAULT_ANDX_PARAM_HEADER + \
            struct.pack(self.PAYLOAD_STRUCT_FORMAT,
                        self.flags,
                        self.access_mode,
                        self.search_attributes,
                        self.file_attributes,
                        self.create_time,
                        self.open_mode,
                        0,  # AllocationSize
                        0,  # Timeout (in milli-secs)
                        0)  # Reserved

        message.data = '\0' + self.filename.encode('UTF-16LE') + '\0\0'


class ComOpenAndxResponse(Payload):
    """
    Contains information about a SMB_COM_OPEN_ANDX response from the server

    After decoding, each instance will contain the following attributes:
    - fid (integer)
    - file_attributes (integer)
    - last_write_time (long)
    - access_rights (integer)
    - resource_type (integer)
    - open_results (integer)

    References:
    ===========
    - [MS-CIFS]: 2.2.4.41.2
    - [MS-SMB]: 2.2.4.1.2
    """

    PAYLOAD_STRUCT_FORMAT = '<BBHHHIIHHHHHHH'
    PAYLOAD_STRUCT_SIZE = struct.calcsize(PAYLOAD_STRUCT_FORMAT)

    def decode(self, message):
        assert message.command == SMB_COM_OPEN_ANDX

        if not message.status.hasError:
            if len(message.parameters_data) < self.PAYLOAD_STRUCT_SIZE:
                raise ProtocolError('Not enough data to decode SMB_COM_OPEN_ANDX parameters', message.raw_data, message)

            _, _, _, self.fid, self.file_attributes, self.last_write_time, _, \
            self.access_rights, self.resource_type, _, self.open_results, _, _, _ = struct.unpack(self.PAYLOAD_STRUCT_FORMAT,
                                                                                                  message.parameters_data[:self.PAYLOAD_STRUCT_SIZE])


class ComWriteAndxRequest(Payload):
    """
    References:
    ===========
    - [MS-CIFS]: 2.2.4.43.1
    - [MS-SMB]: 2.2.4.3.1
    """

    PAYLOAD_STRUCT_FORMAT = '<HIIHHHHHI'
    PAYLOAD_STRUCT_SIZE = struct.calcsize(PAYLOAD_STRUCT_FORMAT)

    def __init__(self, fid, data_bytes, offset, write_mode = 0, timeout = 0):
        """
        @param timeout: Number of milliseconds to wait for blocked write request before failing. Must be zero for writing to regular file
        @type timeout: int
        """
        self.fid = fid
        self.offset = offset
        self.data_bytes = data_bytes
        self.timeout = timeout
        self.write_mode = write_mode

    def initMessage(self, message):
        Payload.initMessage(self, message)
        message.command = SMB_COM_WRITE_ANDX

    def prepare(self, message):
        # constant 1 is to account for the pad byte in the message.data
        # constant 2 is for the ByteCount field in the SMB header (i.e. field which indicates number of data bytes after the SMB parameters)
        data_offset = message.HEADER_STRUCT_SIZE + self.DEFAULT_ANDX_PARAM_SIZE + self.PAYLOAD_STRUCT_SIZE + 1 + 2
        data_len = len(self.data_bytes)

        message.parameters_data = \
            self.DEFAULT_ANDX_PARAM_HEADER + \
            struct.pack(self.PAYLOAD_STRUCT_FORMAT,
                        self.fid,
                        self.offset & 0xFFFFFFFF,
                        self.timeout,
                        self.write_mode,
                        data_len,   # Remaining
                        0x0000,     # Reserved
                        len(self.data_bytes),  # DataLength
                        data_offset,           # DataOffset
                        self.offset >> 32)     # OffsetHigh field defined in [MS-SMB]: 2.2.4.3.1

        message.data = '\0' + self.data_bytes


class ComWriteAndxResponse(Payload):
    """
    References:
    ===========
    - [MS-CIFS]: 2.2.4.43.2
    - [MS-SMB]: 2.2.4.3.2
    """

    PAYLOAD_STRUCT_FORMAT = '<BBHHHHH'  # We follow the SMB_COM_WRITEX_ANDX server extensions in [MS-SMB]: 2.2.4.3.2
    PAYLOAD_STRUCT_SIZE = struct.calcsize(PAYLOAD_STRUCT_FORMAT)

    def decode(self, message):
        assert message.command == SMB_COM_WRITE_ANDX

        if not message.status.hasError:
            if len(message.parameters_data) < self.PAYLOAD_STRUCT_SIZE:
                raise ProtocolError('Not enough data to decode SMB_COM_WRITE_ANDX parameters', message.raw_data, message)

            _, _, _, count, self.available, high_count, _ = struct.unpack(self.PAYLOAD_STRUCT_FORMAT, message.parameters_data[:self.PAYLOAD_STRUCT_SIZE])
            self.count = (count & 0xFFFF) | (high_count << 16)


class ComReadAndxRequest(Payload):
    """
    References:
    ===========
    - [MS-CIFS]: 2.2.4.42.1
    - [MS-SMB]: 2.2.4.2.1
    """

    PAYLOAD_STRUCT_FORMAT = '<HIHHIHI'
    PAYLOAD_STRUCT_SIZE = struct.calcsize(PAYLOAD_STRUCT_FORMAT)

    def __init__(self, fid, offset, max_return_bytes_count, min_return_bytes_count, timeout = 0, remaining = 0):
        """
        @param timeout: If reading from a regular file, this parameter must be 0.
        @type timeout: int
        """
        self.fid = fid
        self.remaining = remaining
        self.max_return_bytes_count = max_return_bytes_count
        self.min_return_bytes_count = min_return_bytes_count
        self.offset = offset
        self.timeout = timeout

    def initMessage(self, message):
        Payload.initMessage(self, message)
        message.command = SMB_COM_READ_ANDX

    def prepare(self, message):
        message.parameters_data = \
            self.DEFAULT_ANDX_PARAM_HEADER + \
            struct.pack(self.PAYLOAD_STRUCT_FORMAT,
                        self.fid,
                        self.offset & 0xFFFFFFFF,
                        self.max_return_bytes_count,
                        self.min_return_bytes_count,
                        self.timeout or (self.max_return_bytes_count >> 32),  # Note that in [MS-SMB]: 2.2.4.2.1, this field can also act as MaxCountHigh field
                        self.remaining, # In [MS-CIFS]: 2.2.4.42.1, this field must be set to 0x0000
                        self.offset >> 32)

        message.data = ''


class ComReadAndxResponse(Payload):
    """
    References:
    ===========
    - [MS-CIFS]: 2.2.4.42.2
    - [MS-SMB]: 2.2.4.2.2
    """

    PAYLOAD_STRUCT_FORMAT = '<BBHHHHHHHHHHH'
    PAYLOAD_STRUCT_SIZE = struct.calcsize(PAYLOAD_STRUCT_FORMAT)

    def decode(self, message):
        assert message.command == SMB_COM_READ_ANDX

        if not message.status.hasError:
            if len(message.parameters_data) < self.PAYLOAD_STRUCT_SIZE:
                raise ProtocolError('Not enough data to decode SMB_COM_READ_ANDX parameters', message.raw_data, message)

            _, _, _, _, _, _, self.data_length, data_offset, _, _, _, _, _ = struct.unpack(self.PAYLOAD_STRUCT_FORMAT,
                                                                                           message.parameters_data[:self.PAYLOAD_STRUCT_SIZE])

            offset = data_offset - message.HEADER_STRUCT_SIZE - self.PAYLOAD_STRUCT_SIZE - 2  # constant 2 is for the ByteCount field in the SMB header (i.e. field which indicates number of data bytes after the SMB parameters)
            self.data = message.data[offset:offset+self.data_length]
            assert len(self.data) == self.data_length


class ComDeleteRequest(Payload):
    """
    References:
    ===========
    - [MS-CIFS]: 2.2.4.7.1
    """

    def __init__(self, filename_pattern, search_attributes = 0):
        self.filename_pattern = filename_pattern
        self.search_attributes = search_attributes

    def initMessage(self, message):
        Payload.initMessage(self, message)
        message.command = SMB_COM_DELETE

    def prepare(self, message):
        message.parameters_data = struct.pack('<H', self.search_attributes)
        message.data = '\x04' + self.filename_pattern.encode('UTF-16LE') + '\0\0'


class ComCreateDirectoryRequest(Payload):
    """
    Although this command has been marked deprecated in [MS-CIFS], we continue to use it for its simplicity
    as compared to its replacement TRANS2_CREATE_DIRECTORY sub-command [MS-CIFS]: 2.2.6.14

    References:
    ===========
    - [MS-CIFS]: 2.2.4.1.1
    """

    def __init__(self, path):
        self.path = path

    def initMessage(self, message):
        Payload.initMessage(self, message)
        message.command = SMB_COM_CREATE_DIRECTORY

    def prepare(self, message):
        message.parameters_data = ''
        message.data = '\x04' + self.path.encode('UTF-16LE') + '\0\0'


class ComDeleteDirectoryRequest(Payload):
    """
    References:
    ===========
    - [MS-CIFS]: 2.2.4.2.1
    """

    def __init__(self, path):
        self.path = path

    def initMessage(self, message):
        Payload.initMessage(self, message)
        message.command = SMB_COM_DELETE_DIRECTORY

    def prepare(self, message):
        message.parameters_data = ''
        message.data = '\x04' + self.path.encode('UTF-16LE') + '\0\0'


class ComRenameRequest(Payload):
    """
    References:
    ===========
    - [MS-CIFS]: 2.2.4.8.1
    """

    def __init__(self, old_path, new_path, search_attributes = 0):
        self.old_path = old_path
        self.new_path = new_path
        self.search_attributes = search_attributes

    def initMessage(self, message):
        Payload.initMessage(self, message)
        message.command = SMB_COM_RENAME

    def prepare(self, message):
        message.parameters_data = struct.pack('<H', self.search_attributes)
        message.data = '\x04' + self.old_path.encode('UTF-16LE') + '\x00\x00\x04\x00' + self.new_path.encode('UTF-16LE') + '\x00\x00'


class ComEchoRequest(Payload):
    """
    References:
    ===========
    - [MS-CIFS]: 2.2.4.39.1
    """

    def __init__(self, echo_data = '', echo_count = 1):
        self.echo_count = echo_count
        self.echo_data = echo_data

    def initMessage(self, message):
        Payload.initMessage(self, message)
        message.command = SMB_COM_ECHO
        message.tid = 0xFFFF

    def prepare(self, message):
        message.parameters_data = struct.pack('<H', self.echo_count)
        message.data = self.echo_data


class ComEchoResponse(Payload):
    """
    References:
    ===========
    - [MS-CIFS]: 2.2.4.39.2
    """

    def decode(self, message):
        self.sequence_number = struct.unpack('<H', message.parameters_data[:2])[0]
        self.data = message.data


class ComNTTransactRequest(Payload):
    """
    References:
    ===========
    - [MS-CIFS]: 2.2.4.62.1
    """
    PAYLOAD_STRUCT_FORMAT = '<BHIIIIIIIIBH'
    PAYLOAD_STRUCT_SIZE = struct.calcsize(PAYLOAD_STRUCT_FORMAT)

    def __init__(self, function, max_params_count, max_data_count, max_setup_count,
                 total_params_count = 0, total_data_count = 0,
                 params_bytes = '', setup_bytes = '', data_bytes = ''):
        self.function = function
        self.total_params_count = total_params_count or len(params_bytes)
        self.total_data_count = total_data_count or len(data_bytes)
        self.max_params_count = max_params_count
        self.max_data_count = max_data_count
        self.max_setup_count = max_setup_count
        self.params_bytes = params_bytes
        self.setup_bytes = setup_bytes
        self.data_bytes = data_bytes

    def initMessage(self, message):
        Payload.initMessage(self, message)
        message.command = SMB_COM_NT_TRANSACT

    def prepare(self, message):
        setup_bytes_len = len(self.setup_bytes)
        params_bytes_len = len(self.params_bytes)
        data_bytes_len = len(self.data_bytes)

        padding0 = ''
        offset = message.HEADER_STRUCT_SIZE + self.PAYLOAD_STRUCT_SIZE + setup_bytes_len + 2 # constant 2 is for the ByteCount field in the SMB header (i.e. field which indicates number of data bytes after the SMB parameters)
        if offset % 4 != 0:
            padding0 = '\0'*(4-offset%4)
            offset += (4-offset%4)

        if params_bytes_len > 0:
            params_bytes_offset = offset
        else:
            params_bytes_offset = 0

        offset += params_bytes_len
        padding1 = ''
        if offset % 4 != 0:
            padding1 = '\0'*(4-offset%4)
            offset += (4-offset%4)

        if data_bytes_len > 0:
            data_bytes_offset = offset
        else:
            data_bytes_offset = 0

        message.parameters_data = \
            struct.pack(self.PAYLOAD_STRUCT_FORMAT,
                        self.max_setup_count,
                        0x00,           # Reserved1. Must be 0x00
                        self.total_params_count,
                        self.total_data_count,
                        self.max_params_count,
                        self.max_data_count,
                        params_bytes_len,
                        params_bytes_offset,
                        data_bytes_len,
                        data_bytes_offset,
                        int(setup_bytes_len / 2),
                        self.function) + \
            self.setup_bytes

        message.data = padding0 + self.params_bytes + padding1 + self.data_bytes


class ComNTTransactResponse(Payload):
    """
    Contains information about a SMB_COM_NT_TRANSACT response from the server

    After decoding, each instance contains the following attributes:
    - total_params_count (integer)
    - total_data_count (integer)
    - setup_bytes (string)
    - data_bytes (string)
    - params_bytes (string)

    References:
    ===========
    - [MS-CIFS]: 2.2.4.62.2
    """
    PAYLOAD_STRUCT_FORMAT = '<3sIIIIIIIIBH'
    PAYLOAD_STRUCT_SIZE = struct.calcsize(PAYLOAD_STRUCT_FORMAT)

    def decode(self, message):
        assert message.command == SMB_COM_NT_TRANSACT

        if not message.status.hasError:
            _, self.total_params_count, self.total_data_count, \
            params_count, params_offset, params_displ, \
            data_count, data_offset, data_displ, setup_count = struct.unpack(self.PAYLOAD_STRUCT_FORMAT,
                                                                             message.parameters_data[:self.PAYLOAD_STRUCT_SIZE])

            self.setup_bytes = message.parameters_data[self.PAYLOAD_STRUCT_SIZE:self.PAYLOAD_STRUCT_SIZE+setup_count*2]

            if params_count > 0:
                params_offset -= message.HEADER_STRUCT_SIZE + self.PAYLOAD_STRUCT_SIZE + setup_count*2 + 2
                self.params_bytes = message.data[params_offset:params_offset+params_count]
            else:
                self.params_bytes = ''

            if data_count > 0:
                data_offset -= message.HEADER_STRUCT_SIZE + self.PAYLOAD_STRUCT_SIZE + setup_count*2 + 2
                self.data_bytes = message.data[data_offset:data_offset+data_count]
            else:
                self.data_bytes = ''
