
import os, sys, struct, types, logging, binascii, time
from StringIO import StringIO
from smb_structs import ProtocolError
from smb_constants import *
from smb2_constants import *
from utils import convertFILETIMEtoEpoch


class SMB2Message:

    HEADER_STRUCT_FORMAT = "<4sHHIHHI"  # This refers to the common header part that is shared by both sync and async SMB2 header
    HEADER_STRUCT_SIZE = struct.calcsize(HEADER_STRUCT_FORMAT)

    ASYNC_HEADER_STRUCT_FORMAT = "<IQQQ16s"
    ASYNC_HEADER_STRUCT_SIZE = struct.calcsize(ASYNC_HEADER_STRUCT_FORMAT)

    SYNC_HEADER_STRUCT_FORMAT = "<IQIIQ16s"
    SYNC_HEADER_STRUCT_SIZE = struct.calcsize(SYNC_HEADER_STRUCT_FORMAT)

    HEADER_SIZE = 64

    log = logging.getLogger('SMB.SMB2Message')
    protocol = 2

    def __init__(self, payload = None):
        self.reset()
        if payload:
            self.payload = payload
            self.payload.initMessage(self)

    def __str__(self):
        b = StringIO()
        b.write('Command: 0x%02X (%s) %s' % ( self.command, SMB2_COMMAND_NAMES.get(self.command, '<unknown>'), os.linesep ))
        b.write('Status: 0x%08X %s' % ( self.status, os.linesep ))
        b.write('Flags: 0x%02X %s' % ( self.flags, os.linesep ))
        b.write('PID: %d %s' % ( self.pid, os.linesep ))
        b.write('MID: %d %s' % ( self.mid, os.linesep ))
        b.write('TID: %d %s' % ( self.tid, os.linesep ))
        b.write('Data: %d bytes %s%s %s' % ( len(self.data), os.linesep, binascii.hexlify(self.data), os.linesep ))
        return b.getvalue()

    def reset(self):
        self.raw_data = ''
        self.command = 0
        self.status = 0
        self.flags = 0

        self.next_command_offset = 0
        self.mid = 0
        self.session_id = 0
        self.signature = '\0'*16
        self.payload = None
        self.data = ''

        # For async SMB2 message
        self.async_id = 0

        # For sync SMB2 message
        self.pid = 0
        self.tid = 0

        # Not used in this class. Maintained for compatibility with SMBMessage class
        self.flags2 = 0
        self.uid = 0
        self.security = 0L
        self.parameters_data = ''

    def encode(self):
        """
        Encode this SMB2 message into a series of bytes suitable to be embedded with a NetBIOS session message.
        AssertionError will be raised if this SMB message has not been initialized with a Payload instance

        @return: a string containing the encoded SMB2 message
        """
        assert self.payload

        self.pid = os.getpid()
        self.payload.prepare(self)

        headers_data = struct.pack(self.HEADER_STRUCT_FORMAT,
                                   '\xFESMB', self.HEADER_SIZE, 0, self.status, self.command, 0, self.flags) + \
                       struct.pack(self.SYNC_HEADER_STRUCT_FORMAT, self.next_command_offset, self.mid, self.pid, self.tid, self.session_id, self.signature)
        return headers_data + self.data

    def decode(self, buf):
        """
        Decodes the SMB message in buf.
        All fields of the SMB2Message object will be reset to default values before decoding.
        On errors, do not assume that the fields will be reinstated back to what they are before
        this method is invoked.

        References
        ==========
        - [MS-SMB2]: 2.2.1

        @param buf: data containing one complete SMB2 message
        @type buf: string
        @return: a positive integer indicating the number of bytes used in buf to decode this SMB message
        @raise ProtocolError: raised when decoding fails
        """
        buf_len = len(buf)
        if buf_len < 64:  # All SMB2 headers must be at least 64 bytes. [MS-SMB2]: 2.2.1.1, 2.2.1.2
            raise ProtocolError('Not enough data to decode SMB2 header', buf)

        self.reset()

        protocol, struct_size, self.credit_charge, self.status, \
            self.command, self.credit_re, self.flags = struct.unpack(self.HEADER_STRUCT_FORMAT, buf[:self.HEADER_STRUCT_SIZE])

        if protocol != '\xFESMB':
            raise ProtocolError('Invalid 4-byte SMB2 protocol field', buf)

        if struct_size != self.HEADER_SIZE:
            raise ProtocolError('Invalid SMB2 header structure size')

        if self.isAsync:
            if buf_len < self.HEADER_STRUCT_SIZE+self.ASYNC_HEADER_STRUCT_SIZE:
                raise ProtocolError('Not enough data to decode SMB2 header', buf)

            self.next_command_offset, self.mid, self.async_id, self.session_id, \
                self.signature = struct.unpack(self.ASYNC_HEADER_STRUCT_FORMAT,
                                               buf[self.HEADER_STRUCT_SIZE:self.HEADER_STRUCT_SIZE+self.ASYNC_HEADER_STRUCT_SIZE])
        else:
            if buf_len < self.HEADER_STRUCT_SIZE+self.SYNC_HEADER_STRUCT_SIZE:
                raise ProtocolError('Not enough data to decode SMB2 header', buf)

            self.next_command_offset, self.mid, self.pid, self.tid, self.session_id, \
                self.signature = struct.unpack(self.SYNC_HEADER_STRUCT_FORMAT,
                                               buf[self.HEADER_STRUCT_SIZE:self.HEADER_STRUCT_SIZE+self.SYNC_HEADER_STRUCT_SIZE])

        if self.next_command_offset > 0:
            self.raw_data = buf[:self.next_command_offset]
            self.data = buf[self.HEADER_SIZE:self.next_command_offset]
        else:
            self.raw_data = buf
            self.data = buf[self.HEADER_SIZE:]

        self._decodeCommand()
        if self.payload:
            self.payload.decode(self)

        return len(self.raw_data)

    def _decodeCommand(self):
        if self.command == SMB2_COM_READ:
            self.payload = SMB2ReadResponse()
        elif self.command == SMB2_COM_WRITE:
            self.payload = SMB2WriteResponse()
        elif self.command == SMB2_COM_QUERY_DIRECTORY:
            self.payload = SMB2QueryDirectoryResponse()
        elif self.command == SMB2_COM_CREATE:
            self.payload = SMB2CreateResponse()
        elif self.command == SMB2_COM_CLOSE:
            self.payload = SMB2CloseResponse()
        elif self.command == SMB2_COM_QUERY_INFO:
            self.payload = SMB2QueryInfoResponse()
        elif self.command == SMB2_COM_SET_INFO:
            self.payload = SMB2SetInfoResponse()
        elif self.command == SMB2_COM_IOCTL:
            self.payload = SMB2IoctlResponse()
        elif self.command == SMB2_COM_TREE_CONNECT:
            self.payload = SMB2TreeConnectResponse()
        elif self.command == SMB2_COM_SESSION_SETUP:
            self.payload = SMB2SessionSetupResponse()
        elif self.command == SMB2_COM_NEGOTIATE:
            self.payload = SMB2NegotiateResponse()
        elif self.command == SMB2_COM_ECHO:
            self.payload = SMB2EchoResponse()

    @property
    def isAsync(self):
        return bool(self.flags & SMB2_FLAGS_ASYNC_COMMAND)

    @property
    def isReply(self):
        return bool(self.flags & SMB2_FLAGS_SERVER_TO_REDIR)


class Structure:

    def initMessage(self, message):
        pass

    def prepare(self, message):
        raise NotImplementedError

    def decode(self, message):
        raise NotImplementedError


class SMB2NegotiateResponse(Structure):
    """
    Contains information on the SMB2_NEGOTIATE response from server

    After calling the decode method, each instance will contain the following attributes,
    - security_mode (integer)
    - dialect_revision (integer)
    - server_guid (string)
    - max_transact_size (integer)
    - max_read_size (integer)
    - max_write_size (integer)
    - system_time (long)
    - server_start_time (long)
    - security_blob (string)

    References:
    ===========
    - [MS-SMB2]: 2.2.4
    """

    STRUCTURE_FORMAT = "<HHHH16sIIIIQQHHI"
    STRUCTURE_SIZE = struct.calcsize(STRUCTURE_FORMAT)

    def decode(self, message):
        assert message.command == SMB2_COM_NEGOTIATE

        if message.status == 0:
            struct_size, self.security_mode, self.dialect_revision, _, self.server_guid, self.capabilities, \
            self.max_transact_size, self.max_read_size, self.max_write_size, self.system_time, self.server_start_time, \
            security_buf_offset, security_buf_len, _ = struct.unpack(self.STRUCTURE_FORMAT, message.raw_data[SMB2Message.HEADER_SIZE:SMB2Message.HEADER_SIZE+self.STRUCTURE_SIZE])

            self.server_start_time = convertFILETIMEtoEpoch(self.server_start_time)
            self.system_time = convertFILETIMEtoEpoch(self.system_time)
            self.security_blob = message.raw_data[security_buf_offset:security_buf_offset+security_buf_len]


class SMB2SessionSetupRequest(Structure):
    """
    References:
    ===========
    - [MS-SMB2]: 2.2.5
    """

    STRUCTURE_FORMAT = "<HBBIIHHQ"
    STRUCTURE_SIZE = struct.calcsize(STRUCTURE_FORMAT)

    def __init__(self, security_blob):
        self.security_blob = security_blob

    def initMessage(self, message):
        Structure.initMessage(self, message)
        message.command = SMB2_COM_SESSION_SETUP

    def prepare(self, message):
        message.data = struct.pack(self.STRUCTURE_FORMAT,
                                   25,   # Structure size. Must be 25 as mandated by [MS-SMB2] 2.2.5
                                   0,    # VcNumber
                                   0x01, # Security mode
                                   0x00, # Capabilities
                                   0,    # Channel
                                   SMB2Message.HEADER_SIZE + self.STRUCTURE_SIZE,
                                   len(self.security_blob),
                                   0) + self.security_blob


class SMB2SessionSetupResponse(Structure):
    """
    Contains information about the SMB2_COM_SESSION_SETUP response from the server.

    If the message has no errors, each instance contains the following attributes:
    - session_flags (integer)
    - security_blob (string)

    References:
    ===========
    - [MS-SMB2]: 2.2.6
    """

    STRUCTURE_FORMAT = "<HHHH"
    STRUCTURE_SIZE = struct.calcsize(STRUCTURE_FORMAT)

    def decode(self, message):
        assert message.command == SMB2_COM_SESSION_SETUP

        struct_size, self.session_flags, security_blob_offset, security_blob_len \
            = struct.unpack(self.STRUCTURE_FORMAT, message.raw_data[SMB2Message.HEADER_SIZE:SMB2Message.HEADER_SIZE+self.STRUCTURE_SIZE])

        self.security_blob = message.raw_data[security_blob_offset:security_blob_offset+security_blob_len]


class SMB2TreeConnectRequest(Structure):
    """
    References:
    ===========
    - [MS-SMB2]: 2.2.9
    """

    STRUCTURE_FORMAT = "<HHHH"
    STRUCTURE_SIZE = struct.calcsize(STRUCTURE_FORMAT)

    def __init__(self, path):
        self.path = path

    def initMessage(self, message):
        Structure.initMessage(self, message)
        message.command = SMB2_COM_TREE_CONNECT

    def prepare(self, message):
        message.data = struct.pack(self.STRUCTURE_FORMAT,
                                   9,  # Structure size. Must be 9 as mandated by [MS-SMB2] 2.2.9
                                   0,  # Reserved
                                   SMB2Message.HEADER_SIZE + self.STRUCTURE_SIZE,
                                   len(self.path)*2) + self.path.encode('UTF-16LE')


class SMB2TreeConnectResponse(Structure):
    """
    Contains information about the SMB2_COM_TREE_CONNECT response from the server.

    If the message has no errors, each instance contains the following attributes:
    - share_type (integer): one of the SMB2_SHARE_TYPE_xxx constants
    - share_flags (integer)
    - capabilities (integer): bitmask of SMB2_SHARE_CAP_xxx
    - maximal_access (integer)

    References:
    ===========
    - [MS-SMB2]: 2.2.10
    """

    STRUCTURE_FORMAT = "<HBBIII"
    STRUCTURE_SIZE = struct.calcsize(STRUCTURE_FORMAT)

    def decode(self, message):
        assert message.command == SMB2_COM_TREE_CONNECT

        if message.status == 0:
            struct_size, self.share_type, _, \
                self.share_flags, self.capabilities, self.maximal_access \
                = struct.unpack(self.STRUCTURE_FORMAT, message.raw_data[SMB2Message.HEADER_SIZE:SMB2Message.HEADER_SIZE+self.STRUCTURE_SIZE])


class SMB2CreateRequest(Structure):
    """
    References:
    ===========
    - [MS-SMB2]: 2.2.13
    """

    STRUCTURE_FORMAT = "<HBBIQQIIIIIHHII"
    STRUCTURE_SIZE = struct.calcsize(STRUCTURE_FORMAT)

    def __init__(self, filename, file_attributes = 0,
                 access_mask = 0, share_access = 0, create_disp = 0, create_options = 0,
                 impersonation = SEC_ANONYMOUS,
                 oplock = SMB2_OPLOCK_LEVEL_NONE,
                 create_context_data = ''):
        self.filename = filename
        self.file_attributes = file_attributes
        self.access_mask = access_mask
        self.share_access = share_access
        self.create_disp = create_disp
        self.create_options = create_options
        self.oplock = oplock
        self.impersonation = impersonation
        self.create_context_data = create_context_data or ''

    def initMessage(self, message):
        Structure.initMessage(self, message)
        message.command = SMB2_COM_CREATE

    def prepare(self, message):
        buf = self.filename.encode('UTF-16LE')
        if self.create_context_data:
            n = SMB2Message.HEADER_SIZE + self.STRUCTURE_SIZE + len(buf)
            if n % 8 != 0:
                buf += '\0'*(8-n%8)
                create_context_offset = SMB2Message.HEADER_SIZE + self.STRUCTURE_SIZE + len(buf)
            else:
                create_context_offset = n
            buf += self.create_context_data
        else:
            create_context_offset = 0
        if not buf:
            buf = '\0'

        assert create_context_offset % 8 == 0
        message.data = struct.pack(self.STRUCTURE_FORMAT,
                                   57,   # Structure size. Must be 57 as mandated by [MS-SMB2] 2.2.13
                                   0,    # SecurityFlag. Must be 0
                                   self.oplock,
                                   self.impersonation,
                                   0,    # SmbCreateFlags. Must be 0
                                   0,    # Reserved. Must be 0
                                   self.access_mask,  # DesiredAccess. [MS-SMB2] 2.2.13.1
                                   self.file_attributes,
                                   self.share_access,
                                   self.create_disp,
                                   self.create_options,
                                   SMB2Message.HEADER_SIZE + self.STRUCTURE_SIZE,  # NameOffset
                                   len(self.filename)*2,    # NameLength in bytes
                                   create_context_offset,   # CreateContextOffset
                                   len(self.create_context_data)   # CreateContextLength
                                  ) + buf

class SMB2CreateResponse(Structure):
    """
    Contains information about the SMB2_COM_CREATE response from the server.

    If the message has no errors, each instance contains the following attributes:
    - oplock (integer): one of SMB2_OPLOCK_LEVEL_xxx constants
    - create_action (integer): one of SMB2_FILE_xxx constants
    - allocation_size (long)
    - file_size (long)
    - file_attributes (integer)
    - fid (16-bytes string)
    - create_time, lastaccess_time, lastwrite_time, change_time (float)

    References:
    ===========
    - [MS-SMB2]: 2.2.14
    """

    STRUCTURE_FORMAT = "<HBBIQQQQQQII16sII"
    STRUCTURE_SIZE = struct.calcsize(STRUCTURE_FORMAT)

    def decode(self, message):
        assert message.command == SMB2_COM_CREATE

        if message.status == 0:
            struct_size, self.oplock, _, self.create_action, \
            create_time, lastaccess_time, lastwrite_time, change_time, \
            self.allocation_size, self.file_size, self.file_attributes, \
            _, self.fid, _, _ = struct.unpack(self.STRUCTURE_FORMAT, message.raw_data[SMB2Message.HEADER_SIZE:SMB2Message.HEADER_SIZE+self.STRUCTURE_SIZE])

            self.create_time = convertFILETIMEtoEpoch(create_time)
            self.lastaccess_time = convertFILETIMEtoEpoch(lastaccess_time)
            self.lastwrite_time = convertFILETIMEtoEpoch(lastwrite_time)
            self.change_time = convertFILETIMEtoEpoch(change_time)


class SMB2WriteRequest(Structure):
    """
    References:
    ===========
    - [MS-SMB2]: 2.2.21
    """

    STRUCTURE_FORMAT = "<HHIQ16sIIHHI"
    STRUCTURE_SIZE = struct.calcsize(STRUCTURE_FORMAT)

    def __init__(self, fid, data, offset, remaining_len = 0, flags = 0):
        assert len(fid) == 16
        self.fid = fid
        self.data = data
        self.offset = offset
        self.remaining_len = remaining_len
        self.flags = flags

    def initMessage(self, message):
        Structure.initMessage(self, message)
        message.command = SMB2_COM_WRITE

    def prepare(self, message):
        message.data = struct.pack(self.STRUCTURE_FORMAT,
                                   49,  # Structure size. Must be 49 as mandated by [MS-SMB2] 2.2.21
                                   SMB2Message.HEADER_SIZE + self.STRUCTURE_SIZE,  # DataOffset
                                   len(self.data),
                                   self.offset,
                                   self.fid,
                                   0,  # Channel. Must be 0
                                   self.remaining_len,  # RemainingBytes
                                   0,  # WriteChannelInfoOffset,
                                   0,  # WriteChannelInfoLength
                                   self.flags) + self.data


class SMB2WriteResponse(Structure):
    """
    Contains information about the SMB2_WRITE response from the server.

    If the message has no errors, each instance contains the following attributes:
    - count (integer)

    References:
    ===========
    - [MS-SMB2]: 2.2.22
    """

    STRUCTURE_FORMAT = "<HHIIHH"
    STRUCTURE_SIZE = struct.calcsize(STRUCTURE_FORMAT)

    def decode(self, message):
        assert message.command == SMB2_COM_WRITE
        if message.status == 0:
            struct_size, _, self.count, _, _, _ = struct.unpack(self.STRUCTURE_FORMAT, message.raw_data[SMB2Message.HEADER_SIZE:SMB2Message.HEADER_SIZE+self.STRUCTURE_SIZE])



class SMB2ReadRequest(Structure):
    """
    References:
    ===========
    - [MS-SMB2]: 2.2.19
    """

    STRUCTURE_FORMAT = "<HBBIQ16sIIIHH"
    STRUCTURE_SIZE = struct.calcsize(STRUCTURE_FORMAT)

    def __init__(self, fid, read_offset, read_len, min_read_len = 0):
        self.fid = fid
        self.read_offset = read_offset
        self.read_len = read_len
        self.min_read_len = min_read_len

    def initMessage(self, message):
        Structure.initMessage(self, message)
        message.command = SMB2_COM_READ

    def prepare(self, message):
        message.data = struct.pack(self.STRUCTURE_FORMAT,
                                   49,   # Structure size. Must be 49 as mandated by [MS-SMB2] 2.2.19
                                   0,    # Padding
                                   0,    # Reserved
                                   self.read_len,
                                   self.read_offset,
                                   self.fid,
                                   self.min_read_len,
                                   0,    # Channel
                                   0,    # RemainingBytes
                                   0,    # ReadChannelInfoOffset
                                   0     # ReadChannelInfoLength
                                  ) + '\0'


class SMB2ReadResponse(Structure):
    """
    References:
    ===========
    - [MS-SMB2]: 2.2.20
    """

    STRUCTURE_FORMAT = "<HBBIII"
    STRUCTURE_SIZE = struct.calcsize(STRUCTURE_FORMAT)

    def decode(self, message):
        assert message.command == SMB2_COM_READ

        if message.status == 0:
            struct_size, data_offset, _, self.data_length, _, _ = struct.unpack(self.STRUCTURE_FORMAT, message.raw_data[SMB2Message.HEADER_SIZE:SMB2Message.HEADER_SIZE+self.STRUCTURE_SIZE])
            self.data = message.raw_data[data_offset:data_offset+self.data_length]


class SMB2IoctlRequest(Structure):
    """
    References:
    ===========
    - [MS-SMB2]: 2.2.31
    """

    STRUCTURE_FORMAT = "<HHI16sIIIIIIII"
    STRUCTURE_SIZE = struct.calcsize(STRUCTURE_FORMAT)

    def __init__(self, fid, ctlcode, flags, in_data, max_out_size = 65536):
        self.ctlcode = ctlcode
        self.fid = fid
        self.flags = flags
        self.in_data = in_data
        self.max_out_size = max_out_size

    def initMessage(self, message):
        Structure.initMessage(self, message)
        message.command = SMB2_COM_IOCTL

    def prepare(self, message):
        message.data = struct.pack(self.STRUCTURE_FORMAT,
                                   57,   # Structure size. Must be 57 as mandated by [MS-SMB2] 2.2.31
                                   0,    # Reserved
                                   self.ctlcode,  # CtlCode
                                   self.fid,
                                   SMB2Message.HEADER_SIZE + self.STRUCTURE_SIZE,  # InputOffset
                                   len(self.in_data),  # InputCount
                                   0,   # MaxInputResponse
                                   0,   # OutputOffset
                                   0,   # OutputCount
                                   self.max_out_size,   # MaxOutputResponse
                                   self.flags,   # Flags
                                   0    # Reserved
                                  ) + self.in_data


class SMB2IoctlResponse(Structure):
    """
    Contains information about the SMB2_IOCTL response from the server.

    If the message has no errors, each instance contains the following attributes:
    - ctlcode (integer)
    - fid (16-bytes string)
    - flags (integer)
    - in_data (string)
    - out_data (string)

    References:
    ===========
    - [MS-SMB2]: 2.2.32
    """

    STRUCTURE_FORMAT = "<HHI16sIIIIII"
    STRUCTURE_SIZE = struct.calcsize(STRUCTURE_FORMAT)

    def decode(self, message):
        assert message.command == SMB2_COM_IOCTL

        if message.status == 0:
            struct_size, _, self.ctlcode, self.fid, \
            input_offset, input_len, output_offset, output_len, \
            self.flags, _ = struct.unpack(self.STRUCTURE_FORMAT, message.raw_data[SMB2Message.HEADER_SIZE:SMB2Message.HEADER_SIZE+self.STRUCTURE_SIZE])

            if input_len > 0:
                self.in_data = message.raw_data[input_offset:input_offset+input_len]
            else:
                self.in_data = ''

            if output_len > 0:
                self.out_data = message.raw_data[output_offset:output_offset+output_len]
            else:
                self.out_data = ''


class SMB2CloseRequest(Structure):
    """
    References:
    ===========
    - [MS-SMB2]: 2.2.15
    """

    STRUCTURE_FORMAT = "<HHI16s"
    STRUCTURE_SIZE = struct.calcsize(STRUCTURE_FORMAT)

    def __init__(self, fid, flags = 0):
        self.fid = fid
        self.flags = flags

    def initMessage(self, message):
        Structure.initMessage(self, message)
        message.command = SMB2_COM_CLOSE

    def prepare(self, message):
        message.data = struct.pack(self.STRUCTURE_FORMAT,
                                   24,  # Structure size. Must be 24 as mandated by [MS-SMB2]: 2.2.15
                                   self.flags,
                                   0,   # Reserved. Must be 0
                                   self.fid)


class SMB2CloseResponse(Structure):
    """
    References:
    ===========
    - [MS-SMB2]: 2.2.16
    """

    def decode(self, message):
        assert message.command == SMB2_COM_CLOSE


class SMB2QueryDirectoryRequest(Structure):
    """
    References:
    ===========
    - [MS-SMB2]: 2.2.33
    """

    STRUCTURE_FORMAT = "<HBBI16sHHI"
    STRUCTURE_SIZE = struct.calcsize(STRUCTURE_FORMAT)

    def __init__(self, fid, filename, info_class, flags, output_buf_len):
        self.fid = fid
        self.filename = filename
        self.info_class = info_class
        self.flags = flags
        self.output_buf_len = output_buf_len

    def initMessage(self, message):
        Structure.initMessage(self, message)
        message.command = SMB2_COM_QUERY_DIRECTORY

    def prepare(self, message):
        message.data = struct.pack(self.STRUCTURE_FORMAT,
                                   33,   # Structure size. Must be 33 as mandated by [MS-SMB2] 2.2.33
                                   self.info_class,   # FileInformationClass
                                   self.flags,        # Flags
                                   0,                 # FileIndex
                                   self.fid,          # FileID
                                   SMB2Message.HEADER_SIZE + self.STRUCTURE_SIZE,  # FileNameOffset
                                   len(self.filename)*2,
                                   self.output_buf_len) + self.filename.encode('UTF-16LE')


class SMB2QueryDirectoryResponse(Structure):
    """
    Contains information about the SMB2_COM_QUERY_DIRECTORY response from the server.

    If the message has no errors, each instance contains the following attributes:
    - data_length (integer)
    - data (string)

    References:
    ===========
    - [MS-SMB2]: 2.2.34
    """

    STRUCTURE_FORMAT = "<HHI"
    STRUCTURE_SIZE = struct.calcsize(STRUCTURE_FORMAT)

    def decode(self, message):
        assert message.command == SMB2_COM_QUERY_DIRECTORY

        if message.status == 0:
            struct_size, offset, self.data_length = struct.unpack(self.STRUCTURE_FORMAT, message.raw_data[SMB2Message.HEADER_SIZE:SMB2Message.HEADER_SIZE+self.STRUCTURE_SIZE])
            self.data = message.raw_data[offset:offset+self.data_length]


class SMB2QueryInfoRequest(Structure):
    """
    References:
    ===========
    - [MS-SMB2]: 2.2.37
    """

    STRUCTURE_FORMAT = "<HBBIHHIII16s"
    STRUCTURE_SIZE = struct.calcsize(STRUCTURE_FORMAT)

    def __init__(self, fid, flags, additional_info, info_type, file_info_class, input_buf, output_buf_len):
        self.fid = fid
        self.flags = flags
        self.additional_info = additional_info
        self.info_type = info_type
        self.file_info_class = file_info_class
        self.output_buf_len = output_buf_len
        self.input_buf = input_buf or ''

    def initMessage(self, message):
        Structure.initMessage(self, message)
        message.command = SMB2_COM_QUERY_INFO

    def prepare(self, message):
        message.data = struct.pack(self.STRUCTURE_FORMAT,
                                   41,  # Structure size. Must be 41 as mandated by [MS-SMB2] 2.2.37
                                   self.info_type,         # InfoType
                                   self.file_info_class,   # FileInfoClass
                                   self.output_buf_len,    # OutputBufferLength
                                   SMB2Message.HEADER_SIZE + self.STRUCTURE_SIZE,  # InputBufferOffset
                                   0,   # Reserved
                                   len(self.input_buf),    # InputBufferLength
                                   self.additional_info,   # AdditionalInformation
                                   self.flags,             # Flags
                                   self.fid                # FileId
                                  ) + self.input_buf


class SMB2QueryInfoResponse(Structure):
    """
    Contains information about the SMB2_COM_QUERY_INFO response from the server.

    If the message has no errors, each instance contains the following attributes:
    - data_length (integer)
    - data (string)

    References:
    ===========
    - [MS-SMB2]: 2.2.38
    """

    STRUCTURE_FORMAT = "<HHI"
    STRUCTURE_SIZE = struct.calcsize(STRUCTURE_FORMAT)

    def decode(self, message):
        assert message.command == SMB2_COM_QUERY_INFO

        if message.status == 0:
            struct_size, buf_offset, self.data_length = struct.unpack(self.STRUCTURE_FORMAT, message.raw_data[SMB2Message.HEADER_SIZE:SMB2Message.HEADER_SIZE+self.STRUCTURE_SIZE])
            self.data = message.raw_data[buf_offset:buf_offset+self.data_length]


class SMB2SetInfoRequest(Structure):
    """
    References:
    ===========
    - [MS-SMB2]: 2.2.39
    """

    STRUCTURE_FORMAT = "<HBBIHHI16s"
    STRUCTURE_SIZE = struct.calcsize(STRUCTURE_FORMAT)

    def __init__(self, fid, additional_info, info_type, file_info_class, data):
        self.fid = fid
        self.additional_info = additional_info
        self.info_type = info_type
        self.file_info_class = file_info_class
        self.data = data or ''

    def initMessage(self, message):
        Structure.initMessage(self, message)
        message.command = SMB2_COM_SET_INFO

    def prepare(self, message):
        message.data = struct.pack(self.STRUCTURE_FORMAT,
                                   33,   # StructureSize. Must be 33 as mandated by [MS-SMB2] 2.2.39
                                   self.info_type,        # InfoType
                                   self.file_info_class,  # FileInfoClass
                                   len(self.data),        # BufferLength
                                   SMB2Message.HEADER_SIZE + self.STRUCTURE_SIZE,  # BufferOffset
                                   0,   # Reserved
                                   self.additional_info,  # AdditionalInformation
                                   self.fid               # FileId
                                  ) + self.data

class SMB2SetInfoResponse(Structure):
    """
    References:
    ===========
    - [MS-SMB2]: 2.2.40
    """

    def decode(self, message):
        pass


class SMB2EchoRequest(Structure):
    """
    References:
    ===========
    - [MS-SMB2]: 2.2.28
    """

    STRUCTURE_FORMAT = '<HH'
    STRUCTURE_SIZE = struct.calcsize(STRUCTURE_FORMAT)

    def initMessage(self, message):
        Structure.initMessage(self, message)
        message.command = SMB2_COM_ECHO

    def prepare(self, message):
        message.data = struct.pack(self.STRUCTURE_FORMAT,
                                   4,   # StructureSize. Must be 4 as mandated by [MS-SMB2] 2.2.29
                                   0)   # Reserved

class SMB2EchoResponse(Structure):
    """
    References:
    ===========
    - [MS-SMB2]: 2.2.29
    """

    def decode(self, message):
        pass
