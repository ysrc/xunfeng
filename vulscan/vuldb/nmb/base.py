
import struct, logging, random
from nmb_constants import *
from nmb_structs import *
from utils import encode_name

class NMBSession:

    log = logging.getLogger('NMB.NMBSession')

    def __init__(self, my_name, remote_name, host_type = TYPE_SERVER, is_direct_tcp = False):
        self.my_name = my_name.upper()
        self.remote_name = remote_name.upper()
        self.host_type = host_type
        self.data_buf = ''

        if is_direct_tcp:
            self.data_nmb = DirectTCPSessionMessage()
            self.sendNMBPacket = self._sendNMBPacket_DirectTCP
        else:
            self.data_nmb = NMBSessionMessage()
            self.sendNMBPacket = self._sendNMBPacket_NetBIOS

    #
    # Overridden Methods
    #

    def write(self, data):
        raise NotImplementedError

    def onNMBSessionMessage(self, flags, data):
        pass

    def onNMBSessionOK(self):
        pass

    def onNMBSessionFailed(self):
        pass

    #
    # Public Methods
    #

    def feedData(self, data):
        self.data_buf = self.data_buf + data

        offset = 0
        while True:
            length = self.data_nmb.decode(self.data_buf, offset)
            if length == 0:
                break
            elif length > 0:
                offset += length
                self._processNMBSessionPacket(self.data_nmb)
            else:
                raise NMBError

        if offset > 0:
            self.data_buf = self.data_buf[offset:]

    def sendNMBMessage(self, data):
        self.sendNMBPacket(SESSION_MESSAGE, data)

    def requestNMBSession(self):
        my_name_encoded = encode_name(self.my_name, TYPE_WORKSTATION)
        remote_name_encoded = encode_name(self.remote_name, self.host_type)
        self.sendNMBPacket(SESSION_REQUEST, remote_name_encoded + my_name_encoded)

    #
    # Protected Methods
    #

    def _processNMBSessionPacket(self, packet):
        if packet.type == SESSION_MESSAGE:
            self.onNMBSessionMessage(packet.flags, packet.data)
        elif packet.type == POSITIVE_SESSION_RESPONSE:
            self.onNMBSessionOK()
        elif packet.type == NEGATIVE_SESSION_RESPONSE:
            self.onNMBSessionFailed()
        else:
            self.log.warning('Unrecognized NMB session type: 0x%02x', packet.type)

    def _sendNMBPacket_NetBIOS(self, packet_type, data):
        length = len(data)
        assert length <= 0x01FFFF
        flags = 0
        if length > 0xFFFF:
            flags |= 0x01
            length &= 0xFFFF
        self.write(struct.pack('>BBH', packet_type, flags, length) + data)

    def _sendNMBPacket_DirectTCP(self, packet_type, data):
        length = len(data)
        assert length <= 0x00FFFFFF
        self.write(struct.pack('>I', length) + data)


class NBNS:

    log = logging.getLogger('NMB.NBNS')

    HEADER_STRUCT_FORMAT = '>HHHHHH'
    HEADER_STRUCT_SIZE = struct.calcsize(HEADER_STRUCT_FORMAT)

    def write(self, data, ip, port):
        raise NotImplementedError

    def decodePacket(self, data):
        if len(data) < self.HEADER_STRUCT_SIZE:
            raise Exception

        trn_id, code, question_count, answer_count, authority_count, additional_count = struct.unpack(self.HEADER_STRUCT_FORMAT, data[:self.HEADER_STRUCT_SIZE])

        is_response = bool((code >> 15) & 0x01)
        opcode = (code >> 11) & 0x0F
        flags = (code >> 4) & 0x7F
        rcode = code & 0x0F

        if opcode == 0x0000 and is_response:
            name_len = ord(data[self.HEADER_STRUCT_SIZE])
            offset = self.HEADER_STRUCT_SIZE+2+name_len+8 # constant 2 for the padding bytes before/after the Name and constant 8 for the Type, Class and TTL fields in the Answer section after the Name
            record_count = (struct.unpack('>H', data[offset:offset+2])[0]) / 6

            offset += 4  # Constant 4 for the Data Length and Flags field
            ret = [ ]
            for i in range(0, record_count):
                ret.append('%d.%d.%d.%d' % struct.unpack('4B', (data[offset:offset + 4])))
                offset += 6
            return trn_id, ret
        else:
            return trn_id, None


    def prepareNameQuery(self, trn_id, name, is_broadcast = True):
        header = struct.pack(self.HEADER_STRUCT_FORMAT,
                             trn_id, (is_broadcast and 0x0110) or 0x0100, 1, 0, 0, 0)
        payload = encode_name(name, 0x20) + '\x00\x20\x00\x01'

        return header + payload

    #
    # Contributed by Jason Anderson
    #
    def decodeIPQueryPacket(self, data):
        if len(data) < self.HEADER_STRUCT_SIZE:
            raise Exception

        trn_id, code, question_count, answer_count, authority_count, additional_count = struct.unpack(self.HEADER_STRUCT_FORMAT, data[:self.HEADER_STRUCT_SIZE])

        is_response = bool((code >> 15) & 0x01)
        opcode = (code >> 11) & 0x0F
        flags = (code >> 4) & 0x7F
        rcode = code & 0x0F
        numnames = struct.unpack('B', data[self.HEADER_STRUCT_SIZE + 44])[0]

        if numnames > 0:
            ret = [ ]
            offset = self.HEADER_STRUCT_SIZE + 45

            for i in range(0, numnames):
                mynme = data[offset:offset + 15]
                mynme = mynme.strip()
                ret.append(( mynme, ord(data[offset+15]) ))
                offset += 18

            return trn_id, ret
        else:
            return trn_id, None

    #
    # Contributed by Jason Anderson
    #
    def prepareNetNameQuery(self, trn_id, is_broadcast = True):
        header = struct.pack(self.HEADER_STRUCT_FORMAT,
                             trn_id, (is_broadcast and 0x0010) or 0x0000, 1, 0, 0, 0)
        payload = encode_name('*', 0) + '\x00\x21\x00\x01'

        return header + payload
