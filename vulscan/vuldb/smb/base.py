
import logging, binascii, time, hmac
from datetime import datetime
from smb_constants import *
from smb2_constants import *
from smb_structs import *
from smb2_structs import *
from nmb.base import NMBSession
from utils import convertFILETIMEtoEpoch
import ntlm, securityblob

try:
    import hashlib
    sha256 = hashlib.sha256
except ImportError:
    from utils import sha256


class NotReadyError(Exception):
    """Raised when SMB connection is not ready (i.e. not authenticated or authentication failed)"""
    pass

class NotConnectedError(Exception):
    """Raised when underlying SMB connection has been disconnected or not connected yet"""
    pass

class SMBTimeout(Exception):
    """Raised when a timeout has occurred while waiting for a response or for a SMB/CIFS operation to complete."""
    pass


def _convert_to_unicode(string):
    if not isinstance(string, unicode):
        string = unicode(string, "utf-8")
    return string


class SMB(NMBSession):
    """
    This class represents a "connection" to the remote SMB/CIFS server.
    It is not meant to be used directly in an application as it does not have any network transport implementations.

    For application use, please refer to
      - L{SMBProtocol.SMBProtocolFactory<smb.SMBProtocol>} if you are using Twisted framework

    In [MS-CIFS], this class will contain attributes of Client, Client.Connection and Client.Session abstract data models.

    References:
    ===========
      - [MS-CIFS]: 3.2.1
    """

    log = logging.getLogger('SMB.SMB')

    SIGN_NEVER = 0
    SIGN_WHEN_SUPPORTED = 1
    SIGN_WHEN_REQUIRED = 2

    def __init__(self, username, password, my_name, remote_name, domain = '', use_ntlm_v2 = True, sign_options = SIGN_WHEN_REQUIRED, is_direct_tcp = False):
        NMBSession.__init__(self, my_name, remote_name, is_direct_tcp = is_direct_tcp)
        self.username = _convert_to_unicode(username)
        self.password = _convert_to_unicode(password)
        self.domain = _convert_to_unicode(domain)
        self.sign_options = sign_options
        self.is_direct_tcp = is_direct_tcp
        self.use_ntlm_v2 = use_ntlm_v2 #: Similar to LMAuthenticationPolicy and NTAuthenticationPolicy as described in [MS-CIFS] 3.2.1.1
        self.smb_message = SMBMessage()
        self.is_using_smb2 = False   #: Are we communicating using SMB2 protocol? self.smb_message will be a SMB2Message instance if this flag is True
        self.pending_requests = { }  #: MID mapped to _PendingRequest instance
        self.connected_trees = { }   #: Share name mapped to TID
        self.next_rpc_call_id = 1    #: Next RPC callID value. Not used directly in SMB message. Usually encapsulated in sub-commands under SMB_COM_TRANSACTION or SMB_COM_TRANSACTION2 messages

        self.has_negotiated = False
        self.has_authenticated = False
        self.is_signing_active = False           #: True if the remote server accepts message signing. All outgoing messages will be signed. Simiar to IsSigningActive as described in [MS-CIFS] 3.2.1.2
        self.signing_session_key = None          #: Session key for signing packets, if signing is active. Similar to SigningSessionKey as described in [MS-CIFS] 3.2.1.2
        self.signing_challenge_response = None   #: Contains the challenge response for signing, if signing is active. Similar to SigningChallengeResponse as described in [MS-CIFS] 3.2.1.2
        self.mid = 0
        self.uid = 0
        self.next_signing_id = 2     #: Similar to ClientNextSendSequenceNumber as described in [MS-CIFS] 3.2.1.2

        # SMB1 and SMB2 attributes
        # Note that the interpretations of the values may differ between SMB1 and SMB2 protocols
        self.capabilities = 0
        self.security_mode = 0     #: Initialized from the SecurityMode field of the SMB_COM_NEGOTIATE message

        # SMB1 attributes
        # Most of the following attributes will be initialized upon receipt of SMB_COM_NEGOTIATE message from server (via self._updateServerInfo_SMB1 method)
        self.use_plaintext_authentication = False  #: Similar to PlaintextAuthenticationPolicy in in [MS-CIFS] 3.2.1.1
        self.max_raw_size = 0
        self.max_buffer_size = 0   #: Similar to MaxBufferSize as described in [MS-CIFS] 3.2.1.1
        self.max_mpx_count = 0     #: Similar to MaxMpxCount as described in [MS-CIFS] 3.2.1.1

        # SMB2 attributes
        self.max_read_size = 0      #: Similar to MaxReadSize as described in [MS-SMB2] 2.2.4
        self.max_write_size = 0     #: Similar to MaxWriteSize as described in [MS-SMB2] 2.2.4
        self.max_transact_size = 0  #: Similar to MaxTransactSize as described in [MS-SMB2] 2.2.4
        self.session_id = 0         #: Similar to SessionID as described in [MS-SMB2] 2.2.4. This will be set in _updateState_SMB2 method

        self._setupSMB1Methods()

        self.log.info('Authentication with remote machine "%s" for user "%s" will be using NTLM %s authentication (%s extended security)',
                      self.remote_name, self.username,
                      (self.use_ntlm_v2 and 'v2') or 'v1',
                      (SUPPORT_EXTENDED_SECURITY and 'with') or 'without')


    #
    # NMBSession Methods
    #

    def onNMBSessionOK(self):
        self._sendSMBMessage(SMBMessage(ComNegotiateRequest()))

    def onNMBSessionFailed(self):
        pass

    def onNMBSessionMessage(self, flags, data):
        while True:
            try:
                i = self.smb_message.decode(data)
            except SMB2ProtocolHeaderError:
                self.log.info('Now switching over to SMB2 protocol communication')
                self.is_using_smb2 = True
                self.mid = 0  # Must reset messageID counter, or else remote SMB2 server will disconnect
                self._setupSMB2Methods()
                self.smb_message = self._klassSMBMessage()
                i = self.smb_message.decode(data)

            next_message_offset = 0
            if self.is_using_smb2:
                next_message_offset = self.smb_message.next_command_offset

            if i > 0:
                if not self.is_using_smb2:
                    self.log.debug('Received SMB message "%s" (command:0x%2X flags:0x%02X flags2:0x%04X TID:%d UID:%d)',
                                   SMB_COMMAND_NAMES.get(self.smb_message.command, '<unknown>'),
                                   self.smb_message.command, self.smb_message.flags, self.smb_message.flags2, self.smb_message.tid, self.smb_message.uid)
                else:
                    self.log.debug('Received SMB2 message "%s" (command:0x%04X flags:0x%04x)',
                                   SMB2_COMMAND_NAMES.get(self.smb_message.command, '<unknown>'),
                                   self.smb_message.command, self.smb_message.flags)
                if self._updateState(self.smb_message):
                    # We need to create a new instance instead of calling reset() because the instance could be captured in the message history.
                    self.smb_message = self._klassSMBMessage()

            if next_message_offset > 0:
                data = data[next_message_offset:]
            else:
                break

    #
    # Public Methods for Overriding in Subclasses
    #

    def onAuthOK(self):
        pass

    def onAuthFailed(self):
        pass

    #
    # Protected Methods
    #

    def _setupSMB1Methods(self):
        self._klassSMBMessage = SMBMessage
        self._updateState = self._updateState_SMB1
        self._updateServerInfo = self._updateServerInfo_SMB1
        self._handleNegotiateResponse = self._handleNegotiateResponse_SMB1
        self._sendSMBMessage = self._sendSMBMessage_SMB1
        self._handleSessionChallenge = self._handleSessionChallenge_SMB1
        self._listShares = self._listShares_SMB1
        self._listPath = self._listPath_SMB1
        self._listSnapshots = self._listSnapshots_SMB1
        self._getAttributes = self._getAttributes_SMB1
        self._retrieveFile = self._retrieveFile_SMB1
        self._retrieveFileFromOffset = self._retrieveFileFromOffset_SMB1
        self._storeFile = self._storeFile_SMB1
        self._storeFileFromOffset = self._storeFileFromOffset_SMB1
        self._deleteFiles = self._deleteFiles_SMB1
        self._resetFileAttributes = self._resetFileAttributes_SMB1
        self._createDirectory = self._createDirectory_SMB1
        self._deleteDirectory = self._deleteDirectory_SMB1
        self._rename = self._rename_SMB1
        self._echo = self._echo_SMB1

    def _setupSMB2Methods(self):
        self._klassSMBMessage = SMB2Message
        self._updateState = self._updateState_SMB2
        self._updateServerInfo = self._updateServerInfo_SMB2
        self._handleNegotiateResponse = self._handleNegotiateResponse_SMB2
        self._sendSMBMessage = self._sendSMBMessage_SMB2
        self._handleSessionChallenge = self._handleSessionChallenge_SMB2
        self._listShares = self._listShares_SMB2
        self._listPath = self._listPath_SMB2
        self._listSnapshots = self._listSnapshots_SMB2
        self._getAttributes = self._getAttributes_SMB2
        self._retrieveFile = self._retrieveFile_SMB2
        self._retrieveFileFromOffset = self._retrieveFileFromOffset_SMB2
        self._storeFile = self._storeFile_SMB2
        self._storeFileFromOffset = self._storeFileFromOffset_SMB2
        self._deleteFiles = self._deleteFiles_SMB2
        self._resetFileAttributes = self._resetFileAttributes_SMB2
        self._createDirectory = self._createDirectory_SMB2
        self._deleteDirectory = self._deleteDirectory_SMB2
        self._rename = self._rename_SMB2
        self._echo = self._echo_SMB2

    def _getNextRPCCallID(self):
        self.next_rpc_call_id += 1
        return self.next_rpc_call_id

    #
    # SMB2 Methods Family
    #

    def _sendSMBMessage_SMB2(self, smb_message):
        if smb_message.mid == 0:
            smb_message.mid = self._getNextMID_SMB2()

        if smb_message.command != SMB2_COM_NEGOTIATE and smb_message.command != SMB2_COM_ECHO:
            smb_message.session_id = self.session_id

        if self.is_signing_active:
            smb_message.flags |= SMB2_FLAGS_SIGNED
            raw_data = smb_message.encode()
            smb_message.signature = hmac.new(self.signing_session_key, raw_data, sha256).digest()[:16]

            smb_message.raw_data = smb_message.encode()
            self.log.debug('MID is %d. Signature is %s. Total raw message is %d bytes', smb_message.mid, binascii.hexlify(smb_message.signature), len(smb_message.raw_data))
        else:
            smb_message.raw_data = smb_message.encode()
        self.sendNMBMessage(smb_message.raw_data)

    def _getNextMID_SMB2(self):
        self.mid += 1
        return self.mid

    def _updateState_SMB2(self, message):
        if message.isReply:
            if message.command == SMB2_COM_NEGOTIATE:
                if message.status == 0:
                    self.has_negotiated = True
                    self.log.info('SMB2 dialect negotiation successful')
                    self._updateServerInfo(message.payload)
                    self._handleNegotiateResponse(message)
                else:
                    raise ProtocolError('Unknown status value (0x%08X) in SMB2_COM_NEGOTIATE' % message.status,
                                        message.raw_data, message)
            elif message.command == SMB2_COM_SESSION_SETUP:
                if message.status == 0:
                    self.session_id = message.session_id
                    try:
                        result = securityblob.decodeAuthResponseSecurityBlob(message.payload.security_blob)
                        if result == securityblob.RESULT_ACCEPT_COMPLETED:
                            self.has_authenticated = True
                            self.log.info('Authentication (on SMB2) successful!')
                            self.onAuthOK()
                        else:
                            raise ProtocolError('SMB2_COM_SESSION_SETUP status is 0 but security blob negResult value is %d' % result, message.raw_data, message)
                    except securityblob.BadSecurityBlobError, ex:
                        raise ProtocolError(str(ex), message.raw_data, message)
                elif message.status == 0xc0000016:  # STATUS_MORE_PROCESSING_REQUIRED
                    self.session_id = message.session_id
                    try:
                        result, ntlm_token = securityblob.decodeChallengeSecurityBlob(message.payload.security_blob)
                        if result == securityblob.RESULT_ACCEPT_INCOMPLETE:
                            self._handleSessionChallenge(message, ntlm_token)
                    except ( securityblob.BadSecurityBlobError, securityblob.UnsupportedSecurityProvider ), ex:
                        raise ProtocolError(str(ex), message.raw_data, message)
                elif message.status == 0xc000006d:  # STATUS_LOGON_FAILURE
                    self.has_authenticated = False
                    self.log.info('Authentication (on SMB2) failed. Please check username and password.')
                    self.onAuthFailed()
                else:
                    raise ProtocolError('Unknown status value (0x%08X) in SMB_COM_SESSION_SETUP_ANDX (with extended security)' % message.status,
                                        message.raw_data, message)

            req = self.pending_requests.pop(message.mid, None)
            if req:
                req.callback(message, **req.kwargs)
                return True


    def _updateServerInfo_SMB2(self, payload):
        self.capabilities = payload.capabilities
        self.security_mode = payload.security_mode
        self.max_transact_size = payload.max_transact_size
        self.max_read_size = payload.max_read_size
        self.max_write_size = payload.max_write_size
        self.use_plaintext_authentication = False   # SMB2 never allows plaintext authentication


    def _handleNegotiateResponse_SMB2(self, message):
        ntlm_data = ntlm.generateNegotiateMessage()
        blob = securityblob.generateNegotiateSecurityBlob(ntlm_data)
        self._sendSMBMessage(SMB2Message(SMB2SessionSetupRequest(blob)))


    def _handleSessionChallenge_SMB2(self, message, ntlm_token):
        server_challenge, server_flags, server_info = ntlm.decodeChallengeMessage(ntlm_token)

        self.log.info('Performing NTLMv2 authentication (on SMB2) with server challenge "%s"', binascii.hexlify(server_challenge))

        if self.use_ntlm_v2:
            self.log.info('Performing NTLMv2 authentication (on SMB2) with server challenge "%s"', binascii.hexlify(server_challenge))
            nt_challenge_response, lm_challenge_response, session_key = ntlm.generateChallengeResponseV2(self.password,
                                                                                                         self.username,
                                                                                                         server_challenge,
                                                                                                         server_info,
                                                                                                         self.domain)

        else:
            self.log.info('Performing NTLMv1 authentication (on SMB2) with server challenge "%s"', binascii.hexlify(server_challenge))
            nt_challenge_response, lm_challenge_response, session_key = ntlm.generateChallengeResponseV1(self.password, server_challenge, True)

        ntlm_data = ntlm.generateAuthenticateMessage(server_flags,
                                                     nt_challenge_response,
                                                     lm_challenge_response,
                                                     session_key,
                                                     self.username,
                                                     self.domain)

        if self.log.isEnabledFor(logging.DEBUG):
            self.log.debug('NT challenge response is "%s" (%d bytes)', binascii.hexlify(nt_challenge_response), len(nt_challenge_response))
            self.log.debug('LM challenge response is "%s" (%d bytes)', binascii.hexlify(lm_challenge_response), len(lm_challenge_response))

        blob = securityblob.generateAuthSecurityBlob(ntlm_data)
        self._sendSMBMessage(SMB2Message(SMB2SessionSetupRequest(blob)))

        if self.security_mode & SMB2_NEGOTIATE_SIGNING_REQUIRED:
            self.log.info('Server requires all SMB messages to be signed')
            self.is_signing_active = (self.sign_options != SMB.SIGN_NEVER)
        elif self.security_mode & SMB2_NEGOTIATE_SIGNING_ENABLED:
            self.log.info('Server supports SMB signing')
            self.is_signing_active = (self.sign_options == SMB.SIGN_WHEN_SUPPORTED)
        else:
            self.is_signing_active = False

        if self.is_signing_active:
            self.log.info("SMB signing activated. All SMB messages will be signed.")
            self.signing_session_key = (session_key + '\0'*16)[:16]
            if self.capabilities & CAP_EXTENDED_SECURITY:
                self.signing_challenge_response = None
            else:
                self.signing_challenge_response = blob
        else:
            self.log.info("SMB signing deactivated. SMB messages will NOT be signed.")


    def _listShares_SMB2(self, callback, errback, timeout = 30):
        if not self.has_authenticated:
            raise NotReadyError('SMB connection not authenticated')

        expiry_time = time.time() + timeout
        path = 'IPC$'
        messages_history = [ ]

        def connectSrvSvc(tid):
            m = SMB2Message(SMB2CreateRequest('srvsvc',
                                              file_attributes = 0,
                                              access_mask = FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_READ_EA | FILE_WRITE_EA | READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
                                              share_access = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                              oplock = SMB2_OPLOCK_LEVEL_NONE,
                                              impersonation = SEC_IMPERSONATE,
                                              create_options = FILE_NON_DIRECTORY_FILE | FILE_OPEN_NO_RECALL,
                                              create_disp = FILE_OPEN))

            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, connectSrvSvcCB, errback)
            messages_history.append(m)

        def connectSrvSvcCB(create_message, **kwargs):
            messages_history.append(create_message)
            if create_message.status == 0:
                call_id = self._getNextRPCCallID()
                # The data_bytes are binding call to Server Service RPC using DCE v1.1 RPC over SMB. See [MS-SRVS] and [C706]
                # If you wish to understand the meanings of the byte stream, I would suggest you use a recent version of WireShark to packet capture the stream
                data_bytes = \
                    binascii.unhexlify("""05 00 0b 03 10 00 00 00 74 00 00 00""".replace(' ', '')) + \
                    struct.pack('<I', call_id) + \
                    binascii.unhexlify("""
b8 10 b8 10 00 00 00 00 02 00 00 00 00 00 01 00
c8 4f 32 4b 70 16 d3 01 12 78 5a 47 bf 6e e1 88
03 00 00 00 04 5d 88 8a eb 1c c9 11 9f e8 08 00
2b 10 48 60 02 00 00 00 01 00 01 00 c8 4f 32 4b
70 16 d3 01 12 78 5a 47 bf 6e e1 88 03 00 00 00
2c 1c b7 6c 12 98 40 45 03 00 00 00 00 00 00 00
01 00 00 00
""".replace(' ', '').replace('\n', ''))
                m = SMB2Message(SMB2WriteRequest(create_message.payload.fid, data_bytes, 0))
                m.tid = create_message.tid
                self._sendSMBMessage(m)
                self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, rpcBindCB, errback, fid = create_message.payload.fid)
                messages_history.append(m)
            else:
                errback(OperationFailure('Failed to list shares: Unable to locate Server Service RPC endpoint', messages_history))

        def rpcBindCB(trans_message, **kwargs):
            messages_history.append(trans_message)
            if trans_message.status == 0:
                m = SMB2Message(SMB2ReadRequest(kwargs['fid'], read_len = 1024, read_offset = 0))
                m.tid = trans_message.tid
                self._sendSMBMessage(m)
                self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, rpcReadCB, errback, fid = kwargs['fid'])
                messages_history.append(m)
            else:
                closeFid(trans_message.tid, kwargs['fid'], error = 'Failed to list shares: Unable to read from Server Service RPC endpoint')

        def rpcReadCB(read_message, **kwargs):
            messages_history.append(read_message)
            if read_message.status == 0:
                call_id = self._getNextRPCCallID()

                padding = ''
                remote_name = '\\\\' + self.remote_name
                server_len = len(remote_name) + 1
                server_bytes_len = server_len * 2
                if server_len % 2 != 0:
                    padding = '\0\0'
                    server_bytes_len += 2

                # The data bytes are the RPC call to NetrShareEnum (Opnum 15) at Server Service RPC.
                # If you wish to understand the meanings of the byte stream, I would suggest you use a recent version of WireShark to packet capture the stream
                data_bytes = \
                    binascii.unhexlify("""05 00 00 03 10 00 00 00""".replace(' ', '')) + \
                    struct.pack('<HHI', 72+server_bytes_len, 0, call_id) + \
                    binascii.unhexlify("""4c 00 00 00 00 00 0f 00 00 00 02 00""".replace(' ', '')) + \
                    struct.pack('<III', server_len, 0, server_len) + \
                    (remote_name + '\0').encode('UTF-16LE') + padding + \
                    binascii.unhexlify("""
01 00 00 00 01 00 00 00 04 00 02 00 00 00 00 00
00 00 00 00 ff ff ff ff 08 00 02 00 00 00 00 00
""".replace(' ', '').replace('\n', ''))
                m = SMB2Message(SMB2IoctlRequest(kwargs['fid'], 0x0011C017, flags = 0x01, max_out_size = 8196, in_data = data_bytes))
                m.tid = read_message.tid
                self._sendSMBMessage(m)
                self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, listShareResultsCB, errback, fid = kwargs['fid'])
                messages_history.append(m)
            else:
                closeFid(read_message.tid, kwargs['fid'], error = 'Failed to list shares: Unable to bind to Server Service RPC endpoint')

        def listShareResultsCB(result_message, **kwargs):
            messages_history.append(result_message)
            if result_message.status == 0:
                # The payload.data_bytes will contain the results of the RPC call to NetrShareEnum (Opnum 15) at Server Service RPC.
                data_bytes = result_message.payload.out_data

                if ord(data_bytes[3]) & 0x02 == 0:
                    sendReadRequest(result_message.tid, kwargs['fid'], data_bytes)
                else:
                    decodeResults(result_message.tid, kwargs['fid'], data_bytes)
            elif result_message.status == 0x0103:   # STATUS_PENDING
                self.pending_requests[result_message.mid] = _PendingRequest(result_message.mid, expiry_time, listShareResultsCB, errback, fid = kwargs['fid'])
            else:
                closeFid(result_message.tid, kwargs['fid'])
                errback(OperationFailure('Failed to list shares: Unable to retrieve shared device list', messages_history))

        def decodeResults(tid, fid, data_bytes):
            shares_count = struct.unpack('<I', data_bytes[36:40])[0]
            results = [ ]     # A list of SharedDevice instances
            offset = 36 + 12  # You need to study the byte stream to understand the meaning of these constants
            for i in range(0, shares_count):
                results.append(SharedDevice(struct.unpack('<I', data_bytes[offset+4:offset+8])[0], None, None))
                offset += 12

            for i in range(0, shares_count):
                max_length, _, length = struct.unpack('<III', data_bytes[offset:offset+12])
                offset += 12
                results[i].name = unicode(data_bytes[offset:offset+length*2-2], 'UTF-16LE')

                if length % 2 != 0:
                    offset += (length * 2 + 2)
                else:
                    offset += (length * 2)

                max_length, _, length = struct.unpack('<III', data_bytes[offset:offset+12])
                offset += 12
                results[i].comments = unicode(data_bytes[offset:offset+length*2-2], 'UTF-16LE')

                if length % 2 != 0:
                    offset += (length * 2 + 2)
                else:
                    offset += (length * 2)

            closeFid(tid, fid)
            callback(results)

        def sendReadRequest(tid, fid, data_bytes):
            read_count = min(4280, self.max_read_size)
            m = SMB2Message(SMB2ReadRequest(fid, 0, read_count))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, readCB, errback,
                                                           fid = fid, data_bytes = data_bytes)

        def readCB(read_message, **kwargs):
            messages_history.append(read_message)
            if read_message.status == 0:
                data_len = read_message.payload.data_length
                data_bytes = read_message.payload.data

                if ord(data_bytes[3]) & 0x02 == 0:
                    sendReadRequest(read_message.tid, kwargs['fid'], kwargs['data_bytes'] + data_bytes[24:data_len-24])
                else:
                    decodeResults(read_message.tid, kwargs['fid'], kwargs['data_bytes'] + data_bytes[24:data_len-24])
            else:
                closeFid(read_message.tid, kwargs['fid'])
                errback(OperationFailure('Failed to list shares: Unable to retrieve shared device list', messages_history))

        def closeFid(tid, fid, results = None, error = None):
            m = SMB2Message(SMB2CloseRequest(fid))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, closeCB, errback, results = results, error = error)
            messages_history.append(m)

        def closeCB(close_message, **kwargs):
            if kwargs['results'] is not None:
                callback(kwargs['results'])
            elif kwargs['error'] is not None:
                errback(OperationFailure(kwargs['error'], messages_history))

        if not self.connected_trees.has_key(path):
            def connectCB(connect_message, **kwargs):
                messages_history.append(connect_message)
                if connect_message.status == 0:
                    self.connected_trees[path] = connect_message.tid
                    connectSrvSvc(connect_message.tid)
                else:
                    errback(OperationFailure('Failed to list shares: Unable to connect to IPC$', messages_history))

            m = SMB2Message(SMB2TreeConnectRequest(r'\\%s\%s' % ( self.remote_name.upper(), path )))
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, connectCB, errback, path = path)
            messages_history.append(m)
        else:
            connectSrvSvc(self.connected_trees[path])

    def _listPath_SMB2(self, service_name, path, callback, errback, search, pattern, timeout = 30):
        if not self.has_authenticated:
            raise NotReadyError('SMB connection not authenticated')

        expiry_time = time.time() + timeout
        path = path.replace('/', '\\')
        if path.startswith('\\'):
            path = path[1:]
        if path.endswith('\\'):
            path = path[:-1]
        messages_history = [ ]
        results = [ ]

        def sendCreate(tid):
            create_context_data = binascii.unhexlify("""
28 00 00 00 10 00 04 00 00 00 18 00 10 00 00 00
44 48 6e 51 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 18 00 00 00 10 00 04 00
00 00 18 00 00 00 00 00 4d 78 41 63 00 00 00 00
00 00 00 00 10 00 04 00 00 00 18 00 00 00 00 00
51 46 69 64 00 00 00 00
""".replace(' ', '').replace('\n', ''))
            m = SMB2Message(SMB2CreateRequest(path,
                                              file_attributes = 0,
                                              access_mask = FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                                              share_access = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                              oplock = SMB2_OPLOCK_LEVEL_NONE,
                                              impersonation = SEC_IMPERSONATE,
                                              create_options = FILE_DIRECTORY_FILE,
                                              create_disp = FILE_OPEN,
                                              create_context_data = create_context_data))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, createCB, errback)
            messages_history.append(m)

        def createCB(create_message, **kwargs):
            messages_history.append(create_message)
            if create_message.status == 0:
                sendQuery(create_message.tid, create_message.payload.fid, '')
            else:
                errback(OperationFailure('Failed to list %s on %s: Unable to open directory' % ( path, service_name ), messages_history))

        def sendQuery(tid, fid, data_buf):
            m = SMB2Message(SMB2QueryDirectoryRequest(fid, pattern,
                                                      info_class = 0x03,   # FileBothDirectoryInformation
                                                      flags = 0,
                                                      output_buf_len = self.max_transact_size))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, queryCB, errback, fid = fid, data_buf = data_buf)
            messages_history.append(m)

        def queryCB(query_message, **kwargs):
            messages_history.append(query_message)
            if query_message.status == 0:
                data_buf = decodeQueryStruct(kwargs['data_buf'] + query_message.payload.data)
                sendQuery(query_message.tid, kwargs['fid'], data_buf)
            elif query_message.status == 0x80000006L:  # STATUS_NO_MORE_FILES
                closeFid(query_message.tid, kwargs['fid'], results = results)
            else:
                closeFid(query_message.tid, kwargs['fid'], error = query_message.status)

        def decodeQueryStruct(data_bytes):
            # SMB_FIND_FILE_BOTH_DIRECTORY_INFO structure. See [MS-CIFS]: 2.2.8.1.7 and [MS-SMB]: 2.2.8.1.1
            info_format = '<IIQQQQQQIIIBB24s'
            info_size = struct.calcsize(info_format)

            data_length = len(data_bytes)
            offset = 0
            while offset < data_length:
                if offset + info_size > data_length:
                    return data_bytes[offset:]

                next_offset, _, \
                create_time, last_access_time, last_write_time, last_attr_change_time, \
                file_size, alloc_size, file_attributes, filename_length, ea_size, \
                short_name_length, _, short_name = struct.unpack(info_format, data_bytes[offset:offset+info_size])

                offset2 = offset + info_size
                if offset2 + filename_length > data_length:
                    return data_bytes[offset:]

                filename = data_bytes[offset2:offset2+filename_length].decode('UTF-16LE')
                short_name = short_name.decode('UTF-16LE')
                results.append(SharedFile(convertFILETIMEtoEpoch(create_time), convertFILETIMEtoEpoch(last_access_time),
                                          convertFILETIMEtoEpoch(last_write_time), convertFILETIMEtoEpoch(last_attr_change_time),
                                          file_size, alloc_size, file_attributes, short_name, filename))

                if next_offset:
                    offset += next_offset
                else:
                    break
            return ''

        def closeFid(tid, fid, results = None, error = None):
            m = SMB2Message(SMB2CloseRequest(fid))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, closeCB, errback, results = results, error = error)
            messages_history.append(m)

        def closeCB(close_message, **kwargs):
            if kwargs['results'] is not None:
                callback(kwargs['results'])
            elif kwargs['error'] is not None:
                errback(OperationFailure('Failed to list %s on %s: Query failed with errorcode 0x%08x' % ( path, service_name, kwargs['error'] ), messages_history))

        if not self.connected_trees.has_key(service_name):
            def connectCB(connect_message, **kwargs):
                messages_history.append(connect_message)
                if connect_message.status == 0:
                    self.connected_trees[service_name] = connect_message.tid
                    sendCreate(connect_message.tid)
                else:
                    errback(OperationFailure('Failed to list %s on %s: Unable to connect to shared device' % ( path, service_name ), messages_history))

            m = SMB2Message(SMB2TreeConnectRequest(r'\\%s\%s' % ( self.remote_name.upper(), service_name )))
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, connectCB, errback, path = service_name)
            messages_history.append(m)
        else:
            sendCreate(self.connected_trees[service_name])

    def _getAttributes_SMB2(self, service_name, path, callback, errback, timeout = 30):
        if not self.has_authenticated:
            raise NotReadyError('SMB connection not authenticated')

        expiry_time = time.time() + timeout
        path = path.replace('/', '\\')
        if path.startswith('\\'):
            path = path[1:]
        if path.endswith('\\'):
            path = path[:-1]
        messages_history = [ ]

        def sendCreate(tid):
            create_context_data = binascii.unhexlify("""
28 00 00 00 10 00 04 00 00 00 18 00 10 00 00 00
44 48 6e 51 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 18 00 00 00 10 00 04 00
00 00 18 00 00 00 00 00 4d 78 41 63 00 00 00 00
00 00 00 00 10 00 04 00 00 00 18 00 00 00 00 00
51 46 69 64 00 00 00 00
""".replace(' ', '').replace('\n', ''))
            m = SMB2Message(SMB2CreateRequest(path,
                                              file_attributes = 0,
                                              access_mask = FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                                              share_access = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                              oplock = SMB2_OPLOCK_LEVEL_NONE,
                                              impersonation = SEC_IMPERSONATE,
                                              create_options = 0,
                                              create_disp = FILE_OPEN,
                                              create_context_data = create_context_data))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, createCB, errback)
            messages_history.append(m)

        def createCB(create_message, **kwargs):
            messages_history.append(create_message)
            if create_message.status == 0:
                p = create_message.payload
                info = SharedFile(p.create_time, p.lastaccess_time, p.lastwrite_time, p.change_time,
                                  p.file_size, p.allocation_size, p.file_attributes,
                                  unicode(path), unicode(path))
                closeFid(create_message.tid, p.fid, info = info)
            else:
                errback(OperationFailure('Failed to get attributes for %s on %s: Unable to open remote file object' % ( path, service_name ), messages_history))

        def closeFid(tid, fid, info = None, error = None):
            m = SMB2Message(SMB2CloseRequest(fid))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, closeCB, errback, info = info, error = error)
            messages_history.append(m)

        def closeCB(close_message, **kwargs):
            if kwargs['info'] is not None:
                callback(kwargs['info'])
            elif kwargs['error'] is not None:
                errback(OperationFailure('Failed to get attributes for %s on %s: Query failed with errorcode 0x%08x' % ( path, service_name, kwargs['error'] ), messages_history))

        if not self.connected_trees.has_key(service_name):
            def connectCB(connect_message, **kwargs):
                messages_history.append(connect_message)
                if connect_message.status == 0:
                    self.connected_trees[service_name] = connect_message.tid
                    sendCreate(connect_message.tid)
                else:
                    errback(OperationFailure('Failed to get attributes for %s on %s: Unable to connect to shared device' % ( path, service_name ), messages_history))

            m = SMB2Message(SMB2TreeConnectRequest(r'\\%s\%s' % ( self.remote_name.upper(), service_name )))
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, connectCB, errback, path = service_name)
            messages_history.append(m)
        else:
            sendCreate(self.connected_trees[service_name])

    def _retrieveFile_SMB2(self, service_name, path, file_obj, callback, errback, timeout = 30):
        return self._retrieveFileFromOffset(service_name, path, file_obj, callback, errback, 0L, -1L, timeout)

    def _retrieveFileFromOffset_SMB2(self, service_name, path, file_obj, callback, errback, starting_offset, max_length, timeout = 30):
        if not self.has_authenticated:
            raise NotReadyError('SMB connection not authenticated')

        expiry_time = time.time() + timeout
        path = path.replace('/', '\\')
        if path.startswith('\\'):
            path = path[1:]
        if path.endswith('\\'):
            path = path[:-1]
        messages_history = [ ]
        results = [ ]

        def sendCreate(tid):
            create_context_data = binascii.unhexlify("""
28 00 00 00 10 00 04 00 00 00 18 00 10 00 00 00
44 48 6e 51 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 18 00 00 00 10 00 04 00
00 00 18 00 00 00 00 00 4d 78 41 63 00 00 00 00
00 00 00 00 10 00 04 00 00 00 18 00 00 00 00 00
51 46 69 64 00 00 00 00
""".replace(' ', '').replace('\n', ''))
            m = SMB2Message(SMB2CreateRequest(path,
                                              file_attributes = 0,
                                              access_mask = FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
                                              share_access = FILE_SHARE_READ,
                                              oplock = SMB2_OPLOCK_LEVEL_NONE,
                                              impersonation = SEC_IMPERSONATE,
                                              create_options = FILE_SEQUENTIAL_ONLY | FILE_NON_DIRECTORY_FILE,
                                              create_disp = FILE_OPEN,
                                              create_context_data = create_context_data))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, createCB, errback, tid = tid)
            messages_history.append(m)

        def createCB(create_message, **kwargs):
            messages_history.append(create_message)
            if create_message.status == 0:
                m = SMB2Message(SMB2QueryInfoRequest(create_message.payload.fid,
                                                     flags = 0,
                                                     additional_info = 0,
                                                     info_type = SMB2_INFO_FILE,
                                                     file_info_class = 0x16,  # FileStreamInformation [MS-FSCC] 2.4
                                                     input_buf = '',
                                                     output_buf_len = 4096))
                m.tid = create_message.tid
                self._sendSMBMessage(m)
                self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, infoCB, errback,
                                                               fid = create_message.payload.fid, file_attributes = create_message.payload.file_attributes)
                messages_history.append(m)
            else:
                errback(OperationFailure('Failed to list %s on %s: Unable to open file' % ( path, service_name ), messages_history))

        def infoCB(info_message, **kwargs):
            messages_history.append(info_message)
            if info_message.status == 0:
                file_len = struct.unpack('<Q', info_message.payload.data[8:16])[0]
                if max_length == 0 or starting_offset > file_len:
                    closeFid(info_message.tid, kwargs['fid'])
                    callback(( file_obj, kwargs['file_attributes'], 0 ))  # Note that this is a tuple of 3-elements
                else:
                    remaining_len = max_length
                    if remaining_len < 0:
                        remaining_len = file_len
                    if starting_offset + remaining_len > file_len:
                        remaining_len = file_len - starting_offset
                    sendRead(info_message.tid, kwargs['fid'], starting_offset, remaining_len, 0, kwargs['file_attributes'])
            else:
                errback(OperationFailure('Failed to list %s on %s: Unable to retrieve information on file' % ( path, service_name ), messages_history))

        def sendRead(tid, fid, offset, remaining_len, read_len, file_attributes):
            read_count = min(self.max_read_size, remaining_len)
            m = SMB2Message(SMB2ReadRequest(fid, offset, read_count))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, readCB, errback,
                                                           fid = fid, offset = offset,
                                                           remaining_len = remaining_len,
                                                           read_len = read_len,
                                                           file_attributes = file_attributes)

        def readCB(read_message, **kwargs):
            # To avoid crazy memory usage when retrieving large files, we do not save every read_message in messages_history.
            if read_message.status == 0:
                data_len = read_message.payload.data_length
                file_obj.write(read_message.payload.data)

                remaining_len = kwargs['remaining_len'] - data_len

                if remaining_len > 0:
                    sendRead(read_message.tid, kwargs['fid'], kwargs['offset'] + data_len, remaining_len, kwargs['read_len'] + data_len, kwargs['file_attributes'])
                else:
                    closeFid(read_message.tid, kwargs['fid'], ret = ( file_obj, kwargs['file_attributes'], kwargs['read_len'] + data_len ))
            else:
                messages_history.append(read_message)
                closeFid(read_message.tid, kwargs['fid'], error = read_message.status)

        def closeFid(tid, fid, ret = None, error = None):
            m = SMB2Message(SMB2CloseRequest(fid))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, closeCB, errback, ret = ret, error = error)
            messages_history.append(m)

        def closeCB(close_message, **kwargs):
            if kwargs['ret'] is not None:
                callback(kwargs['ret'])
            elif kwargs['error'] is not None:
                errback(OperationFailure('Failed to retrieve %s on %s: Read failed' % ( path, service_name ), messages_history))

        if not self.connected_trees.has_key(service_name):
            def connectCB(connect_message, **kwargs):
                messages_history.append(connect_message)
                if connect_message.status == 0:
                    self.connected_trees[service_name] = connect_message.tid
                    sendCreate(connect_message.tid)
                else:
                    errback(OperationFailure('Failed to retrieve %s on %s: Unable to connect to shared device' % ( path, service_name ), messages_history))

            m = SMB2Message(SMB2TreeConnectRequest(r'\\%s\%s' % ( self.remote_name.upper(), service_name )))
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, connectCB, errback, path = service_name)
            messages_history.append(m)
        else:
            sendCreate(self.connected_trees[service_name])

    def _storeFile_SMB2(self, service_name, path, file_obj, callback, errback, timeout = 30):
        self._storeFileFromOffset_SMB2(service_name, path, file_obj, callback, errback, 0L, True, timeout)

    def _storeFileFromOffset_SMB2(self, service_name, path, file_obj, callback, errback, starting_offset, truncate = False, timeout = 30):
        if not self.has_authenticated:
            raise NotReadyError('SMB connection not authenticated')

        path = path.replace('/', '\\')
        if path.startswith('\\'):
            path = path[1:]
        if path.endswith('\\'):
            path = path[:-1]
        messages_history = [ ]

        def sendCreate(tid):
            create_context_data = binascii.unhexlify("""
28 00 00 00 10 00 04 00 00 00 18 00 10 00 00 00
44 48 6e 51 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 20 00 00 00 10 00 04 00
00 00 18 00 08 00 00 00 41 6c 53 69 00 00 00 00
85 62 00 00 00 00 00 00 18 00 00 00 10 00 04 00
00 00 18 00 00 00 00 00 4d 78 41 63 00 00 00 00
00 00 00 00 10 00 04 00 00 00 18 00 00 00 00 00
51 46 69 64 00 00 00 00
""".replace(' ', '').replace('\n', ''))
            m = SMB2Message(SMB2CreateRequest(path,
                                              file_attributes = ATTR_ARCHIVE,
                                              access_mask = FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | FILE_READ_EA | FILE_WRITE_EA | READ_CONTROL | SYNCHRONIZE,
                                              share_access = 0,
                                              oplock = SMB2_OPLOCK_LEVEL_NONE,
                                              impersonation = SEC_IMPERSONATE,
                                              create_options = FILE_SEQUENTIAL_ONLY | FILE_NON_DIRECTORY_FILE,
                                              create_disp = FILE_OVERWRITE_IF if truncate else FILE_OPEN_IF,
                                              create_context_data = create_context_data))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, createCB, errback, tid = tid)
            messages_history.append(m)

        def createCB(create_message, **kwargs):
            messages_history.append(create_message)
            if create_message.status == 0:
                sendWrite(create_message.tid, create_message.payload.fid, starting_offset)
            else:
                errback(OperationFailure('Failed to store %s on %s: Unable to open file' % ( path, service_name ), messages_history))

        def sendWrite(tid, fid, offset):
            write_count = self.max_write_size
            data = file_obj.read(write_count)
            data_len = len(data)
            if data_len > 0:
                m = SMB2Message(SMB2WriteRequest(fid, data, offset))
                m.tid = tid
                self._sendSMBMessage(m)
                self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, writeCB, errback, fid = fid, offset = offset+data_len)
            else:
                closeFid(tid, fid, offset = offset)

        def writeCB(write_message, **kwargs):
            # To avoid crazy memory usage when saving large files, we do not save every write_message in messages_history.
            if write_message.status == 0:
                sendWrite(write_message.tid, kwargs['fid'], kwargs['offset'])
            else:
                messages_history.append(write_message)
                closeFid(write_message.tid, kwargs['fid'])
                errback(OperationFailure('Failed to store %s on %s: Write failed' % ( path, service_name ), messages_history))

        def closeFid(tid, fid, error = None, offset = None):
            m = SMB2Message(SMB2CloseRequest(fid))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, closeCB, errback, fid = fid, offset = offset, error = error)
            messages_history.append(m)

        def closeCB(close_message, **kwargs):
            if kwargs['offset'] is not None:
                callback(( file_obj, kwargs['offset'] ))  # Note that this is a tuple of 2-elements
            elif kwargs['error'] is not None:
                errback(OperationFailure('Failed to store %s on %s: Write failed' % ( path, service_name ), messages_history))

        if not self.connected_trees.has_key(service_name):
            def connectCB(connect_message, **kwargs):
                messages_history.append(connect_message)
                if connect_message.status == 0:
                    self.connected_trees[service_name] = connect_message.tid
                    sendCreate(connect_message.tid)
                else:
                    errback(OperationFailure('Failed to store %s on %s: Unable to connect to shared device' % ( path, service_name ), messages_history))

            m = SMB2Message(SMB2TreeConnectRequest(r'\\%s\%s' % ( self.remote_name.upper(), service_name )))
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, connectCB, errback, path = service_name)
            messages_history.append(m)
        else:
            sendCreate(self.connected_trees[service_name])


    def _deleteFiles_SMB2(self, service_name, path_file_pattern, callback, errback, timeout = 30):
        if not self.has_authenticated:
            raise NotReadyError('SMB connection not authenticated')

        expiry_time = time.time() + timeout
        path = path_file_pattern.replace('/', '\\')
        if path.startswith('\\'):
            path = path[1:]
        if path.endswith('\\'):
            path = path[:-1]
        messages_history = [ ]

        def sendCreate(tid):
            create_context_data = binascii.unhexlify("""
28 00 00 00 10 00 04 00 00 00 18 00 10 00 00 00
44 48 6e 51 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 18 00 00 00 10 00 04 00
00 00 18 00 00 00 00 00 4d 78 41 63 00 00 00 00
00 00 00 00 10 00 04 00 00 00 18 00 00 00 00 00
51 46 69 64 00 00 00 00
""".replace(' ', '').replace('\n', ''))
            m = SMB2Message(SMB2CreateRequest(path,
                                              file_attributes = 0,
                                              access_mask = DELETE | FILE_READ_ATTRIBUTES,
                                              share_access = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                              oplock = SMB2_OPLOCK_LEVEL_NONE,
                                              impersonation = SEC_IMPERSONATE,
                                              create_options = FILE_NON_DIRECTORY_FILE,
                                              create_disp = FILE_OPEN,
                                              create_context_data = create_context_data))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, createCB, errback, tid = tid)
            messages_history.append(m)

        def createCB(open_message, **kwargs):
            messages_history.append(open_message)
            if open_message.status == 0:
                sendDelete(open_message.tid, open_message.payload.fid)
            else:
                errback(OperationFailure('Failed to delete %s on %s: Unable to open file' % ( path, service_name ), messages_history))

        def sendDelete(tid, fid):
            m = SMB2Message(SMB2SetInfoRequest(fid,
                                               additional_info = 0,
                                               info_type = SMB2_INFO_FILE,
                                               file_info_class = 0x0d,  # SMB2_FILE_DISPOSITION_INFO
                                               data = '\x01'))
            '''
                Resources:
                https://msdn.microsoft.com/en-us/library/cc246560.aspx
                https://msdn.microsoft.com/en-us/library/cc232098.aspx
            '''
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, deleteCB, errback, fid = fid)
            messages_history.append(m)

        def deleteCB(delete_message, **kwargs):
            messages_history.append(delete_message)
            if delete_message.status == 0:
                closeFid(delete_message.tid, kwargs['fid'], status = 0)
            else:
                closeFid(delete_message.tid, kwargs['fid'], status = delete_message.status)

        def closeFid(tid, fid, status = None):
            m = SMB2Message(SMB2CloseRequest(fid))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, closeCB, errback, status = status)
            messages_history.append(m)

        def closeCB(close_message, **kwargs):
            if kwargs['status'] == 0:
                callback(path_file_pattern)
            else:
                errback(OperationFailure('Failed to delete %s on %s: Delete failed' % ( path, service_name ), messages_history))

        if not self.connected_trees.has_key(service_name):
            def connectCB(connect_message, **kwargs):
                messages_history.append(connect_message)
                if connect_message.status == 0:
                    self.connected_trees[service_name] = connect_message.tid
                    sendCreate(connect_message.tid)
                else:
                    errback(OperationFailure('Failed to delete %s on %s: Unable to connect to shared device' % ( path, service_name ), messages_history))

            m = SMB2Message(SMB2TreeConnectRequest(r'\\%s\%s' % ( self.remote_name.upper(), service_name )))
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, connectCB, errback, path = service_name)
            messages_history.append(m)
        else:
            sendCreate(self.connected_trees[service_name])

    def _resetFileAttributes_SMB2(self, service_name, path_file_pattern, callback, errback, timeout = 30):
        if not self.has_authenticated:
            raise NotReadyError('SMB connection not authenticated')

        expiry_time = time.time() + timeout
        path = path_file_pattern.replace('/', '\\')
        if path.startswith('\\'):
            path = path[1:]
        if path.endswith('\\'):
            path = path[:-1]
        messages_history = [ ]

        def sendCreate(tid):
            create_context_data = binascii.unhexlify("""
28 00 00 00 10 00 04 00 00 00 18 00 10 00 00 00
44 48 6e 51 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 18 00 00 00 10 00 04 00
00 00 18 00 00 00 00 00 4d 78 41 63 00 00 00 00
00 00 00 00 10 00 04 00 00 00 18 00 00 00 00 00
51 46 69 64 00 00 00 00
""".replace(' ', '').replace('\n', ''))

            m = SMB2Message(SMB2CreateRequest(path,
                                              file_attributes = 0,
                                              access_mask = FILE_WRITE_ATTRIBUTES,
                                              share_access = FILE_SHARE_READ | FILE_SHARE_WRITE,
                                              oplock = SMB2_OPLOCK_LEVEL_NONE,
                                              impersonation = SEC_IMPERSONATE,
                                              create_options = 0,
                                              create_disp = FILE_OPEN,
                                              create_context_data = create_context_data))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, createCB, errback, tid = tid)
            messages_history.append(m)

        def createCB(open_message, **kwargs):
            messages_history.append(open_message)
            if open_message.status == 0:
                sendReset(open_message.tid, open_message.payload.fid)
            else:
                errback(OperationFailure('Failed to reset attributes of %s on %s: Unable to open file' % ( path, service_name ), messages_history))

        def sendReset(tid, fid):
            m = SMB2Message(SMB2SetInfoRequest(fid,
                                               additional_info = 0,
                                               info_type = SMB2_INFO_FILE,
                                               file_info_class = 4,  # FileBasicInformation
                                               data = struct.pack('qqqqii',0,0,0,0,0x80,0))) # FILE_ATTRIBUTE_NORMAL
            '''
                Resources:
                https://msdn.microsoft.com/en-us/library/cc246560.aspx
                https://msdn.microsoft.com/en-us/library/cc232064.aspx
                https://msdn.microsoft.com/en-us/library/cc232094.aspx
                https://msdn.microsoft.com/en-us/library/cc232110.aspx
            '''
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, resetCB, errback, fid = fid)
            messages_history.append(m)

        def resetCB(reset_message, **kwargs):
            messages_history.append(reset_message)
            if reset_message.status == 0:
                closeFid(reset_message.tid, kwargs['fid'], status = 0)
            else:
                closeFid(reset_message.tid, kwargs['fid'], status = reset_message.status)

        def closeFid(tid, fid, status = None):
            m = SMB2Message(SMB2CloseRequest(fid))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, closeCB, errback, status = status)
            messages_history.append(m)

        def closeCB(close_message, **kwargs):
            if kwargs['status'] == 0:
                callback(path_file_pattern)
            else:
                errback(OperationFailure('Failed to reset attributes of %s on %s: Reset failed' % ( path, service_name ), messages_history))

        if not self.connected_trees.has_key(service_name):
            def connectCB(connect_message, **kwargs):
                messages_history.append(connect_message)
                if connect_message.status == 0:
                    self.connected_trees[service_name] = connect_message.tid
                    sendCreate(connect_message.tid)
                else:
                    errback(OperationFailure('Failed to reset attributes of %s on %s: Unable to connect to shared device' % ( path, service_name ), messages_history))

            m = SMB2Message(SMB2TreeConnectRequest(r'\\%s\%s' % ( self.remote_name.upper(), service_name )))
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, connectCB, errback, path = service_name)
            messages_history.append(m)
        else:
            sendCreate(self.connected_trees[service_name])

    def _createDirectory_SMB2(self, service_name, path, callback, errback, timeout = 30):
        if not self.has_authenticated:
            raise NotReadyError('SMB connection not authenticated')

        expiry_time = time.time() + timeout
        path = path.replace('/', '\\')
        if path.startswith('\\'):
            path = path[1:]
        if path.endswith('\\'):
            path = path[:-1]
        messages_history = [ ]

        def sendCreate(tid):
            create_context_data = binascii.unhexlify("""
28 00 00 00 10 00 04 00 00 00 18 00 10 00 00 00
44 48 6e 51 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 18 00 00 00 10 00 04 00
00 00 18 00 00 00 00 00 4d 78 41 63 00 00 00 00
00 00 00 00 10 00 04 00 00 00 18 00 00 00 00 00
51 46 69 64 00 00 00 00
""".replace(' ', '').replace('\n', ''))
            m = SMB2Message(SMB2CreateRequest(path,
                                              file_attributes = 0,
                                              access_mask = FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_EA | FILE_WRITE_EA | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | READ_CONTROL | DELETE | SYNCHRONIZE,
                                              share_access = 0,
                                              oplock = SMB2_OPLOCK_LEVEL_NONE,
                                              impersonation = SEC_IMPERSONATE,
                                              create_options = FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                                              create_disp = FILE_CREATE,
                                              create_context_data = create_context_data))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, createCB, errback)
            messages_history.append(m)

        def createCB(create_message, **kwargs):
            messages_history.append(create_message)
            if create_message.status == 0:
                closeFid(create_message.tid, create_message.payload.fid)
            else:
                errback(OperationFailure('Failed to create directory %s on %s: Create failed' % ( path, service_name ), messages_history))

        def closeFid(tid, fid):
            m = SMB2Message(SMB2CloseRequest(fid))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, closeCB, errback)
            messages_history.append(m)

        def closeCB(close_message, **kwargs):
            callback(path)

        if not self.connected_trees.has_key(service_name):
            def connectCB(connect_message, **kwargs):
                messages_history.append(connect_message)
                if connect_message.status == 0:
                    self.connected_trees[service_name] = connect_message.tid
                    sendCreate(connect_message.tid)
                else:
                    errback(OperationFailure('Failed to create directory %s on %s: Unable to connect to shared device' % ( path, service_name ), messages_history))

            m = SMB2Message(SMB2TreeConnectRequest(r'\\%s\%s' % ( self.remote_name.upper(), service_name )))
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, connectCB, errback, path = service_name)
            messages_history.append(m)
        else:
            sendCreate(self.connected_trees[service_name])

    def _deleteDirectory_SMB2(self, service_name, path, callback, errback, timeout = 30):
        if not self.has_authenticated:
            raise NotReadyError('SMB connection not authenticated')

        expiry_time = time.time() + timeout
        path = path.replace('/', '\\')
        if path.startswith('\\'):
            path = path[1:]
        if path.endswith('\\'):
            path = path[:-1]
        messages_history = [ ]

        def sendCreate(tid):
            create_context_data = binascii.unhexlify("""
28 00 00 00 10 00 04 00 00 00 18 00 10 00 00 00
44 48 6e 51 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 18 00 00 00 10 00 04 00
00 00 18 00 00 00 00 00 4d 78 41 63 00 00 00 00
00 00 00 00 10 00 04 00 00 00 18 00 00 00 00 00
51 46 69 64 00 00 00 00
""".replace(' ', '').replace('\n', ''))
            m = SMB2Message(SMB2CreateRequest(path,
                                              file_attributes = 0,
                                              access_mask = DELETE | FILE_READ_ATTRIBUTES,
                                              share_access = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                              oplock = SMB2_OPLOCK_LEVEL_NONE,
                                              impersonation = SEC_IMPERSONATE,
                                              create_options = FILE_DIRECTORY_FILE,
                                              create_disp = FILE_OPEN,
                                              create_context_data = create_context_data))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, createCB, errback, tid = tid)
            messages_history.append(m)

        def createCB(open_message, **kwargs):
            messages_history.append(open_message)
            if open_message.status == 0:
                sendDelete(open_message.tid, open_message.payload.fid)
            else:
                errback(OperationFailure('Failed to delete %s on %s: Unable to open directory' % ( path, service_name ), messages_history))

        def sendDelete(tid, fid):
            m = SMB2Message(SMB2SetInfoRequest(fid,
                                               additional_info = 0,
                                               info_type = SMB2_INFO_FILE,
                                               file_info_class = 0x0d,  # SMB2_FILE_DISPOSITION_INFO
                                               data = '\x01'))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, deleteCB, errback, fid = fid)
            messages_history.append(m)

        def deleteCB(delete_message, **kwargs):
            messages_history.append(delete_message)
            if delete_message.status == 0:
                closeFid(delete_message.tid, kwargs['fid'], status = 0)
            else:
                closeFid(delete_message.tid, kwargs['fid'], status = delete_message.status)

        def closeFid(tid, fid, status = None):
            m = SMB2Message(SMB2CloseRequest(fid))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, closeCB, errback, status = status)
            messages_history.append(m)

        def closeCB(close_message, **kwargs):
            if kwargs['status'] == 0:
                callback(path)
            else:
                errback(OperationFailure('Failed to delete %s on %s: Delete failed' % ( path, service_name ), messages_history))

        if not self.connected_trees.has_key(service_name):
            def connectCB(connect_message, **kwargs):
                messages_history.append(connect_message)
                if connect_message.status == 0:
                    self.connected_trees[service_name] = connect_message.tid
                    sendCreate(connect_message.tid)
                else:
                    errback(OperationFailure('Failed to delete %s on %s: Unable to connect to shared device' % ( path, service_name ), messages_history))

            m = SMB2Message(SMB2TreeConnectRequest(r'\\%s\%s' % ( self.remote_name.upper(), service_name )))
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, connectCB, errback, path = service_name)
            messages_history.append(m)
        else:
            sendCreate(self.connected_trees[service_name])

    def _rename_SMB2(self, service_name, old_path, new_path, callback, errback, timeout = 30):
        if not self.has_authenticated:
            raise NotReadyError('SMB connection not authenticated')

        expiry_time = time.time() + timeout
        messages_history = [ ]

        new_path = new_path.replace('/', '\\')
        if new_path.startswith('\\'):
            new_path = new_path[1:]
        if new_path.endswith('\\'):
            new_path = new_path[:-1]

        old_path = old_path.replace('/', '\\')
        if old_path.startswith('\\'):
            old_path = old_path[1:]
        if old_path.endswith('\\'):
            old_path = old_path[:-1]

        def sendCreate(tid):
            create_context_data = binascii.unhexlify("""
28 00 00 00 10 00 04 00 00 00 18 00 10 00 00 00
44 48 6e 51 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 18 00 00 00 10 00 04 00
00 00 18 00 00 00 00 00 4d 78 41 63 00 00 00 00
00 00 00 00 10 00 04 00 00 00 18 00 00 00 00 00
51 46 69 64 00 00 00 00
""".replace(' ', '').replace('\n', ''))
            m = SMB2Message(SMB2CreateRequest(old_path,
                                              file_attributes = 0,
                                              access_mask = DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                                              share_access = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                              oplock = SMB2_OPLOCK_LEVEL_NONE,
                                              impersonation = SEC_IMPERSONATE,
                                              create_options = FILE_SYNCHRONOUS_IO_NONALERT,
                                              create_disp = FILE_OPEN,
                                              create_context_data = create_context_data))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, createCB, errback, tid = tid)
            messages_history.append(m)

        def createCB(create_message, **kwargs):
            messages_history.append(create_message)
            if create_message.status == 0:
                sendRename(create_message.tid, create_message.payload.fid)
            else:
                errback(OperationFailure('Failed to rename %s on %s: Unable to open file/directory' % ( old_path, service_name ), messages_history))

        def sendRename(tid, fid):
            data = '\x00'*16 + struct.pack('<I', len(new_path)*2) + new_path.encode('UTF-16LE')
            m = SMB2Message(SMB2SetInfoRequest(fid,
                                               additional_info = 0,
                                               info_type = SMB2_INFO_FILE,
                                               file_info_class = 0x0a,  # SMB2_FILE_RENAME_INFO
                                               data = data))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, renameCB, errback, fid = fid)
            messages_history.append(m)

        def renameCB(rename_message, **kwargs):
            messages_history.append(rename_message)
            if rename_message.status == 0:
                closeFid(rename_message.tid, kwargs['fid'], status = 0)
            else:
                closeFid(rename_message.tid, kwargs['fid'], status = rename_message.status)

        def closeFid(tid, fid, status = None):
            m = SMB2Message(SMB2CloseRequest(fid))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, closeCB, errback, status = status)
            messages_history.append(m)

        def closeCB(close_message, **kwargs):
            if kwargs['status'] == 0:
                callback(( old_path, new_path ))
            else:
                errback(OperationFailure('Failed to rename %s on %s: Rename failed' % ( old_path, service_name ), messages_history))

        if not self.connected_trees.has_key(service_name):
            def connectCB(connect_message, **kwargs):
                messages_history.append(connect_message)
                if connect_message.status == 0:
                    self.connected_trees[service_name] = connect_message.tid
                    sendCreate(connect_message.tid)
                else:
                    errback(OperationFailure('Failed to rename %s on %s: Unable to connect to shared device' % ( old_path, service_name ), messages_history))

            m = SMB2Message(SMB2TreeConnectRequest(r'\\%s\%s' % ( self.remote_name.upper(), service_name )))
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, connectCB, errback, path = service_name)
            messages_history.append(m)
        else:
            sendCreate(self.connected_trees[service_name])

    def _listSnapshots_SMB2(self, service_name, path, callback, errback, timeout = 30):
        if not self.has_authenticated:
            raise NotReadyError('SMB connection not authenticated')

        expiry_time = time.time() + timeout
        path = path.replace('/', '\\')
        if path.startswith('\\'):
            path = path[1:]
        if path.endswith('\\'):
            path = path[:-1]
        messages_history = [ ]

        def sendCreate(tid):
            create_context_data = binascii.unhexlify("""
28 00 00 00 10 00 04 00 00 00 18 00 10 00 00 00
44 48 6e 51 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 10 00 04 00
00 00 18 00 00 00 00 00 4d 78 41 63 00 00 00 00
""".replace(' ', '').replace('\n', ''))
            m = SMB2Message(SMB2CreateRequest(path,
                                              file_attributes = 0,
                                              access_mask = FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                                              share_access = FILE_SHARE_READ | FILE_SHARE_WRITE,
                                              oplock = SMB2_OPLOCK_LEVEL_NONE,
                                              impersonation = SEC_IMPERSONATE,
                                              create_options = FILE_SYNCHRONOUS_IO_NONALERT,
                                              create_disp = FILE_OPEN,
                                              create_context_data = create_context_data))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, createCB, errback, tid = tid)
            messages_history.append(m)

        def createCB(create_message, **kwargs):
            messages_history.append(create_message)
            if create_message.status == 0:
                sendEnumSnapshots(create_message.tid, create_message.payload.fid)
            else:
                errback(OperationFailure('Failed to list snapshots %s on %s: Unable to open file/directory' % ( old_path, service_name ), messages_history))

        def sendEnumSnapshots(tid, fid):
            m = SMB2Message(SMB2IoctlRequest(fid,
                                             ctlcode = 0x00144064,  # FSCTL_SRV_ENUMERATE_SNAPSHOTS
                                             flags = 0x0001,
                                             in_data = ''))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, enumSnapshotsCB, errback, tid = tid, fid = fid)
            messages_history.append(m)

        def enumSnapshotsCB(enum_message, **kwargs):
            messages_history.append(enum_message)
            if enum_message.status == 0:
                results = [ ]
                snapshots_count = struct.unpack('<I', enum_message.payload.out_data[4:8])[0]
                for i in range(0, snapshots_count):
                    s = enum_message.payload.out_data[12+i*50:12+48+i*50].decode('UTF-16LE')
                    results.append(datetime(*map(int, ( s[5:9], s[10:12], s[13:15], s[16:18], s[19:21], s[22:24] ))))
                closeFid(kwargs['tid'], kwargs['fid'], results = results)
            else:
                closeFid(kwargs['tid'], kwargs['fid'], status = enum_message.status)

        def closeFid(tid, fid, status = None, results = None):
            m = SMB2Message(SMB2CloseRequest(fid))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, closeCB, errback, status = status, results = results)
            messages_history.append(m)

        def closeCB(close_message, **kwargs):
            if kwargs['results'] is not None:
                callback(kwargs['results'])
            else:
                errback(OperationFailure('Failed to list snapshots %s on %s: List failed' % ( path, service_name ), messages_history))

        if not self.connected_trees.has_key(service_name):
            def connectCB(connect_message, **kwargs):
                messages_history.append(connect_message)
                if connect_message.status == 0:
                    self.connected_trees[service_name] = connect_message.tid
                    sendCreate(connect_message.tid)
                else:
                    errback(OperationFailure('Failed to list snapshots %s on %s: Unable to connect to shared device' % ( path, service_name ), messages_history))

            m = SMB2Message(SMB2TreeConnectRequest(r'\\%s\%s' % ( self.remote_name.upper(), service_name )))
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, connectCB, errback, path = service_name)
            messages_history.append(m)
        else:
            sendCreate(self.connected_trees[service_name])

    def _echo_SMB2(self, data, callback, errback, timeout = 30):
        messages_history = [ ]

        def echoCB(echo_message, **kwargs):
            messages_history.append(echo_message)
            if echo_message.status == 0:
                callback(data)
            else:
                errback(OperationFailure('Echo failed', messages_history))

        m = SMB2Message(SMB2EchoRequest())
        self._sendSMBMessage(m)
        self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, echoCB, errback)
        messages_history.append(m)


    #
    # SMB1 Methods Family
    #

    def _sendSMBMessage_SMB1(self, smb_message):
        if smb_message.mid == 0:
            smb_message.mid = self._getNextMID_SMB1()
        if not smb_message.uid:
            smb_message.uid = self.uid
        if self.is_signing_active:
            smb_message.flags2 |= SMB_FLAGS2_SMB_SECURITY_SIGNATURE

            # Increment the next_signing_id as described in [MS-CIFS] 3.2.4.1.3
            smb_message.security = self.next_signing_id
            self.next_signing_id += 2  # All our defined messages currently have responses, so always increment by 2
            raw_data = smb_message.encode()

            md = ntlm.MD5(self.signing_session_key)
            if self.signing_challenge_response:
                md.update(self.signing_challenge_response)
            md.update(raw_data)
            signature = md.digest()[:8]

            self.log.debug('MID is %d. Signing ID is %d. Signature is %s. Total raw message is %d bytes', smb_message.mid, smb_message.security, binascii.hexlify(signature), len(raw_data))
            smb_message.raw_data = raw_data[:14] + signature + raw_data[22:]
        else:
            smb_message.raw_data = smb_message.encode()
        self.sendNMBMessage(smb_message.raw_data)

    def _getNextMID_SMB1(self):
        self.mid += 1
        if self.mid >= 0xFFFF: # MID cannot be 0xFFFF. [MS-CIFS]: 2.2.1.6.2
            # We don't use MID of 0 as MID can be reused for SMB_COM_TRANSACTION2_SECONDARY messages
            # where if mid=0, _sendSMBMessage will re-assign new MID values again
            self.mid = 1
        return self.mid

    def _updateState_SMB1(self, message):
        if message.isReply:
            if message.command == SMB_COM_NEGOTIATE:
                if not message.status.hasError:
                    self.has_negotiated = True
                    self.log.info('SMB dialect negotiation successful (ExtendedSecurity:%s)', message.hasExtendedSecurity)
                    self._updateServerInfo(message.payload)
                    self._handleNegotiateResponse(message)
                else:
                    raise ProtocolError('Unknown status value (0x%08X) in SMB_COM_NEGOTIATE' % message.status.internal_value,
                                        message.raw_data, message)
            elif message.command == SMB_COM_SESSION_SETUP_ANDX:
                if message.hasExtendedSecurity:
                    if not message.status.hasError:
                        try:
                            result = securityblob.decodeAuthResponseSecurityBlob(message.payload.security_blob)
                            if result == securityblob.RESULT_ACCEPT_COMPLETED:
                                self.log.debug('SMB uid is now %d', message.uid)
                                self.uid = message.uid
                                self.has_authenticated = True
                                self.log.info('Authentication (with extended security) successful!')
                                self.onAuthOK()
                            else:
                                raise ProtocolError('SMB_COM_SESSION_SETUP_ANDX status is 0 but security blob negResult value is %d' % result, message.raw_data, message)
                        except securityblob.BadSecurityBlobError, ex:
                            raise ProtocolError(str(ex), message.raw_data, message)
                    elif message.status.internal_value == 0xc0000016:  # STATUS_MORE_PROCESSING_REQUIRED
                        try:
                            result, ntlm_token = securityblob.decodeChallengeSecurityBlob(message.payload.security_blob)
                            if result == securityblob.RESULT_ACCEPT_INCOMPLETE:
                                self._handleSessionChallenge(message, ntlm_token)
                        except ( securityblob.BadSecurityBlobError, securityblob.UnsupportedSecurityProvider ), ex:
                            raise ProtocolError(str(ex), message.raw_data, message)
                    elif message.status.internal_value == 0xc000006d:  # STATUS_LOGON_FAILURE
                        self.has_authenticated = False
                        self.log.info('Authentication (with extended security) failed. Please check username and password. You may need to enable/disable NTLMv2 authentication.')
                        self.onAuthFailed()
                    else:
                        raise ProtocolError('Unknown status value (0x%08X) in SMB_COM_SESSION_SETUP_ANDX (with extended security)' % message.status.internal_value,
                                            message.raw_data, message)
                else:
                    if message.status.internal_value == 0:
                        self.log.debug('SMB uid is now %d', message.uid)
                        self.uid = message.uid
                        self.has_authenticated = True
                        self.log.info('Authentication (without extended security) successful!')
                        self.onAuthOK()
                    else:
                        self.has_authenticated = False
                        self.log.info('Authentication (without extended security) failed. Please check username and password')
                        self.onAuthFailed()
            elif message.command == SMB_COM_TREE_CONNECT_ANDX:
                try:
                    req = self.pending_requests[message.mid]
                except KeyError:
                    pass
                else:
                    if not message.status.hasError:
                        self.connected_trees[req.kwargs['path']] = message.tid

            req = self.pending_requests.pop(message.mid, None)
            if req:
                req.callback(message, **req.kwargs)
                return True


    def _updateServerInfo_SMB1(self, payload):
        self.capabilities = payload.capabilities
        self.security_mode = payload.security_mode
        self.max_raw_size = payload.max_raw_size
        self.max_buffer_size = payload.max_buffer_size
        self.max_mpx_count = payload.max_mpx_count
        self.use_plaintext_authentication = not bool(payload.security_mode & NEGOTIATE_ENCRYPT_PASSWORDS)

        if self.use_plaintext_authentication:
            self.log.warning('Remote server only supports plaintext authentication. Your password can be stolen easily over the network.')


    def _handleSessionChallenge_SMB1(self, message, ntlm_token):
        assert message.hasExtendedSecurity

        if message.uid and not self.uid:
            self.uid = message.uid

        server_challenge, server_flags, server_info = ntlm.decodeChallengeMessage(ntlm_token)
        if self.use_ntlm_v2:
            self.log.info('Performing NTLMv2 authentication (with extended security) with server challenge "%s"', binascii.hexlify(server_challenge))
            nt_challenge_response, lm_challenge_response, session_key = ntlm.generateChallengeResponseV2(self.password,
                                                                                                         self.username,
                                                                                                         server_challenge,
                                                                                                         server_info,
                                                                                                         self.domain)

        else:
            self.log.info('Performing NTLMv1 authentication (with extended security) with server challenge "%s"', binascii.hexlify(server_challenge))
            nt_challenge_response, lm_challenge_response, session_key = ntlm.generateChallengeResponseV1(self.password, server_challenge, True)

        ntlm_data = ntlm.generateAuthenticateMessage(server_flags,
                                                     nt_challenge_response,
                                                     lm_challenge_response,
                                                     session_key,
                                                     self.username,
                                                     self.domain)

        if self.log.isEnabledFor(logging.DEBUG):
            self.log.debug('NT challenge response is "%s" (%d bytes)', binascii.hexlify(nt_challenge_response), len(nt_challenge_response))
            self.log.debug('LM challenge response is "%s" (%d bytes)', binascii.hexlify(lm_challenge_response), len(lm_challenge_response))

        blob = securityblob.generateAuthSecurityBlob(ntlm_data)
        self._sendSMBMessage(SMBMessage(ComSessionSetupAndxRequest__WithSecurityExtension(0, blob)))

        if self.security_mode & NEGOTIATE_SECURITY_SIGNATURES_REQUIRE:
            self.log.info('Server requires all SMB messages to be signed')
            self.is_signing_active = (self.sign_options != SMB.SIGN_NEVER)
        elif self.security_mode & NEGOTIATE_SECURITY_SIGNATURES_ENABLE:
            self.log.info('Server supports SMB signing')
            self.is_signing_active = (self.sign_options == SMB.SIGN_WHEN_SUPPORTED)
        else:
            self.is_signing_active = False

        if self.is_signing_active:
            self.log.info("SMB signing activated. All SMB messages will be signed.")
            self.signing_session_key = session_key
            if self.capabilities & CAP_EXTENDED_SECURITY:
                self.signing_challenge_response = None
            else:
                self.signing_challenge_response = blob
        else:
            self.log.info("SMB signing deactivated. SMB messages will NOT be signed.")


    def _handleNegotiateResponse_SMB1(self, message):
        if message.uid and not self.uid:
            self.uid = message.uid

        if message.hasExtendedSecurity or message.payload.supportsExtendedSecurity:
            ntlm_data = ntlm.generateNegotiateMessage()
            blob = securityblob.generateNegotiateSecurityBlob(ntlm_data)
            self._sendSMBMessage(SMBMessage(ComSessionSetupAndxRequest__WithSecurityExtension(message.payload.session_key, blob)))
        else:
            nt_password, _, _ = ntlm.generateChallengeResponseV1(self.password, message.payload.challenge, False)
            self.log.info('Performing NTLMv1 authentication (without extended security) with challenge "%s" and hashed password of "%s"',
                          binascii.hexlify(message.payload.challenge),
                          binascii.hexlify(nt_password))
            self._sendSMBMessage(SMBMessage(ComSessionSetupAndxRequest__NoSecurityExtension(message.payload.session_key,
                                                                                           self.username,
                                                                                           nt_password,
                                                                                           True,
                                                                                           self.domain)))

    def _listShares_SMB1(self, callback, errback, timeout = 30):
        if not self.has_authenticated:
            raise NotReadyError('SMB connection not authenticated')

        expiry_time = time.time() + timeout
        path = 'IPC$'
        messages_history = [ ]

        def connectSrvSvc(tid):
            m = SMBMessage(ComNTCreateAndxRequest('\\srvsvc',
                                                  flags = NT_CREATE_REQUEST_EXTENDED_RESPONSE,
                                                  access_mask = READ_CONTROL | FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES | FILE_WRITE_EA | FILE_READ_EA | FILE_APPEND_DATA | FILE_WRITE_DATA | FILE_READ_DATA,
                                                  share_access = FILE_SHARE_READ | FILE_SHARE_WRITE,
                                                  create_disp = FILE_OPEN,
                                                  create_options = FILE_OPEN_NO_RECALL | FILE_NON_DIRECTORY_FILE,
                                                  impersonation = SEC_IMPERSONATE,
                                                  security_flags = 0))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, connectSrvSvcCB, errback)
            messages_history.append(m)

        def connectSrvSvcCB(create_message, **kwargs):
            messages_history.append(create_message)
            if not create_message.status.hasError:
                call_id = self._getNextRPCCallID()
                # See [MS-CIFS]: 2.2.5.6.1 for more information on TRANS_TRANSACT_NMPIPE (0x0026) parameters
                setup_bytes = struct.pack('<HH', 0x0026, create_message.payload.fid)
                # The data_bytes are binding call to Server Service RPC using DCE v1.1 RPC over SMB. See [MS-SRVS] and [C706]
                # If you wish to understand the meanings of the byte stream, I would suggest you use a recent version of WireShark to packet capture the stream
                data_bytes = \
                    binascii.unhexlify("""05 00 0b 03 10 00 00 00 48 00 00 00""".replace(' ', '')) + \
                    struct.pack('<I', call_id) + \
                    binascii.unhexlify("""
b8 10 b8 10 00 00 00 00 01 00 00 00 00 00 01 00
c8 4f 32 4b 70 16 d3 01 12 78 5a 47 bf 6e e1 88
03 00 00 00 04 5d 88 8a eb 1c c9 11 9f e8 08 00
2b 10 48 60 02 00 00 00""".replace(' ', '').replace('\n', ''))
                m = SMBMessage(ComTransactionRequest(max_params_count = 0,
                                                     max_data_count = 4280,
                                                     max_setup_count = 0,
                                                     data_bytes = data_bytes,
                                                     setup_bytes = setup_bytes))
                m.tid = create_message.tid
                self._sendSMBMessage(m)
                self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, rpcBindCB, errback, fid = create_message.payload.fid)
                messages_history.append(m)
            else:
                errback(OperationFailure('Failed to list shares: Unable to locate Server Service RPC endpoint', messages_history))

        def rpcBindCB(trans_message, **kwargs):
            messages_history.append(trans_message)
            if not trans_message.status.hasError:
                call_id = self._getNextRPCCallID()

                padding = ''
                server_len = len(self.remote_name) + 1
                server_bytes_len = server_len * 2
                if server_len % 2 != 0:
                    padding = '\0\0'
                    server_bytes_len += 2

                # See [MS-CIFS]: 2.2.5.6.1 for more information on TRANS_TRANSACT_NMPIPE (0x0026) parameters
                setup_bytes = struct.pack('<HH', 0x0026, kwargs['fid'])
                # The data bytes are the RPC call to NetrShareEnum (Opnum 15) at Server Service RPC.
                # If you wish to understand the meanings of the byte stream, I would suggest you use a recent version of WireShark to packet capture the stream
                data_bytes = \
                    binascii.unhexlify("""05 00 00 03 10 00 00 00""".replace(' ', '')) + \
                    struct.pack('<HHI', 72+server_bytes_len, 0, call_id) + \
                    binascii.unhexlify("""4c 00 00 00 00 00 0f 00 00 00 02 00""".replace(' ', '')) + \
                    struct.pack('<III', server_len, 0, server_len) + \
                    (self.remote_name + '\0').encode('UTF-16LE') + padding + \
                    binascii.unhexlify("""
01 00 00 00 01 00 00 00 04 00 02 00 00 00 00 00
00 00 00 00 ff ff ff ff 08 00 02 00 00 00 00 00
""".replace(' ', '').replace('\n', ''))
                m = SMBMessage(ComTransactionRequest(max_params_count = 0,
                                                     max_data_count = 4280,
                                                     max_setup_count = 0,
                                                     data_bytes = data_bytes,
                                                     setup_bytes = setup_bytes))
                m.tid = trans_message.tid
                self._sendSMBMessage(m)
                self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, listShareResultsCB, errback, fid = kwargs['fid'])
                messages_history.append(m)
            else:
                closeFid(trans_message.tid, kwargs['fid'])
                errback(OperationFailure('Failed to list shares: Unable to bind to Server Service RPC endpoint', messages_history))

        def listShareResultsCB(result_message, **kwargs):
            messages_history.append(result_message)
            if not result_message.status.hasError:
                # The payload.data_bytes will contain the results of the RPC call to NetrShareEnum (Opnum 15) at Server Service RPC.
                data_bytes = result_message.payload.data_bytes

                if ord(data_bytes[3]) & 0x02 == 0:
                    sendReadRequest(result_message.tid, kwargs['fid'], data_bytes)
                else:
                    decodeResults(result_message.tid, kwargs['fid'], data_bytes)
            else:
                closeFid(result_message.tid, kwargs['fid'])
                errback(OperationFailure('Failed to list shares: Unable to retrieve shared device list', messages_history))

        def decodeResults(tid, fid, data_bytes):
            shares_count = struct.unpack('<I', data_bytes[36:40])[0]
            results = [ ]     # A list of SharedDevice instances
            offset = 36 + 12  # You need to study the byte stream to understand the meaning of these constants
            for i in range(0, shares_count):
                results.append(SharedDevice(struct.unpack('<I', data_bytes[offset+4:offset+8])[0], None, None))
                offset += 12

            for i in range(0, shares_count):
                max_length, _, length = struct.unpack('<III', data_bytes[offset:offset+12])
                offset += 12
                results[i].name = unicode(data_bytes[offset:offset+length*2-2], 'UTF-16LE')

                if length % 2 != 0:
                    offset += (length * 2 + 2)
                else:
                    offset += (length * 2)

                max_length, _, length = struct.unpack('<III', data_bytes[offset:offset+12])
                offset += 12
                results[i].comments = unicode(data_bytes[offset:offset+length*2-2], 'UTF-16LE')

                if length % 2 != 0:
                    offset += (length * 2 + 2)
                else:
                    offset += (length * 2)

            closeFid(tid, fid)
            callback(results)

        def sendReadRequest(tid, fid, data_bytes):
            read_count = min(4280, self.max_raw_size - 2)
            m = SMBMessage(ComReadAndxRequest(fid = fid,
                                              offset = 0,
                                              max_return_bytes_count = read_count,
                                              min_return_bytes_count = read_count))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, readCB, errback, fid = fid, data_bytes = data_bytes)

        def readCB(read_message, **kwargs):
            messages_history.append(read_message)
            if not read_message.status.hasError:
                data_len = read_message.payload.data_length
                data_bytes = read_message.payload.data

                if ord(data_bytes[3]) & 0x02 == 0:
                    sendReadRequest(read_message.tid, kwargs['fid'], kwargs['data_bytes'] + data_bytes[24:data_len-24])
                else:
                    decodeResults(read_message.tid, kwargs['fid'], kwargs['data_bytes'] + data_bytes[24:data_len-24])
            else:
                closeFid(read_message.tid, kwargs['fid'])
                errback(OperationFailure('Failed to list shares: Unable to retrieve shared device list', messages_history))

        def closeFid(tid, fid):
            m = SMBMessage(ComCloseRequest(fid))
            m.tid = tid
            self._sendSMBMessage(m)
            messages_history.append(m)

        def connectCB(connect_message, **kwargs):
            messages_history.append(connect_message)
            if not connect_message.status.hasError:
                self.connected_trees[path] = connect_message.tid
                connectSrvSvc(connect_message.tid)
            else:
                errback(OperationFailure('Failed to list shares: Unable to connect to IPC$', messages_history))

        m = SMBMessage(ComTreeConnectAndxRequest(r'\\%s\%s' % ( self.remote_name.upper(), path ), SERVICE_ANY, ''))
        self._sendSMBMessage(m)
        self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, connectCB, errback, path = path)
        messages_history.append(m)

    def _listPath_SMB1(self, service_name, path, callback, errback, search, pattern, timeout = 30):
        if not self.has_authenticated:
            raise NotReadyError('SMB connection not authenticated')

        expiry_time = time.time() + timeout
        path = path.replace('/', '\\')
        if not path.endswith('\\'):
            path += '\\'
        messages_history = [ ]
        results = [ ]

        def sendFindFirst(tid, support_dfs=False):
            setup_bytes = struct.pack('<H', 0x0001)  # TRANS2_FIND_FIRST2 sub-command. See [MS-CIFS]: 2.2.6.2.1
            params_bytes = \
                struct.pack('<HHHHI',
                            search, # SearchAttributes
                            100,    # SearchCount
                            0x0006, # Flags: SMB_FIND_CLOSE_AT_EOS | SMB_FIND_RETURN_RESUME_KEYS
                            0x0104, # InfoLevel: SMB_FIND_FILE_BOTH_DIRECTORY_INFO
                            0x0000) # SearchStorageType
            if support_dfs:
                params_bytes += ("\\" + self.remote_name + "\\" + service_name + path + pattern + '\0').encode('UTF-16LE')
            else:
                params_bytes += (path + pattern).encode('UTF-16LE')

            m = SMBMessage(ComTransaction2Request(max_params_count = 10,
                                                  max_data_count = 16644,
                                                  max_setup_count = 0,
                                                  params_bytes = params_bytes,
                                                  setup_bytes = setup_bytes))
            m.tid = tid
            if support_dfs:
                m.flags2 |= SMB_FLAGS2_DFS
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, findFirstCB, errback, support_dfs=support_dfs)
            messages_history.append(m)

        def decodeFindStruct(data_bytes):
            # SMB_FIND_FILE_BOTH_DIRECTORY_INFO structure. See [MS-CIFS]: 2.2.8.1.7 and [MS-SMB]: 2.2.8.1.1
            info_format = '<IIQQQQQQIIIBB24s'
            info_size = struct.calcsize(info_format)

            data_length = len(data_bytes)
            offset = 0
            while offset < data_length:
                if offset + info_size > data_length:
                    return data_bytes[offset:]

                next_offset, _, \
                create_time, last_access_time, last_write_time, last_attr_change_time, \
                file_size, alloc_size, file_attributes, filename_length, ea_size, \
                short_name_length, _, short_name = struct.unpack(info_format, data_bytes[offset:offset+info_size])

                offset2 = offset + info_size
                if offset2 + filename_length > data_length:
                    return data_bytes[offset:]

                filename = data_bytes[offset2:offset2+filename_length].decode('UTF-16LE')
                short_name = short_name.decode('UTF-16LE')
                results.append(SharedFile(convertFILETIMEtoEpoch(create_time), convertFILETIMEtoEpoch(last_access_time),
                                          convertFILETIMEtoEpoch(last_write_time), convertFILETIMEtoEpoch(last_attr_change_time),
                                          file_size, alloc_size, file_attributes, short_name, filename))

                if next_offset:
                    offset += next_offset
                else:
                    break
            return ''

        def findFirstCB(find_message, **kwargs):
            messages_history.append(find_message)
            if not find_message.status.hasError:
                if not kwargs.has_key('total_count'):
                    # TRANS2_FIND_FIRST2 response. [MS-CIFS]: 2.2.6.2.2
                    sid, search_count, end_of_search, _, last_name_offset = struct.unpack('<HHHHH', find_message.payload.params_bytes[:10])
                    kwargs.update({ 'sid': sid, 'end_of_search': end_of_search, 'last_name_offset': last_name_offset, 'data_buf': '' })
                else:
                    sid, end_of_search, last_name_offset = kwargs['sid'], kwargs['end_of_search'], kwargs['last_name_offset']

                send_next = True
                if find_message.payload.data_bytes:
                    d = decodeFindStruct(kwargs['data_buf'] + find_message.payload.data_bytes)
                    if not kwargs.has_key('data_count'):
                        if len(find_message.payload.data_bytes) != find_message.payload.total_data_count:
                            kwargs.update({ 'data_count': len(find_message.payload.data_bytes),
                                            'total_count': find_message.payload.total_data_count,
                                            'data_buf': d,
                                            })
                            send_next = False
                    else:
                        kwargs['data_count'] += len(find_message.payload.data_bytes)
                        kwargs['total_count'] = min(find_message.payload.total_data_count, kwargs['total_count'])
                        kwargs['data_buf'] = d
                        if kwargs['data_count'] != kwargs['total_count']:
                            send_next = False

                if not send_next:
                    self.pending_requests[find_message.mid] = _PendingRequest(find_message.mid, expiry_time, findFirstCB, errback, **kwargs)
                elif end_of_search:
                    callback(results)
                else:
                    sendFindNext(find_message.tid, sid, last_name_offset, kwargs.get('support_dfs', False))
            else:
                errback(OperationFailure('Failed to list %s on %s: Unable to retrieve file list' % ( path, service_name ), messages_history))

        def sendFindNext(tid, sid, resume_key, support_dfs=False):
            setup_bytes = struct.pack('<H', 0x0002)  # TRANS2_FIND_NEXT2 sub-command. See [MS-CIFS]: 2.2.6.3.1
            params_bytes = \
                struct.pack('<HHHIH',
                            sid,        # SID
                            100,        # SearchCount
                            0x0104,     # InfoLevel: SMB_FIND_FILE_BOTH_DIRECTORY_INFO
                            resume_key, # ResumeKey
                            0x000a)     # Flags: SMB_FIND_RETURN_RESUME_KEYS | SMB_FIND_CLOSE_AT_EOS | SMB_FIND_RETURN_RESUME_KEYS
            if support_dfs:
                params_bytes += ("\\" + self.remote_name + "\\" + service_name + path + pattern + '\0').encode('UTF-16LE')
            else:
                params_bytes += (path + pattern).encode('UTF-16LE')

            m = SMBMessage(ComTransaction2Request(max_params_count = 10,
                                                  max_data_count = 16644,
                                                  max_setup_count = 0,
                                                  params_bytes = params_bytes,
                                                  setup_bytes = setup_bytes))
            m.tid = tid
            if support_dfs:
                m.flags2 |= SMB_FLAGS2_DFS
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, findNextCB, errback, sid = sid, support_dfs = support_dfs)
            messages_history.append(m)

        def findNextCB(find_message, **kwargs):
            messages_history.append(find_message)
            if not find_message.status.hasError:
                if not kwargs.has_key('total_count'):
                    # TRANS2_FIND_NEXT2 response. [MS-CIFS]: 2.2.6.3.2
                    search_count, end_of_search, _, last_name_offset = struct.unpack('<HHHH', find_message.payload.params_bytes[:8])
                    kwargs.update({ 'end_of_search': end_of_search, 'last_name_offset': last_name_offset, 'data_buf': '' })
                else:
                    end_of_search, last_name_offset = kwargs['end_of_search'], kwargs['last_name_offset']

                send_next = True
                if find_message.payload.data_bytes:
                    d = decodeFindStruct(kwargs['data_buf'] + find_message.payload.data_bytes)
                    if not kwargs.has_key('data_count'):
                        if len(find_message.payload.data_bytes) != find_message.payload.total_data_count:
                            kwargs.update({ 'data_count': len(find_message.payload.data_bytes),
                                            'total_count': find_message.payload.total_data_count,
                                            'data_buf': d,
                                            })
                            send_next = False
                    else:
                        kwargs['data_count'] += len(find_message.payload.data_bytes)
                        kwargs['total_count'] = min(find_message.payload.total_data_count, kwargs['total_count'])
                        kwargs['data_buf'] = d
                        if kwargs['data_count'] != kwargs['total_count']:
                            send_next = False

                if not send_next:
                    self.pending_requests[find_message.mid] = _PendingRequest(find_message.mid, expiry_time, findNextCB, errback, **kwargs)
                elif end_of_search:
                    callback(results)
                else:
                    sendFindNext(find_message.tid, kwargs['sid'], last_name_offset, kwargs.get('support_dfs', False))
            else:
                errback(OperationFailure('Failed to list %s on %s: Unable to retrieve file list' % ( path, service_name ), messages_history))

        def sendDFSReferral(tid):
            setup_bytes = struct.pack('<H', 0x0010)  # TRANS2_GET_DFS_REFERRAL sub-command. See [MS-CIFS]: 2.2.6.16.1
            params_bytes = struct.pack('<H', 3)      # Max referral level 3
            params_bytes += ("\\" + self.remote_name + "\\" + service_name).encode('UTF-16LE')

            m = SMBMessage(ComTransaction2Request(max_params_count = 10,
                                                  max_data_count = 16644,
                                                  max_setup_count = 0,
                                                  params_bytes = params_bytes,
                                                  setup_bytes = setup_bytes))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, dfsReferralCB, errback)
            messages_history.append(m)

        def dfsReferralCB(dfs_message, **kwargs):
            sendFindFirst(dfs_message.tid, True)

        if not self.connected_trees.has_key(service_name):
            def connectCB(connect_message, **kwargs):
                messages_history.append(connect_message)
                if not connect_message.status.hasError:
                    self.connected_trees[service_name] = connect_message.tid
                    if connect_message.payload.optional_support & SMB_TREE_CONNECTX_SUPPORT_DFS:
                        sendDFSReferral(connect_message.tid)
                    else:
                        sendFindFirst(connect_message.tid, False)
                else:
                    errback(OperationFailure('Failed to list %s on %s: Unable to connect to shared device' % ( path, service_name ), messages_history))

            m = SMBMessage(ComTreeConnectAndxRequest(r'\\%s\%s' % ( self.remote_name.upper(), service_name ), SERVICE_ANY, ''))
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, connectCB, errback, path = service_name)
            messages_history.append(m)
        else:
            sendFindFirst(self.connected_trees[service_name])

    def _getAttributes_SMB1(self, service_name, path, callback, errback, timeout = 30):
        if not self.has_authenticated:
            raise NotReadyError('SMB connection not authenticated')

        expiry_time = time.time() + timeout
        path = path.replace('/', '\\')
        if path.startswith('\\'):
            path = path[1:]
        if path.endswith('\\'):
            path = path[:-1]
        messages_history = [ ]

        def sendQuery(tid):
            setup_bytes = struct.pack('<H', 0x0005)  # TRANS2_QUERY_PATH_INFORMATION sub-command. See [MS-CIFS]: 2.2.6.6.1
            params_bytes = \
                struct.pack('<HI',
                            0x0107, # SMB_QUERY_FILE_ALL_INFO ([MS-CIFS] 2.2.2.3.3)
                            0x0000) # Reserved
            params_bytes += (path + '\0').encode('UTF-16LE')

            m = SMBMessage(ComTransaction2Request(max_params_count = 2,
                                                  max_data_count = 65535,
                                                  max_setup_count = 0,
                                                  params_bytes = params_bytes,
                                                  setup_bytes = setup_bytes))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, queryCB, errback)
            messages_history.append(m)

        def queryCB(query_message, **kwargs):
            messages_history.append(query_message)
            if not query_message.status.hasError:
                info_format = '<QQQQIIQQ'
                info_size = struct.calcsize(info_format)
                create_time, last_access_time, last_write_time, last_attr_change_time, \
                file_attributes, _, alloc_size, file_size = struct.unpack(info_format, query_message.payload.data_bytes[:info_size])

                info = SharedFile(create_time, last_access_time, last_write_time, last_attr_change_time,
                                  file_size, alloc_size, file_attributes, unicode(path), unicode(path))
                callback(info)
            else:
                errback(OperationFailure('Failed to get attributes for %s on %s: Read failed' % ( path, service_name ), messages_history))

        if not self.connected_trees.has_key(service_name):
            def connectCB(connect_message, **kwargs):
                messages_history.append(connect_message)
                if not connect_message.status.hasError:
                    self.connected_trees[service_name] = connect_message.tid
                    sendQuery(connect_message.tid)
                else:
                    errback(OperationFailure('Failed to get attributes for %s on %s: Unable to connect to shared device' % ( path, service_name ), messages_history))

            m = SMBMessage(ComTreeConnectAndxRequest(r'\\%s\%s' % ( self.remote_name.upper(), service_name ), SERVICE_ANY, ''))
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, connectCB, errback, path = service_name)
            messages_history.append(m)
        else:
            sendQuery(self.connected_trees[service_name])

    def _retrieveFile_SMB1(self, service_name, path, file_obj, callback, errback, timeout = 30):
        return self._retrieveFileFromOffset(service_name, path, file_obj, callback, errback, 0L, -1L, timeout)

    def _retrieveFileFromOffset_SMB1(self, service_name, path, file_obj, callback, errback, starting_offset, max_length, timeout = 30):
        if not self.has_authenticated:
            raise NotReadyError('SMB connection not authenticated')

        path = path.replace('/', '\\')
        messages_history = [ ]

        def sendOpen(tid):
            m = SMBMessage(ComOpenAndxRequest(filename = path,
                                              access_mode = 0x0040,  # Sharing mode: Deny nothing to others
                                              open_mode = 0x0001,    # Failed if file does not exist
                                              search_attributes = SMB_FILE_ATTRIBUTE_HIDDEN | SMB_FILE_ATTRIBUTE_SYSTEM,
                                              timeout = timeout * 1000))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, openCB, errback)
            messages_history.append(m)

        def openCB(open_message, **kwargs):
            messages_history.append(open_message)
            if not open_message.status.hasError:
                if max_length == 0:
                    closeFid(open_message.tid, open_message.payload.fid)
                    callback(( file_obj, open_message.payload.file_attributes, 0L ))
                else:
                    sendRead(open_message.tid, open_message.payload.fid, starting_offset, open_message.payload.file_attributes, 0L, max_length)
            else:
                errback(OperationFailure('Failed to retrieve %s on %s: Unable to open file' % ( path, service_name ), messages_history))

        def sendRead(tid, fid, offset, file_attributes, read_len, remaining_len):
            read_count = self.max_raw_size - 2
            m = SMBMessage(ComReadAndxRequest(fid = fid,
                                              offset = offset,
                                              max_return_bytes_count = read_count,
                                              min_return_bytes_count = min(0xFFFF, read_count)))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, readCB, errback, fid = fid, offset = offset, file_attributes = file_attributes,
                                                           read_len = read_len, remaining_len = remaining_len)

        def readCB(read_message, **kwargs):
            # To avoid crazy memory usage when retrieving large files, we do not save every read_message in messages_history.
            if not read_message.status.hasError:
                read_len = kwargs['read_len']
                remaining_len = kwargs['remaining_len']
                data_len = read_message.payload.data_length
                if max_length > 0:
                    if data_len > remaining_len:
                        file_obj.write(read_message.payload.data[:remaining_len])
                        read_len += remaining_len
                        remaining_len = 0
                    else:
                        file_obj.write(read_message.payload.data)
                        remaining_len -= data_len
                        read_len += data_len
                else:
                    file_obj.write(read_message.payload.data)
                    read_len += data_len

                if (max_length > 0 and remaining_len <= 0) or data_len < (self.max_raw_size - 2):
                    closeFid(read_message.tid, kwargs['fid'])
                    callback(( file_obj, kwargs['file_attributes'], read_len ))  # Note that this is a tuple of 3-elements
                else:
                    sendRead(read_message.tid, kwargs['fid'], kwargs['offset']+data_len, kwargs['file_attributes'], read_len, remaining_len)
            else:
                messages_history.append(read_message)
                closeFid(read_message.tid, kwargs['fid'])
                errback(OperationFailure('Failed to retrieve %s on %s: Read failed' % ( path, service_name ), messages_history))

        def closeFid(tid, fid):
            m = SMBMessage(ComCloseRequest(fid))
            m.tid = tid
            self._sendSMBMessage(m)
            messages_history.append(m)

        if not self.connected_trees.has_key(service_name):
            def connectCB(connect_message, **kwargs):
                messages_history.append(connect_message)
                if not connect_message.status.hasError:
                    self.connected_trees[service_name] = connect_message.tid
                    sendOpen(connect_message.tid)
                else:
                    errback(OperationFailure('Failed to retrieve %s on %s: Unable to connect to shared device' % ( path, service_name ), messages_history))

            m = SMBMessage(ComTreeConnectAndxRequest(r'\\%s\%s' % ( self.remote_name.upper(), service_name ), SERVICE_ANY, ''))
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, connectCB, errback, path = service_name)
            messages_history.append(m)
        else:
            sendOpen(self.connected_trees[service_name])

    def _storeFile_SMB1(self, service_name, path, file_obj, callback, errback, timeout = 30):
        self._storeFileFromOffset_SMB1(service_name, path, file_obj, callback, errback, 0L, True, timeout)

    def _storeFileFromOffset_SMB1(self, service_name, path, file_obj, callback, errback, starting_offset, truncate = False, timeout = 30):
        if not self.has_authenticated:
            raise NotReadyError('SMB connection not authenticated')

        path = path.replace('/', '\\')
        messages_history = [ ]

        def sendOpen(tid):
            m = SMBMessage(ComOpenAndxRequest(filename = path,
                                              access_mode = 0x0041,  # Sharing mode: Deny nothing to others + Open for writing
                                              open_mode = 0x0012 if truncate else 0x0011,    # Create file if file does not exist. Overwrite or append depending on truncate parameter.
                                              search_attributes = SMB_FILE_ATTRIBUTE_HIDDEN | SMB_FILE_ATTRIBUTE_SYSTEM,
                                              timeout = timeout * 1000))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, openCB, errback)
            messages_history.append(m)

        def openCB(open_message, **kwargs):
            messages_history.append(open_message)
            if not open_message.status.hasError:
                sendWrite(open_message.tid, open_message.payload.fid, starting_offset)
            else:
                errback(OperationFailure('Failed to store %s on %s: Unable to open file' % ( path, service_name ), messages_history))

        def sendWrite(tid, fid, offset):
            # For message signing, the total SMB message size must be not exceed the max_buffer_size. Non-message signing does not have this limitation
            write_count = min((self.is_signing_active and (self.max_buffer_size-64)) or self.max_raw_size, 0xFFFF-1)  # Need to minus 1 byte from 0xFFFF because of the first NULL byte in the ComWriteAndxRequest message data
            data_bytes = file_obj.read(write_count)
            data_len = len(data_bytes)
            if data_len > 0:
                m = SMBMessage(ComWriteAndxRequest(fid = fid, offset = offset, data_bytes = data_bytes))
                m.tid = tid
                self._sendSMBMessage(m)
                self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, writeCB, errback, fid = fid, offset = offset+data_len)
            else:
                closeFid(tid, fid)
                callback(( file_obj, offset ))  # Note that this is a tuple of 2-elements

        def writeCB(write_message, **kwargs):
            # To avoid crazy memory usage when saving large files, we do not save every write_message in messages_history.
            if not write_message.status.hasError:
                sendWrite(write_message.tid, kwargs['fid'], kwargs['offset'])
            else:
                messages_history.append(write_message)
                closeFid(write_message.tid, kwargs['fid'])
                errback(OperationFailure('Failed to store %s on %s: Write failed' % ( path, service_name ), messages_history))

        def closeFid(tid, fid):
            m = SMBMessage(ComCloseRequest(fid))
            m.tid = tid
            self._sendSMBMessage(m)
            messages_history.append(m)

        if not self.connected_trees.has_key(service_name):
            def connectCB(connect_message, **kwargs):
                messages_history.append(connect_message)
                if not connect_message.status.hasError:
                    self.connected_trees[service_name] = connect_message.tid
                    sendOpen(connect_message.tid)
                else:
                    errback(OperationFailure('Failed to store %s on %s: Unable to connect to shared device' % ( path, service_name ), messages_history))

            m = SMBMessage(ComTreeConnectAndxRequest(r'\\%s\%s' % ( self.remote_name.upper(), service_name ), SERVICE_ANY, ''))
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, connectCB, errback, path = service_name)
            messages_history.append(m)
        else:
            sendOpen(self.connected_trees[service_name])

    def _deleteFiles_SMB1(self, service_name, path_file_pattern, callback, errback, timeout = 30):
        if not self.has_authenticated:
            raise NotReadyError('SMB connection not authenticated')

        path = path_file_pattern.replace('/', '\\')
        messages_history = [ ]

        def sendDelete(tid):
            m = SMBMessage(ComDeleteRequest(filename_pattern = path,
                                            search_attributes = SMB_FILE_ATTRIBUTE_HIDDEN | SMB_FILE_ATTRIBUTE_SYSTEM))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, deleteCB, errback)
            messages_history.append(m)

        def deleteCB(delete_message, **kwargs):
            messages_history.append(delete_message)
            if not delete_message.status.hasError:
                callback(path_file_pattern)
            else:
                errback(OperationFailure('Failed to store %s on %s: Delete failed' % ( path, service_name ), messages_history))

        if not self.connected_trees.has_key(service_name):
            def connectCB(connect_message, **kwargs):
                messages_history.append(connect_message)
                if not connect_message.status.hasError:
                    self.connected_trees[service_name] = connect_message.tid
                    sendDelete(connect_message.tid)
                else:
                    errback(OperationFailure('Failed to delete %s on %s: Unable to connect to shared device' % ( path, service_name ), messages_history))

            m = SMBMessage(ComTreeConnectAndxRequest(r'\\%s\%s' % ( self.remote_name.upper(), service_name ), SERVICE_ANY, ''))
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, connectCB, errback, path = service_name)
            messages_history.append(m)
        else:
            sendDelete(self.connected_trees[service_name])

    def _resetFileAttributes_SMB1(self, service_name, path_file_pattern, callback, errback, timeout = 30):
        raise NotReadyError('resetFileAttributes is not yet implemented for SMB1')

    def _createDirectory_SMB1(self, service_name, path, callback, errback, timeout = 30):
        if not self.has_authenticated:
            raise NotReadyError('SMB connection not authenticated')

        path = path.replace('/', '\\')
        messages_history = [ ]

        def sendCreate(tid):
            m = SMBMessage(ComCreateDirectoryRequest(path))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, createCB, errback)
            messages_history.append(m)

        def createCB(create_message, **kwargs):
            messages_history.append(create_message)
            if not create_message.status.hasError:
                callback(path)
            else:
                errback(OperationFailure('Failed to create directory %s on %s: Create failed' % ( path, service_name ), messages_history))

        if not self.connected_trees.has_key(service_name):
            def connectCB(connect_message, **kwargs):
                messages_history.append(connect_message)
                if not connect_message.status.hasError:
                    self.connected_trees[service_name] = connect_message.tid
                    sendCreate(connect_message.tid)
                else:
                    errback(OperationFailure('Failed to create directory %s on %s: Unable to connect to shared device' % ( path, service_name ), messages_history))

            m = SMBMessage(ComTreeConnectAndxRequest(r'\\%s\%s' % ( self.remote_name.upper(), service_name ), SERVICE_ANY, ''))
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, connectCB, errback, path = service_name)
            messages_history.append(m)
        else:
            sendCreate(self.connected_trees[service_name])

    def _deleteDirectory_SMB1(self, service_name, path, callback, errback, timeout = 30):
        if not self.has_authenticated:
            raise NotReadyError('SMB connection not authenticated')

        path = path.replace('/', '\\')
        messages_history = [ ]

        def sendDelete(tid):
            m = SMBMessage(ComDeleteDirectoryRequest(path))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, deleteCB, errback)
            messages_history.append(m)

        def deleteCB(delete_message, **kwargs):
            messages_history.append(delete_message)
            if not delete_message.status.hasError:
                callback(path)
            else:
                errback(OperationFailure('Failed to delete directory %s on %s: Delete failed' % ( path, service_name ), messages_history))

        if not self.connected_trees.has_key(service_name):
            def connectCB(connect_message, **kwargs):
                messages_history.append(connect_message)
                if not connect_message.status.hasError:
                    self.connected_trees[service_name] = connect_message.tid
                    sendDelete(connect_message.tid)
                else:
                    errback(OperationFailure('Failed to delete %s on %s: Unable to connect to shared device' % ( path, service_name ), messages_history))

            m = SMBMessage(ComTreeConnectAndxRequest(r'\\%s\%s' % ( self.remote_name.upper(), service_name ), SERVICE_ANY, ''))
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, connectCB, errback, path = service_name)
            messages_history.append(m)
        else:
            sendDelete(self.connected_trees[service_name])

    def _rename_SMB1(self, service_name, old_path, new_path, callback, errback, timeout = 30):
        if not self.has_authenticated:
            raise NotReadyError('SMB connection not authenticated')

        new_path = new_path.replace('/', '\\')
        old_path = old_path.replace('/', '\\')
        messages_history = [ ]

        def sendRename(tid):
            m = SMBMessage(ComRenameRequest(old_path = old_path,
                                            new_path = new_path,
                                            search_attributes = SMB_FILE_ATTRIBUTE_HIDDEN | SMB_FILE_ATTRIBUTE_SYSTEM))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, renameCB, errback)
            messages_history.append(m)

        def renameCB(rename_message, **kwargs):
            messages_history.append(rename_message)
            if not rename_message.status.hasError:
                callback(( old_path, new_path ))  # Note that this is a tuple of 2-elements
            else:
                errback(OperationFailure('Failed to rename %s on %s: Rename failed' % ( old_path, service_name ), messages_history))

        if not self.connected_trees.has_key(service_name):
            def connectCB(connect_message, **kwargs):
                messages_history.append(connect_message)
                if not connect_message.status.hasError:
                    self.connected_trees[service_name] = connect_message.tid
                    sendRename(connect_message.tid)
                else:
                    errback(OperationFailure('Failed to rename %s on %s: Unable to connect to shared device' % ( old_path, service_name ), messages_history))

            m = SMBMessage(ComTreeConnectAndxRequest(r'\\%s\%s' % ( self.remote_name.upper(), service_name ), SERVICE_ANY, ''))
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, connectCB, errback, path = service_name)
            messages_history.append(m)
        else:
            sendRename(self.connected_trees[service_name])

    def _listSnapshots_SMB1(self, service_name, path, callback, errback, timeout = 30):
        if not self.has_authenticated:
            raise NotReadyError('SMB connection not authenticated')

        expiry_time = time.time() + timeout
        path = path.replace('/', '\\')
        if not path.endswith('\\'):
            path += '\\'
        messages_history = [ ]
        results = [ ]

        def sendOpen(tid):
            m = SMBMessage(ComOpenAndxRequest(filename = path,
                                              access_mode = 0x0040,  # Sharing mode: Deny nothing to others
                                              open_mode = 0x0001,    # Failed if file does not exist
                                              search_attributes = 0,
                                              timeout = timeout * 1000))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, openCB, errback)
            messages_history.append(m)

        def openCB(open_message, **kwargs):
            messages_history.append(open_message)
            if not open_message.status.hasError:
                sendEnumSnapshots(open_message.tid, open_message.payload.fid)
            else:
                errback(OperationFailure('Failed to list snapshots %s on %s: Unable to open path' % ( path, service_name ), messages_history))

        def sendEnumSnapshots(tid, fid):
            # [MS-CIFS]: 2.2.7.2
            # [MS-SMB]: 2.2.7.2.1
            setup_bytes = struct.pack('<IHBB',
                                      0x00144064,  # [MS-SMB]: 2.2.7.2.1
                                      fid,         # FID
                                      0x01,        # IsFctl
                                      0)           # IsFlags
            m = SMBMessage(ComNTTransactRequest(function = 0x0002,  # NT_TRANSACT_IOCTL. [MS-CIFS]: 2.2.7.2.1
                                                max_params_count = 0,
                                                max_data_count = 0xFFFF,
                                                max_setup_count = 0,
                                                setup_bytes = setup_bytes))
            m.tid = tid
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, enumSnapshotsCB, errback, tid = tid, fid = fid)
            messages_history.append(m)

        def enumSnapshotsCB(enum_message, **kwargs):
            messages_history.append(enum_message)
            if not enum_message.status.hasError:
                results = [ ]
                snapshots_count = struct.unpack('<I', enum_message.payload.data_bytes[4:8])[0]
                for i in range(0, snapshots_count):
                    s = enum_message.payload.data_bytes[12+i*50:12+48+i*50].decode('UTF-16LE')
                    results.append(datetime(*map(int, ( s[5:9], s[10:12], s[13:15], s[16:18], s[19:21], s[22:24] ))))
                closeFid(kwargs['tid'], kwargs['fid'])
                callback(results)
            else:
                closeFid(kwargs['tid'], kwargs['fid'])
                errback(OperationFailure('Failed to list snapshots %s on %s: Unable to list snapshots on path' % ( path, service_name ), messages_history))

        def closeFid(tid, fid):
            m = SMBMessage(ComCloseRequest(fid))
            m.tid = tid
            self._sendSMBMessage(m)
            messages_history.append(m)

        if not self.connected_trees.has_key(service_name):
            def connectCB(connect_message, **kwargs):
                messages_history.append(connect_message)
                if not connect_message.status.hasError:
                    self.connected_trees[service_name] = connect_message.tid
                    sendOpen(connect_message.tid)
                else:
                    errback(OperationFailure('Failed to list snapshots %s on %s: Unable to connect to shared device' % ( path, service_name ), messages_history))

            m = SMBMessage(ComTreeConnectAndxRequest(r'\\%s\%s' % ( self.remote_name.upper(), service_name ), SERVICE_ANY, ''))
            self._sendSMBMessage(m)
            self.pending_requests[m.mid] = _PendingRequest(m.mid, expiry_time, connectCB, errback, path = service_name)
            messages_history.append(m)
        else:
            sendOpen(self.connected_trees[service_name])

    def _echo_SMB1(self, data, callback, errback, timeout = 30):
        messages_history = [ ]

        def echoCB(echo_message, **kwargs):
            messages_history.append(echo_message)
            if not echo_message.status.hasError:
                callback(echo_message.payload.data)
            else:
                errback(OperationFailure('Echo failed', messages_history))

        m = SMBMessage(ComEchoRequest(echo_data = data))
        self._sendSMBMessage(m)
        self.pending_requests[m.mid] = _PendingRequest(m.mid, int(time.time()) + timeout, echoCB, errback)
        messages_history.append(m)


class SharedDevice:
    """
    Contains information about a single shared device on the remote server.
    """

    # The following constants are taken from [MS-SRVS]: 2.2.2.4
    # They are used to identify the type of shared resource from the results from the NetrShareEnum in Server Service RPC
    DISK_TREE   = 0x00
    PRINT_QUEUE = 0x01
    COMM_DEVICE = 0x02
    IPC         = 0x03

    def __init__(self, type, name, comments):
        self._type = type
        self.name = name         #: An unicode string containing the name of the shared device
        self.comments = comments #: An unicode string containing the user description of the shared device

    @property
    def type(self):
        """
        Returns one of the following integral constants.
         - SharedDevice.DISK_TREE
         - SharedDevice.PRINT_QUEUE
         - SharedDevice.COMM_DEVICE
         - SharedDevice.IPC
        """
        return self._type & 0xFFFF

    @property
    def isSpecial(self):
        """
        Returns True if this shared device is a special share reserved for interprocess communication (IPC$)
        or remote administration of the server (ADMIN$). Can also refer to administrative shares such as
        C$, D$, E$, and so forth
        """
        return bool(self._type & 0x80000000)

    @property
    def isTemporary(self):
        """
        Returns True if this is a temporary share that is not persisted for creation each time the file server initializes.
        """
        return bool(self._type & 0x40000000)

    def __unicode__(self):
        return u'Shared device: %s (type:0x%02x comments:%s)' % (self.name, self.type, self.comments )


class SharedFile:
    """
    Contain information about a file/folder entry that is shared on the shared device.

    As an application developer, you should not need to instantiate a *SharedFile* instance directly in your application.
    These *SharedFile* instances are usually returned via a call to *listPath* method in :doc:`smb.SMBProtocol.SMBProtocolFactory<smb_SMBProtocolFactory>`.

    If you encounter *SharedFile* instance where its short_name attribute is empty but the filename attribute contains a short name which does not correspond
    to any files/folders on your remote shared device, it could be that the original filename on the file/folder entry on the shared device contains
    one of these prohibited characters: "\/[]:+|<>=;?,* (see [MS-CIFS]: 2.2.1.1.1 for more details).
    """

    def __init__(self, create_time, last_access_time, last_write_time, last_attr_change_time, file_size, alloc_size, file_attributes, short_name, filename):
        self.create_time = create_time  #: Float value in number of seconds since 1970-01-01 00:00:00 to the time of creation of this file resource on the remote server
        self.last_access_time = last_access_time  #: Float value in number of seconds since 1970-01-01 00:00:00 to the time of last access of this file resource on the remote server
        self.last_write_time = last_write_time    #: Float value in number of seconds since 1970-01-01 00:00:00 to the time of last modification of this file resource on the remote server
        self.last_attr_change_time = last_attr_change_time  #: Float value in number of seconds since 1970-01-01 00:00:00 to the time of last attribute change of this file resource on the remote server
        self.file_size = file_size   #: File size in number of bytes
        self.alloc_size = alloc_size #: Total number of bytes allocated to store this file
        self.file_attributes = file_attributes #: A SMB_EXT_FILE_ATTR integer value. See [MS-CIFS]: 2.2.1.2.3
        self.short_name = short_name #: Unicode string containing the short name of this file (usually in 8.3 notation)
        self.filename = filename     #: Unicode string containing the long filename of this file. Each OS has a limit to the length of this file name. On Windows, it is 256 characters.

    @property
    def isDirectory(self):
        """A convenient property to return True if this file resource is a directory on the remote server"""
        return bool(self.file_attributes & ATTR_DIRECTORY)

    @property
    def isReadOnly(self):
        """A convenient property to return True if this file resource is read-only on the remote server"""
        return bool(self.file_attributes & ATTR_READONLY)

    def __unicode__(self):
        return u'Shared file: %s (FileSize:%d bytes, isDirectory:%s)' % ( self.filename, self.file_size, self.isDirectory )


class _PendingRequest:

    def __init__(self, mid, expiry_time, callback, errback, **kwargs):
        self.mid = mid
        self.expiry_time = expiry_time
        self.callback = callback
        self.errback = errback
        self.kwargs = kwargs
