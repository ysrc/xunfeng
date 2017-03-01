
import os, logging, time
from twisted.internet import reactor, defer
from twisted.internet.protocol import ClientFactory, Protocol
from smb_constants import *
from smb_structs import *
from base import SMB, NotConnectedError, NotReadyError, SMBTimeout


__all__ = [ 'SMBProtocolFactory', 'NotConnectedError', 'NotReadyError' ]


class SMBProtocol(Protocol, SMB):

    log = logging.getLogger('SMB.SMBProtocol')

    #
    # Protocol Methods
    #

    def connectionMade(self):
        self.factory.instance = self
        if not self.is_direct_tcp:
            self.requestNMBSession()
        else:
            self.onNMBSessionOK()

    def connectionLost(self, reason):
        if self.factory.instance == self:
            self.instance = None

    def dataReceived(self, data):
        self.feedData(data)

    #
    # SMB (and its superclass) Methods
    #

    def write(self, data):
        self.transport.write(data)

    def onAuthOK(self):
        if self.factory.instance == self:
            self.factory.onAuthOK()
            reactor.callLater(1, self._cleanupPendingRequests)

    def onAuthFailed(self):
        if self.factory.instance == self:
            self.factory.onAuthFailed()

    def onNMBSessionFailed(self):
        self.log.error('Cannot establish NetBIOS session. You might have provided a wrong remote_name')

    #
    # Protected Methods
    #

    def _cleanupPendingRequests(self):
        if self.factory.instance == self:
            now = time.time()
            to_remove = []
            for mid, r in self.pending_requests.iteritems():
                if r.expiry_time < now:
                    try:
                        r.errback(SMBTimeout())
                    except Exception: pass
                    to_remove.append(mid)

            for mid in to_remove:
                del self.pending_requests[mid]

            reactor.callLater(1, self._cleanupPendingRequests)


class SMBProtocolFactory(ClientFactory):

    protocol = SMBProtocol
    log = logging.getLogger('SMB.SMBFactory')

    #: SMB messages will never be signed regardless of remote server's configurations; access errors will occur if the remote server requires signing.
    SIGN_NEVER = 0
    #: SMB messages will be signed when remote server supports signing but not requires signing.
    SIGN_WHEN_SUPPORTED = 1
    #: SMB messages will only be signed when remote server requires signing.
    SIGN_WHEN_REQUIRED = 2

    def __init__(self, username, password, my_name, remote_name, domain = '', use_ntlm_v2 = True, sign_options = SIGN_WHEN_REQUIRED, is_direct_tcp = False):
        """
        Create a new SMBProtocolFactory instance. You will pass this instance to *reactor.connectTCP()* which will then instantiate the TCP connection to the remote SMB/CIFS server.
        Note that the default TCP port for most SMB/CIFS servers using NetBIOS over TCP/IP is 139.
        Some newer server installations might also support Direct hosting of SMB over TCP/IP; for these servers, the default TCP port is 445.

        *username* and *password* are the user credentials required to authenticate the underlying SMB connection with the remote server.
        File operations can only be proceeded after the connection has been authenticated successfully.

        :param string my_name: The local NetBIOS machine name that will identify where this connection is originating from.
                               You can freely choose a name as long as it contains a maximum of 15 alphanumeric characters and does not contain spaces and any of ``\/:*?";|+``.
        :param string remote_name: The NetBIOS machine name of the remote server.
                                   On windows, you can find out the machine name by right-clicking on the "My Computer" and selecting "Properties".
                                   This parameter must be the same as what has been configured on the remote server, or else the connection will be rejected.
        :param string domain: The network domain. On windows, it is known as the workgroup. Usually, it is safe to leave this parameter as an empty string.
        :param boolean use_ntlm_v2: Indicates whether pysmb should be NTLMv1 or NTLMv2 authentication algorithm for authentication.
                                    The choice of NTLMv1 and NTLMv2 is configured on the remote server, and there is no mechanism to auto-detect which algorithm has been configured.
                                    Hence, we can only "guess" or try both algorithms.
                                    On Sambda, Windows Vista and Windows 7, NTLMv2 is enabled by default. On Windows XP, we can use NTLMv1 before NTLMv2.
        :param int sign_options: Determines whether SMB messages will be signed. Default is *SIGN_WHEN_REQUIRED*.
                                 If *SIGN_WHEN_REQUIRED* (value=2), SMB messages will only be signed when remote server requires signing.
                                 If *SIGN_WHEN_SUPPORTED* (value=1), SMB messages will be signed when remote server supports signing but not requires signing.
                                 If *SIGN_NEVER* (value=0), SMB messages will never be signed regardless of remote server's configurations; access errors will occur if the remote server requires signing.
        :param boolean is_direct_tcp: Controls whether the NetBIOS over TCP/IP (is_direct_tcp=False) or the newer Direct hosting of SMB over TCP/IP (is_direct_tcp=True) will be used for the communication.
                                      The default parameter is False which will use NetBIOS over TCP/IP for wider compatibility (TCP port: 139).
        """
        self.username = username
        self.password = password
        self.my_name = my_name
        self.remote_name = remote_name
        self.domain = domain
        self.use_ntlm_v2 = use_ntlm_v2
        self.sign_options = sign_options
        self.is_direct_tcp = is_direct_tcp
        self.instance = None    #: The single SMBProtocol instance for each SMBProtocolFactory instance. Usually, you should not need to touch this attribute directly.

    #
    # Public Property
    #

    @property
    def isReady(self):
        """A convenient property to return True if the underlying SMB connection has connected to remote server, has successfully authenticated itself and is ready for file operations."""
        return bool(self.instance and self.instance.has_authenticated)

    @property
    def isUsingSMB2(self):
        """A convenient property to return True if the underlying SMB connection is using SMB2 protocol."""
        return self.instance and self.instance.is_using_smb2

    #
    # Public Methods for Callbacks
    #

    def onAuthOK(self):
        """
        Override this method in your *SMBProtocolFactory* subclass to add in post-authentication handling.
        This method will be called when the server has replied that the SMB connection has been successfully authenticated.
        File operations can proceed when this method has been called.
        """
        pass

    def onAuthFailed(self):
        """
        Override this method in your *SMBProtocolFactory* subclass to add in post-authentication handling.
        This method will be called when the server has replied that the SMB connection has been successfully authenticated.

        If you want to retry authenticating from this method,
         1. Disconnect the underlying SMB connection (call ``self.instance.transport.loseConnection()``)
         2. Create a new SMBProtocolFactory subclass instance with different user credientials or different NTLM algorithm flag.
         3. Call ``reactor.connectTCP`` with the new instance to re-establish the SMB connection
        """
        pass

    #
    # Public Methods
    #

    def listShares(self, timeout = 30):
        """
        Retrieve a list of shared resources on remote server.

        :param integer/float timeout: Number of seconds that pysmb will wait before raising *SMBTimeout* via the returned *Deferred* instance's *errback* method.
        :return: A *twisted.internet.defer.Deferred* instance. The callback function will be called with a list of :doc:`smb.base.SharedDevice<smb_SharedDevice>` instances.
        """
        if not self.instance:
            raise NotConnectedError('Not connected to server')

        d = defer.Deferred()
        self.instance._listShares(d.callback, d.errback, timeout)
        return d

    def listPath(self, service_name, path,
                 search = SMB_FILE_ATTRIBUTE_READONLY | SMB_FILE_ATTRIBUTE_HIDDEN | SMB_FILE_ATTRIBUTE_SYSTEM | SMB_FILE_ATTRIBUTE_DIRECTORY | SMB_FILE_ATTRIBUTE_ARCHIVE,
                 pattern = '*', timeout = 30):
        """
        Retrieve a directory listing of files/folders at *path*

        :param string/unicode service_name: the name of the shared folder for the *path*
        :param string/unicode path: path relative to the *service_name* where we are interested to learn about its files/sub-folders.
        :param integer search: integer value made up from a bitwise-OR of *SMB_FILE_ATTRIBUTE_xxx* bits (see smb_constants.py).
                               The default *search* value will query for all read-only, hidden, system, archive files and directories.
        :param string/unicode pattern: the filter to apply to the results before returning to the client.
        :param integer/float timeout: Number of seconds that pysmb will wait before raising *SMBTimeout* via the returned *Deferred* instance's *errback* method.
        :return: A *twisted.internet.defer.Deferred* instance. The callback function will be called with a list of :doc:`smb.base.SharedFile<smb_SharedFile>` instances.
        """
        if not self.instance:
            raise NotConnectedError('Not connected to server')

        d = defer.Deferred()
        self.instance._listPath(service_name, path, d.callback, d.errback, search = search, pattern = pattern, timeout = timeout)
        return d

    def listSnapshots(self, service_name, path, timeout = 30):
        """
        Retrieve a list of available snapshots (a.k.a. shadow copies) for *path*.

        Note that snapshot features are only supported on Windows Vista Business, Enterprise and Ultimate, and on all Windows 7 editions.

        :param string/unicode service_name: the name of the shared folder for the *path*
        :param string/unicode path: path relative to the *service_name* where we are interested in the list of available snapshots
        :return: A *twisted.internet.defer.Deferred* instance. The callback function will be called with a list of python *datetime.DateTime*
                 instances in GMT/UTC time zone
        """
        if not self.instance:
            raise NotConnectedError('Not connected to server')

        d = defer.Deferred()
        self.instance._listSnapshots(service_name, path, d.callback, d.errback, timeout = timeout)
        return d

    def getAttributes(self, service_name, path, timeout = 30):
        """
        Retrieve information about the file at *path* on the *service_name*.

        :param string/unicode service_name: the name of the shared folder for the *path*
        :param string/unicode path: Path of the file on the remote server. If the file cannot be opened for reading, an :doc:`OperationFailure<smb_exceptions>` will be raised.
        :return: A *twisted.internet.defer.Deferred* instance. The callback function will be called with a :doc:`smb.base.SharedFile<smb_SharedFile>` instance containing the attributes of the file.
        """
        if not self.instance:
            raise NotConnectedError('Not connected to server')

        d = defer.Deferred()
        self.instance._getAttributes(service_name, path, d.callback, d.errback, timeout = timeout)
        return d

    def retrieveFile(self, service_name, path, file_obj, timeout = 30):
        """
        Retrieve the contents of the file at *path* on the *service_name* and write these contents to the provided *file_obj*.

        Use *retrieveFileFromOffset()* method if you need to specify the offset to read from the remote *path* and/or the maximum number of bytes to write to the *file_obj*.

        The meaning of the *timeout* parameter will be different from other file operation methods. As the downloaded file usually exceeeds the maximum size
        of each SMB/CIFS data message, it will be packetized into a series of request messages (each message will request about about 60kBytes).
        The *timeout* parameter is an integer/float value that specifies the timeout interval for these individual SMB/CIFS message to be transmitted and downloaded from the remote SMB/CIFS server.

        :param string/unicode service_name: the name of the shared folder for the *path*
        :param string/unicode path: Path of the file on the remote server. If the file cannot be opened for reading, an :doc:`OperationFailure<smb_exceptions>` will be called in the returned *Deferred* errback.
        :param file_obj: A file-like object that has a *write* method. Data will be written continuously to *file_obj* until EOF is received from the remote service.
        :return: A *twisted.internet.defer.Deferred* instance. The callback function will be called with a 3-element tuple of ( *file_obj*, file attributes of the file on server, number of bytes written to *file_obj* ).
                 The file attributes is an integer value made up from a bitwise-OR of *SMB_FILE_ATTRIBUTE_xxx* bits (see smb_constants.py)
        """
        return self.retrieveFileFromOffset(service_name, path, file_obj, 0L, -1L, timeout)

    def retrieveFileFromOffset(self, service_name, path, file_obj, offset = 0L, max_length = -1L, timeout = 30):
        """
        Retrieve the contents of the file at *path* on the *service_name* and write these contents to the provided *file_obj*.

        The meaning of the *timeout* parameter will be different from other file operation methods. As the downloaded file usually exceeeds the maximum size
        of each SMB/CIFS data message, it will be packetized into a series of request messages (each message will request about about 60kBytes).
        The *timeout* parameter is an integer/float value that specifies the timeout interval for these individual SMB/CIFS message to be transmitted and downloaded from the remote SMB/CIFS server.

        :param string/unicode service_name: the name of the shared folder for the *path*
        :param string/unicode path: Path of the file on the remote server. If the file cannot be opened for reading, an :doc:`OperationFailure<smb_exceptions>` will be called in the returned *Deferred* errback.
        :param file_obj: A file-like object that has a *write* method. Data will be written continuously to *file_obj* until EOF is received from the remote service.
        :param integer/long offset: the offset in the remote *path* where the first byte will be read and written to *file_obj*. Must be either zero or a positive integer/long value.
        :param integer/long max_length: maximum number of bytes to read from the remote *path* and write to the *file_obj*. Specify a negative value to read from *offset* to the EOF.
                                        If zero, the *Deferred* callback is invoked immediately after the file is opened successfully for reading.
        :return: A *twisted.internet.defer.Deferred* instance. The callback function will be called with a 3-element tuple of ( *file_obj*, file attributes of the file on server, number of bytes written to *file_obj* ).
                 The file attributes is an integer value made up from a bitwise-OR of *SMB_FILE_ATTRIBUTE_xxx* bits (see smb_constants.py)
        """
        if not self.instance:
            raise NotConnectedError('Not connected to server')

        d = defer.Deferred()
        self.instance._retrieveFileFromOffset(service_name, path, file_obj, d.callback, d.errback, offset, max_length, timeout = timeout)
        return d

    def storeFile(self, service_name, path, file_obj, timeout = 30):
        """
        Store the contents of the *file_obj* at *path* on the *service_name*.

        The meaning of the *timeout* parameter will be different from other file operation methods. As the uploaded file usually exceeeds the maximum size
        of each SMB/CIFS data message, it will be packetized into a series of messages (usually about 60kBytes).
        The *timeout* parameter is an integer/float value that specifies the timeout interval for these individual SMB/CIFS message to be transmitted and acknowledged
        by the remote SMB/CIFS server.

        :param string/unicode service_name: the name of the shared folder for the *path*
        :param string/unicode path: Path of the file on the remote server. If the file at *path* does not exist, it will be created. Otherwise, it will be overwritten.
                                    If the *path* refers to a folder or the file cannot be opened for writing, an :doc:`OperationFailure<smb_exceptions>` will be called in the returned *Deferred* errback.
        :param file_obj: A file-like object that has a *read* method. Data will read continuously from *file_obj* until EOF.
        :return: A *twisted.internet.defer.Deferred* instance. The callback function will be called with a 2-element tuple of ( *file_obj*, number of bytes uploaded ).
        """
        if not self.instance:
            raise NotConnectedError('Not connected to server')

        d = defer.Deferred()
        self.instance._storeFile(service_name, path, file_obj, d.callback, d.errback, timeout = timeout)
        return d

    def deleteFiles(self, service_name, path_file_pattern, timeout = 30):
        """
        Delete one or more regular files. It supports the use of wildcards in file names, allowing for deletion of multiple files in a single request.

        :param string/unicode service_name: Contains the name of the shared folder.
        :param string/unicode path_file_pattern: The pathname of the file(s) to be deleted, relative to the service_name.
                                                 Wildcards may be used in th filename component of the path.
                                                 If your path/filename contains non-English characters, you must pass in an unicode string.
        :param integer/float timeout: Number of seconds that pysmb will wait before raising *SMBTimeout* via the returned *Deferred* instance's *errback* method.
        :return: A *twisted.internet.defer.Deferred* instance. The callback function will be called with the *path_file_pattern* parameter.
        """
        if not self.instance:
            raise NotConnectedError('Not connected to server')

        d = defer.Deferred()
        self.instance._deleteFiles(service_name, path_file_pattern, d.callback, d.errback, timeout = timeout)
        return d

    def createDirectory(self, service_name, path):
        """
        Creates a new directory *path* on the *service_name*.

        :param string/unicode service_name: Contains the name of the shared folder.
        :param string/unicode path: The path of the new folder (relative to) the shared folder.
                                    If the path contains non-English characters, an unicode string must be used to pass in the path.
        :param integer/float timeout: Number of seconds that pysmb will wait before raising *SMBTimeout* via the returned *Deferred* instance's *errback* method.
        :return: A *twisted.internet.defer.Deferred* instance. The callback function will be called with the *path* parameter.
        """
        if not self.instance:
            raise NotConnectedError('Not connected to server')

        d = defer.Deferred()
        self.instance._createDirectory(service_name, path, d.callback, d.errback)
        return d

    def deleteDirectory(self, service_name, path):
        """
        Delete the empty folder at *path* on *service_name*

        :param string/unicode service_name: Contains the name of the shared folder.
        :param string/unicode path: The path of the to-be-deleted folder (relative to) the shared folder.
                                    If the path contains non-English characters, an unicode string must be used to pass in the path.
        :param integer/float timeout: Number of seconds that pysmb will wait before raising *SMBTimeout* via the returned *Deferred* instance's *errback* method.
        :return: A *twisted.internet.defer.Deferred* instance. The callback function will be called with the *path* parameter.
        """
        if not self.instance:
            raise NotConnectedError('Not connected to server')

        d = defer.Deferred()
        self.instance._deleteDirectory(service_name, path, d.callback, d.errback)
        return d

    def rename(self, service_name, old_path, new_path):
        """
        Rename a file or folder at *old_path* to *new_path* shared at *service_name*. Note that this method cannot be used to rename file/folder across different shared folders

        *old_path* and *new_path* are string/unicode referring to the old and new path of the renamed resources (relative to) the shared folder.
        If the path contains non-English characters, an unicode string must be used to pass in the path.

        :param string/unicode service_name: Contains the name of the shared folder.
        :param integer/float timeout: Number of seconds that pysmb will wait before raising *SMBTimeout* via the returned *Deferred* instance's *errback* method.
        :return: A *twisted.internet.defer.Deferred* instance. The callback function will be called with a 2-element tuple of ( *old_path*, *new_path* ).
        """
        if not self.instance:
            raise NotConnectedError('Not connected to server')

        d = defer.Deferred()
        self.instance._rename(service_name, old_path, new_path, d.callback, d.errback)
        return d

    def echo(self, data, timeout = 10):
        """
        Send an echo command containing *data* to the remote SMB/CIFS server. The remote SMB/CIFS will reply with the same *data*.

        :param string data: Data to send to the remote server.
        :param integer/float timeout: Number of seconds that pysmb will wait before raising *SMBTimeout* via the returned *Deferred* instance's *errback* method.
        :return: A *twisted.internet.defer.Deferred* instance. The callback function will be called with the *data* parameter.
        """
        if not self.instance:
            raise NotConnectedError('Not connected to server')

        d = defer.Deferred()
        self.instance._echo(data, d.callback, d.errback, timeout)
        return d

    def closeConnection(self):
        """
        Disconnect from the remote SMB/CIFS server. The TCP connection will be closed at the earliest opportunity after this method returns.

        :return: None
        """
        if not self.instance:
            raise NotConnectedError('Not connected to server')

        self.instance.transport.loseConnection()

    #
    # ClientFactory methods
    # (Do not touch these unless you know what you are doing)
    #

    def buildProtocol(self, addr):
        p = self.protocol(self.username, self.password, self.my_name, self.remote_name, self.domain, self.use_ntlm_v2, self.sign_options, self.is_direct_tcp)
        p.factory = self
        return p
