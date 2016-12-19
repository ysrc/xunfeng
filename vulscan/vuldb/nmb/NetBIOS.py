
import os, logging, random, socket, time, select
from base import NBNS, NotConnectedError
from nmb_constants import TYPE_CLIENT, TYPE_SERVER, TYPE_WORKSTATION

class NetBIOS(NBNS):

    log = logging.getLogger('NMB.NetBIOS')

    def __init__(self, broadcast = True, listen_port = 0):
        """
        Instantiate a NetBIOS instance, and creates a IPv4 UDP socket to listen/send NBNS packets.

        :param boolean broadcast: A boolean flag to indicate if we should setup the listening UDP port in broadcast mode
        :param integer listen_port: Specifies the UDP port number to bind to for listening. If zero, OS will automatically select a free port number.
        """
        self.broadcast = broadcast
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if self.broadcast:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if listen_port:
            self.sock.bind(( '', listen_port ))

    def close(self):
        """
        Close the underlying and free resources.

        The NetBIOS instance should not be used to perform any operations after this method returns.

        :return: None
        """
        self.sock.close()
        self.sock = None

    def write(self, data, ip, port):
        assert self.sock, 'Socket is already closed'
        self.sock.sendto(data, ( ip, port ))

    def queryName(self, name, ip = '', port = 137, timeout = 30):
        """
        Send a query on the network and hopes that if machine matching the *name* will reply with its IP address.

        :param string ip: If the NBNSProtocol instance was instianted with broadcast=True, then this parameter can be an empty string. We will leave it to the OS to determine an appropriate broadcast address.
                          If the NBNSProtocol instance was instianted with broadcast=False, then you should provide a target IP to send the query.
        :param integer port: The NetBIOS-NS port (IANA standard defines this port to be 137). You should not touch this parameter unless you know what you are doing.
        :param integer/float timeout: Number of seconds to wait for a reply, after which the method will return None
        :return: A list of IP addresses in dotted notation (aaa.bbb.ccc.ddd). On timeout, returns None.
        """
        assert self.sock, 'Socket is already closed'

        trn_id = random.randint(1, 0xFFFF)
        data = self.prepareNameQuery(trn_id, name)
        if self.broadcast and not ip:
            ip = '<broadcast>'
        elif not ip:
            self.log.warning('queryName: ip parameter is empty. OS might not transmit this query to the network')

        self.write(data, ip, port)

        return self._pollForNetBIOSPacket(trn_id, timeout)

    def queryIPForName(self, ip, port = 137, timeout = 30):
        """
        Send a query to the machine with *ip* and hopes that the machine will reply back with its name.

        The implementation of this function is contributed by Jason Anderson.

        :param string ip: If the NBNSProtocol instance was instianted with broadcast=True, then this parameter can be an empty string. We will leave it to the OS to determine an appropriate broadcast address.
                          If the NBNSProtocol instance was instianted with broadcast=False, then you should provide a target IP to send the query.
        :param integer port: The NetBIOS-NS port (IANA standard defines this port to be 137). You should not touch this parameter unless you know what you are doing.
        :param integer/float timeout: Number of seconds to wait for a reply, after which the method will return None
        :return: A list of string containing the names of the machine at *ip*. On timeout, returns None.
        """
        assert self.sock, 'Socket is already closed'

        trn_id = random.randint(1, 0xFFFF)
        data = self.prepareNetNameQuery(trn_id, False)
        self.write(data, ip, port)
        ret = self._pollForQueryPacket(trn_id, timeout)
        if ret:
            return map(lambda s: s[0], filter(lambda s: s[1] == TYPE_SERVER, ret))
        else:
            return None

    #
    # Protected Methods
    #

    def _pollForNetBIOSPacket(self, wait_trn_id, timeout):
        end_time = time.time() + timeout
        while True:
            try:
                _timeout = end_time - time.time()
                if _timeout <= 0:
                    return None

                ready, _, _ = select.select([ self.sock.fileno() ], [ ], [ ], _timeout)
                if not ready:
                    return None

                data, _ = self.sock.recvfrom(0xFFFF)
                if len(data) == 0:
                    raise NotConnectedError

                trn_id, ret = self.decodePacket(data)

                if trn_id == wait_trn_id:
                    return ret
            except select.error, ex:
                if type(ex) is types.TupleType:
                    if ex[0] != errno.EINTR and ex[0] != errno.EAGAIN:
                        raise ex
                else:
                    raise ex

    #
    # Contributed by Jason Anderson
    #
    def _pollForQueryPacket(self, wait_trn_id, timeout):
        end_time = time.time() + timeout
        while True:
            try:
                _timeout = end_time - time.time()
                if _timeout <= 0:
                    return None

                ready, _, _ = select.select([ self.sock.fileno() ], [ ], [ ], _timeout)
                if not ready:
                    return None

                data, _ = self.sock.recvfrom(0xFFFF)
                if len(data) == 0:
                    raise NotConnectedError

                trn_id, ret = self.decodeIPQueryPacket(data)

                if trn_id == wait_trn_id:
                    return ret
            except select.error, ex:
                if type(ex) is types.TupleType:
                    if ex[0] != errno.EINTR and ex[0] != errno.EAGAIN:
                        raise ex
                else:
                    raise ex
