
import os, logging, random, socket, time
from twisted.internet import reactor, defer
from twisted.internet.protocol import DatagramProtocol
from nmb_constants import TYPE_SERVER
from base import NBNS

IP_QUERY, NAME_QUERY = range(2)

class NetBIOSTimeout(Exception):
    """Raised in NBNSProtocol via Deferred.errback method when queryName method has timeout waiting for reply"""
    pass

class NBNSProtocol(DatagramProtocol, NBNS):

    log = logging.getLogger('NMB.NBNSProtocol')

    def __init__(self, broadcast = True, listen_port = 0):
        """
        Instantiate a NBNSProtocol instance.

        This automatically calls reactor.listenUDP method to start listening for incoming packets, so you **must not** call the listenUDP method again.

        :param boolean broadcast: A boolean flag to indicate if we should setup the listening UDP port in broadcast mode
        :param integer listen_port: Specifies the UDP port number to bind to for listening. If zero, OS will automatically select a free port number.
        """
        self.broadcast = broadcast
        self.pending_trns = { }  # TRN ID -> ( expiry_time, name, Deferred instance )
        self.transport = reactor.listenUDP(listen_port, self)
        if self.broadcast:
            self.transport.getHandle().setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        reactor.callLater(1, self.cleanupPendingTrns)

    def datagramReceived(self, data, from_info):
        host, port = from_info
        trn_id, ret = self.decodePacket(data)

        # pending transaction exists for trn_id - handle it and remove from queue
        if trn_id in self.pending_trns:
            _, ip, d = self.pending_trns.pop(trn_id)
            if ip is NAME_QUERY:
                # decode as query packet
                trn_id, ret = self.decodeIPQueryPacket(data)
            d.callback(ret)

    def write(self, data, ip, port):
        # We don't use the transport.write method directly as it keeps raising DeprecationWarning for ip='<broadcast>'
        self.transport.getHandle().sendto(data, ( ip, port ))

    def queryName(self, name, ip = '', port = 137, timeout = 30):
        """
        Send a query on the network and hopes that if machine matching the *name* will reply with its IP address.

        :param string ip: If the NBNSProtocol instance was instianted with broadcast=True, then this parameter can be an empty string. We will leave it to the OS to determine an appropriate broadcast address.
                          If the NBNSProtocol instance was instianted with broadcast=False, then you should provide a target IP to send the query.
        :param integer port: The NetBIOS-NS port (IANA standard defines this port to be 137). You should not touch this parameter unless you know what you are doing.
        :param integer/float timeout: Number of seconds to wait for a reply, after which the returned Deferred instance will be called with a NetBIOSTimeout exception.
        :return: A *twisted.internet.defer.Deferred* instance. The callback function will be called with a list of IP addresses in dotted notation (aaa.bbb.ccc.ddd).
                 On timeout, the errback function will be called with a Failure instance wrapping around a NetBIOSTimeout exception
        """
        trn_id = random.randint(1, 0xFFFF)
        while True:
            if not self.pending_trns.has_key(trn_id):
                break
            else:
                trn_id = (trn_id + 1) & 0xFFFF

        data = self.prepareNameQuery(trn_id, name)
        if self.broadcast and not ip:
            ip = '<broadcast>'
        elif not ip:
            self.log.warning('queryName: ip parameter is empty. OS might not transmit this query to the network')

        self.write(data, ip, port)

        d = defer.Deferred()
        self.pending_trns[trn_id] = ( time.time()+timeout, name, d )
        return d

    def queryIPForName(self, ip, port = 137, timeout = 30):
        """
        Send a query to the machine with *ip* and hopes that the machine will reply back with its name.

        The implementation of this function is contributed by Jason Anderson.

        :param string ip: If the NBNSProtocol instance was instianted with broadcast=True, then this parameter can be an empty string. We will leave it to the OS to determine an appropriate broadcast address.
                          If the NBNSProtocol instance was instianted with broadcast=False, then you should provide a target IP to send the query.
        :param integer port: The NetBIOS-NS port (IANA standard defines this port to be 137). You should not touch this parameter unless you know what you are doing.
        :param integer/float timeout: Number of seconds to wait for a reply, after which the method will return None
        :return: A *twisted.internet.defer.Deferred* instance. The callback function will be called with a list of names of the machine at *ip*.
                 On timeout, the errback function will be called with a Failure instance wrapping around a NetBIOSTimeout exception
        """
        trn_id = random.randint(1, 0xFFFF)
        while True:
            if not self.pending_trns.has_key(trn_id):
                break
            else:
                trn_id = (trn_id + 1) & 0xFFFF

        data = self.prepareNetNameQuery(trn_id)
        self.write(data, ip, port)

        d = defer.Deferred()
        d2 = defer.Deferred()
        d2.addErrback(d.errback)

        def stripCode(ret):
            if ret is not None: # got valid response. Somehow the callback is also called when there is an error.
                d.callback(map(lambda s: s[0], filter(lambda s: s[1] == TYPE_SERVER, ret)))

        d2.addCallback(stripCode)
        self.pending_trns[trn_id] = ( time.time()+timeout, NAME_QUERY, d2 )
        return d

    def stopProtocol(self):
        DatagramProtocol.stopProtocol(self)

    def cleanupPendingTrns(self):
        now = time.time()

        # reply should have been received in the past
        expired = filter(lambda (trn_id, (expiry_time, name, d)): expiry_time < now, self.pending_trns.iteritems())

        # remove expired items from dict + call errback
        def expire_item(item):
            trn_id, (expiry_time, name, d) = item

            del self.pending_trns[trn_id]
            try:
                d.errback(NetBIOSTimeout(name))
            except: pass

        map(expire_item, expired)

        if self.transport:
            reactor.callLater(1, self.cleanupPendingTrns)
