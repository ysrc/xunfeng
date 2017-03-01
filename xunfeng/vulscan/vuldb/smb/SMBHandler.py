
import os, sys, socket, urllib2, mimetypes, mimetools, tempfile
from urllib import (unwrap, unquote, splittype, splithost, quote,
     addinfourl, splitport, splittag,
     splitattr, ftpwrapper, splituser, splitpasswd, splitvalue)
from nmb.NetBIOS import NetBIOS
from smb.SMBConnection import SMBConnection

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

USE_NTLM = True
MACHINE_NAME = None

class SMBHandler(urllib2.BaseHandler):

    def smb_open(self, req):
        global USE_NTLM, MACHINE_NAME

        host = req.get_host()
        if not host:
            raise urllib2.URLError('SMB error: no host given')
        host, port = splitport(host)
        if port is None:
            port = 139
        else:
            port = int(port)

        # username/password handling
        user, host = splituser(host)
        if user:
            user, passwd = splitpasswd(user)
        else:
            passwd = None
        host = unquote(host)
        user = user or ''

        domain = ''
        if ';' in user:
            domain, user = user.split(';', 1)

        passwd = passwd or ''
        myname = MACHINE_NAME or self.generateClientMachineName()

        n = NetBIOS()
        names = n.queryIPForName(host)
        if names:
            server_name = names[0]
        else:
            raise urllib2.URLError('SMB error: Hostname does not reply back with its machine name')

        path, attrs = splitattr(req.get_selector())
        if path.startswith('/'):
            path = path[1:]
        dirs = path.split('/')
        dirs = map(unquote, dirs)
        service, path = dirs[0], '/'.join(dirs[1:])

        try:
            conn = SMBConnection(user, passwd, myname, server_name, domain=domain, use_ntlm_v2 = USE_NTLM)
            conn.connect(host, port)

            if req.has_data():
                data_fp = req.get_data()
                filelen = conn.storeFile(service, path, data_fp)

                headers = "Content-length: 0\n"
                fp = StringIO("")
            else:
                fp = self.createTempFile()
                file_attrs, retrlen = conn.retrieveFile(service, path, fp)
                fp.seek(0)

                headers = ""
                mtype = mimetypes.guess_type(req.get_full_url())[0]
                if mtype:
                    headers += "Content-type: %s\n" % mtype
                if retrlen is not None and retrlen >= 0:
                    headers += "Content-length: %d\n" % retrlen

            sf = StringIO(headers)
            headers = mimetools.Message(sf)

            return addinfourl(fp, headers, req.get_full_url())
        except Exception, ex:
            raise urllib2.URLError, ('smb error: %s' % ex), sys.exc_info()[2]

    def createTempFile(self):
        return tempfile.TemporaryFile()

    def generateClientMachineName(self):
        hostname = socket.gethostname()
        if hostname:
            return hostname.split('.')[0]
        return 'SMB%d' % os.getpid()
