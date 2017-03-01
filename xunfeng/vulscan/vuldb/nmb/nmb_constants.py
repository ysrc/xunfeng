
# Default port for NetBIOS name service
NETBIOS_NS_PORT = 137

# Default port for NetBIOS session service
NETBIOS_SESSION_PORT = 139

# Owner Node Type Constants
NODE_B = 0x00
NODE_P = 0x01
NODE_M = 0x10
NODE_RESERVED = 0x11

# Name Type Constants
TYPE_UNKNOWN = 0x01
TYPE_WORKSTATION = 0x00
TYPE_CLIENT = 0x03
TYPE_SERVER = 0x20
TYPE_DOMAIN_MASTER = 0x1B
TYPE_MASTER_BROWSER = 0x1D
TYPE_BROWSER = 0x1E

TYPE_NAMES = { TYPE_UNKNOWN: 'Unknown',
               TYPE_WORKSTATION: 'Workstation',
               TYPE_CLIENT: 'Client',
               TYPE_SERVER: 'Server',
               TYPE_MASTER_BROWSER: 'Master Browser',
               TYPE_BROWSER: 'Browser Server',
               TYPE_DOMAIN_MASTER: 'Domain Master'
               }

# Values for Session Packet Type field in Session Packets
SESSION_MESSAGE = 0x00
SESSION_REQUEST = 0x81
POSITIVE_SESSION_RESPONSE = 0x82
NEGATIVE_SESSION_RESPONSE = 0x83
REGTARGET_SESSION_RESPONSE = 0x84
SESSION_KEEPALIVE = 0x85
