"""Services prédéfinis de FortiOS.

FortiOS livre une centaine de services nommés (HTTP, SSH, ALL_TCP…) qui
n'apparaissent pas dans la sauvegarde : seuls les services personnalisés
y figurent. Pour mettre à plat une politique en ports réels, il faut donc
connaître les plus courants. La table ci-dessous couvre ceux que l'on croise
en audit ; un nom absent est conservé tel quel (non résolu).

Chaque entrée : liste de (protocole, ports). « ports » suit la syntaxe
FortiOS des portrange : « 80 », « 6660-6669 », plusieurs plages possibles.
"""

PREDEFINED = {
    "ALL": [("any", "any")],
    "ALL_TCP": [("tcp", "1-65535")],
    "ALL_UDP": [("udp", "1-65535")],
    "ALL_ICMP": [("icmp", "any")],
    "ALL_ICMP6": [("icmp6", "any")],
    "PING": [("icmp", "any")],
    "PING6": [("icmp6", "any")],
    "TRACEROUTE": [("udp", "33434-33535")],
    "HTTP": [("tcp", "80")],
    "HTTPS": [("tcp", "443")],
    "SSH": [("tcp", "22")],
    "TELNET": [("tcp", "23")],
    "FTP": [("tcp", "21")],
    "FTP_GET": [("tcp", "21")],
    "FTP_PUT": [("tcp", "21")],
    "TFTP": [("udp", "69")],
    "SMTP": [("tcp", "25")],
    "SMTPS": [("tcp", "465")],
    "POP3": [("tcp", "110")],
    "POP3S": [("tcp", "995")],
    "IMAP": [("tcp", "143")],
    "IMAPS": [("tcp", "993")],
    "DNS": [("tcp", "53"), ("udp", "53")],
    "NTP": [("udp", "123")],
    "SNMP": [("udp", "161-162")],
    "SYSLOG": [("udp", "514")],
    "DHCP": [("udp", "67-68")],
    "DHCP6": [("udp", "546-547")],
    "RDP": [("tcp", "3389")],
    "VNC": [("tcp", "5900")],
    "SMB": [("tcp", "445")],
    "SAMBA": [("tcp", "139")],
    "NetBIOS": [("tcp", "139"), ("udp", "137-138")],
    "LDAP": [("tcp", "389")],
    "LDAP_UDP": [("udp", "389")],
    "LDAPS": [("tcp", "636")],
    "KERBEROS": [("tcp", "88"), ("udp", "88")],
    "RADIUS": [("udp", "1812-1813")],
    "RADIUS-OLD": [("udp", "1645-1646")],
    "MYSQL": [("tcp", "3306")],
    "MS-SQL": [("tcp", "1433"), ("udp", "1434")],
    "NFS": [("tcp", "111"), ("tcp", "2049"), ("udp", "111"), ("udp", "2049")],
    "RSH": [("tcp", "514")],
    "RLOGIN": [("tcp", "513")],
    "SQUID": [("tcp", "3128")],
    "SOCKS": [("tcp", "1080"), ("udp", "1080")],
    "PPTP": [("tcp", "1723")],
    "L2TP": [("tcp", "1701"), ("udp", "1701")],
    "IKE": [("udp", "500"), ("udp", "4500")],
    "SIP": [("udp", "5060")],
    "H323": [("tcp", "1720")],
    "IRC": [("tcp", "6660-6669")],
    "X-WINDOWS": [("tcp", "6000-6063")],
    "WINS": [("tcp", "1512"), ("udp", "1512")],
    "MS-RPC": [("tcp", "135")],
    "RTSP": [("tcp", "554"), ("udp", "554")],
    "GOPHER": [("tcp", "70")],
    "NNTP": [("tcp", "119")],
    "TIMESTAMP": [("icmp", "any")],
    "INFO_REQUEST": [("icmp", "any")],
    "INFO_ADDRESS": [("icmp", "any")],
}


def lookup(name):
    """Renvoie la liste (protocole, ports) d'un service prédéfini, ou None."""
    return PREDEFINED.get(name)
