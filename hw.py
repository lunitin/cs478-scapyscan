#!/usr/bin/python3

import logging
logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)
import itertools as it

from scapy.all import *
import ipaddress



"""
# TCP Port Scan Helper
"""
def tcp_port_is_open(dst_ip, dst_port):
    print("Check TCP port", dst_ip, dst_port)
    src_port = RandShort()
    tcp_connect_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="S"), timeout=2, verbose=0)

    if( str(type(tcp_connect_scan_resp)) == "<type 'NoneType'>"):
        return False
    elif( tcp_connect_scan_resp and tcp_connect_scan_resp.haslayer(TCP) ):
        if( tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
            send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port, flags="AR"),timeout=2, verbose=0)
            return True
        elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
            return False

"""
# UDP Port scan Helper
"""
def udp_port_is_open(dst_ip, dst_port):

    udp_scan = sr1(IP(dst=dst_ip)/UDP(sport=dst_port, dport=dst_port), timeout=2, verbose=0)
    # No Response, open
    if udp_scan == None:
        return True
    else:
        # IF we got an ICMP response then closed
        if udp_scan and udp_scan.haslayer(ICMP):
            return False
        # IF we got a UDP response (unlikely), Open
        elif udp_scan and udp_scan.haslayer(UDP):
            return True
        else:
            return False




"""
# a TCP connect() scan of ports 20-100, 130-150, and 400-500
"""
def tcp_connect_scan(ip):
    print("Scanning TCP Ports: 20-100, 130-150, and 400-500")

    for i in range(20,30):
    #for port in list(range(20,101)) + list(range(130,151)) + list(range(400,501)):
    #    if (tcp_port_is_open(ip, port)):
    #        o.append(port)

        print(i)

    print("Open TCP Ports: ")
    print(o)



"""
a UDP scan of the top 100 ports
"""
def udp_top_100_scan(ip):
    print("Scanning top 100 UDP Ports...")
    open = closed = []
    top100UDP = [7, 9, 17, 19, 49, 53, 67, 68, 69, 80, 88, 111, 120, 123, 135, 136, 137, 138, 139, 158, 161, 162, 177, 427,
                 443, 445, 497, 500, 514, 515, 518, 520, 593, 623, 626, 631, 996, 997, 998, 999, 1022, 1023, 1025, 1026,
                 1027, 1028, 1029, 1030, 1433, 1434, 1645, 1646, 1701, 1718, 1719, 1812, 1813, 1900, 2000, 2048, 2049, 2222,
                 2223, 3283, 3456, 3703, 4444, 4500, 5000, 5060, 5353, 5632, 9200, 10000, 17185, 20031, 30718, 31337, 32768,
                 32769, 32771, 32815, 33281, 49152, 49153, 49154, 49156, 49181, 49182, 49185, 49186, 49188, 49190, 49191,
                 49192, 49193, 49194, 49200, 49201, 65024]

    for port in top100UDP:
        if (udp_port_is_open(ip, port)):
            open.append(port)
        else:
            closed.append(port)

    print("Open UDP Ports: ")
    print(open)

"""
# Simple OS detection scan
"""
def os_detect(ip):

    icmp_check = sr1(IP(dst=ip)/ICMP(), timeout=2, verbose=0)
    if icmp_check:
        if IP in icmp_check:
            ttl = icmp_check.getlayer(IP).ttl
            if ttl <= 64:
                os = 'Linux'
            elif ttl > 64:
                os = 'Windows'
            else:
                os = 'Unknown'

    print("OS of", ip, "likely", os)

"""
# an IP protocol scan
"""
def protocol_scan(ip):
    return False


"""
# Try scanning your VM's subnet, on TCP ports 20-25.
#
# combine CIDR notation and an exclude list specified on the command line
"""
def network_scan(cidr, exclude = []):
    # Find hosts on the network
    open = closed = []

    for host in ipaddress.ip_network(cidr).hosts():
        ip = str(host)
        if ip in exclude:
            #print("excluded", ip)
            continue
        print(ip)
        #ans,unans=sr(IP(dst=ip)/TCP(flags='S', dport=(20,25)), timeout=2)
        #print(ans.nsummary(), unans.nsummary())
        if tcp_port_is_open(ip, 80):
            open.append(str(ip + " : " + "53"))
        else:
            closed.append(str(ip +" : " + "53") )

    print("Hosts with open ports:") 
    print(open)
    # For each active host, check ports 20 through 25
    # open = closed = []
    #
    # for port in range(20,26):
    #     if (tcp_port_is_open(ip, port)):
    #         open.append(port)
    #     else:
    #         closed.append(port)





ip = '10.0.0.1'
range = '10.0.0.0/29'
# MAIN
tcp_connect_scan(ip)

#udp_top_100_scan(ip)
#os_detect(ip)

#network_scan(range, ['10.0.0.4'])
