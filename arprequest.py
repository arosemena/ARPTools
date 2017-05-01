#!/usr/bin/python
import socket
import re
import sys


def help():
    print("The command takes 4 arguments:")
    print("interface needed_ip source_ip source_mac \n")
    print("needed_ip = The IP address that we need to get the MAC address from")
    print("source_ip = The IP address that is asking for the MAC of the needed_ip")
    print("source_mac = The MAC address that is asking for the MAC of the needed_ip")
    print("example: arprequest.py eth0 10.1.1.1 10.1.1.52 00-0c-40-32-a1-2f")
    print("Tell 10.1.1.25(00-0c-40-32-a1-2f) what's the MAC address of 10.1.1.1")
    print("This command just sends the request, to listen to responses use a tool like wireshark")

if len(sys.argv) < 2 or sys.argv[1] == 'help' or sys.argv[1] == '--help':
    help()
    exit(0)

if len(sys.argv) != 5:
    print("Invalid number of arguments\n")
    help()
    exit(2)

interface = sys.argv[1]
needed_ip = sys.argv[2]
source_ip = sys.argv[3]
source_mac = sys.argv[4]


def mac_to_hex(mac):
    mac_pattern = re.compile("[0-9A-F]{12}", re.IGNORECASE)
    plain_mac = mac.replace("-", "").replace(":", "")
    if re.match(mac_pattern, plain_mac) is None:
        print("Malformed MAC: " + mac)
        print("Use the hex form of 12 digits, can be used with dashes or colons")
        exit(2)
    hex_mac = re.findall('..', plain_mac.lower())  # split the string every 2 characters
    return map(lambda x: int(x, 16), hex_mac)


def ip_to_hex(ip):
    ip_pattern = re.compile("(\d?\d?\d)\.(\d?\d?\d)\.(\d?\d?\d)\.(\d?\d?\d)")
    octets = re.findall(ip_pattern, ip)
    valid_octets = filter(lambda x: 0 <= int(x) <= 255, octets[0])
    if re.match(ip_pattern, ip) is None or len(valid_octets) != 4:
        print("Malformed IP: " + ip)
        print("Please use a correct IPv4 address")
        exit(2)
    return map(lambda x: int(x), valid_octets)  # converts int to hex with padded 0's

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)

try:
    s.bind((interface, 0))
except socket.error:
    print("Couldn't bind the socket, is the interface name correct?")
    exit(1)

needed_ip_hex = ip_to_hex(needed_ip)
source_ip_hex = ip_to_hex(source_ip)
source_mac_hex = mac_to_hex(source_mac)
broadcast_mac_hex = mac_to_hex("FF-FF-FF-FF-FF-FF")
target_mac_hex = mac_to_hex("00-00-00-00-00-00")
packet_type = [0x08, 0x06]  # ARP
hardware_type = [0x00, 0x01]
protocol_type = [0x08, 0x00]  # IPv4
hardware_size = [0x06]
protocol_size = [0x04]
op_code = [0x00, 0x01]  # request
padding = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

packet = \
    broadcast_mac_hex + \
    source_mac_hex + \
    packet_type + \
    hardware_type + \
    protocol_type + \
    hardware_size + \
    protocol_size + \
    op_code + \
    source_mac_hex + \
    source_ip_hex + \
    target_mac_hex + \
    needed_ip_hex + \
    padding

s.send(bytearray(packet))
print("ARP packet sent!")
