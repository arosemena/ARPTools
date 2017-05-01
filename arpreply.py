#!/usr/bin/python
import socket
import re
import sys


def help():
    print("The command takes 5 arguments:")
    print("interface source_mac source_ip destination_mac destination_ip \n")
    print("source_mac = MAC address of the device that has the ip that was asked for")
    print("source_ip = The IP address that was asked for")
    print("destination_mac = MAC address of the device that asked for the ip")
    print("destination_ip = IP address of the device that asked for the ip\n")
    print("example: arpreply.py eth0 00-0c-30-65-a2-1f 10.1.1.1 00-0c-40-32-a1-2f 10.1.1.25")
    print("Tell 10.1.1.25(00-0c-40-32-a1-2f) that 10.1.1.1 is at 00-0c-30-65-a2-1f")

if len(sys.argv) < 2 or sys.argv[1] == 'help' or sys.argv[1] == '--help':
    help()
    exit(0)

if len(sys.argv) != 6:
    print("Invalid number of arguments\n")
    help()
    exit(2)

interface = sys.argv[1]
source_mac = sys.argv[2]
source_ip = sys.argv[3]
destination_mac = sys.argv[4]
destination_ip = sys.argv[5]


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

source_mac_hex = mac_to_hex(source_mac)
source_ip_hex = ip_to_hex(source_ip)
destination_mac_hex = mac_to_hex(destination_mac)
destination_ip_hex = ip_to_hex(destination_ip)
packet_type = [0x08, 0x06]  # ARP
hardware_type = [0x00, 0x01]
protocol_type = [0x08, 0x00]  # IPv4
hardware_size = [0x06]
protocol_size = [0x04]
op_code = [0x00, 0x02]  # reply
padding = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

packet = \
    destination_mac_hex + \
    source_mac_hex + \
    packet_type + \
    hardware_type + \
    protocol_type + \
    hardware_size + \
    protocol_size + \
    op_code + \
    source_mac_hex + \
    source_ip_hex + \
    destination_mac_hex + \
    destination_ip_hex + \
    padding

s.send(bytearray(packet))
print("ARP packet sent!")
