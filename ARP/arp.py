#!/usr/bin/env python3

#   ARP (request, response, IP, resolved MAC, type of arp packet)


import sys
import pyshark
import subprocess
import logging

logging.getLogger().setLevel(logging.DEBUG)
logger = logging.getLogger(__name__)


def arp_request(filename):
    #tcpdump -r forHttpErrorcode.pcap  "arp[7]=1" -n -vvv
    # Using tcpdump 
    Out = subprocess.Popen(['tcpdump', '-r', filename,  "arp[7]=1", '-n', '-vvv'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout,stderr = Out.communicate()
    stdout = stdout.decode('utf-8')
    return stdout


def arp_response(filename):
    #tcpdump -r forHttpErrorcode.pcap  "arp[7]=2" -n -vvv
    # Using tcpdump 
    Out = subprocess.Popen(['tcpdump', '-r', filename,  "arp[7]=2", '-n', '-vvv'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout,stderr = Out.communicate()
    stdout = stdout.decode('utf-8')
    return stdout


def arp_type_of_arp_packet(filename):
    #tshark -r forHttpErrorcode.pcap -Y arp -T fields -e arp.proto.type
    # Using tshark
    Out = subprocess.Popen(['tshark', '-r', filename, '-Y', 'arp', '-T', 'fields', '-e', 'arp.proto.type'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout,stderr = Out.communicate()
    stdout = stdout.decode('utf-8')
    return stdout

def arp_IP(filename):
    # tshark -r forHttpErrorcode.pcap -Y arp.opcode==1 -T fields -e arp.src.proto_ipv4 -e arp.dst.proto_ipv4
    # tcpdump -r forHttpErrorcode.pcap  "arp[7]=1" -n -vvv    #| cut -d' ' -f11,13    
    Out = subprocess.Popen(['tshark', '-r', filename, '-Y', 'arp.opcode==1', '-T', 'fields', '-e', 'arp.src.proto_ipv4', '-e', 'arp.dst.proto_ipv4'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout,stderr = Out.communicate()
    stdout = stdout.decode('utf-8')
    return stdout

def arp_resolved_MAC(filename):
    # tshark -r forHttpErrorcode.pcap -Y arp.opcode==2 -T fields -e arp.src.hw_mac
    Out = subprocess.Popen(['tshark', '-r', filename, '-Y', 'arp.opcode==2', '-T', 'fields', '-e', 'arp.src.hw_mac'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout,stderr = Out.communicate()
    stdout = stdout.decode('utf-8')
    return stdout


def main():
    if len(sys.argv) != 2:
        logger.error('Insufficient arguments')
        print("Usage: <script_name>.py <pcap_file>")
        sys.exit(1)

    filename = sys.argv[1]
    arp_req  = arp_request(filename)
    arp_res  = arp_response(filename)
    arp_ip   = arp_IP(filename)
    arp_mac  = arp_resolved_MAC(filename)
    arp_type = arp_type_of_arp_packet(filename)
    htmlFile = open('arp_packet.html', 'w')
    htmlFile.write('<pre><h1> ARP REQUEST  </h1><br>')
    htmlFile.write(arp_req + '<br> <br> <h1> ARP RESPONSE </h1> <br>')
    htmlFile.write(arp_res + '<br> <br> <h1> ARP IP </h1><br>')
    htmlFile.write(arp_ip + '<br> <br> <h1> ARP RESOLVED MAC ADDRESS </h1><br>')
    htmlFile.write(arp_mac + '<br> <br> <h1> TYPE OF ARP PACKET  </h1><br>')
    htmlFile.write(arp_type + '/<pre>')



if __name__ == "__main__":
    main()




