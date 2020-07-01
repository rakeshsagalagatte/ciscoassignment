#!/usr/bin/env python3


import sys
import pyshark
import subprocess
import logging

##Loggers setup
logging.getLogger().setLevel(logging.DEBUG)
logger = logging.getLogger(__name__)


def error_codes(filename):
    #to get http error codes 
    #tshark -r forHttpErrorcode.pcap -Y "http.response"  -T fields -e http.response.code
    # Out = subprocess.Popen(['tshark', '-r', filename, '-Y', 'http.response.code > 300', '-T', 'fields', '-e', 'http.response.code'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT )
    Out = subprocess.Popen(['tshark', '-r', filename, '-Y', 'http.response.code > 300', '-T', 'fields', '-e', 'http.response.code'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT )
    stdout,stderr = Out.communicate()
    stdout = stdout.decode('utf-8')
    return stdout


def methods_Http(filename):
    #tshark -r httpMethod.pcap -Y "http.request.method == GET" -T fields -e http.request.method
    #fields = '-e http.request.method'
    # Out = subprocess.Popen(['tshark', '-r', filename, '-Y', "http.request.method", '-T', 'fields', '-e', 'http.request.method', '-e', 'text'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    Out = subprocess.Popen(['tshark', '-r', filename, '-Y', "http.request.method", '-T', 'fields', '-e', 'http.request.method'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)  # for only methods not text
    stdout,stderr = Out.communicate()
    stdout = stdout.decode('utf-8')
    return stdout 


def main():
    if len(sys.argv) != 2:
        logger.error('Insufficient arguments')
        print("Usage: <script_name>.py <pcap_file>")
        sys.exit(1)

    filename = sys.argv[1]
    method_out = methods_Http(filename)
    Error_codes = error_codes(filename)
    htmlFile = open('Http_method.html' , 'w')
    htmlFile.write('<pre><h1> Captured Methods </h1><br>')
    htmlFile.write(method_out + '<br> <br> Error Codes <br>')
    htmlFile.write(Error_codes)
    htmlFile.write('/<pre>')



if __name__ == "__main__":
    main()