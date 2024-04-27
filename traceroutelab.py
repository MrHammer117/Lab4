from socket import *
import os
import sys
import struct
import time
import select
import binascii

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 2
ID = os.getpid() & 0xffff

# The packet that we shall send to each router along the path is the ICMP echo
# request packet, which is exactly what we had used in the ICMP ping exercise.
# We shall use the same packet that we built in the Ping exercise
def checksum(string):
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0
    while count < countTo:
        thisVal = ord(string[count+1]) * 256 + ord(string[count])
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count = count + 2
    if countTo < len(string):
        csum = csum + ord(string[len(string) - 1])
        csum = csum & 0xffffffff
    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def build_packet():
# In the sendOnePing() method of the ICMP Ping exercise ,firstly the header of our
# packet to be sent was made, secondly the checksum was appended to the header and
# then finally the complete packet was sent to the destination.
# Make the header in a similar way to the ping exercise.
# Append checksum to the header.
# Don’t send the packet yet , just return the final packet in this function.
# So the function ending should look like this

    # Header is type (8), code (8), checksum (16), id (16), sequence (16)


    myChecksum = 0

    # Make a dummy header with a 0 checksum
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)

    data = struct.pack("d", time.time())

    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(str(header) + str(data))

    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network byte order
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)
        
    packet = header + data
    return packet

def get_route(hostname):

    timeLeft = TIMEOUT
    destAddr = gethostbyname(hostname)
    print(hostname, " is at IP: ", destAddr)


    for ttl in range(1,MAX_HOPS):
 
        for tries in range(TRIES):
            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(TIMEOUT)
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl)) 
            try:
                d = build_packet()
                mySocket.sendto(d, (hostname, 0))
                t = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)
                if whatReady[0] == []:  # Timeout
                    print(ttl," *      *      * Request timed out.")
                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    print(ttl," *      *      * Request timed out.")
            except timeout:
                continue
            else:
                types, = struct.unpack("b", recvPacket[20:21])
                try:
                    if types == 11: # Time Exceeded
                        bytes = struct.calcsize("d")
                        timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                        domain_name = gethostbyaddr(addr[0])[0]
                        print(" %d rtt=%.0f ms IP: %s Domain Name: %s" % (ttl, (timeReceived - t) * 1000, addr[0], domain_name))
                    elif types == 0: # Echo Reply
                        bytes = struct.calcsize("d")
                        timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                        domain_name = gethostbyaddr(addr[0])[0]
                        print(" %d rtt=%.0f ms IP: %s Domain Name: %s" % (ttl, (timeReceived - timeSent) * 1000, addr[0], domain_name))
                    elif types == 3: # unreachable destination
                        bytes = struct.calcsize("d")
                        timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                        domain_name = gethostbyaddr(addr[0])[0]
                        print(" %d rtt=%.0f ms IP: %s Domain Name: %s" % (ttl, (timeReceived - t) * 1000, addr[0], domain_name))
                    else:
                        print("error")
                except (herror, gaierror) as e:
                    if types == 11: # Time Exceeded
                        bytes = struct.calcsize("d")
                        timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                        print(" %d rtt=%.0f ms IP: %s" % (ttl, (timeReceived - t) * 1000, addr[0]), end=" ")
                    elif types == 0: # Echo Reply
                        bytes = struct.calcsize("d")
                        timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                        print(" %d rtt=%.0f ms IP: %s" % (ttl, (timeReceived - timeSent) * 1000, addr[0]), end=" ")
                    elif types == 3: # destination Unreachable
                        bytes = struct.calcsize("d")
                        timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                        print(" %d rtt=%.0f ms IP: %s" % (ttl, (timeReceived - t) * 1000, addr[0]), end=" ")
                    print("Unable to resolve hostname for IP: %s" % addr[0])
                break
            finally:
                mySocket.close()

get_route("www.google.com")