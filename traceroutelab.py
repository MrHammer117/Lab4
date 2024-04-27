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
# The packet that we shall send to each router along the path is the ICMP echo
# request packet, which is exactly what we had used in the ICMP ping exercise.
# We shall use the same packet that we built in the Ping exercise
def checksum(packet):
    # Calculate the checksum of the packet
    if len(packet) % 2 != 0:
        packet += b'\x00'  # Padding if packet length is odd

    # Initialize checksum
    csum = 0
    countTo = len(packet)

    # Iterate over the packet, two bytes at a time
    for count in range(0, countTo, 2):
        thisVal = packet[count + 1] * 256 + packet[count]
        csum += thisVal
        csum &= 0xffffffff  # Force to 32 bits

    csum = (csum >> 16) + (csum & 0xffff)  # Fold once
    csum += (csum >> 16)  # Fold again

    return ~csum & 0xffff  # Invert and truncate to 16 bits

def build_packet():
# In the sendOnePing() method of the ICMP Ping exercise ,firstly the header of our
# packet to be sent was made, secondly the checksum was appended to the header and
# then finally the complete packet was sent to the destination.
# Make the header in a similar way to the ping exercise.
# Append checksum to the header.
# Don’t send the packet yet , just return the final packet in this function.
# So the function ending should look like this

    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    myID = os.getpid() & 0xFFFF

    myChecksum = 0

    # Make a dummy header with a 0 checksum
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)

    data = struct.pack("d", time.time())
    # Concatenate header and data
    packet = header + data

    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(packet)

    # Get the right checksum, and put in the header
    if sys.platform == 'win32' or sys.platform == 'darwin':
        # Convert 16-bit integers from host to network byte order
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)
        
    packet = header + data
    return packet

def get_route(hostname):
    timeLeft = TIMEOUT
    destAddr = gethostbyname(hostname)
    for ttl in range(1, MAX_HOPS):
        for tries in range(TRIES):
            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            try:
                d = build_packet()
                mySocket.sendto(d, (hostname, 0))
                t = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)
                if whatReady[0] == []:  # Timeout
                    print(" *      *      * Request timed out.")
                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    print(" *      *      * Request timed out.")
            except timeout:
                continue
            else:
                types = struct.unpack('B', recvPacket[20:21])[0]
                try:
                    if types == 11:
                        bytes = struct.calcsize("d")
                        timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                        domain_name = gethostbyaddr(addr[0])[0]
                        print(" %d rtt=%.0f ms IP: %s Domain Name: %s" % (ttl, (timeReceived - t) * 1000, addr[0], domain_name))
                    elif types == 0 and addr[0] == destAddr:
                        bytes = struct.calcsize("d")
                        timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                        domain_name = gethostbyaddr(addr[0])[0]
                        print(" %d rtt=%.0f ms IP: %s Domain Name: %s" % (ttl, (timeReceived - timeSent) * 1000, addr[0], domain_name))
                        if addr[0] == destAddr:
                            print("Destination reached:", hostname)
                            return
                    elif types == 0:
                        bytes = struct.calcsize("d")
                        timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                        domain_name = gethostbyaddr(addr[0])[0]
                        print(" %d rtt=%.0f ms IP: %s Domain Name: %s" % (ttl, (timeReceived - timeSent) * 1000, addr[0], domain_name))
                    elif types == 3:
                        bytes = struct.calcsize("d")
                        timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                        domain_name = gethostbyaddr(addr[0])[0]
                        print(" %d rtt=%.0f ms IP: %s Domain Name: %s" % (ttl, (timeReceived - t) * 1000, addr[0], domain_name))
                    else:
                        print("error")
                except (herror, gaierror) as e:
                    print("Unable to resolve hostname for IP: %s" % addr[0])
                break
            finally:
                mySocket.close()

get_route("google.com")