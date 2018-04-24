import socket
import sys
import threading
import time
import struct

def carry_around_add(a, b):
    ''' This is used for using the carry of the checksum in the actual 16 digits of check sum'''
    c = a + b
    return (c & 0xffff) + (c >> 16)


def check_check_sum(packet):
    ''' This is used for calculating the checksum for the passed packet'''
    packet = packet.decode('utf-8')
    sum = 0
    for i in range(0, len(packet), 2):
        if (i + 1) < len(packet):
            temp_sum = ord(packet[i]) + (ord(packet[i + 1]) << 8)
            sum = carry_around_add(temp_sum, sum)
    return sum & 0xffff

def form_packet(packet, seq, packet_type):
    '''This is for packing the packet with 32 bit sequence number, 16 bit check sum and 16 bit type information'''
    check_sum_value = check_check_sum(packet)
    packet_type = str_binary_to_i(packet_type)
    header_value = struct.pack('!LHH', int(seq), int(check_sum_value), int(packet_type))
    return header_value + packet


def extract_from_file(file, mss):
    '''This is used for extracting file into mss chuncj '''
    current_seq = 0
    packet = ''
    try:
        fileread = open(file, 'rb')
        read_mss_bytes = fileread.read(mss)
        while read_mss_bytes:
            packet_to_send.append(form_packet(read_mss_bytes, current_seq, packet_type_data_16_bits))
            read_mss_bytes = fileread.read(mss)
            current_seq += 1
        # packet_to_send.append(form_packet(packet, current_seq, packet_type_data_16_bits))
        packet = "0".encode('utf-8')
        packet_to_send.append(form_packet(packet, current_seq, fin_packet_type))
        fileread.close()
        global total_packets
        total_packets = len(packet_to_send)
    except (FileNotFoundError, IOError):
        print("Wrong file name or file path")
        exit(1)


# def receive_ACK(client_socket):
def rdt_send(client_socket, window_size, server_name, sever_port):
    '''This takes care of sending all the packets that are present in the packets to send list'''
    global packet_number_tracking
    global window_start
    global timestamp

    window_start = last_ack_received + 1 # initially will be at 0 - first packet
    timestamp = [0.0]*total_packets

    while window_start < total_packets:
        lock.acquire()
        if (packet_number_tracking < window_size) and ((window_start + packet_number_tracking) < total_packets):
            send_packet(packet_to_send[window_start + packet_number_tracking])
            timestamp[window_start + packet_number_tracking] = time.time()
            packet_number_tracking += 1
        if packet_number_tracking > 0 and (time.time() - timestamp[window_start]) > RTO:
            print("Time out, Sequence number: " + str(window_start))
            global retransmissions
            retransmissions+=1
            packet_number_tracking = 0
        lock.release()



def send_packet(packet):
    global client_socket
    client_socket.sendto(packet, (server_name, server_port))

def decapsulate(packet):
    """ https://docs.python.org/2/library/struct.html """
    tcp_headers = struct.unpack('!LHH', packet[0:8]) # the tcp header information that we are passing are nine bytes - seq num, checksum and EOF message
    sequence_number = tcp_headers[0]
    zeroes = tcp_headers[1]
    packet_type = tcp_headers[2]
    return sequence_number, zeroes, packet_type

def str_binary_to_i(str):
    return int(str, 2)

def receive_ACK(client_socket):
    '''This takes care of receiving the acknowledgements from the server for the sent paclets.
    This runs in parallel thread to the main thread, that runs the sending packets'''
    global packet_number_tracking, last_ack_received
    global window_start
    while window_start < total_packets:
        if packet_number_tracking > 0:
            data = client_socket.recv(2048)
            lock.acquire()
            ack_number, zeroes_received, packet_type = decapsulate(data)
            if not zeroes_received == str_binary_to_i(zeros) or not packet_type == str_binary_to_i(packet_type_ack_16_bits):
                print("Invalid Acknowledgement, Sequence number = ", window_start)
                packet_number_tracking = 0

            elif ack_number == window_start:
                packet_number_tracking -=1
                last_ack_received = window_start
                window_start += 1
            else:
                packet_number_tracking = 0
            lock.release()

if __name__ == "__main__":
    '''The main function where all the configurations happens'''
    client_host = socket.gethostname()
    client_ip = socket.gethostbyname(client_host)
    print("received host",client_ip)
    client_port = 60000
    packet_to_send = []
    last_ack_received = -1
    packet_number_tracking = 0
    window_start = 0
    timestamp = []
    lock = threading.Lock()
    total_packets = 0
    packet_type_data_16_bits = "0101010101010101"  # the bits that conforms if its a data packet
    fin_packet_type = "1111111111111111"  # the bits that confirm if its a fin packet
    packet_type_ack_16_bits = "1010101010101010"  # the bits that confirm if its a ack packet
    zeros = "0000000000000000"  # the bits that confirm if its a ack packet
    retransmissions = 0

    RTO = 0.05 # value in seconds - this is the retransmission timeout
    if len(sys.argv) == 6 and sys.argv[1] and sys.argv[2] and sys.argv[1] and sys.argv[3] and sys.argv[4] and sys.argv[5]:
        ''' we read the command line arguments here. If not present in the expected format we raise an exception'''
        server_name = sys.argv[1]
        server_port = int(sys.argv[2])
        file = sys.argv[3]
        n = int(sys.argv[4])
        mss = int(sys.argv[5])

    else:
        raise ValueError("Please enter valid arguments in the order: server host name, server port, download file name, window size and MSS")
    print("Server name: " + str(server_name) + " and port " + str(server_port))
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.bind(('0.0.0.0', client_port))  # we are binding with 0.0.0.0, which is a wildchar IP used for accepting any incoming requests
    print("client running on IP " + str(client_ip) + " and port " + str(client_port))
    extract_from_file(file, mss)
    print("Total Packets present : "+str(total_packets))
    t = threading.Thread(target= receive_ACK, args= (client_socket,))
    t.start()
    start_time = time.time()
    rdt_send(client_socket, n, server_name, server_port)
    t.join()
    end_time = time.time()
    time_taken = end_time - start_time
    print("Time for sending and receiving Acknowledgements", str(time_taken))
    print("Retransmissions", str(retransmissions))
    client_socket.close()