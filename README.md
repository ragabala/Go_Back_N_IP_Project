# GO Back N Project

This is a Simple file transfer protocol execution that runs on UDP using the Go Back N protocol


## Environment for execution:

**use python 3**

**We tested the program on : python 'v3.6.3'**


## For execution do the following:

Run the server first on any of the machines of choice

python Server.py <server_port_num> <file_name_to_be_downloaded_under> <probability_packet_loss>

example:

**python Server.py 7735 /Downloads/download.txt 0.05**


Then run the client in any other sytem or the same machine

If using the same machine, give the server ip as localhost

python Client.py <server_host_name> <server_port> <file_name_to_be_uploaded> <window_size> <mss>


example:

**python Client.py 192.168.1.8 7735 ./Files/doc.txt 64 500**

for running client and server on the same machine

**python Client.py localhost 7735 ./Files/doc.txt 64 500**