import socket, random, sys
import dns_utility as dns_query

args = (sys.argv)
print(args)

domain_name = str(args[1])
tcp_enabled = 0
if args[2]=='tcp':
	tcp_enabled = 1

print("domain_name", domain_name)
# sk = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
data = dns_query.dnsquery(random.randint(0, 65535).to_bytes(2, byteorder='big'), str(domain_name))
print("DATA", data)
# Simply set up a target address and port ...
# addr = ('127.0.0.1',53)
# ... and send data out to it!
# sk.sendto(data,addr)
response_data = dns_query.sendtoserver('127.0.0.1',53, data, tcp_enabled)
print("DATA", response_data)

