import socket, random, sys
import json

def dnsquery(transaction_id, domain_name):
	# transaction_id = random.randint(0, 65535)
	ID = transaction_id #.to_bytes(2, byteorder='big')
	QR = '0'
	OPCODE = '0000'
	AA = '0'
	TC = '0'
	RD = '0'  #### recursive is set
	RA = '0'
	Z = '000'
	RCODE = '0000'
	flags = int(QR+OPCODE+AA+TC+RD, 2).to_bytes(1, byteorder='big')+int(RA+Z+RCODE, 2).to_bytes(1, byteorder='big')

	QDCOUNT = b'\x00\x01'  ### ASSUMPTION - only 1 question at a time

	### ANSWER COUNT
	ans_count = 0
	ANCOUNT = ans_count.to_bytes(2, byteorder='big')
	#print('ANCOUNT', ANCOUNT)
	# Nameserver Count
	ns_count = 0
	NSCOUNT = ns_count.to_bytes(2, byteorder='big')
	#print('NSCOUNT', NSCOUNT)
	# Additonal Count
	ar_count = 0
	ARCOUNT = ar_count.to_bytes(2, byteorder='big')

	header = ID+flags+QDCOUNT+ANCOUNT+NSCOUNT+ARCOUNT
	print("Response Header", header)

	######################### Response Question #################################
	print(domain_name)
	domain_parts = domain_name.split(".")
	question = b''
	for part in domain_parts:
		question += bytes([len(part)])
		question += bytes(part, 'utf-8')
	question += b'\x00'
	question += b'\x00\x01' ## Question Type
	question += b'\x00\x01' ## Question Class

	print("question", question)

	return header+question


def sendtoserver(ip_address, port, data, tcp_enabled):
	if tcp_enabled:
		sk = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		sk.connect((ip_address, port))
		sk.send(data)
		response_data = sk.recv(1024)
		print(response_data)
	else:
		sk = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
		# Simply set up a target address and port ...
		addr = (ip_address, port)
		# ... and send data out to it!
		sk.sendto(data,addr)
		response_data = sk.recv(512)
	sk.close()
	return response_data

def parseresponse(data):
    rec_lst = []
    header_length = 12
    position = header_length
    question_len = data[position]
    domain_parts = []
    while question_len!=0:
        domain_parts.append(data[position+1:position+question_len+1])
        position += question_len + 1
        question_len = data[position]
        end_position = position
    domain_name = str(b'.'.join(domain_parts), encoding='UTF-8') 
    rec_lst.append(domain_name)
    ans_count = int.from_bytes(data[7:8], byteorder='big')
    rec_start = end_position+5
    for i in range(ans_count):
        ttl = int.from_bytes(data[rec_start+6:rec_start+10],byteorder='big')
        ip1 = data[rec_start+12]
        ip2 = data[rec_start+13]
        ip3 = data[rec_start+14]
        ip4 = data[rec_start+15]
        ip_str = '{ttl:'+str(ttl)+', ip:'+str(ip1)+'.'+str(ip2)+'.'+str(ip3)+'.'+str(ip4)+'}'
        rec_lst.append(ip_str);
        rec_start = rec_start+16
    return rec_lst
def json_response(data):
    rec_lst = []
    header_length = 12
    position = header_length
    question_len = data[position]
    domain_parts = []
    while question_len!=0:
        domain_parts.append(data[position+1:position+question_len+1])
        position += question_len + 1
        question_len = data[position]
        end_position = position
    domain_name = str(b'.'.join(domain_parts), encoding='UTF-8')
    rec_lst.append(domain_name)
    res = "{ \"domainname\" : \""+domain_name
    res = res+"\" ,\"a\": ["
    ans_count = int.from_bytes(data[7:8], byteorder='big')
    rec_start = end_position+5
    for i in range(ans_count):
        ttl = int.from_bytes(data[rec_start+6:rec_start+10],byteorder='big')
        ip1 = data[rec_start+12]
        ip2 = data[rec_start+13]
        ip3 = data[rec_start+14]
        ip4 = data[rec_start+15]
        res = res+"{\"ttl\":"+str(ttl)+",\"value\":\""+str(ip1)+'.'+str(ip2)+'.'+str(ip3)+'.'+str(ip4)+'\"},'
        ip_str = '{ttl:'+str(ttl)+', ip:'+str(ip1)+'.'+str(ip2)+'.'+str(ip3)+'.'+str(ip4)+'},'
        rec_lst.append(ip_str);
        rec_start = rec_start+16
    res = res[:-1]+"] }"
    print(res)
    return json.loads(res)




# args = (sys.argv)
# print(args)

# domain_name = str(args[1])
# print("domain_name", domain_name)
# # sk = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
# data = dnsquery(random.randint(0, 65535), str(domain_name))
# print("DATA", data)
# # Simply set up a target address and port ...
# # addr = ('127.0.0.1',53)
# # ... and send data out to it!
# # sk.sendto(data,addr)
# response_data = sendtoserver('127.0.0.1',53, data)
# print("DATA", response_data)

