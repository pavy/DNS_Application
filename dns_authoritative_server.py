import socket, sys
import pymongo
import logging
import time, datetime

client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["dns_db"]
dbcol = db["dnsrecord"]

args = (sys.argv)
print(args)

tcp_enabled = 0
if args[1]=='tcp':
	tcp_enabled = 1

HOST = ''
PORT = 53
logging.basicConfig(filename='auth_server.log',level=logging.DEBUG)

if tcp_enabled:
	sk = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	sk.bind((HOST, PORT))
	sk.listen(5)  ### queue up 5 requests
else:
	sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sk.bind((HOST, PORT))

def createresponse(data):
	ts = time.time()
	st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
	logStr = st + " - Received Query from Local Server"
	logging.info(logStr)
	##################### EXTRACT QUESTION DETAILS ###############################
	print("\n\n")
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
	
	question_type = data[position+1:position+3]
	if question_type == b'\x00\x01':
		record_type = 'a'
	elif question_type == b'\x00\x02':
		record_type = 'ns'
	elif question_type == b'\x00\x05':
		record_type = 'cname'
	elif question_type == b'\x00\xff':
		record_type = 'mx'

	##################### Extract response from DB ###############################
	db_query = { "domainname" : domain_name}

	dns_records=dbcol.find_one(db_query)
	print(dns_records)


	######################### Response Header #####################################
	###Transaction ID
	ID = data[:2]

	### FLAGS
	QR = '1'
	OPCODE = '0000'
	AA = '1'
	TC = '0'
	RD = '0'
	RA = '0'
	Z = '000'
	RCODE = '0000'
	flags = int(QR+OPCODE+AA+TC+RD, 2).to_bytes(1, byteorder='big')+int(RA+Z+RCODE, 2).to_bytes(1, byteorder='big')

	### QUESTION COUNT
	#q_count = (data[4] << 8) + data[5]
	#print('q_count',q_count)
	#QDCOUNT = q_count.to_bytes(2, byteorder='big') #b'\x00\x01'
	QDCOUNT = b'\x00\x01'  ### ASSUMPTION - only 1 question at a time
	#print('QDCOUNT',QDCOUNT)

	### ANSWER COUNT
	ans_count = len(dns_records[record_type]) #fetch from DB
	ANCOUNT = ans_count.to_bytes(2, byteorder='big')
	#print('ANCOUNT', ANCOUNT)
	# Nameserver Count
	ns_count = 0
	NSCOUNT = ns_count.to_bytes(2, byteorder='big')
	#print('NSCOUNT', NSCOUNT)
	# Additonal Count
	ar_count = 0
	ARCOUNT = ar_count.to_bytes(2, byteorder='big')

	response_header = ID+flags+QDCOUNT+ANCOUNT+NSCOUNT+ARCOUNT
	print("Response Header", response_header)

	######################### Response Question #################################
	
	response_question = data[header_length:end_position+5]
	print("Response question........", response_question)


	######################### Response Body #################################
	response_body = b''

	for rec in dns_records[record_type]:
		response_body += bytes([192]) + bytes([12])  ## Name - compression applied
		response_body += question_type  ## record type
		response_body += b'\x00\x01'    ## record class
		ttl = int(rec['ttl']).to_bytes(4, byteorder='big') #b'\x00\x00\x00\x04' ## 4 bytes
		response_body += ttl
		response_body += bytes([0])+bytes([4])
		ipv4_addr = b''
		for ip_octet in rec['value'].split("."):
			ipv4_addr += bytes([int(ip_octet)])
		response_body += ipv4_addr
	ts = time.time()
	st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
	logStr = st + " - DNS Resolved; IP Addr:" + str(ipv4_addr) + " sent to Local Server"
	logging.info(logStr)
	# print("response_body", response_body)

	return response_header + response_question + response_body



while True:
	if tcp_enabled:
		connect, client_addr = sk.accept()
		print(client_addr)
		print("\n")
		data = (connect.recv(1024)).strip()
		print('DATA',data)
		res = createresponse(data)
		print('RESPONSE DATA', res)
		connect.send(res)
		connect.close()
	else:
		data, client_addr = sk.recvfrom(512)
		print(data)
		res = createresponse(data)
		print('DATA', res)
		sk.sendto(res, client_addr)
sk.close()
