import socket, sys
import dns_utility as dns_query
from lru import LRU
import logging
import time
import datetime


'''
Things required to be done by local dns:
1. Implement a LRU cache
2. Implement connections over tcp/udp
3. Take client query and check its cache
4. If entry is found in cache check its ttl, if valid reply back with the answer
5. If ttl has expired/entry not found in cache, check iterative/recursive flag and connect to the root server.
6. Input parameters: rootIp, rootPort, tcp/udp
'''


args = (sys.argv)
print(args)

tcp_enabled = 0
if args[1]=='tcp':
	tcp_enabled = 1

HOST = ''
PORT = 53
logging.basicConfig(filename='local_server.log',level=logging.DEBUG)
cache_counter = 0

lru_dict = LRU(5) 

if tcp_enabled:
    sk = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sk.bind((HOST, PORT))
    sk.listen(5)  ### queue up 5 requests
else:
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sk.bind((HOST, PORT))

#=========================Server logic with LRU Cache=====================================

# A simple atoi() function 
def myAtoi(string): 
    res = 0
    # initialize sign as positive 
    sign = 1
    i = 0
  
    # if number is negative then update sign 
    if string[0] == '-': 
        sign = -1
        i+=1
  
    # Iterate through all characters of input string and update result 
    for j in range(i,len(string)): 
        res = res*10 + (ord(string[j]) - ord('0')) 
  
    return sign*res 


def createresponse(data):

	##################### EXTRACT QUESTION DETAILS ##############################
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

	##################### Extract response from Cache ###############################
    #cache_query = { "domainname" : domain_name}
    dns_records = {}
    cache_query = domain_name
    #print(cache_query)
    recFlag = str(int(data[2])&1)
    RDFlag = myAtoi(recFlag)
    #print("RecFlag: ")
    #print(recFlag)
    #print("\n")
    if(lru_dict.has_key(cache_query)):
        #print("Hellooooooo......cache hit")
        global cache_counter
        cache_counter+=1
        ts = time.time()
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        logStr = st + " - Cache Hit; Cache Counter : " + str(cache_counter)
        logging.info(logStr)
        dns_records = lru_dict[cache_query];
        print(dns_records,cache_query)
        ######################### Response Header #####################################
	   ###Transaction ID
        ID = data[:2]
        RD = str(int(data[2])&1)
	   ### FLAGS
        QR = '1'
        OPCODE = '0000'
        AA = '1'
        TC = '0'
	   # RD = '0'
        RA = '1'
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
        print("response_body", response_body)
        return response_header + response_question + response_body
    elif RDFlag==1:
        #print("I'm in recFlag section....")
        ts = time.time()
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        logStr = st + " - Rec:Sending to Root Server..."
        logging.info(logStr)
        response1 = dns_query.sendtoserver('35.196.214.148',53,data, tcp_enabled)
        ts = time.time()
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        logStr = st + " - Rec:Receive from Root Server..." + str(response1)
        logging.info(logStr)
        jsonres = dns_query.json_response(response1)
        lru_dict[cache_query] = jsonres
        print(lru_dict[cache_query])
        return response1
    elif RDFlag==0: 
        #creating response for iterative
        #print("Here in not RD state \n\n")
        ts = time.time()
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        logStr = st + " - Itr:Sending to Root Server..." 
        logging.info(logStr)
        rootResponse = dns_query.sendtoserver('35.196.214.148', 53, data, tcp_enabled)
        responseList = []
        responseList = dns_query.parseresponse(rootResponse)

        itrIp = responseList[1]
        authIp = itrIp[13:-1]
        #print(authIp)
        ts = time.time()
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        logStr = st + " - Itr:Receive from Root, Auth IP : " + authIp
        log.info(logStr)
        response1 = dns_query.sendtoserver(authIp, 53, data, tcp_enabled)
        ts = time.time()
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        logStr = st + " - Itr:Receive from Auth Server..." + str(response1)
        logging.info(logStr)
        jsonres = dns_query.json_response(response1)
        lru_dict[cache_query] = jsonres
        print(lru_dict[cache_query])
        return response1






#===============================Server Logic=======================================

while True:
    if tcp_enabled:
        connect, client_addr = sk.accept()
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



