import socket, random, sys
import dns_utility as dns_query
import pandas
import matplotlib.pyplot as plt
import random
import math
import time
import numpy as np
import csv
import logging
import datetime
#===================================Input Parameters========================================
args = (sys.argv)
print(args)

# args : localdns ip, local dns port, tcp/udp, iterative/recirsive 0, #requests, 

HOST = '35.237.0.104'
PORT = 53
tcp_enabled = 0
if args[1]=='tcp':
	tcp_enabled = 1
iterative = 0
if args[2]=='itr':
     iterative = 1
numreq = int(args[3])

#print (HOST,PORT,tcp_enabled,iterative,numreq)
logging.basicConfig(filename='client.log',level=logging.DEBUG)
#===============================Dataframe of IP addresses with mutiple keys==================
correctcnt = 0
data = pandas.read_csv('test.csv',sep=',');
cols = ['ID','Start Time','End Time','Response Time']
lst=[]
for i in range(numreq):
    dnameid = random.randint(0,57)
    dname = data.iloc[dnameid]["Domain Name"]
    tid = random.randint(10000, 65535).to_bytes(2, byteorder='big')
    query_data = dns_query.dnsquery(tid, str(dname))
    #print("DATA", query_data)
    ts = time.time()
    st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    logStr = st + " - " + dname
    logging.info(logStr)
    start = time.time()
    response_data = dns_query.sendtoserver(HOST,PORT,query_data, tcp_enabled)
    end = time.time()
    print("DATA", response_data)
    ID = int.from_bytes(response_data[:2], byteorder='big')
    tidf = int.from_bytes(tid, byteorder='big')
    rec_lst = []
    if(str(tidf) == str(ID)):
        rec_lst = dns_query.parseresponse(response_data)
    print(rec_lst)
    ts = time.time()
    st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    logStr = st+" - "+str(rec_lst)
    logging.info(logStr)
    if((str(data.iloc[dnameid]["IP1"]) in rec_lst[1]) and (str(data.iloc[dnameid]["IP2"]) in rec_lst[2])):
        correctcnt = correctcnt+1
    resp_time = end-start
    print("time taken",resp_time) # response time in seconds
    lst.append([i,start,end,resp_time])# request id, start time, end time,responsetime
    timeexp = math.log(random.random()) * 1 * (-1); # generating requests following expoenential distribution lambda = 1 sec
    #print dnameid, dname,time
    time.sleep(timeexp)
reslist = pandas.DataFrame(lst,columns=cols);    
#print(reslist)
ts = time.time()
st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
logStr = st + " - Total Queries sent:"+str(numreq)+" and received "+str(correctcnt)+" correctly"
logging.info(logStr)
#for i in range(numreq):
#    print(lst[i])

reslist.to_csv("output.csv", index=False, header=False)
    



#=================================Analysis and Graphs of Response Time =========================
    
