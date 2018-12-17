# DNS_Application

Message Format (DNS RFC): https://www.ietf.org/rfc/rfc1035.txt

a. Environment settings
   1. The environment running the servers should have mongo installed in them. 
   2. We need the following packages as well, which can be easily downloaded using pip
      ```
      pip3 install pymongo
      pip3 install lru-dict
      pip3 install numpy
      ```
   
b. How to run the code
   ```
   DNS Root Server: sudo python3 dns_root_server.py tcp/udp
   DNS Authoritative Server: sudo python3 dns_authoritative_server.py tcp/udp
   DNS Local Server: sudo python3 dns_local_server.py tcp/udp (pip install lru-dict,https://pypi.org/project/lru-dict/)
   DNS Client: python client.py tcp/udp itr/rec <#requests>
   ```

c. How to interpret the results
   1. Client logs - `~/DNS_Application/client.log`
   2. Authoritatve Server logs - `~/DNS_Application/auth_server.log`
   3. Root Server logs - '~/DNS_Application/root_server.log`
   4. Local Server logs - `~/DNS_Application/local_server.log`

d. Any sample input and output files
   1. Input Files:
      `test.csv` contains list of IPs to be uploaded onto the MongoDB
   
   2. Output Files:
      `output.csv` in the Client system contains Response Time for every query
   

