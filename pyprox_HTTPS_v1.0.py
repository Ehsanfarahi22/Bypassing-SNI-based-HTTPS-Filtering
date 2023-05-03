import pip._vendor.requests as requests
import json
import socket
import threading
import time
import random
import re
from logging.handlers import TimedRotatingFileHandler

listen_PORT = 2500
cf_DoH_ip="1.0.0."+str(random.randint(0,255))      # 1.0.0.0  to  1.0.0.255

my_socket_timeout = 21 # default for google is ~21 sec , recommend 60 sec unless you have low ram and need close soon
first_time_sleep = 0.1 # speed control , avoid server crash if huge number of users flooding
accept_time_sleep = 0.01 # avoid server crash on flooding request -> max 100 sockets per second



class ThreadedServer(object):
    def __init__(self, host, port):
        self.host = host
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))

    def multi_listen(self):
        thread_web = threading.Thread(target = self.listen , args = (self.sock,) )
        thread_web.start()

    def listen(self , sock):
        sock.listen(128)  # up to 128 concurrent unaccepted socket queued , the more is refused untill accepting those.
        while True:
            client_sock , client_addr = sock.accept()                    
            client_sock.settimeout(my_socket_timeout)

            time.sleep(accept_time_sleep)   # avoid server crash on flooding request
            thread_up = threading.Thread(target = self.my_upstream , args =(client_sock,) )
            thread_up.daemon = True   #avoid memory leak by telling os its belong to main program , its not a separate program , so gc collect it when thread finish
            thread_up.start()
            

    def my_upstream(self, client_sock):
        first_flag = True
        backend_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        backend_sock.settimeout(my_socket_timeout)
        backend_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)   #force localhost kernel to send TCP packet immediately (idea: @free_the_internet)
        
        while True:
            try:
                if( first_flag == True ):                        
                    first_flag = False

                    time.sleep(first_time_sleep)   # speed control + waiting for packet to fully recieve
                    data = client_sock.recv(16384)                   

                    x = re.search("(www\.)?[-a-zA-Z0-9._]{2,256}\.[a-zA-Z0-9]{2,6}", str(data)) #find url in ClientHello
                    url=x.group(0)

                    position=str(data).find(x.group(0))  #remove unwanted characters like \x06 or \r from url
                    lastchar=str(data)[position-1:position]
                    if lastchar=='\\':                       
                     if url.startswith('x'):
                       url=url[3:]
                     if url.startswith('r'):
                       url=url[1:]
                    
                    remote_ip = dns(url)   #connect to cloudflare dns and get ip

                    url_index=data.find(url.encode())     #calculate url index in data packet
                    fragment_index = url_index + len(url.encode())//2
                    
                    if data and remote_ip != False:                                                                    
                        backend_sock.connect((remote_ip,443))
                        thread_down = threading.Thread(target = self.my_downstream , args = (backend_sock , client_sock) )
                        thread_down.daemon = True
                        thread_down.start()
                        send_data_in_fragment(data,backend_sock,fragment_index)

                    else:                   
                        raise Exception('cli syn close')

                else:
                    data = client_sock.recv(16384)
                    if data:
                        backend_sock.sendall(data)                        
                    else:
                        raise Exception('cli pipe close')
                    
            except Exception as e:
                #print('upstream : '+ repr(e) )
                time.sleep(2) # wait two second for another thread to flush
                client_sock.close()
                backend_sock.close()
                return False



            
    def my_downstream(self, backend_sock , client_sock):
        first_flag = True
        while True:
            try:
                if( first_flag == True ):
                    first_flag = False            
                    data = backend_sock.recv(16384)
                    if data:
                        client_sock.sendall(data)
                    else:
                        raise Exception('backend pipe close at first')
                    
                else:
                    data = backend_sock.recv(4096)
                    if data:
                        client_sock.sendall(data)
                    else:
                        raise Exception('backend pipe close')
            
            except Exception as e:
                #print('downstream ' +' : '+ repr(e)) 
                time.sleep(2)
                backend_sock.close()
                client_sock.close()
                return False


def send_data_in_fragment(data , sock , fragment_index):     #just a single chup at right index!
    fragment_data = data[:fragment_index]
    sock.sendall(fragment_data)
    time.sleep(0.1)
    fragment_data = data[fragment_index:]
    sock.sendall(fragment_data) 


urls=[]
ips=[]  
def dns(url):
  try:
    return ips[urls.index(url)]    #return ip if cached before
  except ValueError:
    if url.endswith("youtube.com") or url.endswith("ytimg.com") or url.endswith("googleapis.com") or url.endswith("googlevideos.com") :
      ip =socket.gethostbyname('google.com')     # working google ip based on client's ISP
      urls.append(url)
      ips.append(ip)
      print("DoH success:",url,ip)
      return ip
    elif url=="one.one.one.one":
      return cf_DoH_ip 
    
    headers = {
    'Accept': 'application/dns-json',
    'Connection': 'keep-alive',
    'Host': 'one.one.one.one',
    'Upgrade-Insecure-Requests': '1',
    }

    params = {
    'name': url,
    'type': 'A',
    }

    try:
      response = requests.get('https://one.one.one.one/dns-query', params=params, headers=headers)
      data=response.text
      js=json.loads(data)
      if "Answer" in js:
        for j in range (len(js["Answer"])):
          try:
            ip=js["Answer"][j]['data']
            socket.inet_aton(ip)   #validate ip
            urls.append(url)
            ips.append(ip)
            print("DoH success:",url,ip)
            return ip
          except socket.error:
            pass
      print("DoH couldn't find:",url)
      urls.append(url)
      ips.append(False)
      return False
    except requests.exceptions.RequestException as e:
      ip =socket.gethostbyname(url)     #failed to connect Cloudflare DoH (CF ips possibly filtered)
      urls.append(url)                  #use client's default DNS
      ips.append(ip)
      print("DoH connection failed",url,ip)
      return ip


ThreadedServer('',listen_PORT).multi_listen()
print ("now listening at: 127.0.0.1:"+str(listen_PORT))
