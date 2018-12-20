'''
    BGP prefix injection tool
    
*****************************************************************************************
Copyright (c) 2018 Jorge Borreicho
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*****************************************************************************************
'''
 
import socket
import sys
import time
from datetime import datetime
import struct
import threading
import http.server
import socketserver
import json


def KeepAliveThread(conn, interval):
     
    #infinite loop so that function do not terminate and thread do not end.
    while True:
        time.sleep(interval)
        KeepAliveBGP(conn)

def ReceiveThread(conn):
     
    #infinite loop so that function do not terminate and thread do not end.
    while True:
        
        #Receiving from client
        r = conn.recv(1500)
        while True:
            start_ptr = r.find(b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff') + 16
            end_ptr = r[16:].find(b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff') + 16
            if start_ptr >= end_ptr:#a single message was sent in the BGP packet OR it is the last message of the BGP packet
                DecodeBGP(r[start_ptr:])
                break        
            else:#more messages left to decode
                DecodeBGP(r[start_ptr:end_ptr])
                r = r[end_ptr:]
            
def DecodeBGP(msg):
    
    msg_length, msg_type = struct.unpack('!HB',msg[0:3])
    if msg_type == 4:
        #print(timestamp + " - " + "Received KEEPALIVE") #uncomment to debug
        pass
    elif msg_type == 2:
        timestamp = str(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        print(timestamp + " - " + "Received UPDATE")

        withdrawn_routes_length = struct.unpack('!H',msg[3:5])[0]
        withdrawn_routes = msg[5:5+ withdrawn_routes_length]
        total_path_attributes_length = struct.unpack('!H',msg[5 + withdrawn_routes_length: 7 + withdrawn_routes_length])[0]
        path_attributes = msg[3 + 2 + withdrawn_routes_length + 2 : 3 + 2 + withdrawn_routes_length + 2 + total_path_attributes_length]
        nlri = msg[3 + 2 + withdrawn_routes_length + 2 + total_path_attributes_length:]
        
        attr = DecodePathAttribute(path_attributes)

        for r in DecodeIPv4Prefix(withdrawn_routes):
            del(rib[r])
        for r in DecodeIPv4Prefix(nlri):
            rib[r] = attr
        
        #uncomment to debug
        #print()
        #print(rib)
        #print()
        
    elif msg_type == 1:
        version, remote_as, holdtime, i1, i2, i3, i4, opt_length = struct.unpack('!BHHBBBBB',msg[3:13])
        timestamp = str(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        print(timestamp + " - " + "Received OPEN")
        print()
        print("--> Version:" + str(version) + ", Remote AS: " + str(remote_as) + ", Hold Time:" + str(holdtime) + ", Remote ID: " + str(i1) + "." + str(i2) + "." + str(i3) + "." + str(i4))
        print()
    elif msg_type == 3:
        timestamp = str(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        print(timestamp + " - " + "Received NOTIFICATION")
            

def OpenBGP(conn):
    
    #Build the BGP Message
    bgp_version = b'\x04'
    bgp_as = struct.pack('!H',65001)
    bgp_hold_time = struct.pack('!H',30)
    bgp_identifier = struct.pack('!BBBB',10,10,1,1) 

    bgp_opt_lenght = struct.pack('!B',0)
    
    bgp_message = bgp_version + bgp_as + bgp_hold_time + bgp_identifier + bgp_opt_lenght
    
    #Build the BGP Header
    total_length = len(bgp_message) + 16 + 2 + 1;
    bgp_marker = b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
    bgp_length = struct.pack('!H', total_length)
    bgp_type = b'\x01'
    bgp_header = bgp_marker + bgp_length + bgp_type
    
    bgp_packet = bgp_header + bgp_message
    
    
    conn.send(bgp_packet)
    return 0
    
def KeepAliveBGP(conn):
    
    #Build the BGP Header
    total_length = 16 + 2 + 1;
    bgp_marker = b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
    bgp_length = struct.pack('!H', total_length)
    bgp_type = b'\x04'
    bgp_header = bgp_marker + bgp_length + bgp_type
    
    bgp_packet = bgp_header
    
    
    conn.send(bgp_packet)
    return 0


def EncodeIPv4Prefix(address, netmask):
    
    octet = address.split('.')
    length = struct.pack('!B',int(netmask))

    if int(netmask) <= 8:
        prefix = struct.pack('!B',int(octet[0]))
    elif int(netmask) <= 16:
        prefix = struct.pack('!BB',int(octet[0]),int(octet[1]))
    elif int(netmask) <= 24:
        prefix = struct.pack('!BBB',int(octet[0]),int(octet[1]),int(octet[2]))
    else:
        prefix = struct.pack('!BBBB',int(octet[0]),int(octet[1]),int(octet[2]),int(octet[3]))

    return length+prefix

def DecodeIPv4Prefix(bytes):
    ptr = 0
    prefixes = []
    while ptr < len(bytes):
        o1 = 0
        o2 = 0
        o3 = 0 
        o4 = 0
        netmask = struct.unpack('!B',bytes[ptr:ptr+1])[0]
        if netmask <= 8:
            o1 = struct.unpack('!B',bytes[ptr+1:ptr+2])[0]
            ptr = ptr + 2
        elif netmask <= 16:
            o1, o2 = struct.unpack('!BB',bytes[ptr+1:ptr+3])
            ptr = ptr + 3
        elif netmask <= 24:
            o1, o2, o3 = struct.unpack('!BBB',bytes[ptr+1:ptr+4])
            ptr = ptr + 4
        else:
            o1, o2, o3, o4 = struct.unpack('!BBBB',bytes[ptr+1:ptr+5])
            ptr = ptr + 5             
            
        prefixes.append(str(o1) + "." + str(o2) + "." + str(o3) + "." + str(o4) + "/" + str(netmask))
    return prefixes
    
def EncodePathAttribute(type, value):

   
    path_attributes = {"origin": [b'\x40', 1, 1], "as-path": [b'\x40', 2, 4], "next-hop": [b'\x40', 3, 4], "med": [b'\x80', 4, 4], "local_pref": [b'\x40', 5, 4], "communities": [b'\xc0', 8, 4]}


    attribute_flag = path_attributes[type][0]
    attribute_type_code = struct.pack('!B', int(path_attributes[type][1]))
    attribute_length = struct.pack('!B', int(path_attributes[type][2]))
    if type == "origin":
        attribute_value = struct.pack('!B', 1)
    elif type == "as-path":
        attribute_value = struct.pack('!BBH', 2, 1, value)
    elif type == "next-hop":
        octet = value.split('.')
        attribute_value = struct.pack('!BBBB',int(octet[0]),int(octet[1]),int(octet[2]),int(octet[3]))
    elif type == "med":
        attribute_value = struct.pack('!I', value)
    elif type == "local_pref":
        attribute_value = struct.pack('!I', value)
    elif type == "communities":
        aux = value.split(':')
        attribute_value = struct.pack('!HH', int(aux[0]), int(aux[1]))
    
    return attribute_flag + attribute_type_code + attribute_length + attribute_value  

def DecodePathAttribute(bytes):
    ptr = 0
    path_attributes = dict()
    
    while ptr < len(bytes):
        attribute_flag, attribute_type_code, attribute_length = struct.unpack('!BBB',bytes[ptr:ptr+3])
        if attribute_type_code == 1: #origin
            attribute_value = struct.unpack('!B',bytes[ptr+3:ptr+4])[0]
            if attribute_value == 0:
                path_attributes["origin"] = "IGP"
            elif attribute_value == 1:
                path_attributes["origin"] = "EGP"
            else:
                path_attributes["origin"] = "INCOMPLETE"
        elif attribute_type_code == 2: #as-path  
            as_path = ""
            as_path_type, as_path_length = struct.unpack('!BB',bytes[ptr+3:ptr+5])
            for i in range(as_path_length):
                as_path += str(struct.unpack('!H',bytes[ptr+5+2*i:ptr+7+2*i])[0]) + " "
            path_attributes["as-path"] = as_path.strip() #remove last trailing space    
        elif attribute_type_code == 3: #next-hop
            o1, o2, o3, o4 = struct.unpack('!BBBB',bytes[ptr+3:ptr+7])
            path_attributes["next-hop"] =  str(o1) + "." + str(o2) + "." + str(o3) + "." + str(o4)
        elif attribute_type_code == 4: #med
            path_attributes["med"] = struct.unpack('!I', bytes[ptr+3:ptr+7])[0]
        elif attribute_type_code == 5: #local_pref
            path_attributes["local_pref"] = struct.unpack('!I', bytes[ptr+3:ptr+7])[0]
        elif attribute_type_code == 8: #communities
            communities = ""
            for i in range(attribute_length//4):
                aa = str(struct.unpack('!H',bytes[ptr+3+4*i:ptr+5+4*i])[0])
                nn = str(struct.unpack('!H',bytes[ptr+5+4*i:ptr+7+4*i])[0])
                communities += aa + ":" + nn + " "
            path_attributes["communities"] = communities.strip() #remove last trailing space
            
        ptr = ptr + 3 + attribute_length 
       
    return path_attributes 
    
def UpdateBGP(conn, bgp_mss, withdrawn_routes, nlri):
    
    #Build the BGP Message
    
    #Expired Routes
    #1 - Withdrawn Routes
    
    bgp_withdrawn_routes = b''
    max_length_reached = False
    
    while len(withdrawn_routes) > 0 and not max_length_reached:
        route = withdrawn_routes.pop(0)
        addr, mask = route.split("/")
        bgp_withdrawn_routes += EncodeIPv4Prefix(addr, mask)
        if len(bgp_withdrawn_routes) + 16 + 2 + 1 + 2 + 2 + 100 >= bgp_mss: # + header + withdrawn_routes_length + total_path_attributes_length + 100 bytes margin for attributes
            max_length_reached = True
 
    bgp_withdrawn_routes_length = struct.pack('!H',len(bgp_withdrawn_routes))
    bgp_withdrawn_routes = bgp_withdrawn_routes_length + bgp_withdrawn_routes  
    
    #New Routes
    #2 - Path Attributes
    
    bgp_total_path_attributes = b''
    
    if not max_length_reached:
        bgp_total_path_attributes = EncodePathAttribute("origin", 1) + EncodePathAttribute("as-path", 65001)  + EncodePathAttribute("next-hop", "10.10.1.1") + EncodePathAttribute("med", 20) + EncodePathAttribute("local_pref", 150)
        bgp_total_path_attributes = bgp_total_path_attributes + EncodePathAttribute("communities", "65111:222")
    
    bgp_total_path_attributes_length = struct.pack('!H',len(bgp_total_path_attributes))
    bgp_total_path_attributes = bgp_total_path_attributes_length + bgp_total_path_attributes
    
    #3- Network Layer Reachability Information (NLRI)
    
    bgp_new_routes = b''
    while len(nlri) > 0 and not max_length_reached:
        route = nlri.pop(0)
        addr, mask = route.split("/")
        bgp_new_routes += EncodeIPv4Prefix(addr, mask)
        if len(bgp_withdrawn_routes) + len(bgp_new_routes) + 16 + 2 + 1 + 2 + 2 + 100 >= bgp_mss:# + header + withdrawn_routes_length + total_path_attributes_length + 100 bytes margin for attributes
            max_length_reached = True       
    
    bgp_message = bgp_withdrawn_routes + bgp_total_path_attributes + bgp_new_routes
    
    #Build the BGP Header
    total_length = len(bgp_message) + 16 + 2 + 1;
    bgp_marker = b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
    bgp_length = struct.pack('!H', total_length)
    bgp_type = b'\x02'
    bgp_header = bgp_marker + bgp_length + bgp_type
    
    bgp_packet = bgp_header + bgp_message
    
    conn.send(bgp_packet)
    
    timestamp = str(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    print(timestamp + " - " + "Sent UPDATE.")
    
    if len(withdrawn_routes) > 0 or len(nlri) > 0:#there are still BGP info to be updated that didn't fit this last Update message 
        UpdateBGP(conn, bgp_mss, withdrawn_routes, nlri)
    
    return 0
    
def ip2str(ip_bytes):
    ip_addr = struct.unpack("!BBBB",ip_bytes)
    return str(int(ip_addr[0])) + "." + str(int(ip_addr[1])) + "." + str(int(ip_addr[2])) + "." + str(int(ip_addr[3]))

def str2ip(ip_str):
    s_octet = ip_str.split('.')
    ip_addr = struct.pack('!BBBB',int(s_octet[0]),int(s_octet[1]),int(s_octet[2]),int(s_octet[3]))
    return ip_addr
    
def prefix_generator(start_address, netmask):
    addr = str2ip(start_address)
    i = 0
    while True:
        yield ip2str(struct.pack('!I', struct.unpack('!I', addr)[0] + i * (2 ** (32 - netmask))))
        i += 1

if __name__ == '__main__':
    
    BGP_PEER = '10.10.1.2'   
    BGP_PORT = 179 # BGP port
    BGP_MSS = 4000
    
    CONFIG_FILENAME = "bgp_injector.cfg"
    
    input_file = open(CONFIG_FILENAME, "r")
    
    config = json.loads(input_file.read())
    
    rib = dict()
    timestamp = str(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    print(timestamp + " - " + "Starting BGP... (peer: " + str(BGP_PEER) + ")")
    
    try:
        bgp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bgp_socket.connect((BGP_PEER, BGP_PORT))   
        OpenBGP(bgp_socket)
        
    except TimeoutError:
        timestamp = str(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        print(timestamp + " - " + "Error: Cannot connect to peer.")
        exit()
        
        
    receive_worker = threading.Thread(target=ReceiveThread, args=(bgp_socket,))#wait from BGP msg from peer and process them
    receive_worker.setDaemon(True)
    receive_worker.start()
    
    keep_alive_worker = threading.Thread(target=KeepAliveThread, args=(bgp_socket,10,))#send keep alives every 10s
    keep_alive_worker.setDaemon(True)
    keep_alive_worker.start()
    
    timestamp = str(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    print(timestamp + " - " + "BGP is up.")

    prefixes_to_withdraw = []            
    prefixes_to_advertise = []
    
    prefix_gen = prefix_generator(config["start_address"], config["netmask"])
    
    for i in range(config["number_of_prefixes_to_inject"]):
        prefix = next(prefix_gen)
        prefixes_to_advertise.append(prefix + "/" + str(config["netmask"]))
        
    time.sleep(3)
    UpdateBGP(bgp_socket, BGP_MSS, prefixes_to_withdraw, prefixes_to_advertise)
    
    try:
        while True:
            time.sleep(60)
                  
    except KeyboardInterrupt:
        timestamp = str(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        print(timestamp + " - " + "^C received, shutting down.")
        api_server.socket.close()
        bgp_socket.close()
        exit()
        
        
    
    