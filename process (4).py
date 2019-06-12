import socket
import time
import sys
import threading
import os
import copy
import gnupg
import select
import math


class choices:
    def __init__(self):
        sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.initial_value = math.inf
        self.rcv_buf = 4096
        self.nickname='' 
        self.self_id = ''
        self.destination_id = ''
        self.neighbor_nodes = {}
        self.routing_table = {}
        self.active_hist = {}
        self.adjacent_links = {}
        self.connxn = {}

    def private_chat(self,recvSock,destId,message2Send):
            tempVar = self.self_id.split(":")
            selfId = tempVar[0]
            destinationIP = self.strIptoint(destId)
            destinationPort = main.destination_port()
            sourcePort = temp[1]
            nickname = self.nickname
            timeLog = time.strftime('%H:%M:%S', time.localtime(time.time()))
            message = '['+str(timeLog)+'] ' + "@" + selfId + ": " + str(message2Send)
            sendDictionary = { 'type': 0x02, 'message': message, 'senderID': selfId,\
                               'receiverID': destinationIP,'sourcePort': sourcePort, 'destinationPort':destinationPort,'nickname':nickname}
            self.list_users(receivedSocket,sendDictionary)

    def group_chat(self,connxn,sock):
        message=input("Input message to send: ")
        tempVar = self.self_id.split(":")
        selfId=tempVar[0]
        timeLog = time.strftime('%H:%M:%S', time.localtime(time.time()))
        message = '['+str(timeLog)+'] ' + "@" + selfId+ ": " + str(message)
        sendDictionary = { 'type': 0x02, 'message': message, 'senderID': selfId,'time':timeLog}
        package = json.dumps(sendDictionary) 
        if not os.path.isfile("first.asc"):
            msg_Enc.generate_certificates()
            try:
                 encryptPackage= msg_Enc.encrypt(package)
            except pgpy.errors.PGPError:
                print('ENVRYPTION FAILED')
            for socket in connxn:
                for chunk in self.chunks(encryptPackage, 100):
                    try:
                       sock.sendto(chunk, socket)
                    except:
                        print("Unable to Send Data")

    def file_transfer(self,receivedSocket,destination,fileName):
        tempVar = self.self_id.split(":")
        selfId=tempVar[0]
        destinationIP = self.ip2int(destination)
        destinationPort = 9999
        sourcePort = tempVar[1]
        nickname = self.nickname
        timeLog = time.strftime('%H:%M:%S', time.localtime(time.time()))
        print(self.self_id)
        textInside="This is message in the file"
        open('{}.txt'.format(fileName), 'wb').write(bytes(textInside,'utf-8'))
        file=open(fileName+".txt", 'r')
        data=file.read(1024)
        if data:
            sendDictionary = { 'type': 0x03, 'file': data, 'senderID': selfId,\
            'receiverID': destinationIP,'fileName': fileName,'sourcePort': sourcePort, 'destinationPort':destinationPort,'time':timeLog,'nickname':nickname}
            self.list_users(receivedSocket,sendDictionary)

    def view_routing_table(self,routingTable):
        timeLog = time.strftime('%H:%M:%S', time.localtime(time.time()))
        print (str(timeLog), "Routing Table for", (self.self_id), "is:")
        print("*******************************************************")
        print(" | "+ "--Time--"+ " | "+ "--Dest--" + "     | " + "---Link--- " + "      | " + "--Cost--" + " | ")
        for n in self.routingTable:
            link = self.routingTable[n]['link']
            
            print (" | " + str(timeLog) +  " |" + str(n) +  "| " + link + "   |"+ str(self.routingTable[n]['cost']) + "         | ")
            print ("***************************************************")

        
    def list_users(self,socket,payLoad):
        package = json.dumps(payLoad)
        if not os.path.isfile("first.asc"):
            msg_Enc.generate_certificates()
            try:
                 encryptPackage= msg_Enc.encrypt(package)
            except pgpy.errors.PGPError:
                print('Encryption failed!')
            for i in self.neighbor_nodes:
                tempVar = i.split(":")
                for chunk in self.seg(encryptPackage, 100):
                    try:
                       socket.sendto(chunk, (tempVar[0], int(tempVar[1])))    
                    except:
                        print("Sorry, unable to send data")        


    def updatingneighbor(self,receivedScoket):
        for i in copy.deepcopy(self.neighbor_nodes):
            tempVar = i.split(":")
            address = (tempVar[0],int(tempVar[1]))

            sendDictionary = {'type':'update','routing_table':{},}
            rt_copy = copy.deepcopy(self.routing_table)
            for n in rt_copy:
                sendDictionary['routing_table'][n] = rt_copy[n]
                if n != i and rt_copy[n]['link'] == i:
                    sendDictionary['routing_table'][n]['cost'] = self.initial_value
            messag=json.dumps(sendDictionary).encode('utf-8')
            receivedSocket.sendto(message, address)
    def close(self):
        sys.exit("(%s) bye-bye,offline ON." % self.self_id)

    def n_timer(self,receivedSocket,time_out=10):
        for i in copy.deepcopy(self.neighbor_nodes):
            if i in self.active_hist:
                t_threshold = (3 * time_out)
                if ((int(time.time()) - self.active_hist[i]) > t_threshold):
                    if self.routing_table[i]['cost'] != self.initial_value:
                        self.routing_table[i]['cost'] = self.initial_value
                        self.routing_table[i]['link'] = "n/a"
                        self.routing_table[i]['i'] = "n/a"
                        del self.neighbor_nodes[i]
                        # reinitialize table
                        for n in self.routing_table:
                            if n in self.neighbors:
                                self.routing_table[n]['cost'] = self.adjacent_links[n]
                                self.routing_table[n]['link'] = n
                                self.routing_table[n]['nickname'] = self.nickname
                            else:
                                self.routing_table[n]['cost'] = self.initial_value
                                self.routing_table[n]['link'] = "n/a"
                                self.routing_table[n]['nickname'] = "n/a"

                        sendDictionary = { 'type': 'close', 'target': i }
                        for i in self.neighbor_nodes:
                            tempVar = i.split(':')
                            receivedSocket.sendto(json.dumps(sendDictionary), (tempVar[0], int(tempVar[1])))

                    else:
                        self.updatingneighbor(receivedSocket)

        try:
            t = threading.Timer(30, self.n_timer, [time_out])
            t.setDaemon(True)
            t.start()
        except:
            pass
    def parseing_header():
        Anita, [12.06.19 19:05]
"""packet header"""
header_len = 20

class packet_header:
   udp_data = bytes()
   dest = bytes()
   source = bytes()
   version = 0
   packet_type = 0
   flags = 0
   session = 0
   seq = 0

   #definite variables to be called 
    def init(self,udp_data,dest,source,version,packet_type,flags,session,sequence):
        self.udp_data = data
        self.dest = dest 
        self.source = source 
        self.version = version
        self.packet_type = packet_type
        self.flags = flags
        self.session = session 
        self.sequence = sequence

    #message
    def packet(self,udp_data):
        #packet with header

        if (len(udp_data) >= header_len):
            byte0 = int.from_bytes(udp_data[0:1], byteorder = "big")
            dest = udp_data[9:17]
            source = udp_data[1:9]
            sequence = int.from_bytes(udp_data[18:20], byteorder = 'big')
            version = ((byte0) >> 6)
            packet_type = ((byte0) >> 3)
            flags = byte0
            session = int.from_bytes(udp_data[17:18], byteorder='big')
            length = int.from_bytes(udp_data[9:10], byteorder='big')
            payload = data[20:]
            
            return packet_header(packet_type, flags, source, dest, session, seq, payload)

         else:

            raise Exception("cannot parse packet, as it is too short:", len(data))
    #encoding
    def encode(self):
        byte = bytearray()
        byte.append((self.version << 6) | (self.packet_type << 3)| self.flags)
        byte.extend(self.udp_data)
        byte.extend(self.session.to_bytes(1, byteorder = 'big'))
        byte.extend(self.source)
        byte.extend(self.destination)
        byte.extend(self.sequence.to_bytes(2, byteorder = 'big'))

        return bytes(b)

    def ack(self):
        return packet_header(self.packet_type, 0x04, self.source, self.destination,self.session,self.sequence,bytes())
 
    def  str(self):
        return "version: " + hex(self.version) + "\n" + \
            "type: " + hex(self.packet_type) + "\n" + \
                "flags: " + hex(self.flags) + "\n" + \
                    + "session: " + hex(self.session) + "\n" + \
                        + "sequence: " + hex(self.sequence) + "\n" + \
                            "source: " + print_hex("self.source") + "\n" + \
                                + "destination: " + print_hex(self.destination) + "\n" + \
                                    + "udp_data: " + print_hex(self.udp_data) + "\n"


class segmentation:
    session = 0
    packet_type = 0
    source = bytes()
    destination = bytes()
    udp_data = bytes()

    def init(self, packet_type, source, destination, session, udp_data):
        self.session = session
        self.packet_type = packet_type
        self.source = source
        self.destination = destination
        self.udp_data = udp_data
    
    def init_assemble(self, packets):
        
        first_packets = self.find_packet_with_flags(self, 0x03, packets)
        second_packets = self.find_packet_with_flags(self, 0x01, packets)
        last_packets = self.find_packet_with_flags(self, 0x02, packets)
        if (first_packets != None):
            return segmentation(first_packets.packet_type, first_packets.source, first_packets.destination,
                                    first_packets.session, first_packets.udp_data)
        

        elif (second_packets != None and last_packets != None):
            next_packet = second_packets
            total_seq = last_packet.seq
            cur_seq = next_packet.seq
            packetdata = bytearray()

            while (cur_seq < total_seq and next_packet != None):
                cur_seq = next_packet.seq
                packetdata.extend(next_packet.udp_data)
                next_packet = self.find_next_packet(self, cur_seq, packets)


        if (cur_seq == total_seq)
                return segmentation(second_packets.packet_type, second_packets.source, second_packets.destination,
                                        second_packets.session, bytes(packetdata))
            else:
                raise Exception("not all packets are available!")
        else:
            raise Exception("not all packets are available!")
    
    def handlingMessage(self,receivedSocket ,rcv_data, tuple_addr):
        global self_id
        table_changed = False
        t_now = int(time.time())
        address = str(tuple_addr[0]) + ":" + str(tuple_addr[1])

        if rcv_data['type'] == 'update':
                self.active_hist[address] = t_now

                # update our existing neighbor table for this address
                if address in neighbor_nodes:
                    neighbor_nodes[address] = rcv_data['routing_table']

                if address in self.routing_table:
                    if self.routing_table[address]['cost'] == self. initial_value:
                        self.routing_table[address]['cost'] = self.adjacent_links[address]
                        self.routing_table[address]['link'] = address
                        self.routing_table[address]['nickname'] = self.nickname
                        table_changed = True
                        
                        if address in self.adjacent_links:
                            neighbor_nodes[address] = rcv_data['routing_table']

                elif rcv_data['routing_table'].has_key(self.self_id):
                    self.routing_table[address] = {}
                    self.routing_table[address]['cost'] = rcv_data['routing_table'][self.self_id]['cost']
                    self.routing_table[address]['link'] = address
                    self.routing_table[address]['nickname'] = self.nickname
                    table_changed = True

                    
                    if rcv_data['routing_table'][self.self_id]['link'] == self.self_id:
                        neighbors_nodes[address] = rcv_data['routing_table']
                        self.adjacent_links[address] = rcv_data['routing_table'][self.self_id]['cost']
                else:
                        sys.exit("Sorry, may be error in topology!")

                for n in rcv_data['routing_table']:
                    if n != self.self_id:
                       
                        if n not in self.routing_table:
                            self.routing_table[n] = {
                            'cost': self.INFINITY,
                            'link': "n/a"
                            }
                            table_changed = True

                        for dest in self.routing_table:
                            old_cost = self.routing_table[dest]['cost']
                            if address in neighbor_nodes and dest in neighbor_nodes[address]:
                                new_cost = self.routing_table[address]['cost'] + neighbor_nodes[address][dest]['cost']

                                if new_cost < old_cost:
                                    self.routing_table[dest]['cost'] = new_cost
                                    self.routing_table[dest]['link'] = address
                                    self.table_changed = True

                    if table_changed:
                        self.updatingneighbor(receivedSocket)
                        table_changed = False

        elif rcv_data['type'] == 0x02:
            if rcv_data['sender'] != self.self_id:
                self.active_hist[address] = t_now
                print ('\n' + rcv_data['msg'])
                main1()
            
            elif rcv_data['type'] == 0x03:
                if rcv_data['sender'] != self.self_id:
                    t_log = time.strftime('%H:%M:%S', time.localtime(time.time()))
                    print ('\n You have recieved a file @['+str(t_log)+'] ' + rcv_data['file_Name']+'.txt')
                    with open('{}.txt'.format(rcv_data['file_Name']), 'wb').write(bytes(rcv_data['file'])) as f:
                        f.close()
                    main1() 	###########

            elif rcv_data['type'] == 'close':

                print ("DEBUG: [received CLOSE message from %s]" % str(tuple_addr))
                self.active_hist[address] = t_now
                close_node = rcv_data['target']
                if self.routing_table[close_node]['cost'] != self. initial_value:
                    self.routing_table[close_node]['cost'] = self. initial_value
                    self.routing_table[close_node]['link'] = "n/a"

                    if close_node in neighbor_nodes:
                        del neighbor_nodes[close_node]

                    # reinitialize routing table
                    for n in self.routing_table:
                        if n in neighbor_nodes:
                            self.routing_table[n]['cost'] = self.adjacent_links[n]
                            self.routing_table[n]['link'] = n
                        else:
                            self.routing_table[n]['cost'] = self.initial_value
                            self.routing_table[n]['link'] = "n/a"

                            sendDictionary = { 'type': 'close', 'target': close_node, }
                            self.list_users(receivedSocket, sendDictionary)

                else:
                    self.updatingneighbor(receivedSocket)


    def strIptoint(self,ip_address):
        if ip_address == 'localhost':
            ip_address = '127.0.0.1'
        return [int(x) for x in ip_address.split('.')]
    def seg(self,list1,n): 
        "Yield successive n-sized chunks from lst"
        for i in range(0, len(list1), n):
            yield list1[i:i+n]

        
class start(object):
    def __init__(self,choice):
        self.choice = choice
        self.process()
        self.sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    def process(self):
        if self.choice == 1:
            destId = input("enter the partner address:")
            msg = input("enter the message to yur partner:")
            choices.destination_id = destId
            choices.private_chat(sock,destId,msg)
            return True
        elif self.choice == 2:
            choices.group_chat(sock,connxn)
            return True
        elif self.choice == 3:
            destId = input("enter the partner address:")
            fileName = input("enter the filename:")
            choices.file_transfer(sock,destId,fileName)
            return True
        elif self.choice == 4:
            choices.view_routing_table(choices.routing_table)
            return True
        elif self.choice == 5:
            choices.list_users()        ###########
            return True
        elif self.choice == 6:
            return False
        else:
            print("Enter your choice in the range of 1 to 6!")
            return True

class menu:
     
    def main():
        print("****************************")
        print("!-Welcome to Chatting-!")        
        print("****************************")

        print("""enter either of the following(Press 1 - 6):
                1. One-to-one chat
                2. Group chat
                3. File Transfer
                4. View routing table
                5. List Users
                6. Exit """)

        choice = int(input("enter your choice:"))
        print("yes!")
        return choice
    
    def source_name():
        src_id = socket.gethostname()
        return src_id
    def source_port():
        src_port = 9999
        return src_port
    def p_ip():
        p_ip = input("Enter the Peer IP address:")
        return p_ip
    def node_id():
        n_id = gpg_key
    def destination_port():
        return 9999
    def destination_address():
        destination_address = input("Enter the destination address:")
        return destination_address
    def p_port():
        return "9999"
    def cost_matrix():
        cost = int(input("Please input link cost of the node: "))
        return cost
    def time_out():
        return 30
    def packet_type(self,typee):
        if typee == "data":
            return 0x02
        elif typee == "conf":
            return 0x04
        else:
            print("Error in Packet Type")




class sockk:


    # gpg =
    m = menu()
    r = choices()
    r_buf = 1024
    connxn = {}
    seg = []

    def messageReceived(sock,listen,p_port,p_ip,cost,n_id):
            sock.bind(("",listen))
            host = socket.gethostbyname(socket.gethostname())
            host = str(host)
            listen = str(listen)
            r.self_id = host + ":" + listen
            neigh_ip = socket.gethostname(p_ip)
            neigh_ip = str(neigh_ip)
            neigh_id = neigh_ip + ":" + p_port
            r.routing_table[neigh_id] = {}   
            r.routing_table[neigh_id]['cost'] = cost
            r.routing_table[neigh_id]['link'] = neigh_id
            r.routing_table[neigh_id]['nickname'] = n_id
            r.adj_links[neigh_id] = cost
            r.neigh[neigh_id] = {}
            r.time_out = m.time_out()
            os.system("clear")
            start.process(sock,connxn)

            while 1:
                sock_lst = [sys.stdin,sock]
                try:
                    sread,swrite,serror = select.select(sock_lst,[],[])
                except select.error:
                    break
                except socket.error:
                    break

                for s in sread:
                    if s == sock:
                        data,address = sock.recvfrom(r_buf)
                        connxn[address] = n_id
                        if not os.path.isfile("first.asc"):
                                pgp.generate_certificates()
                                seg.append(data)
                                deseg = join(seg)
                        try:
                                decry = pgp.decrypt(deseg)
                                data = json.loads(decry)
                                seg[:]=[]
                                r.msg_handler(s_socket,data, address)      #########
                                time.sleep(0.01)
                        except:
                                pass 
                    
                    else:
                            data = sys.stdin.readline().rstrip()
                            if data=="MENU":
                                os.system("clear")      
                                strat.process(_socket,conn)
                            else:
                                r.private_msg(sock,r.destination_id,data)
                                main1()  #################
            sock.close()

    def join(data):
        joineddata = b''
        for x in data:
            joineddata +=x
        return joineddata
        
    def updatingtime(s_socket,timeout_interval):
            r.updatingneighbor(s_socket)
    def updatingroute(serverSocket,timeout_interval):
            r.n_timer(s_socket)



    if __name__ == "__main__":
            os.system("clear")
            p_ip = menu.p_ip()
            p_port= menu.p_port()
            source_port = menu.source_port()
            destination_port = menu.destination_port()
            n_id= main.node_id()
            cost = main.cost_matrix()
            time_out= main.time_out()
            s_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            s_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
            messageReceived(s_socket,source_port,p_port,p_ip,cost,n_id)
            t = threading.Timer(time_out, time_update, [time_out])
            t.setDaemon(True)
            t.start()
            time = threading.Timer(time_out, updatingroute, [time_out])
            time.setDaemon(True)
            time.start()


def main1():
    
    choice = menu.main()
    s = start(choice)
    time.sleep(1)
    if s == "True":
        main1()
    else:
        print("bye-bye!")
        print("See you later!")
        sys.exit()
    
main1()

        

