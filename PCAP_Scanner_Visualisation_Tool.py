#Import library
import dpkt
from dpkt.tcp import TCP
import matplotlib.pyplot as plt
import time
import socket
from collections import Counter

#Users options string
users_ops = """

Choose one of the following options

Plot Bar Chart of IP-Source = 1
Plot Bar Chart of IP-Dest = 2
Plot Line Graph of Port-Source = 3
Plot Line Graph of Port-Dest = 4
FTP-Traffic v TCP Dest Port Traffic = 5
List Packet Types = 6
List URLs found = 7
List Source IPs = 8
List Dest IPs = 9
"""

def program():
   #Asks user to choose option and input filename
   print("\nWelcome to my PCAP visualiser script!")
   time.sleep(1)
   users_choice = input(users_ops)
   time.sleep(1)
   users_filename = input("Enter your pcap file name ")

   #Setup, Opens file, List creation
   j = open(users_filename, 'rb')
   pcap = dpkt.pcap.Reader(j)
   optionList = []
   ipList = []
   timeList = []
   ftp_traff = []
   ftp_time = []
   yLab = 0
   #Loop over each packet in pcap
   for ts, buf in pcap:
       eth = dpkt.ethernet.Ethernet(buf)
       ip = eth.data
       tcp = ip.data
       #Specifying TCP traffic
       if type(ip.data) == TCP: 
           if users_choice == '1':
               #Adding source IPs to a list
               source_ip = socket.inet_ntoa(ip.src)
               ipList.append(source_ip)
               yLab = "Source IP Address'"

               #Counting each set of IPs
               ip_counts = {}
               for ip in ipList:
                   if ip in ip_counts:
                       ip_counts[ip] += 1
                   else:
                       ip_counts[ip] = 1

               # Get the unique IP addresses and their counts
               ipList = list(ip_counts.keys())
               ip_counts = list(ip_counts.values())

           elif users_choice == '2':
               #Adding destination IPs to list
               destination_ip = socket.inet_ntoa(ip.dst)
               ipList.append(destination_ip)
               yLab = "Destination IP Address'"

               #Counting each set of IPs
               ip_counts = {}
               for ip in ipList:
                   if ip in ip_counts:
                       ip_counts[ip] += 1
                   else:
                       ip_counts[ip] = 1

               # Get the unique IP addresses and their counts
               ipList = list(ip_counts.keys())
               ip_counts = list(ip_counts.values())

           if users_choice == "3":
               #Adding TCP Source Ports Numbers to list
               yLab = 'Source Port Numbers'
               optionList.append(tcp.sport)
               timeList.append(ts)

           elif users_choice == "4":
               #Adding TCP Desination Port Numbers to lidt
               yLab = 'Destination Port Numbers'
               optionList.append(tcp.dport)
               timeList.append(ts)
          
           elif users_choice == "5":
               #Adding FTP and Dest Ports to list
               yLab = 'FTP traffic v Port Destination Numbers'
               optionList.append(tcp.dport)
               timeList.append(ts)
               if tcp.dport == 21:
                   ftp_traff.append(tcp.dport)
                   ftp_time.append(ts)

           elif users_choice == '8':
                   #Printing source IPs
                   source_ip = socket.inet_ntoa(ip.src)
                   print (source_ip)

           elif users_choice == '9':
                   #Printing dest IPs
                   source_ip = socket.inet_ntoa(ip.dst)
                   print (source_ip)

   if users_choice == "6":
       #Setting packet type variables to 0
       counter=0
       udpC=0
       tcpC=0
       ipC=0
       icmpC=0
       igmpC=0

       #Variables for re-used text
       tao = "Total amount of"
       pt = 'packets:'

       #Iterating over the pcap and finds protocols
       for ts, pkt in dpkt.pcap.Reader(open(users_filename, "rb")):
           counter+=1
           eth=dpkt.ethernet.Ethernet(pkt)
           if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
               continue
           ip=eth.data
           ipC+=1
           if ip.p==dpkt.ip.IP_PROTO_TCP:
               tcpC+=1
           if ip.p==dpkt.ip.IP_PROTO_UDP:
               udpC+=1
           if ip.p==dpkt.ip.IP_PROTO_ICMP:
               icmpC+=1
           if ip.p==dpkt.ip.IP_PROTO_IGMP:
               igmpC+=1

       #Outputting the amount of time each protocol is used
       print(tao, pt, counter)
       print(tao,'IP', pt, ipC)
       print(tao,'UDP', pt, udpC)
       print(tao,'TCP', pt, tcpC)
       print(tao,'ICMP', pt, icmpC)
       print(tao,'IGMP', pt, igmpC)

   if users_choice == '7':

       #Iterating over the pcap
       for ts, pkt in dpkt.pcap.Reader(open(users_filename,'rb')):
           eth=dpkt.ethernet.Ethernet(pkt)
           ip = eth.data
           tcp = ip.data

           #Getting URLs
           if type(ip.data) == TCP:
               if tcp.dport == 80 and len(tcp.data) > 0:
                   http = dpkt.http.Request(tcp.data)
                   print (http.uri)

   #Graph to be plotted
   def graph(timeList, optionList):
       plt.plot(timeList, optionList)
       plt.plot(ftp_time, ftp_traff)
       plt.title('Port v Time')
       plt.xlabel('Time Line')
       plt.ylabel(yLab)
       plt.show()

   #Bar chart to be plotted
   def bar(elements, num_occurrences):
       plt.bar(ipList, ip_counts)
       plt.xlabel("IP Address's")               
       plt.ylabel('Count')
       plt.show()

   if users_choice == '3' or '4' or '5':
       graph(timeList, optionList)

   if users_choice == '1' or '2':
       bar(ipList, ip_counts)
     
   j.close()

#Using the program function to run the main block of code
program()
