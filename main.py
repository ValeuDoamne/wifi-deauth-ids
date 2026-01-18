import argparse

from functools import partial
from time import time
from scapy.all import sniff, Packet
from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Beacon

BROADCAST_BSSID="ff:ff:ff:ff:ff:ff"
AP_BSSID=""
MAXIMUM_PACKETS=5
PREVIOUS_PACKET=0
LATEST_PACKET=0
TIMEOUT_RESET=10

COUNT = 0

def handle_deauth(pkt: Packet, ap_bssid: str):
    global COUNT, PREVIOUS_PACKET, LATEST_PACKET
    dot11 = pkt[Dot11]
    receiver = dot11.addr1
    sender   = dot11.addr2
    bssid    = dot11.addr3
    reason   = pkt[Dot11Deauth].reason

    if sender == ap_bssid and receiver == BROADCAST_BSSID:
        print(
            f"[DEAUTH] from={sender} to={receiver} "
            f"bssid={bssid} reason={reason}"
        )
        print("Attack detected with broadcast deauth!")
        return

    # Deauth sent to AP or from AP
    if receiver == ap_bssid or bssid == ap_bssid:
        PREVIOUS_PACKET = LATEST_PACKET
        LATEST_PACKET = time()
        print(
            f"[DEAUTH] from={sender} to={receiver} "
            f"bssid={bssid} reason={reason}"
        )
        COUNT += 1
        # Reset the counter if 
        if abs(LATEST_PACKET - PREVIOUS_PACKET) >= TIMEOUT_RESET:
            COUNT = 0 
        if COUNT >= MAXIMUM_PACKETS:
            print("[DEAUTH] ATTACK Detected!")

def main(args: argparse.Namespace):
    watched_bssid = args.bssid.lower()
    sniff(iface=args.interface, prn=partial(handle_deauth, ap_bssid=watched_bssid), store=False, lfilter=lambda p: p.haslayer(Dot11Deauth))

if __name__ == "__main__":
    p = argparse.ArgumentParser("wpa-ids")
    p.add_argument("-i", "--interface", action="store", help="Interface to bind to", required=True)
    p.add_argument("-b", "--bssid", action="store", help="AP BSSID that you would like to watch for", required=True)
    args = p.parse_args()
    main(args)
