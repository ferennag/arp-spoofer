## Overview 

This is a very simple ARP spoofer script. It spoofs a single client, and does a man-in-the-middle attack.

After the spoofing is complete, the tool automatically sniffs the HTTP packets of the victim.

## Usage

```
$ python -m venv venv
$ source venv/bin/activate
$ pip install -r requirements.txt
$ sudo python ./arp-spoof.py --victim-ip <victim IP> --router-ip <router IP>
```

The program can be terminated with CTRL-C.
It automatically restores the ARP tables for the router and the victim to prevent the loss of network connection for the victim.