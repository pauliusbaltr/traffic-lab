"""Read DNS questions and IPv4 answers; this does not establish visits."""
import argparse
from scapy.all import DNS, DNSQR, DNSRR, PcapReader

def label(value):
    return value.decode('ascii', errors='replace').rstrip('.') if isinstance(value, bytes) else str(value)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture')
    args = parser.parse_args()
    # Scapy already decodes DNS on UDP/53, which is what the teaching
    # captures use; no extra port binding is needed.
    with PcapReader(args.capture) as packets:
        for number, packet in enumerate(packets, 1):
            if DNS not in packet:
                continue
            dns = packet[DNS]
            if dns.qr == 0 and dns.qd:
                print(f'{number}: QUERY id={dns.id} {label(dns.qd[0].qname)}')
            elif dns.qr == 1:
                for answer in dns.an:
                    if isinstance(answer, DNSRR) and answer.type == 1:
                        print(f'{number}: ANSWER id={dns.id} {label(answer.rrname)} A {answer.rdata}')

if __name__ == '__main__':
    main()
