#!/usr/bin/env python3
import argparse
import os
import re
import sys
import time
from queue import Queue, Empty
from typing import Union

from scapy.config import Conf
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, AsyncSniffer

ETHER_TYPE_IPV4 = 0x0800


class Debugger(object):
    # keep track of packet sniffers
    _sniffers = []
    # pattern to match switch interfaces (s*-eth*)
    _sw_intf_pattern = re.compile('(s\\d+)-(eth\\d+)')
    # queues to store packets, indexed by interface name
    _queues = {}
    # network interfaces location
    _intfs_location = '/sys/class/net'
    # should debug be activated?
    _debug = False

    def print(self, *opts):
        if self._debug:
            print(*opts)

    def __init__(self, debug=False):
        self._debug = debug
        self.print('[*] created a new debugger instance')

    def start_sniffing_packets(self, interface: str, queue: Queue):
        def sniff(pkt: Ether):
            queue.put(pkt)

            self.print(
                '\n[*] received packet on interface `{}`:'.format(interface))
            self.print(pkt.summary())

        def sniff_began():
            self.print('[*] sniffing interface `{}`'.format(interface))

        sniffer = AsyncSniffer(
            iface=interface,
            prn=lambda pkt: sniff(pkt),
            store=True,
            started_callback=sniff_began
        )

        self._sniffers.append(sniffer)
        sniffer.start()

    def stop_sniffing_packets(self):
        self.print('[*] killing sniffers')
        for sniffer in self._sniffers:
            sniffer.stop(join=True)

        print('[*] shutting down debugger')

    def _get_queue(self, interface) -> Queue:
        if interface not in self._queues:
            print('[*] interface `{}` not found'.format(interface))
            sys.exit(1)

        q = self._queues.get(interface)
        with q.mutex:
            return q

    def clear_interface(self, interface: str):
        self._get_queue(interface).queue.clear()

    def update_interfaces(self, start_sniffing: bool = False, whitelist: Union[list, str] = None,
                          blacklist: Union[list, str] = None):
        self.print('[*] updating interfaces')

        # clear previous state
        self._queues = {}

        if whitelist is None:
            whitelist = []

        elif isinstance(whitelist, str):
            whitelist = [whitelist]
            self.print('[*] whitelist: {}'.format(whitelist))

        elif not isinstance(whitelist, list):
            print('[*] whitelist must either be a string or a list')
            sys.exit(1)

        if blacklist is None:
            blacklist = []

        elif isinstance(blacklist, str):
            blacklist = [blacklist]
            self.print('[*] blacklist: {}'.format(blacklist))

        elif not isinstance(blacklist, list):
            print('[*] blacklist must either be a string or a list')
            sys.exit(1)

        # iterate over registered interfaces
        found_intfs = 0
        interfaces = os.listdir(self._intfs_location)
        self.print('[*] found interfaces: {}'.format(interfaces))

        for intf in interfaces:
            # if the interface does not match the expected format, ignore it
            if re.match(self._sw_intf_pattern, intf) is None:
                continue

            # if the interface is in the blacklist, discard it
            if intf in blacklist:
                continue

            # if a whitelist is provided and the interface is not there, discard it
            if len(whitelist) != 0 and intf not in whitelist:
                continue

            # one more interface was found
            found_intfs += 1

            self._queues[intf] = Queue()
            if start_sniffing:
                self.start_sniffing_packets(
                    interface=intf,
                    queue=self._queues[intf]
                )

        # no switch interfaces were found
        if found_intfs == 0:
            print(
                '[*] no filtered switch interfaces have been found, maybe switch is not running?')
            sys.exit(1)

        self.print('[*] new interfaces: {}'.format(self._queues))
        print('[*] waiting 1 second before proceeding')
        time.sleep(1)

    def send_packet(self, packet: Ether, interface: str = None):
        if interface is None:
            print('[*] an interface must be provided')
            sys.exit(1)

        sendp(packet, iface=interface, verbose=Conf.verb)
        self.print('[*] sent packet through interface `{}`'.format(interface))

    def get_packet(self, interface: str, timeout: int = None) -> Ether:
        try:
            return self._get_queue(interface).get(timeout=timeout)

        except Empty as e:
            # print('[*] expected a packet on interface `{}` but nothing was received'.format(interface))
            raise e


def not_implemented():
    print('[*] function not yet implemented')
    sys.exit(1)


def handle_nop(debugger: Debugger):
    print('[*] handling nop')
    # start sniffing
    debugger.update_interfaces(start_sniffing=True)

    src_mac = '00:00:00:00:00:00'
    dst_mac = src_mac

    print()
    print('[*] test h1 -> h2')

    pkt_out = Ether(dst=dst_mac, src=src_mac, type=ETHER_TYPE_IPV4)
    debugger.clear_interface(interface='s1-eth2')
    debugger.send_packet(packet=pkt_out, interface='s1-eth1')

    try:
        pkt_in = debugger.get_packet(interface='s1-eth2', timeout=1)
        pkt_in_ether = pkt_in.getlayer(Ether)

        # assert mac addresses have changed
        assert pkt_in_ether.dst == '00:00:00:00:00:02'
        print('[*] dst mac address: check')
        assert pkt_in_ether.src == '00:00:00:00:00:01'
        print('[*] src mac address: check')

    except Empty:
        sys.exit(1)

    print()
    print('[*] test h2 -> h1')

    pkt_out = Ether(dst=dst_mac, src=src_mac, type=ETHER_TYPE_IPV4)
    debugger.clear_interface(interface='s1-eth1')
    debugger.send_packet(packet=pkt_out, interface='s1-eth2')

    try:
        pkt_in = debugger.get_packet(interface='s1-eth1', timeout=1)
        pkt_in_ether = pkt_in.getlayer(Ether)

        # assert mac addresses have changed
        assert pkt_in_ether.dst == '00:00:00:00:00:01'
        print('[*] dst mac address: check')
        assert pkt_in_ether.src == '00:00:00:00:00:02'
        print('[*] src mac address: check')

    except Empty:
        sys.exit(1)

    print()


def handle_bridge_static(debugger: Debugger):
    print('[*] handling bridge-static')
    # start sniffing
    debugger.update_interfaces(start_sniffing=True)

    h1_addr = ('00:00:00:00:00:01', '10.0.0.1')
    h2_addr = ('00:00:00:00:00:02', '10.0.0.2')

    print()
    print('[*] test h1 -> h2')

    pkt_out = Ether(
        src=h1_addr[0], dst=h2_addr[0], type=ETHER_TYPE_IPV4
    ) / IP(
        src=h1_addr[1], dst=h2_addr[1]
    )

    debugger.clear_interface('s1-eth1')
    debugger.send_packet(packet=pkt_out, interface='s1-eth1')

    try:
        pkt_in = debugger.get_packet(interface='s1-eth2', timeout=1)
        pkt_in_ether = pkt_in.getlayer(Ether)
        pkt_in_ip = pkt_in.getlayer(IP)

        # assert mac addresses have changed
        assert pkt_in_ether.dst == h2_addr[0]
        print('[*] dst mac address: check')
        assert pkt_in_ether.src == h1_addr[0]
        print('[*] src mac address: check')

        # assert ip addresses remain unchanged
        assert pkt_in_ip.dst == h2_addr[1]
        print('[*] dst ip address: check')
        assert pkt_in_ip.src == h1_addr[1]
        print('[*] src ip address: check')

    except Empty:
        sys.exit(1)


def handle_bridge(debugger: Debugger):
    print('[*] handling bridge-static')
    # start sniffing
    debugger.update_interfaces(start_sniffing=True)

    h1_addr = ('00:00:00:00:00:01', '10.0.0.1')
    h2_addr = ('00:00:00:00:00:02', '10.0.0.2')

    print()
    print('[*] test h1 -> h2')

    pkt_out = Ether(
        src=h1_addr[0], dst=h2_addr[0], type=ETHER_TYPE_IPV4
    ) / IP(
        src=h1_addr[1], dst=h2_addr[1]
    )

    debugger.clear_interface('s1-eth2')
    debugger.send_packet(packet=pkt_out, interface='s1-eth1')

    try:
        pkt_in = debugger.get_packet(interface='s1-eth2', timeout=1)
        pkt_in_ether = pkt_in.getlayer(Ether)
        pkt_in_ip = pkt_in.getlayer(IP)

        # assert mac addresses have changed
        assert pkt_in_ether.dst == h2_addr[0]
        print('[*] dst mac address: check')
        assert pkt_in_ether.src == h1_addr[0]
        print('[*] src mac address: check')

        # assert ip addresses remain unchanged
        assert pkt_in_ip.dst == h2_addr[1]
        print('[*] dst ip address: check')
        assert pkt_in_ip.src == h1_addr[1]
        print('[*] src ip address: check')

    except Empty:
        sys.exit(1)


def handle_pol(debugger: Debugger):
    not_implemented()


def handle_nat(debugger: Debugger):
    not_implemented()


def handle_fw(debugger: Debugger):
    print('[*] handling simple-firewall')
    # start sniffing
    debugger.update_interfaces(start_sniffing=True)

    lan = ('00:00:00:00:00:01', '10.0.0.1')
    wan = ('00:00:00:00:00:02', '10.0.0.2')

    srcPort = 2894
    dstPort = 7264

    print()
    print('[*] testing WAN -> LAN')

    pkt_out = Ether(
        src=wan[0], dst=lan[0], type=ETHER_TYPE_IPV4
    ) / IP(
        src=wan[1], dst=lan[1], proto=17
    ) / TCP(
        sport=srcPort, dport=dstPort
    )

    debugger.clear_interface('s1-eth2')
    debugger.send_packet(packet=pkt_out, interface='s1-eth2')

    try:
        pkt_in = debugger.get_packet(interface='s1-eth1', timeout=1)
        print("[-] unexpected packet received on s1-eth1")
        sys.exit(1)

    except Empty:
        print("[+] no packet received on s1-eth1")

    print()
    print('[*] testing LAN -> WAN')

    pkt_out = Ether(
        src=lan[0], dst=wan[0], type=ETHER_TYPE_IPV4
    ) / IP(
        src=lan[1], dst=wan[1], proto=17
    ) / TCP(
        sport=dstPort, dport=srcPort
    )

    debugger.clear_interface('s1-eth1')
    debugger.send_packet(packet=pkt_out, interface='s1-eth1')

    try:
        pkt_in = debugger.get_packet(interface='s1-eth2', timeout=1)
        print("[+] received packet on s1-eth2")

    except Empty:
        print("[-] expected a packet on interface s1-eth2 but nothing was received")
        sys.exit(1)

    numberOfTries = 50
    while numberOfTries > 0:
        print()
        print('[*] testing WAN -> LAN')

        pkt_out = Ether(
            src=wan[0], dst=lan[0], type=ETHER_TYPE_IPV4
        ) / IP(
            src=wan[1], dst=lan[1], proto=17
        ) / TCP(
            sport=srcPort, dport=dstPort
        )

        debugger.clear_interface('s1-eth2')
        debugger.send_packet(packet=pkt_out, interface='s1-eth2')

        try:
            pkt_in = debugger.get_packet(interface='s1-eth1', timeout=1)
            print("[*] packet received")

        except Empty:
            print("[-] still waiting for packet")

        numberOfTries -= 1


def handle_lb(debugger: Debugger):
    not_implemented()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='SyNAPSE network functions debugging')

    # --nf-name
    parser.add_argument('--nf-name', help='Network function name', type=str, action='store', required=False,
                        default='nop')

    # (--no)--debug
    parser.add_argument('--debug', dest='debug', action='store_true')
    parser.add_argument('--no-debug', dest='debug', action='store_false')
    parser.set_defaults(debug=False)

    args = parser.parse_args()

    # non-verbose scapy
    Conf.verb = 0

    # debugger instance
    d = Debugger(args.debug)

    try:
        if args.nf_name == 'nop':
            handle_nop(debugger=d)

        elif args.nf_name == 'bridge-static':
            handle_bridge_static(debugger=d)

        elif args.nf_name == 'bridge':
            handle_bridge(debugger=d)

        elif args.nf_name == 'pol':
            handle_pol(debugger=d)

        elif args.nf_name == 'nat':
            handle_nat(debugger=d)

        elif args.nf_name == 'fw':
            handle_fw(debugger=d)

        elif args.nf_name == 'lb':
            handle_lb(debugger=d)

        else:
            print('[*] unknown network function `{}`'.format(args.nf_name))
            sys.exit(1)

    finally:
        d.stop_sniffing_packets()
