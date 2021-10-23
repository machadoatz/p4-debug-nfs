#!/usr/bin/env python3

import argparse
import json
import os
from time import sleep

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.topo import Topo

from p4runtime_lib.mininet.host import P4Host
from p4runtime_lib.mininet.switch import P4RuntimeSwitch


def configure_p4_switch(**switch_args):
    """
    Helper called by Mininet to initialize the virtual P4 switches.
    The purpose is to ensure each switch's thrift server is using a unique port.
    """

    if 'sw_path' in switch_args and 'grpc' in switch_args['sw_path']:
        # If grpc appears in the BMv2 switch target, we assume will start P4Runtime
        class ConfiguredP4RuntimeSwitch(P4RuntimeSwitch):
            def __init__(self, *opts, **kwargs):
                kwargs.update(switch_args)
                P4RuntimeSwitch.__init__(self, *opts, **kwargs)

            def describe(self):
                print('=====================================')
                print('Switch Device ID: %s' % str(self.device_id))
                print('Switch CPU port: %s' % str(self.cpu_port))
                print('%s -> gRPC port: %d' % (self.name, self.grpc_port))

        return ConfiguredP4RuntimeSwitch

    else:
        raise Exception('Only P4Runtime switches are supported')


class NetworkFunctionTopology(Topo):
    """
    The Mininet network topology for the P4 network functions.
    """

    @staticmethod
    def parse_switch_node(node):
        assert len(node.split('-')) == 2
        sw_name, sw_port = node.split('-')

        try:
            sw_port = int(sw_port[1:])

        except ValueError:
            raise Exception('Invalid switch node in topology file: {}'.format(node))

        return sw_name, sw_port

    def __init__(self, hosts, switches, links, log_dir, bmv2_exe, pcap_dir, **opts):
        Topo.__init__(self, **opts)
        host_links = []
        switch_links = []

        # assumes host always comes first for host<-->switch links
        for link in links:
            if link['node1'][0] == 'h':
                host_links.append(link)

            else:
                switch_links.append(link)

        # add switch(es) to the topology
        for sw, params in switches.items():
            self.addSwitch(sw, log_file='%s/%s.log' % (log_dir, sw),
                           cls=configure_p4_switch(sw_path=bmv2_exe, log_console=True, pcap_dump=pcap_dir))

        # add host links to the topology
        for link in host_links:
            host_name = link['node1']
            sw_name, sw_port = self.parse_switch_node(link['node2'])

            host_ip = hosts[host_name]['ip']
            host_mac = hosts[host_name]['mac']

            self.addHost(host_name, ip=host_ip, mac=host_mac)
            self.addLink(host_name, sw_name, delay=link['latency'], bw=link['bandwidth'], port2=sw_port)

        # add switch links to the topology
        for link in switch_links:
            sw1_name, sw1_port = self.parse_switch_node(link['node1'])
            sw2_name, sw2_port = self.parse_switch_node(link['node2'])

            self.addLink(sw1_name, sw2_name, port1=sw1_port, port2=sw2_port, delay=link['latency'],
                         bw=link['bandwidth'])


class NetworkFunctionRunner:
    """
    Attributes:
        log_dir     : string                // directory for Mininet log files
        pcap_dir    : string                // directory for Mininet switch pcap files

        hosts       : dict<string, dict>    // Mininet host names and their associated properties
        switches    : dict<string, dict>    // Mininet switch names and their associated properties
        links       : list<dict>            // list of Mininet link properties

        bmv2_exe    : string                // name or path of the P4 switch binary

        topology    : Topo object           // The Mininet topology instance
        network     : Mininet object        // The Mininet instance
    """

    @staticmethod
    def logger(*items):
        print(' '.join(items))

    @staticmethod
    def format_latency(latency):
        """
        Helper method for parsing link latencies from the topology JSON.
        """

        return str(latency) + 'ms'

    def parse_links(self, unparsed_links):
        """
        Given a list of links descriptions of the form [node1, node2, latency, bandwidth],
        with the latency and bandwidth being optional, parses these descriptions into dictionaries,
        and stores them as self.links.
        """

        links = []
        for link in unparsed_links:
            # make sure each link's endpoints are ordered alphabetically
            s, t, = link[0], link[1]
            if s > t:
                s, t = t, s

            link_dict = {'node1': s, 'node2': t, 'latency': '0ms', 'bandwidth': 300}
            if len(link) > 2:
                link_dict['latency'] = self.format_latency(link[2])

            if len(link) > 3:
                link_dict['bandwidth'] = link[3]

            if link_dict['node1'][0] == 'h':
                assert link_dict['node2'][0] == 's', 'Hosts should be connected to switches, not ' + str(
                    link_dict['node2'])

            links.append(link_dict)

        return links

    def __init__(self, topology_file, log_dir, pcap_dir, bmv2_exe):
        """
        Initializes some attributes, and reads the topology JSON.
        Does not actually run the network function. Use run() for that.
        """

        self.logger('[*] reading topology file')
        with open(topology_file, 'r') as f:
            topology = json.load(f)

        self.hosts = topology['hosts']
        self.switches = topology['switches']
        self.links = self.parse_links(topology['links'])

        # ensure all the needed directories exist and are directories
        for dir_name in [log_dir, pcap_dir]:
            if not os.path.isdir(dir_name):
                if os.path.exists(dir_name):
                    raise Exception('\'%s\' exists and is not a directory!' % dir_name)

                os.mkdir(dir_name)

        self.log_dir = log_dir
        self.pcap_dir = pcap_dir
        self.bmv2_exe = bmv2_exe

    def create_network(self):
        """
        Creates the Mininet network object, and store it as self.network.
        The Mininet topology instance is stored as self.topology.
        """

        self.logger('[*] building Mininet topology')
        self.topology = NetworkFunctionTopology(self.hosts, self.switches, self.links, self.log_dir, self.bmv2_exe,
                                                self.pcap_dir)
        self.network = Mininet(topo=self.topology, link=TCLink, host=P4Host,
                               switch=configure_p4_switch(sw_path=self.bmv2_exe, log_console=True,
                                                          pcap_dump=self.pcap_dir),
                               controller=None)

    def program_hosts(self):
        """
        Execute any commands provided in the topology.json file on each Mininet host.
        """

        for host_name, host_info in self.hosts.items():
            host = self.network.get(host_name)

            if 'commands' in host_info:
                for cmd in host_info['commands']:
                    host.cmd(cmd)

    def do_net_cli(self):
        """
        Starts up the mininet CLI and prints some helpful output.
        The method assumes that a Mininet instance is stored as self.network,
        and self.network.start() has been called.
        """

        for s in self.network.switches:
            s.describe()

        for h in self.network.hosts:
            h.describe()

        self.logger('[*] starting mininet CLI')

        # Generate a message that will be printed by the Mininet CLI to make
        # interacting with the simple switch a little easier.
        print('')
        print('======================================================================')
        print('Welcome to the BMV2 Mininet CLI!')
        print('======================================================================')
        print('Your P4 program is installed into the BMV2 software switch')
        print('and your initial runtime configuration is loaded. You can interact')
        print('with the network using the mininet CLI below.')
        print('')
        print('To view a switch log, run this command from your host OS:')
        print('  tail -f %s/<switchname>.log' % self.log_dir)
        print('')
        print('To view the switch output pcap, check the pcap files in %s:' % self.pcap_dir)
        print(' for example run:  sudo tcpdump -xxx -r s1-eth1.pcap')
        print('')

        # if 'grpc' in self.bmv2_exe:
        #     print('To view the P4Runtime requests sent to the switch, check the')
        #     print('corresponding txt file in %s:' % self.log_dir)
        #     print(' for example run:  cat %s/s1-p4runtime-requests.txt' % self.log_dir)
        #     print('')

        CLI(self.network)

    def run(self):
        """
        Sets up the Mininet instance, programs the switch(es), and starts the Mininet CLI.
        This is the main method to run after initializing the object.
        """

        # initialize Mininet with the topology specified by the configuration JSON
        self.create_network()
        self.network.start()
        sleep(1)

        # some programming that must happen after the net has started
        self.program_hosts()
        sleep(1)

        self.do_net_cli()
        # stop right after the CLI is exited
        self.network.stop()


def get_parser_arguments():
    cwd = os.getcwd()
    default_logs = os.path.join(cwd, 'logs')
    default_pkt_captures = os.path.join(cwd, 'pcaps')

    parser = argparse.ArgumentParser(description='P4 Network Function Runner')
    parser.add_argument('-b', '--behavioral-exe', help='Path to behavioral executable', type=str, required=False,
                        default='simple_switch_grpc')
    parser.add_argument('-t', '--topology', help='Path to topology JSON', type=str, required=True)
    parser.add_argument('-l', '--log-dir', help='Log directory', type=str, required=False, default=default_logs)
    parser.add_argument('-p', '--pcap-dir', help='Interfaces packet dumps directory', type=str, required=False,
                        default=default_pkt_captures)

    return parser.parse_args()


if __name__ == '__main__':
    setLogLevel('info')

    # read main arguments and build network function runner
    args = get_parser_arguments()

    # create the network function runner
    network_function = NetworkFunctionRunner(args.topology, args.log_dir, args.pcap_dir, args.behavioral_exe)
    # run it
    network_function.run()
