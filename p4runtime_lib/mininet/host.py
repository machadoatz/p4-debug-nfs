#!/usr/bin/env python3

from mininet.node import Host


class P4Host(Host):
    def config(self, **params):
        r = super(Host, self).config(**params)

        self.defaultIntf().rename('eth0')

        for off in ['rx', 'tx', 'sg']:
            cmd = '/sbin/ethtool --offload eth0 %s off' % off
            self.cmd(cmd)

        # disable IPv6
        self.cmd('sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1')
        self.cmd('sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1')
        self.cmd('sudo sysctl -w net.ipv6.conf.lo.disable_ipv6=1')

        return r

    def describe(self):
        print('**********')
        print(self.name)
        print('default interface: %s\t%s\t%s' % (
            self.defaultIntf().name, self.defaultIntf().IP(), self.defaultIntf().MAC()))
        print('**********')
