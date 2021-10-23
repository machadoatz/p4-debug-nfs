#!/usr/bin/env python3

import os
import socket
import tempfile
from time import sleep

from mininet.log import info, error, debug
from mininet.moduledeps import pathCheck
from mininet.node import Switch

from p4runtime_lib.netstat import check_listening_on_port

SWITCH_START_TIMEOUT = 10  # seconds
CPU_PORT = 509  # default packet-in/packet-out port usage


class P4Switch(Switch):
    """
    P4 virtual switch.
    """

    device_id = 0

    def __init__(self, name, sw_path=None, json_path=None, thrift_port=None, pcap_dump=False, log_console=False,
                 verbose=False, device_id=None, enable_debugger=False, **kwargs):
        Switch.__init__(self, name, **kwargs)

        assert sw_path
        assert json_path

        # make sure that the provided sw_path is valid
        pathCheck(sw_path)

        # make sure that the provided JSON file exists
        if not os.path.isfile(json_path):
            error('Invalid JSON file.\n')
            exit(1)

        self.sw_path = sw_path
        self.json_path = json_path
        self.verbose = verbose
        logfile = '/tmp/p4s.{}.log'.format(self.name)
        self.output = open(logfile, 'w')
        self.thrift_port = thrift_port
        self.pcap_dump = pcap_dump
        self.enable_debugger = enable_debugger
        self.log_console = log_console

        if device_id is not None:
            self.device_id = device_id
            P4Switch.device_id = max(P4Switch.device_id, device_id)

        else:
            self.device_id = P4Switch.device_id
            P4Switch.device_id += 1

        self.nanomsg = 'ipc:///tmp/bm-{}-log.ipc'.format(self.device_id)

    @classmethod
    def setup(cls):
        pass

    def check_switch_started(self, pid):
        """
        While the process is running (pid exists), we check if the Thrift server has been started.
        If the Thrift server is ready, we assume that the switch was started successfully.
        This is only reliable if the Thrift server is started at the end of the init process.
        """

        while True:
            if not os.path.exists(os.path.join('/proc', str(pid))):
                return False

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.settimeout(0.5)
                result = sock.connect_ex(('localhost', self.thrift_port))

            finally:
                sock.close()

            if result == 0:
                return True

    def start(self, controllers):
        """
        Start up a new P4 switch.
        """

        info('Starting P4 switch {}.\n'.format(self.name))
        args = [self.sw_path]
        for port, intf in self.intfs.items():
            if not intf.IP():
                args.extend(['-i', str(port) + '@' + intf.name])

        if self.pcap_dump:
            args.append('--pcap')
            # args.append('--useFiles')

        if self.thrift_port:
            args.extend(['--thrift-port', str(self.thrift_port)])

        if self.nanomsg:
            args.extend(['--nanolog', self.nanomsg])

        args.extend(['--device-id', str(self.device_id)])
        P4Switch.device_id += 1

        args.append(self.json_path)
        if self.enable_debugger:
            args.append('--debugger')

        if self.log_console:
            args.append('--log-console')

        logfile = '/tmp/p4s.{}.log'.format(self.name)
        info(' '.join(args) + '\n')

        with tempfile.NamedTemporaryFile() as f:
            # self.cmd(' '.join(args) + ' > /dev/null 2>&1 &')
            self.cmd(' '.join(args) + ' >' + logfile + ' 2>&1 & echo $! >> ' + f.name)
            pid = int(f.read())
        debug('P4 switch {} PID is {}.\n'.format(self.name, pid))

        if not self.check_switch_started(pid):
            error('P4 switch {} did not start correctly.\n'.format(self.name))
            exit(1)
        info('P4 switch {} has been started.\n'.format(self.name))

    def stop(self, **kwargs):
        """
        Terminate P4 switch.
        """

        self.output.flush()
        self.cmd('kill %' + self.sw_path)
        self.cmd('wait')
        self.deleteIntfs()


class P4RuntimeSwitch(P4Switch):
    """
    BMv2 switch with gRPC support.
    """

    next_grpc_port = 50051
    next_thrift_port = 9090

    def __init__(self, name, sw_path=None, json_path=None, grpc_port=None, thrift_port=None, pcap_dump=False,
                 log_console=False, verbose=False, device_id=None, enable_debugger=False, log_file=None, **kwargs):
        Switch.__init__(self, name, **kwargs)

        assert sw_path
        self.sw_path = sw_path

        # make sure that the provided sw_path is valid
        pathCheck(sw_path)

        if json_path is not None:
            # make sure that the provided JSON file exists
            if not os.path.isfile(json_path):
                error('Invalid JSON file: {}\n'.format(json_path))
                exit(1)

            self.json_path = json_path

        else:
            self.json_path = None

        if grpc_port is not None:
            self.grpc_port = grpc_port

        else:
            self.grpc_port = P4RuntimeSwitch.next_grpc_port
            P4RuntimeSwitch.next_grpc_port += 1

        if thrift_port is not None:
            self.thrift_port = thrift_port

        else:
            self.thrift_port = P4RuntimeSwitch.next_thrift_port
            P4RuntimeSwitch.next_thrift_port += 1

        if check_listening_on_port(self.grpc_port):
            error('%s cannot bind port %d because it is bound by another process\n' % (self.name, self.grpc_port))
            exit(1)

        self.verbose = verbose
        logfile = '/tmp/p4s.{}.log'.format(self.name)
        self.output = open(logfile, 'w')
        self.pcap_dump = pcap_dump
        self.enable_debugger = enable_debugger
        self.log_console = log_console

        if log_file is not None:
            self.log_file = log_file

        else:
            self.log_file = '/tmp/p4s.{}.log'.format(self.name)

        if device_id is not None:
            self.device_id = device_id
            P4Switch.device_id = max(P4Switch.device_id, device_id)

        else:
            self.device_id = P4Switch.device_id
            P4Switch.device_id += 1

        self.nanomsg = 'ipc:///tmp/bm-{}-log.ipc'.format(self.device_id)
        self.cpu_port = CPU_PORT

    def check_switch_started(self, pid):
        for _ in range(SWITCH_START_TIMEOUT * 2):
            if not os.path.exists(os.path.join('/proc', str(pid))):
                return False

            if check_listening_on_port(self.grpc_port):
                return True

            sleep(0.5)

    def start(self, controllers):
        info('Starting P4 switch {}.\n'.format(self.name))

        args = [self.sw_path]
        for port, intf in self.intfs.items():
            if not intf.IP():
                args.extend(['-i', str(port-1) + '@' + intf.name])

        if self.pcap_dump:
            args.append('--pcap %s' % self.pcap_dump)

        if self.nanomsg:
            args.extend(['--nanolog', self.nanomsg])

        args.extend(['--device-id', str(self.device_id)])
        P4Switch.device_id += 1

        if self.json_path:
            args.append(self.json_path)

        else:
            args.append('--no-p4')

        if self.enable_debugger:
            args.append('--debugger')

        args.append("--log-level trace")
        args.append("--log-flush")
        
        if self.log_console:
            args.append('--log-console')

        if self.thrift_port:
            args.append('--thrift-port ' + str(self.thrift_port))

        if self.grpc_port:
            args.append('-- --grpc-server-addr 0.0.0.0:' + str(self.grpc_port))

        if self.cpu_port:
            args.append('--cpu-port ' + str(self.cpu_port))

        cmd = ' '.join(args)
        info(cmd + '\n')

        with tempfile.NamedTemporaryFile() as f:
            self.cmd(cmd + ' >' + self.log_file + ' 2>&1 & echo $! >> ' + f.name)
            pid = int(f.read())
        debug('P4 switch {} PID is {}.\n'.format(self.name, pid))
        debug('CPU port is {}.\n'.format(self.cpu_port))

        if not self.check_switch_started(pid):
            error('P4 switch {} did not start correctly.\n'.format(self.name))
            exit(1)
        info('P4 switch {} has been started.\n'.format(self.name))
