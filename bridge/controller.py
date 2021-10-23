import argparse
import os
import time
import grpc
from scapy.layers.l2 import Ether

from p4runtime_lib.connector.connector import SwitchConnectorV2
from p4runtime_lib.connector.error import print_grpc_error
from p4runtime_lib.connector.helper import SwitchConnectorV2Helper


def install_multicast_group(sw: SwitchConnectorV2):
    sw.write_multicast_group_entry(
        multicast_group_id=1,
        replicas={
            1: 1,  # egress_port: instance
            2: 2
        }
    )

    print('[*] installed multicast group')


def get_ingress_port(helper: SwitchConnectorV2Helper, metadata, packet_in_info):
    return helper.converter.decode(
        encoded_bytes=metadata.value,
        bitwidth=helper.get_controller_packet_metadata_metadata_info(
            controller_packet_metadata_info=packet_in_info,
            metadata_id=metadata.metadata_id
        ).bitwidth
    )


def learn_mac_address(sw: SwitchConnectorV2, mac_addr: str, ingress_port: int):
    sw.write_table_entries({
        'MyIngress.mac_src': [
            {
                'match_fields': {
                    'hdr.ethernet.srcAddr': mac_addr
                },
                'action_name': 'NoAction'
            }
        ],

        'MyIngress.mac_dst': [
            {
                'match_fields': {
                    'hdr.ethernet.dstAddr': mac_addr
                },
                'action_name': 'MyIngress.forward',
                'action_params': {
                    'egress_port': ingress_port
                },
                'idle_timeout_ns': 600000000000
            } 
        ]
    })

def main(grpc_addr, p4info_file_path, bmv2_json_file_path):
    helper = SwitchConnectorV2Helper(p4_info_filepath=p4info_file_path)

    s1 = SwitchConnectorV2(
        name='s1',
        grpc_addr=grpc_addr,
        helper=helper,
        device_id=0,
        proto_dump_file='logs/s1-p4runtime-requests.txt'
    )

    controller_access = 0
    deleted_entries = 0
    first_run = True
    timeout_controller = 0
    while True:
        try:
            # establish this controller as primary
            s1.make_primary()

            if first_run:
                first_run = False

                # install the P4 program on the switch
                s1.install_program(bmv2_json_file_path=bmv2_json_file_path)

                install_multicast_group(sw=s1)

            # get metadata information
            packet_in_info = helper.get_controller_packet_metadata_info(
                controller_packet_metadata_name='packet_in'  # according to the p4 header
            )

            while True:
                # receive message and parse it
                message = s1.receive_stream_message_response_pb()
                update = message.WhichOneof('update')

                if update == 'packet':
                    controller_access += 1
                    print('[*] {} packets sent to controller'.format(controller_access))
                    pkt = message.packet.payload

                    # rebuild input packet (which is of type Ether)
                    src_mac_addr = Ether(pkt).getlayer(Ether).src

                    # get the ingress port from the packet_in metadata (entry 0)
                    ingress_port = get_ingress_port(
                        helper=helper,
                        metadata=message.packet.metadata[0],
                        packet_in_info=packet_in_info
                    )

                    # register new mac address
                    learn_mac_address(
                        sw=s1,
                        mac_addr=src_mac_addr,
                        ingress_port=ingress_port
                    )

                    # send packet out to make sure flood happens if destination is unknown
                    s1.send_packet_out(
                        packet=pkt,
                        metadata={
                            'ingress_port': ingress_port
                        }
                    )


                elif update == 'idle_timeout_notification':
                    message = message.idle_timeout_notification
                    
                    # remove all table entries that have expired
                    s1.delete_table_entries(
                        table_entries=message.table_entry
                    )
                    deleted_entries += 1
                    print('[*] {} packets deleted'.format(deleted_entries))

        except KeyboardInterrupt:
            print('[*] shutting down')
            break

        except grpc.RpcError as e:
           timeout_controller += 1
           if timeout_controller  == 350:
              print("DEAD SWITCH")
              print_grpc_error(e)
              break
# time.sleep(10)

    #SwitchConnectorV2.shutdown_connectors()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--grpc-addr', help='gRPC address',
                        type=str, action='store', required=True)
    parser.add_argument('--p4info', help='p4info proto in text format from p4c', type=str, action='store',
                        required=True)
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action='store', required=True)
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print(
            '\np4info file not found: %s\nHave you run \'make [compile]\'?' % args.p4info)
        parser.exit(1)

    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print(
            '\nBMv2 JSON file not found: %s\nHave you run \'make [compile]\'?' % args.bmv2_json)
        parser.exit(1)

    main(args.grpc_addr, args.p4info, args.bmv2_json)
