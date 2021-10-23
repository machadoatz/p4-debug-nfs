#!/usr/bin/env python3

from datetime import datetime
from queue import Queue

import grpc
from p4.v1 import p4runtime_pb2, p4runtime_pb2_grpc
import pprint
from p4runtime_lib.connector.helper import SwitchConnectorV2Helper


class SwitchConnectorV2(object):
    __connectors = []

    def __init__(self, name: str, grpc_addr: str, helper: SwitchConnectorV2Helper, device_id=0, proto_dump_file=None):
        # basic properties of the switch
        self.name = name
        self.grpc_addr = grpc_addr
        self.device_id = device_id

        # insecure channel to the switch
        self.channel = grpc.insecure_channel(self.grpc_addr)

        # if a dump file is provided, intercept channel and dump requests to file
        if proto_dump_file is not None:
            interceptor = GrpcRequestLogger(proto_dump_file)
            self.channel = grpc.intercept_channel(self.channel, interceptor)

        # create client stub
        self.stub = p4runtime_pb2_grpc.P4RuntimeStub(self.channel)

        # initialize bidirectional stream
        self.requests_stream = IterableQueue()
        self.responses_stream = self.stub.StreamChannel(
            iter(self.requests_stream))

        # memorize this connector to facilitate connection shutdown
        self.__connectors.append(self)
        # store connector helper to help build objects
        self.helper = helper

    @staticmethod
    def shutdown_connectors():
        for connector in SwitchConnectorV2.__connectors:
            connector.shutdown()

    def shutdown(self):
        self.requests_stream.close()
        self.responses_stream.cancel()

    def make_primary(self):
        self.requests_stream.put(
            self.helper.build_stream_message_request(
                arbitration=self.helper.build_master_arbitration_update_pb(
                    device_id=self.device_id
                )
            )
        )

        res = None
        for item in self.responses_stream:
            res = item
            break

        if res is None:
            print('[*] did not receive the arbitration update response')
            exit(1)

        notif = res.arbitration
        notif_status_code = notif.status.code

        if notif_status_code == grpc.StatusCode.ALREADY_EXISTS.value[0]:
            print('[*] a primary controller already exists')
            exit(1)
        elif notif_status_code == grpc.StatusCode.OK.value[0]:
            print('[*] this controller is now primary')
        else:
            print('[*] cannot parse arbitration update response')
            exit(1)

    @staticmethod
    def __get_p4_device_config(bmv2_json_file_path: str):
        """
        Unsure about the correctness of this method.
        See https://ask.csdn.net/questions/3756951.
        """

        with open(bmv2_json_file_path, 'rb') as bmv2_json_f:
            return bmv2_json_f.read()

    def install_program(self, bmv2_json_file_path: str):
        self.stub.SetForwardingPipelineConfig(
            self.helper.build_set_forwarding_pipeline_config_request(
                device_id=self.device_id,
                action_enum=p4runtime_pb2.SetForwardingPipelineConfigRequest.VERIFY_AND_COMMIT,
                config_pb=self.helper.build_forwarding_pipeline_config(
                    p4info_pb=self.helper.p4info,
                    p4_device_config=self.__get_p4_device_config(
                        bmv2_json_file_path)
                )
            )
        )

        print('[*] installed the P4 program on switch {}'.format(self.device_id))

    """
    read operations
    """

    def read_table_entries(self, table_name: str, match_fields: dict = None):
        table_info = self.helper.get_table_info(
            table_name=table_name
        )

        match_fields_pb = []
        if match_fields:
            for name, value in match_fields.items():
                match_field_info = self.helper.get_match_field_info(
                    table_info=table_info,
                    match_field_name=name
                )

                match_fields_pb.append(
                    self.helper.build_match_field_pb(
                        match_field_info=match_field_info,
                        value=self.helper.converter.encode(
                            x=value,
                            bitwidth=match_field_info.bitwidth
                        )
                    )
                )

        return list(self.stub.Read(
            self.helper.build_read_request_pb(
                device_id=self.device_id,
                entities_pb=[
                    self.helper.build_entity_pb(
                        table_entry=self.helper.build_table_entry_pb(
                            table_info=table_info,
                            match_fields_pb=match_fields_pb
                        )
                    )
                ]
            )
        ))

    """
    write operations
    """

    def write_multicast_group_entry(self, multicast_group_id: int, replicas):
        assert isinstance(replicas, dict)
        replicas_pb = [self.helper.build_replica_pb(
            egress_port=port,
            instance=instance
        ) for port, instance in replicas.items()]

        self.stub.Write(
            self.helper.build_write_request_pb(
                device_id=self.device_id,
                updates_pb=[
                    self.helper.build_update_pb(
                        type_pb=p4runtime_pb2.Update.INSERT,
                        entity_pb=self.helper.build_entity_pb(
                            packet_replication_engine_entry=self.helper.build_packet_replication_engine_entry_pb(
                                multicast_group_entry=self.helper.build_multicast_group_entry_pb(
                                    multicast_group_id=multicast_group_id,
                                    replicas_pb=replicas_pb
                                )
                            )
                        )
                    )
                ]
            )
        )

    def write_table_entries(self, table_entries: dict = None):
        # fixme remove line below
        #pprint.pprint(table_entries)

        updates_pb = []
        for table_name, table_entries_lst in table_entries.items():
            table_info = self.helper.get_table_info(table_name=table_name)

            for table_entry in table_entries_lst:
                action_info = self.helper.get_action_info(
                    action_name=table_entry['action_name'])

                match_fields_pb = [self.helper.build_match_field_pb(
                    match_field_info=self.helper.get_match_field_info(
                        table_info=table_info, match_field_name=name),
                    value=value
                ) for name, value in table_entry['match_fields'].items()]

                action_params_pb = []
                if 'action_params' in table_entry:
                    action_params_pb.extend(self.helper.build_action_param_pb(
                        action_param_info=self.helper.get_action_param_info(
                            action_info=action_info, param_name=name),
                        value=value
                    ) for name, value in table_entry['action_params'].items())

                updates_pb.append(
                    self.helper.build_update_pb(
                        type_pb=p4runtime_pb2.Update.INSERT,
                        entity_pb=self.helper.build_entity_pb(
                            table_entry=self.helper.build_table_entry_pb(
                                table_info=table_info,
                                match_fields_pb=match_fields_pb,
                                table_action_pb=self.helper.build_table_action_pb(
                                    action_pb=self.helper.build_action_pb(
                                        action_info=action_info,
                                        action_params_pb=action_params_pb
                                    )
                                ),
                                idle_timeout_ns=table_entry[
                                    'idle_timeout_ns'] if 'idle_timeout_ns' in table_entry else None
                            )
                        )
                    )
                )

        self.stub.Write(
            self.helper.build_write_request_pb(
                device_id=self.device_id,
                updates_pb=updates_pb
            )
        )

    def write_table_entry(self, table_name: str, action_name: str, match_fields: dict, action_params=None,
                          idle_timeout_ns=None):
        self.write_table_entries({
            table_name: [
                {
                    'match_fields': match_fields,
                    'action_name': action_name,
                    'action_params': action_params,
                    'idle_timeout_ns': idle_timeout_ns
                }
            ]
        })

    """
    delete operations
    """

    def delete_table_entries(self, table_entries):
        self.stub.Write(
            self.helper.build_write_request_pb(
                device_id=self.device_id,
                updates_pb=[
                    self.helper.build_update_pb(
                        type_pb=p4runtime_pb2.Update.DELETE,
                        entity_pb=self.helper.build_entity_pb(
                            table_entry=table_entry
                        )
                    ) for table_entry in table_entries
                ]
            )
        )

    def delete_table_entry(self, table_entry):
        self.delete_table_entries(table_entries=[
            table_entry
        ])

    """
    modify operations
    """

    def modify_table_entries(self, table_entries):
        self.stub.Write(
            self.helper.build_write_request_pb(
                device_id=self.device_id,
                updates_pb=[
                    self.helper.build_update_pb(
                        type_pb=p4runtime_pb2.Update.MODIFY,
                        entity_pb=self.helper.build_entity_pb(
                            table_entry=table_entry
                        )
                    ) for table_entry in table_entries
                ]
            )
        )

    def modify_table_entry(self, table_entry):
        self.modify_table_entries(table_entries={
            table_entry
        })

    """
    stream operations
    """

    def receive_stream_message_response_pb(self):
        for message in self.responses_stream:
            return message

    def send_packet_out(self, packet, metadata=None):
        packet_out_info = self.helper.get_controller_packet_metadata_info(
            controller_packet_metadata_name='packet_out'
        )

        metadata_lst = []
        for name, value in metadata.items():
            metadata_info = self.helper.get_controller_packet_metadata_metadata_info(
                controller_packet_metadata_info=packet_out_info,
                metadata_name=name
            )

            metadata_lst.append(self.helper.build_packet_metadata_pb(
                metadata_id=metadata_info.id,
                value=self.helper.converter.encode(
                    x=value,
                    bitwidth=metadata_info.bitwidth
                )
            ))

        self.requests_stream.put(
            self.helper.build_stream_message_request(
                packet=self.helper.build_packet_out(
                    payload=packet,
                    metadata_pb=metadata_lst
                )
            )
        )


class GrpcRequestLogger(grpc.UnaryUnaryClientInterceptor, grpc.UnaryStreamClientInterceptor):
    """
    Implementation of a gRPC interceptor that logs requests to a file.
    """

    __MSG_LOG_MAX_LEN = 1024

    def __init__(self, log_file):
        self.log_file = log_file
        with open(self.log_file, 'w') as f:
            # Clear content if it exists.
            f.write('')

    def log_message(self, method_name, body):
        with open(self.log_file, 'a') as f:
            ts = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            msg = str(body)
            f.write('\n[%s] %s\n---\n' % (ts, method_name))

            if len(msg) < self.__MSG_LOG_MAX_LEN:
                f.write(str(body))

            else:
                f.write('Message too long (%d bytes)! Skipping log...\n' % len(msg))

            f.write('---\n')

    def intercept_unary_unary(self, continuation, client_call_details, request):
        self.log_message(client_call_details.method, request)
        return continuation(client_call_details, request)

    def intercept_unary_stream(self, continuation, client_call_details, request):
        self.log_message(client_call_details.method, request)
        return continuation(client_call_details, request)


class IterableQueue(Queue):
    _sentinel = object()

    def __iter__(self):
        return iter(self.get, self._sentinel)

    def close(self):
        self.put(self._sentinel)
