#!/usr/bin/env python3

import google.protobuf.text_format
from p4.config.v1 import p4info_pb2
from p4.v1 import p4runtime_pb2

from p4runtime_lib.connector.converter import Converter

CPU_PORT = 255  # default packet-in/packet-out port usage


class SwitchConnectorV2Helper(object):
    def __init__(self, p4_info_filepath):
        # read p4 info object into memory
        p4info = p4info_pb2.P4Info()

        # load the p4info file into a skeleton P4Info object
        with open(p4_info_filepath, 'r') as p4info_f:
            google.protobuf.text_format.Merge(p4info_f.read(), p4info)

        self.p4info = p4info

        # create a convert to convert between str and numbers/addresses
        self.converter = Converter()

    """
    getters
    """

    @staticmethod
    def __get_child_info_pb(obj: object, child_type: str, child_id: int = None, child_name: str = None):
        if not hasattr(obj, child_type):
            raise AssertionError('Entity \'{}\' does not exist.'.format(child_type))

        if child_id is None and child_name is None:
            raise AssertionError('A {} ID or name must be provided.'.format(child_type))

        for child in getattr(obj, child_type):
            if type(obj) == p4info_pb2.P4Info:
                lookup_child = child.preamble
            else:
                lookup_child = child

            if child_id:
                if child_id == lookup_child.id:
                    return child

            elif child_name:
                if child_name == lookup_child.name:
                    return child

        if child_id:
            raise AttributeError('Could not find {} with ID \'{}\'.'.format(child_type, child_id))
        else:
            raise AttributeError('Could not find {} with name \'{}\'.'.format(child_type, child_name))

    def get_table_info(self, table_id: int = None, table_name: str = None):
        return self.__get_child_info_pb(self.p4info, child_type='tables', child_id=table_id, child_name=table_name)

    def get_action_info(self, action_id: int = None, action_name: str = None):
        return self.__get_child_info_pb(self.p4info, child_type='actions', child_id=action_id, child_name=action_name)

    def get_action_param_info(self, action_info: p4info_pb2.Action, param_id: int = None, param_name: str = None):
        return self.__get_child_info_pb(obj=action_info, child_type='params', child_id=param_id, child_name=param_name)

    def get_match_field_info(self, table_info: p4info_pb2.Table, match_field_id: int = None,
                             match_field_name: str = None):
        return self.__get_child_info_pb(obj=table_info, child_type='match_fields', child_id=match_field_id,
                                        child_name=match_field_name)

    def get_controller_packet_metadata_info(self, controller_packet_metadata_id: int = None,
                                            controller_packet_metadata_name: str = None):
        return self.__get_child_info_pb(obj=self.p4info, child_type='controller_packet_metadata',
                                        child_id=controller_packet_metadata_id,
                                        child_name=controller_packet_metadata_name)

    def get_controller_packet_metadata_metadata_info(
            self,
            controller_packet_metadata_info: p4info_pb2.ControllerPacketMetadata = None,
            metadata_id: int = None, metadata_name: str = None
    ):
        return self.__get_child_info_pb(obj=controller_packet_metadata_info, child_type='metadata',
                                        child_id=metadata_id, child_name=metadata_name)

    """
    builders
    """

    def build_match_field_pb(self, match_field_info: p4info_pb2.MatchField, value: object = None):
        obj = p4runtime_pb2.FieldMatch()
        obj.field_id = match_field_info.id

        bitwidth = match_field_info.bitwidth
        match_type = match_field_info.match_type

        if match_type == p4info_pb2.MatchField.EXACT:
            exact = obj.exact
            exact.value = self.converter.encode(value, bitwidth)

        elif match_type == p4info_pb2.MatchField.TERNARY:
            assert isinstance(value, list) or isinstance(value, tuple)

            lpm = obj.ternary
            lpm.value = self.converter.encode(value[0], bitwidth)
            lpm.mask = self.converter.encode(value[1], bitwidth)

        elif match_type == p4info_pb2.MatchField.LPM:
            assert isinstance(value, list) or isinstance(value, tuple)

            lpm = obj.lpm
            lpm.value = self.converter.encode(value[0], bitwidth)
            lpm.prefix_len = value[1]

        elif match_type == p4info_pb2.MatchField.RANGE:
            assert isinstance(value, list) or isinstance(value, tuple)

            lpm = obj.range
            lpm.low = self.converter.encode(value[0], bitwidth)
            lpm.high = self.converter.encode(value[1], bitwidth)

        elif match_type == p4info_pb2.MatchField.OPTIONAL:
            optional = obj.optional
            optional.value = self.converter.encode(value, bitwidth)

        else:
            raise Exception('Unsupported match type \'{}\'.'.format(match_type))

        return obj

    @staticmethod
    def build_action_pb(action_info: p4info_pb2.Action, action_params_pb=None):
        obj = p4runtime_pb2.Action()

        assert isinstance(action_info, p4info_pb2.Action)
        obj.action_id = action_info.preamble.id

        if action_params_pb:
            obj.params.extend(action_params_pb)

        return obj

    @staticmethod
    def build_table_action_pb(action_pb: p4runtime_pb2.Action = None):
        obj = p4runtime_pb2.TableAction()

        if action_pb:
            obj.action.CopyFrom(action_pb)

        else:
            raise AssertionError('A type is required.')

        return obj

    def build_action_param_pb(self, action_param_info: p4info_pb2.Action.Param, value: object):
        obj = p4runtime_pb2.Action.Param()

        obj.param_id = action_param_info.id
        obj.value = self.converter.encode(value, action_param_info.bitwidth)

        return obj

    @staticmethod
    def build_table_entry_pb(table_info: p4info_pb2.Table, match_fields_pb: list = None,
                             table_action_pb: p4runtime_pb2.TableAction = None, idle_timeout_ns: int = 0):
        obj = p4runtime_pb2.TableEntry()

        assert isinstance(table_info, p4info_pb2.Table)
        obj.table_id = table_info.preamble.id

        if table_action_pb:
            assert isinstance(table_action_pb, p4runtime_pb2.TableAction)
            obj.action.CopyFrom(table_action_pb)

        if match_fields_pb:
            assert isinstance(match_fields_pb, list)
            obj.match.extend(match_fields_pb)

        if idle_timeout_ns:
            assert isinstance(idle_timeout_ns, int)
            obj.idle_timeout_ns = idle_timeout_ns

        return obj

    @staticmethod
    def __build_oneof(obj, **kwargs):
        # force oneof
        if len(kwargs) != 1:
            raise AssertionError('Exactly one parameter must be provided.')

        for item, value in kwargs.items():
            getattr(obj, item).CopyFrom(value)
            return obj

    @staticmethod
    def build_entity_pb(**kwargs):
        return SwitchConnectorV2Helper.__build_oneof(p4runtime_pb2.Entity(), **kwargs)

    @staticmethod
    def build_update_pb(type_pb: p4runtime_pb2.Update, entity_pb: p4runtime_pb2.Entity):
        obj = p4runtime_pb2.Update()

        obj.type = type_pb
        obj.entity.CopyFrom(entity_pb)

        return obj

    @staticmethod
    def build_write_request_pb(device_id: int, updates_pb: list = None):
        obj = p4runtime_pb2.WriteRequest()

        obj.device_id = device_id
        obj.election_id.low = 1
        obj.updates.extend(updates_pb)

        return obj

    @staticmethod
    def build_replica_pb(egress_port: int, instance: int):
        obj = p4runtime_pb2.Replica()

        obj.egress_port = egress_port
        obj.instance = instance

        return obj

    @staticmethod
    def build_multicast_group_entry_pb(multicast_group_id: int, replicas_pb: list = None):
        obj = p4runtime_pb2.MulticastGroupEntry()

        obj.multicast_group_id = multicast_group_id
        if replicas_pb:
            obj.replicas.extend(replicas_pb)

        return obj

    @staticmethod
    def build_packet_replication_engine_entry_pb(**kwargs):
        return SwitchConnectorV2Helper.__build_oneof(p4runtime_pb2.PacketReplicationEngineEntry(), **kwargs)

    @staticmethod
    def build_master_arbitration_update_pb(device_id: int):
        obj = p4runtime_pb2.MasterArbitrationUpdate()

        obj.device_id = device_id
        obj.election_id.low = 1
        obj.election_id.high = 0

        return obj

    @staticmethod
    def build_stream_message_request(**kwargs):
        return SwitchConnectorV2Helper.__build_oneof(p4runtime_pb2.StreamMessageRequest(), **kwargs)

    @staticmethod
    def build_forwarding_pipeline_config(p4info_pb: p4info_pb2.P4Info, p4_device_config: bytes):
        obj = p4runtime_pb2.ForwardingPipelineConfig()

        obj.p4info.CopyFrom(p4info_pb)
        obj.p4_device_config = p4_device_config

        return obj

    @staticmethod
    def build_set_forwarding_pipeline_config_request(device_id: int,
                                                     action_enum: p4runtime_pb2.SetForwardingPipelineConfigRequest,
                                                     config_pb: p4runtime_pb2.ForwardingPipelineConfig):
        obj = p4runtime_pb2.SetForwardingPipelineConfigRequest()

        obj.device_id = device_id
        obj.election_id.low = 1
        obj.action = action_enum
        obj.config.CopyFrom(config_pb)

        return obj

    @staticmethod
    def build_packet_metadata_pb(metadata_id: int, value: bytes):
        obj = p4runtime_pb2.PacketMetadata()

        obj.metadata_id = metadata_id
        obj.value = value

        return obj

    @staticmethod
    def build_packet_out(payload, metadata_pb: list = None):
        obj = p4runtime_pb2.PacketOut()

        obj.payload = payload
        if metadata_pb:
            obj.metadata.extend(metadata_pb)

        return obj

    @staticmethod
    def build_read_request_pb(device_id: int, entities_pb: list = None):
        obj = p4runtime_pb2.ReadRequest()

        obj.device_id = device_id
        if entities_pb:
            obj.entities.extend(entities_pb)

        return obj
