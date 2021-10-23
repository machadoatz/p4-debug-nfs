#!/usr/bin/env python3

import sys

import grpc
from google.rpc import status_pb2, code_pb2
from p4.v1 import p4runtime_pb2
import traceback


class P4RuntimeErrorFormatException(Exception):
    """
    Used to indicate that the gRPC error Status object returned by the server has
    an incorrect format.
    """

    def __init__(self, message):
        super(P4RuntimeErrorFormatException, self).__init__(message)


def parse_grpc_error_binary_details(grpc_error):
    """
    Parse the binary details of the gRPC error. This is required to print some
    helpful debugging information in tha case of batched Write / Read
    requests. Returns None if there are no useful binary details and throws
    P4RuntimeErrorFormatException if the error is not formatted
    properly. Otherwise, returns a list of tuples with the first element being the
    index of the operation in the batch that failed and the second element being
    the p4.Error Protobuf message.
    """

    if grpc_error.code() != grpc.StatusCode.UNKNOWN:
        return None
    error = None

    # The gRPC Python package does not have a convenient way to access the
    # binary details for the error: they are treated as trailing metadata.
    for meta in grpc_error.trailing_metadata():
        if meta[0] == 'grpc-status-details-bin':
            error = status_pb2.Status()
            error.ParseFromString(meta[1])
            break

    if error is None:  # no binary details field
        return None

    if len(error.details) == 0:
        # binary details field has empty Any details repeated field
        return None

    indexed_p4_errors = []
    for idx, one_error_any in enumerate(error.details):
        p4_error = p4runtime_pb2.Error()

        if not one_error_any.Unpack(p4_error):
            raise P4RuntimeErrorFormatException('Cannot convert Any message to p4.Error')

        if p4_error.canonical_code == code_pb2.OK:
            continue

        indexed_p4_errors += [(idx, p4_error)]
    return indexed_p4_errors


def print_grpc_error(grpc_error):
    """
    P4Runtime uses a 3-level message in case of an error during the processing of
    a write batch. This means that some care is required when printing the
    exception if we do not want to end-up with a non-helpful message in case of
    failure as only the first level will be printed. In this function, we extract
    the nested error message when present (one for each operation included in the
    batch) in order to print error code + user-facing message. See P4Runtime
    documentation for more details on error-reporting.
    """

    print('gRPC Error', grpc_error.details())
    status_code = grpc_error.code()
    print('({})'.format(status_code.name))
    print(traceback.format_exc())

    if status_code != grpc.StatusCode.UNKNOWN:
        return

    p4_errors = parse_grpc_error_binary_details(grpc_error)
    if p4_errors is None:
        return

    print('[*] errors in batch:')
    for idx, p4_error in p4_errors:
        code_name = code_pb2._CODE.values_by_number[p4_error.canonical_code].name
        print('\t* At index {}: {}, \'{}\'\n'.format(idx, code_name, p4_error.message))
