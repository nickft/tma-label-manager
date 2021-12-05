import pyshark
import os
from django.conf import settings

def captureTraffic(interface, session):

    # Flush existing bandwidth rules
    flushNetworkLimitation(interface)

    # Enforce new bandwidth limitation
    # enforceNetworkLimitation(interface, session)

    capture = pyshark.LiveCapture(interface=interface, output_file=getPcapFileFromSession(session))
    capture.sniff(timeout=session.training.session_duration)

    # Flush applied bandwidth rules
    flushNetworkLimitation(interface)

    return

def flushNetworkLimitation(interface):

    os.system("echo flush {}>{}".format(interface, settings.BW_LIMITATION_PIPE))

    return

def enforceNetworkLimitation(interface, session):

    if(session.bw_limitation == -1):
        return

    #TODO Calculate correct value for Kbps
    bandwidth = session.bw_limitation

    os.system("echo enforce {} {}>{}".format(interface, bandwidth, settings.BW_LIMITATION_PIPE))

    return

def getTstatStatistics(interface, session):

    input_file = getPcapFileFromSession(session)

    # Get statistics executing Tstat tool
    statistics_as_string = tstatExecute(input_file)

    # Express statistics in json format
    statistics_as_json = fromTstatToJson(statistics_as_string)

    return statistics_as_json

def tstatExecute(input_file):
    # TODO
    return ""

def fromTstatToJson(statistics_as_string):
    # TODO
    return '{"pckt_size": 500,"avgSize": 10}'


def getPcapFileFromSession(session):
    return "/code/captured/session_{}_training_{}.pcap".format(session.id, session.training.id)