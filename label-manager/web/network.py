import pyshark

def captureTraffic(interface='wlp3s0', session):

    # Flush existing bandwidth limitation
    flushNetworkLimitation(interface)

    # Enforce new bandwidth limitation
    enforceNetworkLimitation(interface, session)

    capture = pyshark.LiveCapture(interface=interface, output_file=getPcapFileFromSession(session))
    capture.sniff(timeout=session.training.session_duration)
    return

def flushNetworkLimitation(interface='wlp3s0'):
    # TODO
    return

def enforceNetworkLimitation(interface='wlp3s0', session):
    # TODO
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