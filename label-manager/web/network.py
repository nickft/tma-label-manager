import pyshark

def captureTraffic(interface='wlp3s0', session=None):
    capture = pyshark.LiveCapture(interface=interface, output_file="/code/captured/session_{}_training_{}.pcap".format(session.id, session.training.id))
    capture.sniff(timeout=session.training.session_duration)
    return