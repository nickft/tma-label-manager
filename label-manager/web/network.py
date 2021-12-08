import pyshark
import os
from django.conf import settings
import statistics
import json  
import subprocess
import re
import time
import signal

def captureTraffic(interface, session):

    # Flush existing bandwidth rules
    flushNetworkLimitation(interface)

    # Enforce new bandwidth limitation
    # enforceNetworkLimitation(interface, session)
   
    devnull = open('/dev/null', 'w')
    #p = subprocess.Popen(["tstat","-li",interface,"-s", getPcapFileFromSession(session)], stdout=devnull, shell=False)
    
    p = subprocess.Popen(["tcpdump","-s 0", "-i", interface,"-w", getPcapFileFromSession(session)], stdout=devnull, shell=False)

    print("Start Network Capturing. It will last for {} seconds".format(session.training.session_duration))
    time.sleep(session.training.session_duration)

    print("Killing Network Capturing")
    p.send_signal(signal.SIGINT)

    # Flush applied bandwidth rules
    flushNetworkLimitation(interface)

    print("Finished network capturing")

    return

def flushNetworkLimitation(interface):
    os.system("echo flush {}>{}".format(interface, settings.BW_LIMITATION_PIPE))
    return

def enforceNetworkLimitation(interface, session):

    if(session.bw_limitation == -1):
        return

    # Calculate correct value for Kbps
    bandwidth = session.bw_limitation * 1024

    os.system("echo enforce {} {}>{}".format(interface, bandwidth, settings.BW_LIMITATION_PIPE))

    return

def getTstatStatistics(session):

    input_file = getPcapFileFromSession(session)

    statistics_dir = getTstatOutputFromSession(session)

    tstatExecute(input_file, statistics_dir)

    # Get statistics in json format
    statistics = fromTstatToJson(statistics_dir)

    return statistics

# This function is never called leaving it here for reference
def tstatExecute(input_file, statistics_dir):

    # capture directory:
    os.chdir(settings.CAPTURED_DIR)
    bash_command = "tstat {pcap} -s {out}".format(pcap=input_file, out=statistics_dir)

    os.system(bash_command)

    os.remove(input_file)

def fromTstatToJson(statistics_dir):
    os.chdir(statistics_dir)

    # Access to the latest modified folder
    all_subdirs = [d for d in os.listdir('.') if os.path.isdir(d)]
    latest_subdir = max(all_subdirs, key=os.path.getmtime)
    os.chdir(latest_subdir)

    # Open the tcp complete doc
    logs = open("log_tcp_complete").readlines()

    if(len(logs) == 1):
        print("ERROR: No TCP flows were analyzed. Discarding session")
        return None

    # Basic TCP Set
    packets = []                # total number of packets observed form the client/server
    data_pkts = []              # number of bytes transmitted in the payload, including retransmissions
    data_bytes = []             # number of bytes transmitted in the payload, including retransmissions
    rexmit_pkts = []            # number of retransmitted segments
    rexmit_bytes = []           # number of retransmitted bytes
    # TCP End to End
    rtt_avg = []                # Average RTT computed measuring the time elapsed between the data segment and the corresponding ACK
    rtt_min = []                # Minimum RTT observed during connection lifetime
    rtt_max = []                # Maximum RTT observed during connection lifetime
    stdev_rtt = []              # Standard deviation of the RTT
    rtt_count = []              # Standard deviation of the RTT
    ttl_min = []                # Standard deviation of the RTT
    ttl_max = []                # Standard deviation of the RTT
    # TCP Options
    max_seg_size = []           # Maximum segment size observed
    min_seg_size = []           # Minimum segment size observed
    win_max = []                # Maximum receiver window announced (already scale by the window scale factor)
    win_min = []                # Maximum receiver window announced (already scale by the window scale factor)
    rtx_RTO = []                # Number of retransmitted segments due to timeout expiration
    rtx_FR = []                 # Number of retransmitted segments due to Fast Retransmit (three dup-ack)
    reordering = []             # Number of packet reordering observed
    net_dup = []                # Number of network duplicates observed
    flow_control = []           # Number of retransmitted segments to probe the receiver window
    unnece_rtx_RTO = []         # Number of unnecessary transmissions following a timeout expiration
    unnece_rtx_FR  = []         # Number of unnecessary transmissions following a fast retransmit

    for x in logs:
        packets.append((x.split(' ')[2]))
        data_pkts.append((x.split(' ')[7]))
        data_bytes.append((x.split(' ')[8]))
        rexmit_pkts.append((x.split(' ')[9]))
        rexmit_bytes.append((x.split(' ')[10]))
        rtt_avg.append((x.split(' ')[44]))
        rtt_min.append((x.split(' ')[45]))
        rtt_max.append((x.split(' ')[46]))
        stdev_rtt.append((x.split(' ')[47]))
        rtt_count.append((x.split(' ')[48]))
        ttl_min.append((x.split(' ')[49]))
        ttl_max.append((x.split(' ')[50]))
        max_seg_size.append((x.split(' ')[70]))
        min_seg_size.append((x.split(' ')[71]))
        win_max.append((x.split(' ')[72]))
        win_min.append((x.split(' ')[73]))
        rtx_RTO.append((x.split(' ')[78]))
        rtx_FR.append((x.split(' ')[79]))
        reordering.append((x.split(' ')[80]))
        net_dup.append((x.split(' ')[81]))
        flow_control.append((x.split(' ')[83]))
        unnece_rtx_RTO.append((x.split(' ')[84]))
        unnece_rtx_FR.append((x.split(' ')[85]))

    # Cast all the list elements into floats
    for i in range(len(rtt_avg)):
        if i != 0:
            packets[i] = float(packets[i])
            data_pkts[i] = float(data_pkts[i])
            data_bytes[i] = float(data_bytes[i])
            rexmit_pkts[i] = float(rexmit_pkts[i])
            rexmit_bytes[i] = float(rexmit_bytes[i])
            rtt_avg[i] = float(rtt_avg[i])
            rtt_min[i] = float(rtt_min[i])
            rtt_max[i] = float(rtt_max[i])
            stdev_rtt[i] = float(stdev_rtt[i])
            rtt_count[i] = float(rtt_count[i])
            ttl_min[i] = float(ttl_min[i])
            ttl_max[i] = float(ttl_max[i])
            max_seg_size[i] = float(max_seg_size[i])
            min_seg_size[i] = float(min_seg_size[i])
            win_max[i] = float(win_max[i])
            win_min[i] = float(win_min[i])
            rtx_RTO[i] = float(rtx_RTO[i])
            rtx_FR[i] = float(rtx_FR[i])
            reordering[i] = float(reordering[i])
            net_dup[i] = float(net_dup[i])
            flow_control[i] = float(flow_control[i])
            unnece_rtx_RTO[i] = float(unnece_rtx_RTO[i])
            unnece_rtx_FR[i] = float(unnece_rtx_FR[i])
          
    # Average calculation between all the collected flows
    packets = sum(packets[1:])     
    data_pkts = sum(data_pkts[1:])
    data_bytes = statistics.fmean(data_bytes[1:])
    rexmit_pkts = sum(rexmit_pkts[1:])
    rexmit_bytes = sum(rexmit_bytes[1:])
    rtt_avg = statistics.fmean(rtt_avg[1:])         
    rtt_min = statistics.fmean(rtt_min[1:])     
    rtt_max = statistics.fmean(rtt_max[1:])        
    stdev_rtt = statistics.fmean(stdev_rtt[1:])   
    rtt_count = sum(rtt_count[1:])
    ttl_min = statistics.fmean(ttl_min[1:])
    ttl_max = statistics.fmean(ttl_max[1:])
    max_seg_size = statistics.fmean(max_seg_size[1:])
    min_seg_size = statistics.fmean(min_seg_size[1:])
    win_max = statistics.fmean(win_max[1:])
    win_min = statistics.fmean(win_min[1:])
    rtx_RTO = sum(rtx_RTO[1:])      
    rtx_FR =  sum(rtx_FR[1:])
    reordering = sum(reordering[1:])
    net_dup = sum(net_dup[1:])
    flow_control = sum(flow_control[1:])
    unnece_rtx_RTO = sum(unnece_rtx_RTO[1:])
    unnece_rtx_FR = sum(unnece_rtx_FR[1:])
    
    json_syntax = ["packets", "data_pkts", "data_bytes", "rexmit_pkts", "rexmit_bytes", "rtt_avg", "rtt_min", "rtt_max", "stdev_rtt", "rtt_count", "reordering", "ttl_min", "ttl_max", "max_seg_size" , "min_seg_size", "win_max", "win_min", "rtx_RTO", "rtx_FR", "reordering", "net_dup", "flow_control", "unnece_rtx_RTO", "unnece_rtx_FR"]
    jsonList = ({json_syntax[0] : packets, json_syntax[1] : data_pkts, json_syntax[2] : data_bytes, json_syntax[3] : rexmit_pkts, json_syntax[4] : rexmit_bytes, json_syntax[5] : rtt_avg, json_syntax[6] : rtt_min, json_syntax[7] : rtt_max, json_syntax[8] : stdev_rtt, json_syntax[9] : rtt_count, json_syntax[10] : ttl_min, json_syntax[11] : ttl_max, json_syntax[12] : max_seg_size, json_syntax[13] : min_seg_size, json_syntax[14] : win_max, json_syntax[15] : win_min, json_syntax[16] : rtx_RTO, json_syntax[17] : rtx_FR, json_syntax[18] : reordering, json_syntax[19] : net_dup, json_syntax[20] : flow_control, json_syntax[21] : unnece_rtx_RTO, json_syntax[22] : unnece_rtx_FR})


    # For debug purpose
    # output_file = str(input_file)+".json"
    # with open (output_file, "w") as outfile:
    #     outfile.write(json.dumps(jsonList))

    return(json.dumps(jsonList))

def getPcapFileFromSession(session):
    return settings.CAPTURED_DIR+"/training_{}_session_{}.pcap".format(session.training.id, session.id)

def getTstatOutputFromSession(session):
    return settings.CAPTURED_DIR+"/training_{}_session_{}".format(session.training.id, session.id)
