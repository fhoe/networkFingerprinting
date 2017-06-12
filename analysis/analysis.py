import os
import re
import sys
from matplotlib import pyplot as plt
import numpy as np
import collections
import ipaddress as ip
import matplotlib.font_manager as fm
from matplotlib import rc
import operator
from pathlib import Path



#global variables
responses = {}
tos = {}
mpls = {}




def graph_ecdf():
    """ Draw a ecdf graph that represents the distribution of ITTLs value"""

    labels = ['time-expired', 'tcp', 'echo', 'timestamp', 'port unreachable']
    colors = ['b', 'r', 'm', 'g', 'k']
    lines = ['solid' ,'dashed', 'dashdot', 'dotted' , 'dashdot']
    plt.figure(figsize=(12, 9))
    plt.rc('font', family='serif', serif='Palatino') 
    ax = plt.subplot(111)
    
    
    for idx in range(0,5):
        data = np.empty(len(responses))
        i = 0
        for (key,val) in responses.items():

            if val[idx] == 32:
                data[i] = 0
            elif val[idx] == 64:
                data[i] = 1
            elif val[idx] == 128:
                data[i] = 2
            elif val[idx] == 255:
                data[i] = 3
            elif val[idx] == -1:
                data[i] = 4
            
            i += 1
         
                
        uni = np.array([0,1,2,3,4,5])
         
        plt.hist(data, bins = uni, normed=1, histtype='step', cumulative = True, linewidth=4.0, color=colors[idx], label = labels[idx], ls = lines[idx])
    
    
    ax.get_xaxis().tick_bottom()    
    ax.get_yaxis().tick_left()  
    plt.xlabel("TTL values", fontsize = 24)
    plt.ylabel("CDF", fontsize = 24)
    plt.xticks(uni, ['32', '64', '128', '255', '*', ''], fontsize = 22)
    plt.yticks(fontsize=20)
    plt.grid()
    axes = plt.gca()
    axes.set_xlim([-1,4.75])
    plt.legend(loc='upper left',fancybox=True, shadow=True)
    plt.savefig("ecdf.png")
    
    
    
def graph_ecdf_packet_size():
    """ Draw a ecdf graph that represents the distribution of packet lengths"""

    plt.figure(figsize=(12, 9))
    plt.rc('font', family='serif', serif='Palatino') 
    ax = plt.subplot(111)

    data = []
    i = 0
    for (key,val) in responses.items():

        if val[5] == 56:
            data.append(0)
        elif val[5] == 68:
            data.append(1)
        elif val[5] == 96:
            data.append(2)
        elif val[5] == 168:
            data.append(3)
        elif val[5] == 172:
            data.append(4)
        elif val[5] > 172:
            data.append(5)
        
        i += 1
     
            
    uni = np.array([0,1,2,3,4,5,6])
     
    plt.hist(data, bins = uni, normed=1, histtype='step', cumulative = True, linewidth=4.0)
    
    
    ax.get_xaxis().tick_bottom()    
    ax.get_yaxis().tick_left()  
    plt.xlabel(r"ICMP time-exceeded packet length", fontsize = 24)
    plt.ylabel(r"CDF", fontsize = 24)
    plt.xticks(uni, ['56', '68', '96', '168', '172', '> 172', ''], fontsize = 22)
    plt.yticks(fontsize=22)
    plt.grid()
    axes = plt.gca()
    axes.set_xlim([-1,5.75])
    axes.set_ylim([0,1.05])
    plt.tight_layout()
    plt.savefig("pcklengthecdf.eps")


    
def signature_freq():
    """ Calculate the frequency of each signature inferred
        
    """    
    
    data = responses.values()
    
    d = {}
    x = np.zeros(9)
    for cols in data:
        x[0] = cols[0]
        x[1] = cols[1]
        x[2] = cols[2]
        x[3] = cols[3]
        x[4] = cols[4]
        x[5] = cols[5]
        x[6] = cols[6]
        x[7] = cols[7]
        x[8] = cols[8]
        t = tuple(x)
        if t in d:
            d[t] += 1
        else:
            d[t] = 1
    
    sorted_d = sorted(d.items(), key=operator.itemgetter(1), reverse = True)
    
    arr = np.asarray(sorted_d)
    
    l = float(len(responses))
    
    for i in range(0,15):
        arr[i][1] /= l
        print arr[i]
    
    return

    
def echo_ts_compare():
    """
        compare the ittl of echo probes and ittl of timestamp probes
        calculate the proportion or values equal to each other
        non responses are ignored
        
            
        ret: the proportion of values that are equal
            
    """    
    
    count_resp_received = 0;
    count_same = 0
    for elem in responses.values():
        if elem[2] != -1 and elem[3] != -1:
            
            count_resp_received += 1
            if elem[2] == elem[3]:
                count_same += 1
    
    print "{0:.2f}".format(count_same/float(count_resp_received))

    return   


def resp_cmp(first, second):

    """
    Function to compare a signature with another signature
        
        Arg:    first: first signature
                second: second signature
                
        Ret:    0    if second already in first
                1    signature inconsistent
                -1   incorrect
                
                if inconsistent, returns the merged signature
    """

    
    
    new_sig = first
    
    inconst = False

    for i in range(0,9):
        if first[i] == second[i]:
            continue
        
        elif first[i] == -1:
            new_sig[i] = second[i]
            inconst = True
        
        elif second[i] == -1:
            inconst = True
        
        elif i == 5:#packet length
            if not (first[8] == 1 or second[8] == 1):#not because of MPLS labels
                return -1, None
        
        #if we arrive there, it means than one sig has a TOS and not the other
        #Choice has been made to indicate that the signature has TOS capabilities
        elif i == 7:#TOS
            new_sig[7] = 1 
        
        #same idea as TOS but for MPLS
        elif i == 8:#MPLS
            new_sig[8] = 1
        
        else:
            return -1, None
    
    if inconst:

        return 1, new_sig
    
    
    return 0, None
    
    
def exp_echo_prop():
    """
        bar graph corresponding to the proportion of the different
        2-tuples signature (time-exceeded, echo)
    """
    exp_ping = {}
    for elem in responses.values():
        time_exc = elem[0]
        echo = elem[2]
        if echo == -1:
            echo = '*'
        exp_ping_key = (time_exc, echo)
        
        if not exp_ping_key in exp_ping:
            exp_ping[exp_ping_key] = 0
        exp_ping[exp_ping_key] += 1
    
    tot = sum(exp_ping.values())
    valSorted = []
    keySorted = []
    other = 0
    for k in sorted(exp_ping, key=exp_ping.get, reverse = True):
        per = exp_ping[k]/float(tot)
        if per > 0.01:
            valSorted.append(per)
            keySorted.append(k)
        else:
            other += per
        
    valSorted.append(other)
    keySorted.append('other')
    


    plt.figure(figsize=(12, 9))
    ax = plt.subplot(111)
    x = np.arange(len(valSorted))
    ax.bar(x + 0.1, valSorted,width=0.2,color='b',align='center')
    ax.get_xaxis().tick_bottom()    
    ax.get_yaxis().tick_left() 
 
    plt.xlabel("TTL expired - ping pairs", fontsize = 24)
    plt.ylabel("Proportion", fontsize = 24)
    plt.xticks(x + 0.1, keySorted, fontsize = 20)
    plt.yticks(fontsize=20)
    plt.grid()
    plt.tight_layout()
    plt.savefig("expEcho.eps")
    return



def bar_graph(idx):
    
    """
        bar graph of router having TOS (idx = 7) or MPLS (idx = 8) capabilities
    """    
        
    kind = ''

    if idx == 7:
        kind = "TOS"
    elif idx == 8:
        kind = "MPLS"
    else:
        return
    
    exp_ping = collections.OrderedDict()
    exp_ping_num = collections.OrderedDict()

    for elem in responses.values():
        time_exc = elem[0]
        echo = elem[2]
        if echo == -1:
            echo = '*'
        exp_ping_key = (time_exc, echo)
              
        
        val = elem[idx]
        

        if val == 1:
            if not exp_ping_key in exp_ping:
                exp_ping[exp_ping_key] = 1
            else:
                exp_ping[exp_ping_key] += 1
            
            if not exp_ping_key in exp_ping_num:
                exp_ping_num[exp_ping_key] = 1
            else:
                exp_ping_num[exp_ping_key] += 1
            
        else:
            if not exp_ping_key in exp_ping_num:
                exp_ping_num[exp_ping_key] = 1
            else:
                exp_ping_num[exp_ping_key] += 1
    
    
    for key in exp_ping:
        if exp_ping_num[key] < 25: #not enough elements
            del exp_ping[key]
        else:
            exp_ping[key] /= float(exp_ping_num[key])
    
    plt.figure(figsize=(12, 9))
    ax = plt.subplot(111)
    x = np.arange(len(exp_ping))
    ax.bar(x + 0.1, exp_ping.values(),width=0.2,color='b',align='center')
    ax.get_xaxis().tick_bottom()    
    ax.get_yaxis().tick_left() 
 
    plt.xlabel("TTL expired - ping pairs", fontsize = 24)
    plt.ylabel("Proportion having " + kind + " capabilities", fontsize = 24)
    plt.xticks(x + 0.1, exp_ping.keys(), fontsize = 20)
    plt.yticks(fontsize=20)
    plt.grid()
    plt.tight_layout()
    plt.savefig(kind + "bargraph.eps")     
        
    return
    


def tos_analysis():

    """
        generate heatmap of the different TOS values taken by a class of router
    """

    ttl = [32,64,128,255,-1]

    heat_dict = {}

    for key,val in responses.items():
        if val[7] == 1:
            time_exc_idx = ttl.index(val[0])
            echo_idx = ttl.index(val[2])
            
            
            for elem in tos[key]:
                if elem in heat_dict:
                    heat_dict[elem][time_exc_idx*5 +echo_idx] += 1
                else:
                    tmp = np.zeros(20)
                    tmp[time_exc_idx*5+echo_idx] = 1
                    heat_dict[elem] = tmp
    
    
    heat = np.zeros(20,len(heat_dict))
        
    return
                
        
def mpls_analysis():
    
    """
        generate heatmap of the different MPLS label values taken by a class of routers
    """
    
    exp_ping = collections.OrderedDict()
    
    for key,val in responses.items():
        if val[8] != 1:
            continue
        
        time_exc = val[0]
        echo = val[2]
        if echo == -1:
            echo = '*'
        exp_ping_key = (time_exc, echo)
        
        if not exp_ping_key in exp_ping:
            exp_ping[exp_ping_key] = np.zeros(14)
        
        for label in mpls[key]:
            num_bits = int(label[0]).bit_length()-1
            index = 0
            if num_bits < 7:
                index = 0
            else:
                index = num_bits - 7
                
            exp_ping[exp_ping_key][index] += 1
    
    
    exp_ping_normalized = collections.OrderedDict()
    for k in sorted(exp_ping):
        exp_ping_normalized[k] = exp_ping[k]/sum(exp_ping[k]) 
    


    
    heat = np.zeros((len(exp_ping),14))
    i = 0
    for v in exp_ping_normalized.values():
        for j in range(0,14):
            heat[i][j] = v[j]
        i += 1
    

    heat = np.transpose(heat)
    plt.figure(figsize=(12, 9))
    plt.rc('font', family='serif', serif='Palatino')
    plt.imshow(heat, cmap='YlOrBr', vmin=0, vmax=1, interpolation='nearest', origin='lower')
    cb = plt.colorbar(shrink=0.7)
    cb.ax.tick_params(labelsize=16) 
    plt.ylabel("number of bits used for the label", fontsize = 22)
    plt.xlabel(r"(ittl time-exceeded - ittl echo) pair values", fontsize = 22)
    plt.xticks(np.arange(len(exp_ping)), exp_ping_normalized.keys(), fontsize = 20, rotation = 70)
    plt.yticks(np.arange(14), ['<7', '7','8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20'], fontsize=20)
    
    
    ax = plt.gca();
    ax.set_xticks(np.arange(-.5, len(exp_ping), 1), minor=True);
    ax.set_yticks(np.arange(-.5, 14, 1), minor=True);
    
    
    plt.grid(which = 'minor')
    plt.tight_layout()
    plt.savefig("mpls" + "_heatmap.pdf")
        
    
    return


def ttl_analysis(idx):

    """
        generate heatmap of the different ITTL values taken by a class of routers
    """

    methods=['time-exceeded', 'tcp', 'echo', 'timestamp' , 'port unreachable']
    exp_ping = {}
    non = []
    alls = {}

    for elem in responses.values():
        time_exc = elem[0]
        echo = elem[2]
        if echo == -1:
            echo = '*'
        exp_ping_key = (time_exc, echo)
              
        
        val = elem[idx]
        
        if not exp_ping_key in alls:
            alls[exp_ping_key] = 1
        else:
            alls[exp_ping_key] += 1
        
        
        if val == -1:
            if (not exp_ping_key in non) and (not exp_ping_key in exp_ping):
                non.append(exp_ping_key)
            continue
        else:
            if not exp_ping_key in exp_ping:
                exp_ping[exp_ping_key] = np.zeros(4)
        
        if val == 32:
            exp_ping[exp_ping_key][0] += 1
        elif val == 64:
            exp_ping[exp_ping_key][1] += 1
        elif val == 128:
            exp_ping[exp_ping_key][2] += 1
        elif val == 255:
            exp_ping[exp_ping_key][3] += 1
        else:
            print "error in ttl_analysis"
    
    ttl = [32,64,128,255]

    
    exp_ping_normalized = collections.OrderedDict()
    for k in sorted(exp_ping):
        exp_ping_normalized[k] = exp_ping[k]/sum(exp_ping[k]) 
    


    
    heat = np.zeros((len(exp_ping),4))
    i = 0
    for v in exp_ping_normalized.values():
        for j in range(0,4):
            heat[i][j] = v[j]
        i += 1
    

    heat = np.transpose(heat)
    plt.figure(figsize=(12, 9))
    plt.rc('font', family='serif', serif='Palatino')
    plt.imshow(heat, cmap='YlOrBr', vmin=0, vmax=1, interpolation='nearest', origin='lower')
    cb = plt.colorbar(shrink=0.7)
    cb.ax.tick_params(labelsize=16) 
    plt.ylabel(r"ITTL values (" + methods[idx] + ")", fontsize = 22)
    plt.xlabel(r"(ITTL time-exceeded - ITTL echo) pair values", fontsize = 22)
    plt.xticks(np.arange(len(exp_ping)), exp_ping_normalized.keys(), fontsize = 20, rotation = 70)
    plt.yticks(np.arange(4), ['32','64','128','255'], fontsize=20)
    plt.tight_layout()
    plt.savefig(str(idx) + "_heatmap.eps")

    return
    
def pck_len_analysis():
    
    """
        generate heatmap of the different packet sizes by classes of routers
    """

    exp_ping = collections.OrderedDict()
    
    for key,val in responses.items():
        if val[5] == -1:
            continue
            
        
        time_exc = val[0]
        echo = val[2]
        if echo == -1:
            echo = '*'
        exp_ping_key = (time_exc, echo)
        
        if not exp_ping_key in exp_ping:
            exp_ping[exp_ping_key] = np.zeros(5)
            
            
        if val[5] == 56:
            exp_ping[exp_ping_key][0] += 1
        elif val[5] == 68:
            exp_ping[exp_ping_key][1] += 1
        elif val[5] == 96:
            exp_ping[exp_ping_key][2] += 1
        elif val[5] == 168:
            exp_ping[exp_ping_key][3] += 1
        elif val[5] > 168:
            exp_ping[exp_ping_key][4] += 1
        
    
    
    exp_ping_normalized = collections.OrderedDict()
    for k in sorted(exp_ping):
        exp_ping_normalized[k] = exp_ping[k]/sum(exp_ping[k]) 
    


    
    heat = np.zeros((len(exp_ping),5))
    i = 0
    for v in exp_ping_normalized.values():
        for j in range(0,5):
            heat[i][j] = v[j]
        i += 1
    

    heat = np.transpose(heat)
    plt.figure(figsize=(12, 9))
    plt.rc('font', family='serif', serif='Palatino')
    plt.imshow(heat, cmap='YlOrBr', vmin=0, vmax=1, interpolation='nearest', origin='lower')
    cb = plt.colorbar(shrink=0.7)
    cb.ax.tick_params(labelsize=16) 
    plt.ylabel("ICMP time-exceeded pck length", fontsize = 24)
    plt.xlabel(r"(ITTL time-exceeded - ITTL echo) pair values", fontsize = 24)
    plt.xticks(np.arange(len(exp_ping)), exp_ping_normalized.keys(), fontsize = 22, rotation = 70)
    plt.yticks(np.arange(5), ['56', '68','96', '168', '>168'], fontsize=22)
    
    
    ax = plt.gca();
    ax.set_xticks(np.arange(-.5, len(exp_ping), 1), minor=True);
    ax.set_yticks(np.arange(-.5, 5, 1), minor=True);
    
    
    plt.grid(which = 'minor')
    plt.tight_layout()
    plt.savefig("pcklen" + "_heatmap.eps")
        
    
    return        
    
def prop_tos_mpls(is_tos = True):

    """
        Calculate the proportion of non responses, of value = 0 and of valuer != 0
        for TOS field or MPLS field
        
        arg:
            is_tos  boolean to indicate that we want the proportion for TOS, otherwise, it is for MPLS
    """
    idx = 7
    non_resp = 0
    non_val = 0
    val = 0
    if is_tos:
        idx = 7
    else:
        idx = 8
    
    for elem in responses.values():
        if elem[idx] == -1:
            non_resp += 1
        elif elem[idx] == 0:
            non_val += 1
        else:
            val += 1
    
    l = float(len(responses))    
    
    return non_resp/l, non_val/l, val/l

def complete_resp():

    """
    Calculate the proportion of signatures that have at least 1,2,3,4 or 5 responses
    """    
    
    num_responding = np.zeros(6)
    for elem in responses.values():
        i = 0
        if elem[0] != -1:
            i += 1
        if elem[1] != -1:
            i += 1
        if elem[2] != -1:
            i += 1
        if elem[3] != -1:
            i += 1
        if elem[4] != -1:
            i += 1
            
        for x in range(0,i):
            num_responding[x] += 1
           
        
    return num_responding/float(len(responses))
     

def parseWarts(filename):

    """
    function that parse the warts files and create the main dictionaries for the rest of the analysis
    """
    
    regex = "\(\s+(\d+\.\d+\.\d+\.\d+),\s+(\d+),\s+([+-]?\d+),\s+([+-]?\d+),\s+([+-]?\d+),\s+([+-]?\d+),\s+([+-]?\d+),\s+([+-]?\d+),\s+([+-]?\d+),\s+([+-]?\d+)\)"
    regex_mpls = "(MPLS)\s+(\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(label)\s+(\d+)"
        

    dump = os.popen("sc_wartsdump " + filename)
    dump2 = os.popen("sc_wartsdump " + filename)        

    dt = np.dtype([('ip',np.str_, 16), ('ttlexp', np.int32),  ('tcp ittl', np.int32),  ('echo ittl', np.int32),  ('ts ittl', np.int32),  ('pu ittl', np.int32),  ('ttlexp size', np.int32),  ('df', np.int32),  ('tos', np.int32),  ('mpls', np.int32)])        

    dt2 = np.dtype([('x','S4'),('num',np.int32),('ip',np.str_, 16),('y', 'S5'),('label',np.int32)])

    output = np.fromregex(dump, regex, dt)
    output_mpls = np.fromregex(dump2, regex_mpls, dt2)
    
    inc = {}
    incorrect = []
    
    for cols in output:
        
        source = ip.ip_address(u"{}".format(cols[0]))

        if source.is_private: #reject private IP addresses
            continue
        

        
        if cols[8] > 0:# do not consider the TOS value range for the moment
            if cols[0] in tos:
                if not (cols[8] in tos[cols[0]]):
                    tos[cols[0]].append(cols[8])
            else:
                tos[cols[0]] = [cols[8]]
            cols[8] = 1
        

        if cols[0] in responses:
            cmp_test, new_sig = resp_cmp(responses[cols[0]], [cols[1],cols[2],cols[3],cols[4],cols[5],cols[6],cols[7],cols[8],cols[9]])
            if cmp_test == 1:
                responses[cols[0]] = new_sig
                if not (cols[0] in inc):
                    inc[cols[0]] = 1
                else:
                    inc[cols[0]] += 1
            elif cmp_test == -1:
                if not (cols[0] in incorrect):
                    incorrect.append(cols[0])           
        else:
            responses[cols[0]] = [cols[1],cols[2],cols[3],cols[4],cols[5],cols[6],cols[7],cols[8],cols[9]]

        
    
    for cols in output_mpls:
        lab = [cols[4],cols[1]]
        if cols[2] in mpls:
            if not(lab in mpls[cols[2]]):
                mpls[cols[2]].append(lab)
        else:
            mpls[cols[2]] = [lab]
            
    
    
    return



def main():

    global responses, tos, mpls
    
    
    # If arg is given, it should be the folder name of warts files
    if len(sys.argv) > 1:
        path = sys.argv[1]
        dirNames = os.listdir(path)

        listname = []

        for dirName in dirNames:
            newPath = path + dirName + "/warts/"
            subDirNames = os.listdir(newPath)
    
            for subDirName in subDirNames:
                newPath = path + dirName + "/warts/" + subDirName + "/warts/"
                fileNames = os.listdir(newPath)
                if not (subDirName) in listname:
                    listname.append(subDirName)
                for fileName in fileNames:
                    parseWarts(newPath + fileName)
    
    #No arg given, we try to load registered file                    
    else:
        resp_file = Path("responses.npy")
        tos_file = Path("tos.npy")
        mpls_file = Path("mpls.npy")
        
        if resp_file.exists() and tos_file.exists() and mpls_file.exists():
            
            responses = np.load('responses.npy').item()
            tos = np.load('tos.npy').item()
            mpls = np.load('mpls.npy').item()
        
        else:
        
            print "Usage python analysis [warts folder name]"
            print "No arguments to load npy files"
            sys.exit(-1)
            
            

    
    print "* Generating distribution of ITTLS for each probing methods *"
    graph_ecdf()
    
    print "* Generating distribution of tuple ICMP time-exceeded ITTL - ICMP echo ITTL *"
    exp_echo_prop()
        
    print "* Generating ITTL heatmap *"
    ttl_analysis(1)
    ttl_analysis(3)
    ttl_analysis(4)
    
    print "* echo timestamp comparison"
    echo_ts_compare()
        
    print "* Generating packet length ecdf *"
    graph_ecdf_packet_size()
    
    print "* Generating heatmap for packet lengths *"
    pck_len_analysis()
    
    print "* TOS proportion *"
    print prop_tos_mpls(True)
        
    print "* MPLS proportion *"
    print prop_tos_mpls(False)
    
    print "* Generating graph proportion TOS and MPLS *"
    bar_graph(7)
    bar_graph(8)
    
    print "* Generating MPLS heatmap *"
    mpls_analysis()
    
    print "* reponsivness of probing *"
    print complete_resp()
    
    print "* complete signature frequencies * "
    signature_freq()
    
        
     
    
    sys.exit(0)

if __name__ == "__main__":
    main()

