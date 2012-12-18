#!/usr/bin/env python
import sys
import getopt


#TODO

#provide an ouput filter for octets, i only want to see things matching this partial octet ex: (192.168), (10), (172.16)

#add the ability to process XML files as well as plain text fierce outputs

#gank ARIN results formatting code out of fierce2 (or find something that does the same thing) and port to python for automating range discovery
    #write whois range discovery bits
    
#add option to run a command on hosts after sorting them out

#add option to output all hosts to a file in various formats (just IPs, hostnames and IPs)

#give option to filter hosts based on a common list of critical words (access, vpn, mail, employee, portal, cms, etc)




#COMMAND LINE OPTION DEFAULTS
OUTPUT = None
VERBOSE = False
DISPLAY_SPLIT = 2


def usage():
    #thanks to http://www.network-science.de/ascii/ for the ascii art
    print "              __ _                   \n             / _(_)                  \n _ __ ______| |_ _  ___ _ __ ___ ___ \n| '_ \______|  _| |/ _ \ '__/ __/ _ \\\n| |_) |     | | | |  __/ | | (_|  __/\n| .__/      |_| |_|\___|_|  \___\___|\n| |                                  \n|_| \n"
    print "p-fierce v0.1"
    print "takes a fierce2 xml or plain text file(s) (eventually)\nand processes out ranges of IPs, groups ips in lists, etc"
    print "(currently only does Prefix Bruteforce section copy-pasted into a new file)"
    print "written by:\n@odd_meta - odd.meta@gmail.com"
    print "\nreleased under the 'you'll just steal it for work anyway'(tm) license 2012/12/18"

    print """
    
    Usage:
        -v: be more verbose
        -h: display this screen and exit
            --help
        -n: the number of octets to group up IPs by (default is 2)
            1 = 10.0.0.0/8
            2 = 10.0.0.0/16
            3 = 10.0.0.0/24
	example:
        ./p-fierce.py -n 1 fierce.output.txt
    """


try:
    opts, args = getopt.getopt(sys.argv[1:], "hvn:", ["help"])
except getopt.GetoptError as err:
    # print help information and exit:
    print str(err) # will print something like "option -a not recognized"
    usage()
    sys.exit(2)
OUTPUT = None
VERBOSE = False
DISPLAY_SPLIT = 2

if len(args) == 0:
    usage()
    sys.exit(2)
    
fierce_files = []

fierce_files = args[:]

for o, a in opts:
    if o == "-v":
        VERBOSE = True
    elif o == "-n":
        DISPLAY_SPLIT = int( a[0] )
    elif o in ("-h", "--help"):
        usage()
        sys.exit()
    else:
        assert False, "unhandled option"


#takes a list of file handles of a thing that will be changed when i have time
def temp_process_fierce_files(raw_fierce_handles):
    fierce_hosts = []
    for fhandle in raw_fierce_handles:
        for line in fhandle:
            split_line = line.split("\t")
            
            clean_line = []
            
            for item in split_line:
                clean_line.append( item.strip() )
            if len(clean_line) > 1:
                fierce_hosts.append(clean_line)

        fhandle.close()

    return process_hosts(fierce_hosts)


def process_hosts(fierce_hosts):
    internal_ips = []

    external_ips = []

    ip_lookup_table = {}

    for host in fierce_hosts:
        ip = host[0]
        ip_split = ip.split(".")
        
        if ip_split[0] == "10":
            internal_ips.append(host)
            continue

        if ip_split[0] == "192" and ip_split[1] == "168":
            internal_ips.append(host)
            continue
            
        if ip_split[0] == "172" and ( ip_split[1] > 15 or ip_split[1] < 32 ):
            internal_ips.append(host)
            continue
            
        if ip_split[0] == "127":
            internal_ips.append(host)
            continue
            
        
        octet_counter = 0
        
        while octet_counter < 3:
            
            pseudo_network_class = ""
            if octet_counter == 0:
                pseudo_network_class = ip_split[0]
            elif octet_counter == 1:
                pseudo_network_class = "%s.%s" % (ip_split[0], ip_split[1])
            elif octet_counter == 2:
                pseudo_network_class = "%s.%s.%s" % (ip_split[0], ip_split[1], ip_split[2])
            
            
            if pseudo_network_class in ip_lookup_table:
                ip_lookup_table[pseudo_network_class].append(host)
            else:
                ip_lookup_table[pseudo_network_class] = [host]
                
            octet_counter += 1
                
        
        
    return (internal_ips,ip_lookup_table)




fierce_file_handles = []
for fname in fierce_files:
    try:
        raw_fierce = open( fname, "r" )
        fierce_file_handles.append(raw_fierce)
    except Exception as e:
        print e
        print "You probably put the options AFTER the filename\nput them **BEFORE** the filename. lolgetopts.\n<3"
        print "quitting..."
        sys.exit(2)
        
internal_ips, ip_lookup_table = temp_process_fierce_files(fierce_file_handles)
    
        
print internal_ips
#print ip_lookup_table
        
for pseudo_network_class, hosts in ip_lookup_table.items():
    if len(pseudo_network_class.split(".")) == DISPLAY_SPLIT:
        print "%s" % (pseudo_network_class)
        print "**********"
        for host in hosts:
            print "%s:%s" % (host[0], host[1])
        print ""
        
        
        

