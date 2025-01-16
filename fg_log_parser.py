#!/usr/bin/python3
"""Fortigate Log Parser
Parses a Fortigate log file and presents a communication matrix.

Usage: fg_log_parser.py
  fg_log_parser.py (-f <logfile> | --file <logfile>) [options]

Options:
    -s --showaction         Show action field.
    -b --countbytes         Count bytes for each communication quartet
    -h --help               Show this message
    -v --verbose            Activate verbose messages
    --version               Shows version information
    -n --noipcheck          Do not check if src and dst ip are present
    -c --csv                Print matrix in csv format (default is nested format)
    --onlyports=<port>      Print only the specified port from the communication matrix
    --service               Include service information in the output

    Log Format Options (case sensitive):
    --srcipfield=<srcipfield>       Src ip address field [default: srcip]
    --dstipfield=<dstipfield>       Dst ip address field [default: dstip]
    --dstportfield=<dstportfield>   Dst port field [default: dstport]
    --protofield=<protofield>       Protocol field [default: proto]
    --actionfield=<actionfield>     Action field [default: action]


    If countbytes options is set you may have to specify:
    --sentbytesfield=<sentbytesfield>  Field for sent bytes [default: sentbyte]
    --rcvdbytesfield=<rcvdbytesfield>  Field for rcvd bytes [default: rcvdbyte]

Examples:
    Parse Fortigate Log:
        fg_log_parser.py -f fg.log
    Parse Iptables Log:
        fg_log_parser.py -f filter --srcipfield=SRC --dstipfield=DST --dstportfield=DPT --protofield=PROTO
    Parse Fortianalyzer Log:
        fg_log_parser.py -f faz.log --srcipfield=src --dstipfield=dst

"""

__author__ = 'r4vanan'
__title__ = 'Fortigate Log Parser'
__version__ = '1.0'

try:
    from docopt import docopt
    import re
    import sys
    import logging as log
    import ipaddress
    import datetime
    from tqdm import tqdm  # Add tqdm for progress bar
except ImportError as ioex:
    log.error("Could not import a required module")
    log.error(ioex)
    sys.exit(1)


def split_kv(line):
    """
    Splits lines in key and value pairs and returns a dictionary.

    Example:
        >>> line = 'srcip=192.168.1.1 dstip=8.8.8.8 \
        ...         dport=53 proto=53 dstcountry="United States" action="allow"'
        >>> split_kv(line)
        {'srcip': '192.168.1.1', 'dport': '53', 'dstip': '8.8.8.8', 'dstcountry': '"United States"', 'proto': '53'}

    """
    kvdelim = '='  # key and value deliminator
    logline = {}  # dictionary for logline
    # split line in key and value pairs
    # regex matches internal sub strings such as key = "word1 word2"
    for field in re.findall(r'(\w+)=("[^"]*"|[^,]+)', line):
        key, value = field
        logline[key.strip()] = value.strip().strip('"')  # Remove surrounding quotes if present
    return logline


def check_log_format(line, srcipfield, dstipfield):
    """
    checks if srcipfield and dstipfield are in logline

    Examples:
        >>> line ='srcip=192.168.1.1 dstip=8.8.8.8 dstport=53 proto=53'
        >>> check_log_format(line, "srcip", "dstip")
        True
        >>> line ='srcip=192.168.1.1 dstport=53 proto=53'
        >>> check_log_format(line, "srcip", "dstip")
        False
        >>> line = ''
        >>> check_log_format(line, "srcip", "dstip")
        False
    """
    log.info("check_log_format: checking line: ")
    log.info(line)
    if srcipfield in line and dstipfield in line:
        log.info("check_log_format: found srcipfield %s", srcipfield)
        log.info("check_log_format: found dstipfield %s", dstipfield)
        return True
    else:
        return False


def translate_protonr(protocolnr):
    """
    Translates ports as names.

    Examples:
        >>> translate_protonr(53)
        53
        >>> translate_protonr(1)
        'ICMP'
        >>> translate_protonr(6)
        'TCP'
        >>> translate_protonr(17)
        'UDP'
    """
    # check if function input was a integer
    # and translate if we know translation
    try:
        if int(protocolnr) == 1:
            return "ICMP"   # icmp has protocol nr 1
        elif int(protocolnr) == 6:
            return "TCP"    # tcp has protocol nr 6
        elif int(protocolnr) == 17:
            return "UDP"    # udp has protocol nr 17
        else:
            return int(protocolnr)
    # if function input was something else than int
    except (ValueError, AttributeError, TypeError):
        return protocolnr

def parse_and_display_action(log_line):
    # Remove extra quotes and split the log string by commas
    log_line = log_line.replace('""', '"')  # Fix any double quotes within the field
    for item in log_line.split('","'):
        if item.startswith('action='):
            # Extract the value after 'action="'
            action = item.split('=')[1].strip('"')
            #print(f"The action value is: {action}")
            #return action
    #print("Action not found.")
    return action

def parse_and_display_services(log_line):
    # Remove extra quotes and split the log string by commas
    log_line = log_line.replace('""', '"')  # Fix any double quotes within the field
    services = None  # Initialize services variable
    for item in log_line.split('","'):
        if item.startswith('service='):
            # Extract the value after 'service="'
            services = item.split('=')[1].strip('"')
    return services  # Return the services instead of printing


def check_ip_type(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            return "\033[1;92m" + ip + " (Local/Private IP)" + "\033[0m"  # Bold Green
        else:
            return "\033[1;91m" + ip + " (Public IP)" + "\033[0m"  # Bold Red
    except ValueError:
        "\033[1;93m" + ip + " (Invalid IP address)" + "\033[0m"  # Bold Yellow


def get_communication_matrix(logfile,
                             logformat,
                             countbytes=False,
                             noipcheck=False,
                             showaction=False,
                             service=False):
    """
    Reads firewall logfile and returns communication matrix as a dictionary.

    Parameters:
        logfile         Logfile to parse
        logformat       dictionary containing log format
        countbytes      sum up bytes sent and received

    Sample return matrix (one logline parsed):
        {'192.168.1.1': {'8.8.8.8': {'53': {'UDP': {'count': 1}}}}}

    Example:

    """

    log.info("get_communication_matrix() started with parameters: ")
    log.info("Option logfile: %s", logfile)
    log.info("Option countbytes: %s", countbytes)
    log.info("Option showaction: %s", showaction)
    log.info("Option service: %s", service)

    # assign log format options from logformat dict
    srcipfield = logformat['srcipfield']
    dstipfield = logformat['dstipfield']
    dstportfield = logformat['dstportfield']
    protofield = logformat['protofield']
    sentbytesfield = logformat['sentbytesfield']
    rcvdbytesfield = logformat['rcvdbytesfield']
    actionfield = logformat['actionfield']

    matrix = {}  # communication matrix

    with open(logfile, 'r') as infile:
        total_lines = sum(1 for _ in infile)
        infile.seek(0)  # Reset file pointer to the beginning
        with tqdm(total=total_lines, desc="Processing log file", unit=" lines") as pbar:
            for linecount, line in enumerate(infile, start=1):
                """
                For loop creates a nested dictionary with multiple levels.

                Level description:
                Level 1:        srcips (source ips)
                Level 2:        dstips (destination ips)
                Level 3:        dstport (destination port number)
                Level 4:        proto (protocol number)
                Level 4.5:      action (Fortigate action)
                Level 5:        occurrence count
                                sentbytes
                                rcvdbytes
                """

                # check if necessary fields are in first line
                if linecount == 1 and not noipcheck:
                    # print error message if srcip or dstip are missing
                    if not check_log_format(line, srcipfield, dstipfield):
                        log.error("srcipfield or dstipfield not in line: %s ", linecount)
                        log.error("Check Log Format options and consult help message!")
                        sys.exit(1)

                # split each line in key and value pairs.
                logline = split_kv(line)
                if logline is None:
                    pbar.update(1)
                    continue  # Skip this log entry

                # get() does substitute missing values with None
                # missing log fields will show None in the matrix
                srcip = logline.get(srcipfield, "IP not found")
                dstip = logline.get(dstipfield, "Not found")
                dstport = logline.get(dstportfield)
                proto = translate_protonr(logline.get(protofield))
                itime = logline.get('itime', 'Unknown time')
                
                # Convert Unix timestamp to human-readable format
                try:
                    time = datetime.datetime.fromtimestamp(int(itime)).strftime('%Y-%m-%d %H:%M:%S')
                except (ValueError, TypeError):
                    time = 'Unknown time'
                
                # Check IP types
                if not noipcheck:
                    check_ip_type(srcip)
                    check_ip_type(dstip)
                
                # user has set --action
                if showaction:
                    action = parse_and_display_action(line)  # Use parse_and_display_action to get the action value
                else:
                    action = None
                # user has set --service
                if service:
                    service_value = parse_and_display_services(line)  # Correctly assign the service value
                else:
                    service_value = None
                # if user has set --countbytes
                if countbytes:
                    sentbytes = int(logline.get(sentbytesfield, 0))
                    rcvdbytes = int(logline.get(rcvdbytesfield, 0))
                else:
                    sentbytes = rcvdbytes = 0

                # extend matrix for each source ip
                srcip_dict = matrix.setdefault(srcip, {})
                # extend matrix for each dstip in srcip
                dstip_dict = srcip_dict.setdefault(dstip, {})
                # extend matrix for each port in comm. pair
                dstport_dict = dstip_dict.setdefault(dstport, {})
                # if proto not in matrix extend matrix
                proto_dict = dstport_dict.setdefault(proto, {"count": 0, "time": time})
                proto_dict["count"] += 1

                if showaction:
                    proto_dict["action"] = action  # Ensure action is added to the matrix
                if service:
                    proto_dict["service"] = service_value  # Ensure service is added to the matrix
                if countbytes:
                    proto_dict["sentbytes"] = proto_dict.get("sentbytes", 0) + sentbytes
                    proto_dict["rcvdbytes"] = proto_dict.get("rcvdbytes", 0) + rcvdbytes

                # Print the log line for debugging
                log.debug("Processed line %s: %s", linecount, line.strip())
                pbar.update(1)
            pbar.clear()  # Ensure the progress bar is closed after processing
    log.info("Parsed %s lines in logfile: %s ", linecount, logfile)
    return matrix


def print_communication_matrix(matrix, port_filter=None):
    """
    Prints the details of the communication matrix.

    Example:
    >>> matrix = {'192.168.1.1': {'8.8.8.8': {'53': {'UDP': {'count': 1}}}}}
    >>> print_communication_matrix(matrix)
    srcip: 192.168.1.1, dstip: 8.8.8.8, dport: 53
      proto: UDP
        count: 1
    """
    for srcip in matrix.keys():
        for dstip in matrix.get(srcip):
            for dport in matrix[srcip][dstip].keys():
                if port_filter is None or dport == port_filter:
                    print(f"srcip: {check_ip_type(srcip)}, dstip: {check_ip_type(dstip)}, dport: {dport}")
                    for proto, details in matrix[srcip][dstip][dport].items():
                        print(f"  proto: {proto}")
                        for key, value in details.items():
                            if key != "action" and key != "service":
                                print(f"    {key}: {value}")
                            elif key == "action" and value:
                                print(f"    action: {value}")
                            elif key == "service" and value:
                                print(f"    service: {value}")
                            else:
                                print(f"    {key}: None")


def print_communication_matrix_as_csv(matrix, countbytes=False, showaction=False, service=False):
    """
    Prints communication matrix in csv format.

    Example:
    >>> matrix = {'192.168.1.1': {'8.8.8.8': {'53': {'UDP': {'count': 1}}}}}
    >>> print_communication_matrix_as_csv(matrix)
    srcip;dstip;dport;proto;count;action;service;sentbytes;rcvdbytes
    192.168.1.1;8.8.8.8;53;UDP;1;None;Unknown

    Example 2 (option countbytes set):
    >>> matrix = {'192.168.1.1': {'8.8.8.8': {'53': {'UDP': {'count': 1, 'sentbytes': 10, 'rcvdbytes': 10}}}}}
    >>> print_communication_matrix_as_csv(matrix, countbytes=True)
    srcip;dstip;dport;proto;count;action;service;sentbytes;rcvdbytes
    192.168.1.1;8.8.8.8;53;UDP;1;None;Unknown;10;10

    """
    # Header
    print("srcip;dstip;dport;proto;count;action;service;sentbytes;rcvdbytes")
    for srcip in matrix.keys():
        for dstip in matrix.get(srcip):
            for dport in matrix[srcip][dstip].keys():
                for proto in matrix[srcip][dstip].get(dport):
                    count = matrix[srcip][dstip][dport][proto].get("count")
                    action = matrix[srcip][dstip][dport][proto].get("action", "None")
                    service_info = matrix[srcip][dstip][dport][proto].get("service", "Unknown")
                    if countbytes:
                        rcvdbytes = matrix[srcip][dstip][dport][proto].get("rcvdbytes")
                        sentbytes = matrix[srcip][dstip][dport][proto].get("sentbytes")
                        print("%s;%s;%s;%s;%s;%s;%s;%s;%s" % (srcip, dstip, dport, proto, count, action, service_info, sentbytes, rcvdbytes))
                    else:
                        print("%s;%s;%s;%s;%s;%s;%s" % (srcip, dstip, dport, proto, count, action, service_info))

def print_ports(matrix, port_filter=None):
    """
    Prints the details of the communication matrix for the specified port.

    Example:
    >>> matrix = {'192.168.1.1': {'8.8.8.8': {'53': {'UDP': {'count': 1}}}}}
    >>> print_ports(matrix)
    53
    """
    port_found = False
    for srcip in matrix.keys():
        for dstip in matrix.get(srcip):
            for dport in matrix[srcip][dstip].keys():
                if port_filter is None or str(dport) == str(port_filter):
                    port_found = True
                    print(f"srcip: {check_ip_type(srcip)}, dstip: {check_ip_type(dstip)}, dport: {dport}")
                    for proto, details in matrix[srcip][dstip][dport].items():
                        print(f"  proto: {proto}")
                        for key, value in details.items():
                            print(f"    {key}: {value}")
    return port_found

def main():
    """
    Main function.
    """
    # get arguments from docopt
    arguments = docopt(__doc__, version='Fortigate Log Parser 0.3')
    # assign docopt argument
    # check module documentation for argument description
    logfile = arguments['<logfile>']
    countbytes = arguments['--countbytes']
    verbose = arguments['--verbose']
    noipcheck = arguments['--noipcheck']
    csv = arguments['--csv']
    showaction = arguments['--showaction']  # Ensure showaction is assigned correctly
    onlyports = arguments['--onlyports']
    service = arguments['--service']

    # define logfile format
    # note: default values are set in the docopt string, see __doc__
    logformat = {'srcipfield': arguments['--srcipfield'],
                 'dstipfield': arguments['--dstipfield'],
                 'dstportfield': arguments['--dstportfield'],
                 'protofield': arguments['--protofield'],
                 'sentbytesfield': arguments['--sentbytesfield'],
                 'rcvdbytesfield': arguments['--rcvdbytesfield'],
                 'actionfield': arguments['--actionfield']
                 }

    # set loglevel
    if verbose:
        log.basicConfig(format="%(levelname)s: %(message)s", level=log.DEBUG)
        log.info("Verbose output activated.")
    else:
        log.basicConfig(format="%(levelname)s: %(message)s")
    log.info("Script was started with arguments: ")
    log.info(arguments)

    # check if logfile argument is present
    if logfile is None:
        print(__doc__)
        sys.exit(1)

    # parse log
    log.info("Reading firewall log...")
    print("Start processing log file...")
    matrix = get_communication_matrix(logfile, logformat, countbytes, noipcheck, showaction, service)  # Pass service
    log.debug("Communication matrix: %s", matrix)
    if onlyports:
        if not print_ports(matrix, onlyports):
            print("port not found!")
    elif csv:
        print_communication_matrix_as_csv(matrix, countbytes, showaction, service)
    else:
        print_communication_matrix(matrix)
    return 0

if __name__ == "__main__":
    sys.exit(main())
