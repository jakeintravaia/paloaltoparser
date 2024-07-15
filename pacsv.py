import re
import argparse
import sys

# Author: Jake Intravaia
# Date Created: 07/12/2024
# Program: pacsv.py (Palo Alto CSV Parser)
# Version: 1.0.1
# Description: Python script to parse Palo Alto logs to make log interpretation easier.

# CHANGELOG 07/15/2024
# ============================================================================
# - Added log type functionality to support Palo Alto Firewall logs.
# - Added RegEx logic to ensure date recieved is first data point.
# - Added type checking to ensure inputted log matches expected inputted type.
# - Fixed list OOB error, added warning to user.
# ============================================================================

class Warnings:
    def type_warning(self, log_type, data_points, expected_type):
        print("\nWARNING: Log supplied does not seem to be {} generated. Type: {} does not match expected Type: {}.".format(log_type, data_points[2], expected_type))

    def format_warning(self):
        print("\nWARNING: RegEx pattern of first inputted data point does not match expected format (YYYY/MM/DD HR:MM:SS). Please ensure log is entered correctly, with the recieve time being the first data point.")

    def length_warning(self, headers, data_points):
        print("\nWARNING: Length of supplied log is larger than associated known data headers. Some data points will not be printed with associated headers. ({} headers, {} data points, {} unprinted data points)".format(len(headers), len(data_points), (len(data_points)-len(headers))))

class Validator:
    warnings = Warnings()

    def validate_recieve_time(self, data_points):
        date_pattern = re.compile("\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}")
        validation = date_pattern.match(str(data_points[0]))
        return validation

    def validate_ids_log(self, data_points):
        if data_points[2] != "THREAT":
            return False
        return True

    def validate_firewall_log(self, data_points):
        if data_points[2] != "TRAFFIC":
            return False
        return True
    
    def validate_length(self, headers, data_points):
        # Warning logic if log data points supplied out number known data headers
        if len(data_points) > len(headers):
           return False
        return True
    
    def validate(self, headers, data_points, log_type, expected_type):
        # Warning logic if log supplied is not IDS/IPS
        if expected_type == "TRAFFIC":
            if not self.validate_firewall_log(data_points):
                self.warnings.type_warning(log_type, data_points, expected_type)
        elif expected_type == "THREAT":
            if not self.validate_ids_log(data_points):
                self.warnings.type_warning(log_type, data_points, expected_type)
    
        # Warning logic if date recieved is not first data point
        if not self.validate_recieve_time(data_points):
            self.warnings.format_warning()

        # Warning logic if the length of supplied data points exceeds known header values
        if not self.validate_length(headers, data_points):
            self.warnings.length_warning(headers, data_points)
    
        


parser = argparse.ArgumentParser(
    prog='pacsv.py',
    description='A simple python script to help parse Palo Alto CSV logs.',
    epilog='Hopefully this makes it easier on your eyes :)'
)

parser.add_argument('-t', '--type', help='Usage: -t [IDS, FIREWALL]\nUse this to specify the type of data to be parsed (IDS, FIREWALL)')
parser.add_argument('-i', '--input', help='Usage: -i "data1,data2,data3..."')


args = parser.parse_args()

csv_ids_headers = [
    "Receive Time",
    "Serial Number",
    "Type",
    "Threat/Content Type",
    "FUTURE_USE",
    "Generated Time",
    "Source Address",
    "Destination Address",
    "NAT Source IP",
    "NAT Destination IP",
    "Rule Name",
    "Source User",
    "Destination User",
    "Application",
    "Virtual System",
    "Source Zone",
    "Destination Zone",
    "Inbound Interface",
    "Outbound Interface",
    "Log Action",
    "FUTURE_USE",
    "Session ID",
    "Repeat Count",
    "Source Port",
    "Destination Port",
    "NAT Source Port",
    "NAT Destination Port",
    "Flags",
    "Protocol",
    "Action",
    "Bytes",
    "Bytes Sent",
    "Bytes Received",
    "Packets",
    "Start Time",
    "Elapsed Time",
    "Category",
    "FUTURE_USE",
    "Sequence Number",
    "Action Flags",
    "Source Location",
    "Destination Location",
    "FUTURE_USE",
    "Packets Sent",
    "Packets Received",
    "Session End Reason",
    "Device Group Hierarchy Level 1",
    "Device Group Hierarchy Level 2",
    "Device Group Hierarchy Level 3",
    "Device Group Hierarchy Level 4",
    "Virtual System Name",
    "Device Name",
    "Action Source",
    "Source VM UUID",
    "Destination VM UUID",
    "Tunnel ID/IMSI",
    "Monitor Tag/IMEI",
    "Parent Session ID",
    "Parent Start Time",
    "Tunnel Type",
    "SCTP Association ID",
    "SCTP Chunks",
    "SCTP Chunks Sent",
    "SCTP Chunks Received",
    "UUID for rule",
    "HTTP/2 Connection"
]

csv_firewall_headers = [
    "Receive Time", "Serial Number", "Type", "Threat/Content Type", "FUTURE_USE", 
    "Generated Time", "Source Address", "Destination Address", "NAT Source IP", 
    "NAT Destination IP", "Rule Name", "Source User", "Destination User", 
    "Application", "Virtual System", "Source Zone", "Destination Zone", 
    "Inbound Interface", "Outbound Interface", "Log Action", "FUTURE_USE", 
    "Session ID", "Repeat Count", "Source Port", "Destination Port", 
    "NAT Source Port", "NAT Destination Port", "Flags", "Protocol", "Action", 
    "Bytes", "Bytes Sent", "Bytes Received", "Packets", "Start Time", 
    "Elapsed Time", "Category", "FUTURE_USE", "Sequence Number", "Action Flags", 
    "Source Location", "Destination Location", "FUTURE_USE", "Packets Sent", 
    "Packets Received", "Session End Reason", "Device Group Hierarchy Level 1", 
    "Device Group Hierarchy Level 2", "Device Group Hierarchy Level 3", 
    "Device Group Hierarchy Level 4", "Virtual System Name", "Device Name", 
    "Action Source", "Source VM UUID", "Destination VM UUID", "Tunnel ID/IMSI", 
    "Monitor Tag/IMEI", "Parent Session ID", "Parent Start Time", "Tunnel Type", 
    "SCTP Association ID", "SCTP Chunks", "SCTP Chunks Sent", "SCTP Chunks Received", 
    "UUID for rule", "HTTP/2 Connection"
]

def print_data(headers, data_points):
    for i in range(0, len(headers)):
        print('{}: {}'.format(headers[i], data_points[i]))



# Logic for Palo Alto IDS/IPS CSV logs

def parse_ids():
    # Create a list from CSV input

    csv = args.input
    csv_list = csv.split(",")

    validator = Validator()

    # Print out IDS/IPS headers with associated data points
    print_data(csv_ids_headers, csv_list)

    validator.validate(csv_ids_headers, csv_list, "IDS/IPS", "THREAT")
  
# Logic for Palo Alto Firewall CSV logs

def parse_firewall():
    # Create a list from CSV input
    csv = args.input
    csv_list = csv.split(",")

    validator = Validator()

    # Print out Firewall headers with associated data points
    print_data(csv_firewall_headers, csv_list)

    validator.validate(csv_firewall_headers, csv_list, "FIREWALL", "TRAFFIC")

def main():
    if len(sys.argv) == 1 or args.type is None:
        parser.print_help()
    elif args.type.upper() == 'IDS':
        parse_ids()
    elif args.type.upper() == 'FIREWALL':
        parse_firewall()
    else:
        print("ERROR: Type {} does not match any known log types (IDS,FIREWALL).\n".format(args.type.upper()))
        parser.print_help()

if __name__ == "__main__":
    main()
