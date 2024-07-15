# Palo Alto CSV Parser
A python script designed to beautify CSV formatted Palo Alto Firewall and IDS/IPS logs.

# Help Page

```
usage: pacsv.py [-h] [-t TYPE] [-i INPUT]

A simple python script to help parse Palo Alto CSV logs.

optional arguments:
  -h, --help            show this help message and exit
  -t TYPE, --type TYPE  Usage: -t [IDS, FIREWALL] Use this to specify the type
                        of data to be parsed (IDS, FIREWALL)
  -i INPUT, --input INPUT
                        Usage: -i "data1,data2,data3..."

Hopefully this makes it easier on your eyes :)
```

# Sample Usage
```
python3 pacsv.py -t FIREWALL -i "2020/05/04 17:08:06,12312312312,TRAFFIC,start,1234,2020/05/04 17:02:38,172.0.0.0,172.0.0.10,0.0.0.0,0.0.0.0,RULE NAME,,,ping,vsys123,SZONE,DZONE,ae2.5,ae2.8,SEND_LOG,2020/05/04 17:02:38,123123123,1,0,0,0,0,0x100000,icmp,allow,60,60,0,1,2020/05/04 17:02:38,0,any,0,6769113173998737673,0x8000000000000000,172.16.0.0-172.31.255.255,172.16.0.0-172.31.255.255,0,1,0,n/a,48,0,0,0,,TEST_HOST,from-policy,,,0,,0,,N/A,0,0,0,0,2c36wer8-8570-4dsb-a78f-ea6ac8ca3f0a,0"
```

# Sample Output
```Receive Time: 2020/05/04 17:08:06
Serial Number: 12312312312
Type: TRAFFIC
Threat/Content Type: start
FUTURE_USE: 1234
Generated Time: 2020/05/04 17:02:38
Source Address: 172.0.0.0
Destination Address: 172.0.0.10
NAT Source IP: 0.0.0.0
NAT Destination IP: 0.0.0.0
Rule Name: RULE NAME
Source User: 
Destination User: 
Application: ping
Virtual System: vsys123
Source Zone: SZONE
Destination Zone: DZONE
Inbound Interface: ae2.5
Outbound Interface: ae2.8
Log Action: SEND_LOG
FUTURE_USE: 2020/05/04 17:02:38
Session ID: 123123123
Repeat Count: 1
Source Port: 0
Destination Port: 0
NAT Source Port: 0
NAT Destination Port: 0
Flags: 0x100000
Protocol: icmp
Action: allow
Bytes: 60
Bytes Sent: 60
Bytes Received: 0
Packets: 1
Start Time: 2020/05/04 17:02:38
Elapsed Time: 0
Category: any
FUTURE_USE: 0
Sequence Number: 6769113173998737673
Action Flags: 0x8000000000000000
Source Location: 172.16.0.0-172.31.255.255
Destination Location: 172.16.0.0-172.31.255.255
FUTURE_USE: 0
Packets Sent: 1
Packets Received: 0
Session End Reason: n/a
Device Group Hierarchy Level 1: 48
Device Group Hierarchy Level 2: 0
Device Group Hierarchy Level 3: 0
Device Group Hierarchy Level 4: 0
Virtual System Name: 
Device Name: TEST_HOST
Action Source: from-policy
Source VM UUID: 
Destination VM UUID: 
Tunnel ID/IMSI: 0
Monitor Tag/IMEI: 
Parent Session ID: 0
Parent Start Time: 
Tunnel Type: N/A
SCTP Association ID: 0
SCTP Chunks: 0
SCTP Chunks Sent: 0
SCTP Chunks Received: 0
UUID for rule: 2c36wer8-8570-4dsb-a78f-ea6ac8ca3f0a
HTTP/2 Connection: 0
```
