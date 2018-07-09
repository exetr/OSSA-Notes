# OSSA Notes

Notes for ThinkSECURE's Organisational Systems Security Analyst (OSSA) Certification. Information here was sourced from both study guides provided by ThinkSECURE and personal anecdotes from the March 2018 run of the certification examination.

_Information listed here may not accurately reflect content that is involved in any particular future runs of the examination_

## Table of Contents

1. [Introduction](#Introduction)
2. [Course Content](#Course-Content)
    - [What Is Information Security](#What-Is-Information-Security)
        - [Origins of Cyberattacks](#Origins-of-Cyberattacks)
        - [Basic Security Concepts](#Basic-Security_Concepts)
        - [8-Step Security Gameplan](#8-Step-Security-Gameplan)
    - [Defending Your Turf & Security Policy Formulation](#Defending-Your-Turf-&-Security-Policy-Formulation)
        - [4Ps of Defence](#4Ps-of-Defence)
        - [4 Steps of Defending Networks & Systems](#4-Steps-of-Defending-Networks-&-Systems)
    - [Network 101](#Network-101)

## Introduction

The examination duration is 4 hours long and includes 45 multiple choice questions with five options. There may be more than one correct answer, no correct answers or all five correct options for each question. For every option that is correctly selected, 1 mark is awarded, and for every incorrect option that is selected, one mark is deducted. To effectively answer a question, you must ensure that the `Answer?` checkbox is checked. If it is not checked, you will be awarded 0 marks for that question since it is considered that you have not chosen to answer that question.

Since this examination involves negative marking, I highly suggest that you do not answer questions that you are completely uncertain of as trying to guess answers to questions brings a higher chance of getting the answers wrong and hence getting more marks deducted.

The bulk of the examination focuses on two topics: analysing network traffic and network scanning. Hence, I would suggest placing more focus on getting comfortable with using wireshark and nmap. Additionally, I would also advice that you read up on concepts that are related to these two tools. Some of the aforementioned concepts may include but are not limited to:

- TCP three way handshakes
- TCP flags
- TCP protocols

During the examination, I highly suggest that you begin off by performing nmap scans of all the hosts involved and specified in the question paper and record down all the information you can retrieve. During this time, focus on answering questions from other sections and topics during this time. This is because in a class of 20 students, the limited bandwidth will result in very long scan times so having to repeat the nmap scans multiple times over to get infomation you have missed out on will be a huge waste of time.

## Course Content

This section contains the information included in the training programme for the certification

### 1. What Is Information Security

#### Origins of Cyberattacks

- The Curious: people who found tools on the internet and randomly picks IP addresses to test on
- The Malicious: dislike of other persons or organisations
- The Criminal: attacks with intent to commit crime
- The Competitor: attacks against competing businesses in the same industry
- The Natural: natural causes such as disasters resulting in denial of service
- The Politically-charged: politically or bureaucratically motivated attacks

#### Basic Security Concepts

##### CIA Triad

- Confidentiality: preventing others from finding out about things (encryption)
- Integrity: how to keep data and platform in a state of "wholeness" (hash)
- Availability: notion of maintianing on-demand accessibility (redundancy)

##### SOB Troika

The CIA triad answers many concerns to IT security, however in a real world perspective, IT security is a cost centre and it does not exist for IT security's sale alone, many other factors may be considered along with IT security within an organization

- Security
- Operations
- Business

##### Trust & Verify

The concept of not taking anything at face value is important in IT security. For instance if a vendor says their product can perform the job, you have to test the vendo's assertion and find out yourself.

##### Ask The Oracle

Another good habit is the skill of looking for information whenever you are unsure of something, want to find out more about a topic, encounter an error message or face a problem that needs to be resolved. The oracle in question is defined a source of information, a good example being Google due to its comprehensiveness

If your choice of tool are search engines such as Google, it is also good to develop your skill in phrasing search entries and validating and narrowing search results.

#### 8-Step Security Gameplan

The Security Gameplan is a summary framework which shows the general execution of a security implementation. This is because security impleentations are not full-featured products that can be bought form vendors, but must be approacehd in a holistic perspective that takes accouunt policies, people and other non-technical factors

1. Identify Centers of Gravity
    - What are considered important assets
    - Where are they located
    - Is danger real or imagined
    - Establish valuation baseline
    - Determine consequence of a threat materializing
2. Understand the Threats
    - Identify what constitutes a threat to your assets
    - Segregate into categories such as internal/external, natural/man-made
    - Take the perspective of attackers
    - Understand the environment you operate in
3. Gather Information from Stakeholders
    - Get roles of stakeholders in assets to be protected
    - Get feedback from parties involved in changes to reduce resistance
    - Maintian dialogure with concerned parties to refine plan
4. Develop Baselines
    - Take stock of equipment, configurations, applications
    - Set in place policies, procedures and platforms to idenfity deviations to baselines
    - Develop baselines based on normal operating periods
5. User and Corporate Education
    - People are weakest link, as technical defences can be circumvented through human exploitation
    - Explain rationale for proposals and convince management by equating security benefit to bottom-line results
    - Emphasise impact on bottom line
6. Establish Platform Defense
    - Setup defensive procedures & emplace defensive platforms
    - Conduct research into applicable defensive mechanisms and optimum employment
    - Understand how attackers may try to circumvent the defensive mechanisms
7. Establish Business Continuity & Disaster Recovery
    - Conduct regular drills
8. Maintian Balance
    - Ensure initiatives are followed up on
    - Continue to highlight evolving challenges and threats
    - Undertake applicability reviews
    - Patching
    - Check for compliance with law

### 2. Defending Your Turf & Security Policy Formulation

#### 4Ps of Defence

- Policies: direction a company is going to take in order to achieve whatever goals it states in the policy
- Procedures: detailed seteps, standards and workflow necessary to achieve the milestones needed to ensure policy is complied with
- Platforms: deployed to support the delivery and fufiment of the procedures
- People: operates the platforms in the manner dictated by procedures in order to attain and be compliant to the policies

#### 4 Steps of Defending Networks & Systems

1. Vulnerability Identification
    - Keep track of both technical and non-technical issues in order to be able to identify areas which need attention
2. Platform Lockdown
    - Principle of least privilege applies
    - Deploy Triple-A (authentication, authorization, accounting)
    - Implement logging mechanisms to record actions on critical servers and send logs to secure servers or write-one media
3. Monitor The Setup
    - Implement management overlay to keep track of traffic, access, user numbers, etc and ensure it is protected
    - Automate alerting mechanism
4. Damage Control
    - If breach is detected, implement containment procedures
    - Conduct triage to limit fallout and contain damage
    - Involve forensis team to assess impact

### 3. Network 101

#### Sniffing

THe identification of network traffic, to give a better idea of the true nature of traffic whtin yout network.

The sniffer of choice for most IT security practitioners is Wireshark. **For the purpose of this certification, it is important for you to be proficiet at the usage of Wireshark as a significant portion of the examination will involve analysis of network traffic**

#### OSI Model

|Layer 7|Application|
|Layer 6|Presentation|
|Layer 5|Sessions|
|Layer 4|Transport|
|Layer 3|Network|
|Layer 2|Data Link|
|Layer 1|Physical|

#### Layer 2 Frames

A frame is like an envelope containing a letter, it has an address directed towards a recipient and some content inside.

##### Components of a frame

- Frame headers and trailers perform synchronization
- Header of a frame contains MAC address of origin and destination network adapter, in the format of xx:xx:xx:yy:yy:yy (6 bytes)
- MAC address allows identification for type of device

##### Attacking Switches

Attackers can target the Content Addressable Memory (CAM) table with bogus entries, with tools such as Macof, to take up CAM table space. Legitimate entries are crowded out, causing the switch to be unable to determine legitimately connected clients, causing it to forward all frames out of every port in attmept to get frame to its destination address, enabling attackers to sniff traffic within the network.

#### Layer 3 IP

Internet Protocol is used to deliver packets from source to destination. Similarly, the source and destination headers are stored in headers.

IP is connectionless, meaning there is no pre-established connection bewtwen sender and recipient, instead relying on upper layer protocols to ensure delivery and to re-assemble the IP packets in the right order at the destination.

Addressing is in the format of aa.bb.xx.yy (32-bit) for IPv4. The last block of IPv4 addressing having been distributed in 2011, IPv6 was developed to deal with the address shortage, utilising 128-bit hexadecimal addressing.

Routers are used to route packets. They receive packets from one interface and forwards it to another interface. No known routes will result in dropped packets.

##### Time To Live (TTL) Values

TTL values can be used to determine the operating system of a host as they are usually consistent across many different machine running the same operating system.

|OS|TTL|
|--|---|
|Windows 95|32|
|Linux|64|
|Windows XP/Vista/7/Server|128|

*Note that due to hops over a network, the TTL value of a system may differ from the values stated above, generally, the closest estimate will be sufficient enough to determine the operating system*

##### Private IP Ranges

Due to the lack of IPv4 addresses, certain ranges of IP addresses were reserved for use on private networks. They include:

- Class A: 10.0.0.0 through 10.255.255.255
- Class B: 172.0.0.0 through 172.31.255.255.255
- Class C: 192.168.0.0 through 192.168.255.255

These addresses can be used anywhere so long as Network Address Translation (NAT) is performed as they are non-routable over the internet. As a result, they are based on destination, as the source can be spoofed by attackers within private ranges in Distributed Denial of Service Attacks (DDoS)

##### Amplification Attacks Through IP Broadcast

Each network contains broadcast address which relays all packets sent to the broadcast address to be forwarded to all hosts within the network.

Attackers can spoof source IP address to reflect attack back on a third party.

Smurf Attacks

1. Attacker sends 23KB ICMP echo request with destination address of 3.3.3.255 to network 3.3.3.0/24 with source address as 2.2.2.2
2. Gateway router at 3.3.3.0/24 receives echo requests and detects the destiantion address is a broadcast address, forwarding the echo request to all hosts within the 3.3.3.0/24 network
3. All live hosts receive echo request and responds with ICMP echo reply, flooding host at 2.2.2.2 with responses, possibly overwhelming it

#### Address Resoution Protocol (ARP)

ARP is employed by a host when it wants to find out the IPv4 address held by a network adapter address (MAC address). This system can result in some problems:

- ARP has no way of telling whether information contained in ARP reply is legitimate
- Attacker can send unsolicited ARP replies to hosts informing them that the IP address for a particular host is held by the attacker's MAC address
- Host accepts this ARP reply, poisoning its cache
- Any packets sent to IP address will instead be redirected to the attacker
- Attacker can "insert" himself between poisoned hosts, called a Man-In-The-Middle attack

##### Routing

Routing is the process of getting a packet from source host A to destination host B.

To send a packet to the internet, the gateway first has to be determined, which involves ARP requests to determine the MAC address of the gateway. Data is thus sent from host-to-host, host-to-router, router-to-router

#### Layer 4 TCP & UDP

##### Transmission Control Protocol (TCP)

TCP provides reliable, ordered and error-checked delivery of a stream of data between applications running on hosts communicating over an IP network.

##### Three-way Handshake

Three way handshakes are required to be established between two hosts before data can be transferred between two hosts over TCP.

Establishing connection between Host A and Host B:

|Packet|Type|Direction|
|Packet 1|SYN|Host A --> Host B|
|Packet 2|SYN/ACK|Host A <-- Host B|
|Packet 3|ACK|Host A --> Host B|

Attackers can exploit this by never sending ACK packets to complete the handshake and sending more SYN packets, resulting in the target assigning more memory to hold incomplete handshakes.

##### Four-way Termination

Four way terminations are used to indicate that two hosts want to stop communications

Establishing termination between Host A and Host B:

|Packet|Type|Direction|
|Packet 1|FIN/ACK|Host A --> Host B|
|Packet 2|ACK|Host A <-- Host B|
|Packet 3|FIN/ACK|Host A <-- Host B|
|Packet 4|ACK|Host A --> Host B|

Attackers can use FIN flagged packets to conduct reconnaissance if a firewall is stopping SYN flagged packets from going through. The default reaction to receiving a FIN packet is to terminate an existing connection using a 4-way termination. However, if there is no existing connection prior to the FIN packet, the host may send a RST packet in response. The receipt of an RST flagged packet shows that there is a host behind the firewall.

##### User Datagram Protocol (UDP)

UDP is a protocol used to transfer packets between hosts in a connectionless method, based on best-effort delivery of packets. It is used for applications such as SNMP or DNS where speed is of priority.

UDP poses challenges to identifying services as a response can only be obtained under the following conditions:

- Target with open service residing behind UDP port receives UDP packet with matching payload protocol (eg: DNS query payload for DNS service behind UDP port 53 will receive a DNS response)
- Target with no service residing behind UDP port receiving UDP packet will return ICMP unreachable packet
- All other scenarios will result in no replies from the host

#### Domain Name System (DNS)

DNS ties IP addresses to canonical names which usually include memorable phrases, allowing users to be able to access service easily.

DNS Query:

- DNS query sent (who is example.com)
- Server checks cache for DNS record, if absent, forwards to .com root server, the authoritative name server for secure**.com**
- Receives reply from authoritative name server (example.com is 8.8.8.8)
- Sends response to requester (example.com is at 8.8.8.8)

##### DNS Poisoning

A classic case of DNS poisoning starts with an attacker sending an email to their target with a link to a domain controlled by the attacker. The client will try to query the ISP DNS server for the attacker's DNS server. Once verified, the client will now receive DNS responses from the attacker's DNS. Attacker can provide illegitimate responses to the client's queries and can redirect them to malicious websites.

DNS poisoning can occur when an attacker pre-locates himself along the path of transmission of a DNS response from the ISP DNS server to the client making the request. He can then rewrite the contents of the response from the DNS server to the client with an arbitrary value.
