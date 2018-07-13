# OSSA Notes

Notes for the ThinkSECURE Organizational Systems Security Analyst (OSSA) Certification. Information here was sourced from both study guides provided by ThinkSECURE and personal anecdotes from the March 2018 run of the certification examination.

NOTE: *Information listed here may not accurately reflect content that is involved in any particular future runs of the examination*

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

The bulk of the examination focuses on two topics: analyzing network traffic and network scanning. Hence, I would suggest placing more focus on getting comfortable with using WireShark and nmap. Additionally, I would also advice that you read up on concepts that are related to these two tools. Some of the aforementioned concepts may include but are not limited to:

- TCP three way handshakes
- TCP flags
- TCP protocols

During the examination, I highly suggest that you begin off by performing nmap scans of all the hosts involved and specified in the question paper and record down all the information you can retrieve. During this time, focus on answering questions from other sections and topics during this time. This is because in a class of 20 students, the limited bandwidth will result in very long scan times so having to repeat the nmap scans multiple times over to get information you have missed out on will be a huge waste of time.

## Course Content

This section contains the information included in the training programme for the certification

### 1. What Is Information Security

#### Origins of Cyberattacks

- The Curious: people who found tools on the internet and randomly picks IP addresses to test on
- The Malicious: dislike of other persons or organizations
- The Criminal: attacks with intent to commit crime
- The Competitor: attacks against competing businesses in the same industry
- The Natural: natural causes such as disasters resulting in denial of service
- The Politically-charged: politically or bureaucratically motivated attacks

#### Basic Security Concepts

##### CIA Triad

- Confidentiality: preventing others from finding out about things (encryption)
- Integrity: how to keep data and platform in a state of "wholeness" (hash)
- Availability: notion of maintaining on-demand accessibility (redundancy)

##### SOB Troika

The CIA triad answers many concerns to IT security, however in a real world perspective, IT security is a cost centre and it does not exist for IT security's sale alone, many other factors may be considered along with IT security within an organization

- Security
- Operations
- Business

##### Trust & Verify

The concept of not taking anything at face value is important in IT security. For instance if a vendor says their product can perform the job, you have to test the vendor's assertion and find out yourself.

##### Ask The Oracle

Another good habit is the skill of looking for information whenever you are unsure of something, want to find out more about a topic, encounter an error message or face a problem that needs to be resolved. The oracle in question is defined a source of information, a good example being Google due to its comprehensiveness

If your choice of tool are search engines such as Google, it is also good to develop your skill in phrasing search entries and validating and narrowing search results.

#### 8-Step Security Gameplan

The Security Gameplan is a summary framework which shows the general execution of a security implementation. This is because security implementations are not full-featured products that can be bought form vendors, but must be approached in a holistic perspective that takes account policies, people and other non-technical factors

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
    - Maintain dialogue with concerned parties to refine plan
4. Develop Baselines
    - Take stock of equipment, configurations, applications
    - Set in place policies, procedures and platforms to identify deviations to baselines
    - Develop baselines based on normal operating periods
5. User and Corporate Education
    - People are weakest link, as technical defences can be circumvented through human exploitation
    - Explain rationale for proposals and convince management by equating security benefit to bottom-line results
    - Emphasize impact on bottom line
6. Establish Platform Defense
    - Setup defensive procedures & emplace defensive platforms
    - Conduct research into applicable defensive mechanisms and optimum employment
    - Understand how attackers may try to circumvent the defensive mechanisms
7. Establish Business Continuity & Disaster Recovery
    - Conduct regular drills
8. Maintain Balance
    - Ensure initiatives are followed up on
    - Continue to highlight evolving challenges and threats
    - Undertake applicability reviews
    - Patching
    - Check for compliance with law

### 2. Defending Your Turf & Security Policy Formulation

#### 4Ps of Defence

- Policies: direction a company is going to take in order to achieve whatever goals it states in the policy
- Procedures: detailed steps, standards and workflow necessary to achieve the milestones needed to ensure policy is complied with
- Platforms: deployed to support the delivery and fulfillment of the procedures
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
    - Involve forensics team to assess impact

### 3. Network 101

#### Sniffing

THe identification of network traffic, to give a better idea of the true nature of traffic within your network.

The sniffer of choice for most IT security practitioners is Wireshark. **For the purpose of this certification, it is important for you to be proficient at the usage of Wireshark as a significant portion of the examination will involve analysis of network traffic**

#### OSI Model

|Number|Name|
|---|---|
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

Attackers can target the Content Addressable Memory (CAM) table with bogus entries, with tools such as Macof, to take up CAM table space. Legitimate entries are crowded out, causing the switch to be unable to determine legitimately connected clients, causing it to forward all frames out of every port in attempt to get frame to its destination address, enabling attackers to sniff traffic within the network.

#### Layer 3 IP

Internet Protocol is used to deliver packets from source to destination. Similarly, the source and destination headers are stored in headers.

IP is connectionless, meaning there is no pre-established connection between sender and recipient, instead relying on upper layer protocols to ensure delivery and to re-assemble the IP packets in the right order at the destination.

Addressing is in the format of aa.bb.xx.yy (32-bit) for IPv4. The last block of IPv4 addressing having been distributed in 2011, IPv6 was developed to deal with the address shortage, utilizing 128-bit hexadecimal addressing.

Routers are used to route packets. They receive packets from one interface and forwards it to another interface. No known routes will result in dropped packets.

##### Time To Live (TTL) Values

TTL values can be used to determine the operating system of a host as they are usually consistent across many different machine running the same operating system.

|OS|TTL|
|--|---|
|Windows 95|32|
|Linux|64|
|Windows XP/Vista/7/Server|128|

NOTE: *Due to hops over a network, the TTL value of a system may differ from the values stated above, generally, the closest estimate will be sufficient enough to determine the operating system*

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
2. Gateway router at 3.3.3.0/24 receives echo requests and detects the destination address is a broadcast address, forwarding the echo request to all hosts within the 3.3.3.0/24 network
3. All live hosts receive echo request and responds with ICMP echo reply, flooding host at 2.2.2.2 with responses, possibly overwhelming it

#### Address Resolution Protocol (ARP)

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
|---|---|---|
|Packet 1|SYN|Host A --> Host B|
|Packet 2|SYN/ACK|Host A <-- Host B|
|Packet 3|ACK|Host A --> Host B|

Attackers can exploit this by never sending ACK packets to complete the handshake and sending more SYN packets, resulting in the target assigning more memory to hold incomplete handshakes.

##### Four-way Termination

Four way terminations are used to indicate that two hosts want to stop communications

Establishing termination between Host A and Host B:

|Packet|Type|Direction|
|---|---|---|
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

### 4. Defensive Tools & Lockdown

#### Firewall

Firewalls act as barriers between computers in an network.

Firewalls can come in multiple forms, which include and are not limited to:

- Appliance - Firmware code residing on dedicated hardware platform
- Software - Installed on server as point defence
- Personal - For workstations and individuals

There are also different types of firewalls:

- Packet Filter

Sits between internal network nd rest of the world, allowing packets to pass through it when travelling to and fro the internal network and the internet. The packet filter will compare packets to a set of rules which decides whether the packet should be forwarded onto the next hop or discarded.

Certain firewalls will send a notice when a packet has been dropped, it is discouraged to have such setup, instead the firewall should silently drop packets which do not match rules.

Packet filters compare packets to rules usually based on factors such as source addresses and ports, destination addresses and ports.

As a result, packet filters are normally fast as they do not perform data checking, easy to setup, wide compatibility with applications. Additionally, Network Address Translations and Network Address Port Translation also adds to the security of packet filters.

- Stateful Packet Inspection (SPI)

SPIs are similar to packet filters, but maintain state about each connection passing through them. It has built in knowledge about TCP/IP rules for data flow between two hosts and can detect incorrectly sequenced packets and inconsistent IP protocol options as a result.

Attackers cannot send packets that appear to be part of an existing connection (packets sent to port 80 without initiating a connection will be rejected).

SPIs can help to mitigate DoS attacks (SYN floods), track established connections and allow inbound packets based on state and is relatively fast

- Application Proxy

Proxies break up connection between server and client, acting as a middleman handling connection between each other. It masks the IP stack and characteristics of server it is protecting, resulting in any fingerprinting attempt against the network stack hitting the proxy first and not the server. Additionally, if an attacker tries to make use of fragmented packets of fields in IP packet, the internal server will never receive the packet.

Certain proxies have knowledge of application-specific data and cen therefore check the legality of traffic between the server and client. (Web application proxy can check the legality of a HTTP GET request before forwarding it to the web server)

One major disadvantage is that it since it is application specific, it has to be written to handle specific application protocols. A web application proxy may not be able to understand traffic meant for a FTP server.

- Proxy Firewall

Adding on to application proxies, it is able to perform payload-level inspection. It combines stateful packet inspection, proxy technologies and application-protocol awareness.

Proxy firewalls still act like proxies, it acts as a middleman and receives packets between clients and servers and examines the packets between the 2 connections. It interrogates the behavior and logic of what is being requested and returned, protecting against application-specific attacks. (eg: A web-app firewall protects against attacks such as SQL injection and XSS, parameter or URL tampering and buffer overflows by analysing the contents of each incoming and outgoing attack)

##### Firewall Rules of Thumb

- Block inbound packets (ingress)
- Block outbound packets (egress)
- Implicit deny-all

##### Firewall Deployment

- Internet -> External DMZ -> External FW -> Internal DMZ -> Internal FW -> Network (expensive to purchase equipment for)
- Internet -> FW -> DMZ / Network (risk of rule confusion due to multiple interfaces)

#### Network Intrusion Detection System (NIDS)

A NIDS monitors traffic on its network segment as a data source, accomplished by placing the network interface card in promiscuous mode to capture all network traffic that crosses it. Network based identification involves looking at packets and are considered to be of interest if it matches a signature.

There are three primary types of signatures:

- String Signatures: Looks for text strings that indicate a possible attack, can be refined to reduce number of false positives by using compound string signatures
- Port Signatures: Watches for connection attempts to well-known ports, if directed to unused ports, it is an indication of suspicious activity
- Header Condition Signatures: Watches for dangerous or illogical combinations in packet headers

NIDS requires a connection to a network segment to monitor, which can include hubs, switch-port monitoring or active taps

An example of a NIDS is [Snort](http://www.snort.org)

#### Host-based Intrusion Detection System (HIDS)

HIDS focus on monitoring and analyzing the internals of a system rather than its external interfaces. It usually uses a database of system objects it should monitor and can also be made to check that appropriate regions of memory have not been modified.

Some problems with HIDS include:

- Many HIDS can only monitor certain types of systems
- HIDS do not have access to core communication functionality of system, incapable of fending off attacks against protocol stack
- Cannot inform before something happens
- Expensive

An example of a HIDS software is [Tripwire](http://sorceforge.net/projects/tripwire)

#### Honeypots

A honeypot is a trap set to detect, deflect or to counteract attempts at unauthorized use of information systems. It generally consists of a computer system, data or a network that appears to be part of a network but is actually isolated and protected. It also seems to contain information or resources that would be of value to attackers.

##### Low-Interaction Honeypots

Low-interaction honeypots have allow attackers limited abilities, they normally work by emulating services and operating systems.

Advantages:

- Easy to deploy and maintain with minimal risk
- Requires only installation of software, OS and services to be emulated and monitored.
- Emulated services mitigate risk by containing attacker's activity, attacker never has access to OS

Disadvantages:

- Logs only limited information and are designed to capture known activity
- Easy for attacker to detect low-interaction honeypot

##### High-Interaction Honeypots

High-interaction honeypots are more complex solutions which involve real operating systems and applications. Nothing is simulated, allow attackers to access real services.

Advantages:

- Can capture extensive amounts of information. Allowing attackers full and real extent of systems to interact with, their full behavior can be learnt
- Provides an open environment that captures all activity, allowing high-interaction solutions to learn unexpected behavior

Disadvantages:

- Risk is increased as attackers can use real OS to attack non-honeypot systems
- More complex to deploy and maintain

##### Common Errors In Deploying Honeypots

- Creating contiguous range of fake hosts with have exactly the same characteristics
- Attacker would only have to scan entire target range to identify hosts which appear to have same configuration
- In normal enterprise environments, real servers are deployed on business requirements and are rarely exactly identical
- Try to make each honeypot host as unique as possible and spread across IP subnet

An example of a honeypot is [Honeyd](http://honeyd.org)

#### Cryptography

Cryptography is the field of mathematics and computer science concerned with encryption and authentication.

##### Transposition Cipher

A transposition cipher changes the position of one character from the plaintext to another in the cipher text. An example of a transposition cipher is the Railfence Cipher.

``` raw
WE ARE DISCOVERED FLEE AT ONCE

W R I O R F E O E
E E S V E L A N R
A D C E D E T C X
```

##### Substitution Cipher

A substitution cipher is a method of encryption by which units of plaintext are substituted with cipher text according to a regular system.

``` raw
Plaintext alphabet:  abcdefghijklmnopqestuvwxyz
Ciphertext alphabet: ZEBRASCDFGHIJKLMNOPQTUVWXY

Message: Flee at once, we are discovered
Cipher:  SIAA ZA LKBA, VA ZOA RFPBLUAOAR
```

##### Block Cipher

Block ciphers are a symmetric key cipher which operates on fixed-length groups of bits as plaintext and ciphertext. Examples include Data Encryption Standard (DES), Triple DES (3DES) and Advanced Encryption Standard (AES).

##### Stream Cipher

Stream ciphers are a symmetric cipher where plaintext digits are encrypted one at a time and in which the transformation of successive digits varies during encryption. Examples include Rivest Cipher 4 (RC4), HC-256 and CryptMT.

Stream ciphers are preferred over block ciphers where lower latency encrypted communications is desired. For example, RC4 is used as a cipher for WEP and WPA encryption under the 802.11 wireless networking implementation.

##### Uses of Cryptography

1. Proving Integrity by Hashing

   A hash function is a function which examines the input data and produces an output of a fixed length, called a hash value. Even if two values differ by a bit, the output will have significant differences. If two hashes of the same function are different, the inputs are definitely different. Examples of hash algorithms include Message Digest 5 (MD5) and Secure Hashing Algorithm (SHA).

2. Sending Data Using Symmetric Key Encryption

   Symmetric-key algorithms are a class of algorithms for cryptography that use the same key for encryption and decryption. In practice, it means that it represents a shared secret between two or more parties that can be used to maintian a private information link. It is not feasable for cases involving large numbers of people, as the comprimise of one key requires changing keys for all parties involved, having different keys for everyone means maintining a whole array of keys per person.

3. Remote Networking Using Virtual Private Networking

   VPNs use symmetric key encryption to encrypt communications between two end points.

   a. Transport Mode with Authentication Header (AH):

    ```raw
    <-----Original IP Packet----->
    --------------------------------------------------------
    | Data | TCP/UDP | IP Header | AH | Original IP Header |
    --------------------------------------------------------
    <---------------------Signed by AH--------------------->
    ```

    AH used in transport mode will create a checksum of the original IP packet and store the hash within the AH. The IP header is added to the new header of the packet. At the destination, the hash of the payload is calculated again and checked against the AH to ensure that it has not been modified. AHs in transport mode help to ensure integrity of the packet.

   b. Transport Mode with Encapsulating Security Payload (ESP):

    ```raw
                                    <-----Original IP Packet----->
    ------------------------------------------------------------------------------------------------
    |ESP Auth Trailer | ESP Trailer | Data | TCP/UDP | IP Header | ESP Header | Original IP Header |
    ------------------------------------------------------------------------------------------------
                      <---------Encrypted with ESP Header-------->
                      <---------------Signed by ESP Auth Trailer-------------->
    ```

   ESP used in transport mode will encrypt the original IP packet with the ESP header. The data within this portion of the packet is now unreadable to people without the decryption key. The ESP Auth header is then used to create a checksum of the now encrypted packet. The original IP header is then inserted at the head of the packet. At the destination, a hash of the encrypted portion of the packet is generated and compared to the ESP Auth Trailer to ensure it has not been modified and is then decrypted using the ESP header. AH in transport mode ensures that the confidentiality and integrity of the packet.

   c. Tunnel Mode with AH

   ```raw
    <-----Original IP Packet----->
    ---------------------------------------------------
    | Data | TCP/UDP | IP Header | AH | New IP Header |
    ---------------------------------------------------
    <---------------------Signed by AH---------------->
    ```
    AH in tunnel mode works the same way as AH in transport mode, with the exception that a new IP header is added to the head of the packet instead of re-using the original IP header.

   d. Tunnel Mode with ESP

    ```raw
                                    <-----Original IP Packet----->
    -------------------------------------------------------------------------------------------
    |ESP Auth Trailer | ESP Trailer | Data | TCP/UDP | IP Header | ESP Header | New IP Header |
    -------------------------------------------------------------------------------------------
                      <---------Encrypted with ESP Header-------->
                      <---------------Signed by ESP Auth Trailer-------------->
    ```

    ESP in tunnel mode works the same way as ESP in transport mode, with the exception that a new IP header is added to the head of the packet instead of re-using the original IP header.

   In transport mode, the original IP headers remain unmodified while only the payload is authenticated and/or encrypted. Transport mode is incompatible in networks with communications required to be made over NAT.

   In tunnel mode, the entire IP packet is authenticated and/or authenticated. A new IP header is added to the packet. It is generally used for end-to-end communications (gateway-to-gateway).

4. Sending Data Using Public-Key Cryptography

   Public key crpytography is a form of cryptography which allows users to communicate without having prior access to a shared key. This is done by using keypairs, designated public and private keys. It should not be possible to deduce the private key given a public key. Public-key crryptography can be used to perform encryption (keeping a message secret to anyone who does not possess a specific private key) as digital signatures (allow anyone to verify a message has been created using a specific private key)

   ```raw
   receipient's public key + plaintext = ciphertext
   ciphertext + receipient's private key = plaintext
   ```

5. Proving Identity Using Digital Signatures

   Digital signatures are encryption schemes for authenticating digital information.

6. Ransomware

   Ransomware are malicious software which uses asymmetric encryption to encrypt files in order to extort money from victims in exchange for the private key to decrypt their files.

##### Trust Standards: Public Key Cryptography (PKI)

PKI is an arrangement which provides for third-party vetting of and vouching for user identities. Public keys are typically contained in certificates. PKI arrangements enable users to be authenticated to each other, and to use information in identity certificates to encrypt and decrypt messages travelling to and fro. PKIs usually consist of client software, server software and hardware and operational procedures. A user may digitally sign messages using his private key and another user can check the signature using the public key contained in that user's digital certificate. An example of such software is [GNUPrivacyGuard (GPG)](http://www.gnupg.org)

### 5. The 5E Attacker Methodology

#### Preparation

- Sandboxing

- Tool Repositories

- Checking Tool Authenticity

#### Exploration

#### Enumeration

#### Exploitation

#### Embedding

#### Egress

### 6. Wireless Insecurity

#### 802.11 Basics

Security/encryption implementations for WLAN include:

1. Open

    Anyone can connect, typically used in hotspots, can be used as jump-off points for attacks

2. Wired Equivalent Privacy (WEP)

    Characteristics: Uses 40/64 or 104/128 bit keys as standard, was part of 802.11i standard

    WEP revolves around a stream cipher, the RC4 encryption algorithm, data is encrypted as it is fed into the cipher to produce stream of cipher text via XOR operation based on a random initialization vector and a pre-shared key. WEP also uses a CRC algorithm to test the integrity of a transmitted packet. A weakness of this implementation is the possibility of IV collisions.

3. WiFi Protected Access - Pre-Shared Key (WPA-PSK)/WPA2-PSK

    Characteristics: Uses TKIP in place of WEP, uses an ASCII passphrase up to 64 characters long to derive key hierarchy used by TKIP, aka Simple Secure Network (SSN) for WPA-PSK and Robust Secure Network (RSN) for WPA2-PSK

    Problems: Can be broken, in under 5 minutes at 150mbps with steady flow of traffic if ARP-replay injected is used, also breakable if passphrase is dictionary-guessable or if first two frames of 4-way handshake are captured, problems demonstrate need for more robust forms of 802.11 frame encryption

4. WPA/WPA2

    Characteristics: Similar to WPA/WPA2-PSK but uses 802.1x together with authentication server to generate key hierarchy in place of pre-shared key element, master key is now considered truely random, not known to be crackable using current generation of WPA-crackingtools.

5. VPNoL

    Characteristics: Uses VPN architecture riding at layer 3 over WLAN, independent of frame layer payload encryption, effective even it 802.11 level security is breached by current or future attacks.

#### Attacks

- Warchalking: Tool to search for free 802.11 services in the area
- Wardriving: Active search for free WLAN access, considered a crime in many countries.

#### Typical WLAN Deficiencies

- Not enabling frame level encryption (WPA/WPA2)
- Using dictionary based WPA-PSK passphrases
- Not turning off SSID broadcasts in beacon frames
- Not using MAC or IP address filtering
- Not segmenting the WLAN as a DMZ
- Not turning off unneeded AP services (telnet, SNMP)
- Leaving AP settings defaulted (logins, passwords)
- SSID defaulted/revealing
- Not minimizing RF emanations

### 7. Incident Response & Computer Forensics

### 8. The Impact of Law

## Useful Commands
