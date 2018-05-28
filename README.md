# OSSA Notes

Notes for ThinkSECURE's Organisational Systems Security Analyst (OSSA) Certification. Information here was sourced from both study guides provided by ThinkSECURE and personal anecdotes from the March 2018 run of the certification examination.

_Information listed here may not accurately reflect content that is involved in any particular future runs of the examination_

## Table of Contents

1. [Introduction](Introduction)
2. [Course Content](Course-Content)
    - [What Is Information Security](What-Is-Information-Security)
        - [Origins of Cyberattacks](Origins-of-Cyberattacks)
        - [Basic Security Concepts](Basic-Security_Concepts)
        - [8-Step Security Gameplan](8-Step-Security-Gameplan)
    - [Defending Your Turf & Security Policy Formulation](Defending-Your-Turf-&-Security-Policy-Formulation)
        - [4Ps of Defence](4Ps-of-Defence)
        - [4 Steps of Defending Networks & Systems](4-Steps-of-Defending-Networks-&-Systems)
    - [Network 101](Network-101)

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

#### OSI Model 

#### Layer 2 Frames


### 4. Defensive Tools & Lockdown

### 5. The 5E Attacker Methodlogy

### 6. Wireless Insecurity

### 7. Incident Response & Computer Forensics

### 8. The Impact of Law

## Useful Commands
