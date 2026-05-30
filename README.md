# 🔍 Microsoft Sentinel KQL Log Analysis Lab

**Tools Used:** Microsoft Sentinel · Azure Log Analytics · KQL (Kusto Query Language) · Windows Security Events · Azure Virtual Machines  
**Environment:** Azure cloud — Windows Server 2025 VM connected to Microsoft Sentinel workspace  
**Focus:** Real-time security event ingestion, KQL threat detection queries, brute force identification  

---

## Overview

This lab involved deploying a cloud-based Security Operations Centre environment using Microsoft Azure and Microsoft Sentinel. A Windows Server VM was provisioned, connected to a Log Analytics workspace, and configured to stream Windows Security Events into Sentinel in real time. KQL queries were then used to analyse the ingested logs, detect failed login attempts, and identify potential brute force patterns — replicating core L1 SOC analyst workflows.

---

## Environment Setup

- **Cloud Provider:** Microsoft Azure (Australia East)
- **VM:** Windows Server 2025 — Standard B2s v2
- **SIEM:** Microsoft Sentinel connected to Log Analytics workspace (soc-lab-workspace)
- **Data Connector:** Windows Security Events via AMA — collecting all security events
- **Resource Group:** SOC-Lab-RG

---

## What Was Built

### 1. Azure VM Deployment
Provisioned a Windows Server 2025 virtual machine in Azure with RDP access enabled. Configured Network Security Group rules to control inbound traffic. Connected the VM to a Log Analytics workspace to begin forwarding Windows Security Event logs to Microsoft Sentinel.

### 2. Sentinel Workspace Configuration
Created a Microsoft Sentinel workspace and installed the Windows Security Events data connector via Content Hub. Set up a Data Collection Rule (SOC-Lab-DCR) targeting the VM to collect all security events and forward them to the Sentinel workspace for analysis.

### 3. Security Event Generation
Connected to the VM via RDP and generated real authentication events including failed login attempts (Event ID 4625) and successful logons (Event ID 4624). Verified event capture through Windows Event Viewer before confirming ingestion into Sentinel.

---

## KQL Queries Written & Executed

### Query 1 — Detect Failed Login Attempts
```kql
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Account, Computer, IpAddress, EventID
| order by TimeGenerated desc
```
**Result:** Returned 4 failed login events from IP 121.200.7.68 targeting SOC-Lab-VM — confirmed real-time log ingestion working correctly.

---

### Query 2 — Brute Force Detection
```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by Account, Computer, IpAddress
| order by FailedAttempts desc
```
**Result:** Identified account with 4 failed attempts from a single IP — pattern consistent with brute force behaviour. This query replicates standard L1 SOC triage for RDP brute force detection.

---

### Query 3 — Login Activity Dashboard
```kql
SecurityEvent
| where EventID in (4624, 4625)
| summarize 
    SuccessfulLogins = countif(EventID == 4624),
    FailedLogins = countif(EventID == 4625)
    by Account, Computer
| order by FailedLogins desc
```
**Result:** Side-by-side view of successful vs failed logins per account across the VM. Identified 10 system accounts with normal activity and flagged the one account with failed logins and zero successful logins — a high-priority indicator for investigation.

---

## Key Findings

| Account | Computer | Successful Logins | Failed Logins |
|---|---|---|---|
| akashprakash471@gmail.com | SOC-Lab-VM | 0 | 4 |
| NT AUTHORITY\SYSTEM | SOC-Lab-VM | 136 | 0 |
| SOC-Lab-VM\akash | SOC-Lab-VM | 3 | 0 |

**Analyst note:** The Microsoft account showing 4 failed logins with 0 successful logins from a single external IP is a high-confidence indicator of unauthorised RDP access attempts. In a real SOC environment this would trigger an incident and the source IP would be blocked at the firewall level.

---

## Skills Demonstrated

- Azure VM deployment and network security group configuration
- Microsoft Sentinel workspace setup and data connector configuration
- Windows Security Event log ingestion via AMA agent
- KQL query writing for threat detection and log analysis
- Failed login detection (Event ID 4625) and successful logon analysis (Event ID 4624)
- Brute force pattern identification and analyst documentation
- Cloud-native SIEM operations replicating real L1 SOC workflows

