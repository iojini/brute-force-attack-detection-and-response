# Incident Response: Brute Force Attack Detection and Response

---

## Executive Summary
Coordinated brute force authentication attempts targeting two Azure Virtual Machines within the organization's cloud infrastructure were observed. Over 170 failed Remote Desktop Protocol (RDP) login attempts originating from two distinct public IP addresses over a five-hour period were identified. The Security Operations Center immediately initiated incident response procedures in accordance with **NIST 800-61** guidelines. 

Investigation confirmed no successful unauthorized access occurred. Containment measures included network isolation via Microsoft Defender for Endpoint (MDE), comprehensive malware scanning, and Network Security Group (NSG) hardening to restrict RDP access exclusively to authorized corporate IP addresses. This incident represents a true positive security event that was successfully detected and mitigated with no data compromise or system breach. Policy recommendations have been proposed to prevent similar exposure across the enterprise virtual machine fleet.

---
## Incident Classification

### MITRE ATT&CK Framework Mapping

| Tactic | Technique ID | Technique Name |
|--------|--------------|----------------|
| Initial Access | T1078 | Valid Accounts |
| Credential Access | T1110.001 | Brute Force: Password Guessing |

---
### Severity Assessment
**Severity Rating**: MEDIUM

**Justification**:
-	No successful unauthorized access achieved
-	Attack detected and contained within organizational SLA
-	Network exposure identified requiring remediation
-	No data exfiltration or system compromise
-	Indicators of systematic credential stuffing attempts

---
## Incident Timeline

| Time | Event |
|------|-------|
| T-5:00 | Initial brute force attempts begin |
| T+0:00 | Brute force attempts detected |
| T+0:15 | SOC analyst assigned, status: Active |
| T+0:45 | KQL query confirms no successful authentication |
| T+1:00 | Containment: Device isolation via MDE |
| T+1:30 | NSG rules updated to restrict RDP access |
| T+2:00 | Malware scans complete - negative results |
| T+3:00 | Incident closed as True Positive - Benign |

---
## Technical Analysis
The incident involved coordinated brute force authentication attempts targeting two Azure Virtual Machines. Analysis of DeviceLogonEvents telemetry revealed systematic password guessing behavior characteristic of automated credential stuffing tools.

### Affected Assets

| Device Name | Attack Source IP | Failed Attempts |
|-------------|------------------|-----------------|
| corey-win-machi | 80.64.18.199 | 97 |
| windows-target-1 | 88.214.50.59 | 74 |
| **Total:** | **2 Unique IPs** | **171** |

---

### KQL Detection Query
```kql
DeviceLogonEvents
| where TimeGenerated >= ago(5h)
| where ActionType == "LogonFailed"
| summarize NumberOfFailures = count() by RemoteIP, ActionType, DeviceName
| where NumberOfFailures >= 10
```
<img width="1659" height="350" alt="IR1" src="https://github.com/user-attachments/assets/e00b5858-4caa-43f3-96fb-10e6c2a34c1c" />

---
### Investigation Query

The following KQL query was executed to verify whether any of the attacking IP addresses successfully authenticated to the targeted systems:

```kql
DeviceLogonEvents
| where RemoteIP in (“80.64.18.199”, “88.214.50.59”)
| where ActionType != “LogonFailed”
```

**Result:** No successful login events were recorded from either attacking IP address. All authentication attempts from these sources resulted in LogonFailed actions.

---
## Findings & Impact Assessment

### Key Findings
-	**No successful unauthorized access was achieved**
-	All 171 authentication attempts resulted in LogonFailed events
-	Attack originated from geographically distributed IP addresses
-	Network Security Groups were configured with overly permissive RDP access rules
-	Detection and response occurred within acceptable SLA parameters
-	No malware or persistence mechanisms were identified on affected systems

---

### Impact Assessment

| Category | Impact Level | Findings |
|----------|--------------|---------|
| **Confidentiality:** | None | No data accessed or exfiltrated |
| **Integrity:** | None | No system modifications detected |
| **Availability:** | Minimal | Brief isolation period during investigation |
| **Financial:** | None | No financial loss incurred |
| **Reputational:** | None | Internal incident with no external notification required |

---

## Response Actions (NIST 800-61)
### <ins>Preparation</ins>
-	Incident response procedures documented and accessible
-	Microsoft Sentinel analytics rules configured and operational
-	Microsoft Defender for Endpoint deployed across virtual machine fleet
-	SOC team trained on brute force attack response procedures

---

### <ins>Detection & Analysis</ins>
#### Initial Detection
-	Automated alert triggered via Microsoft Sentinel scheduled query rule
-	Incident automatically created with entity mappings (RemoteIP and DeviceName)
-	SOC analyst notified via SIEM alerting mechanism

#### Investigation Methodology
-	Incident assigned to analyst and status updated to Active
-	Sentinel investigation graph utilized to visualize entity relationships
-	KQL queries executed to identify attack patterns and verify authentication status
-	Failed logon events analyzed across 5-hour detection window
-	Verification performed to confirm no successful authentication from attacking IPs

---

### <ins>Containment, Eradication, and Recovery</ins>
#### Containment Measures
-	Device isolation initiated via Microsoft Defender for Endpoint on all affected systems
-	Anti-malware scans executed on isolated devices
-	Network Security Group rules updated to restrict RDP access to authorized corporate IP addresses only
-	Public internet RDP exposure eliminated through NSG hardening

#### Eradication
-	Anti-malware scan results: No threats detected
-	No persistence mechanisms or malware artifacts identified
-	Assessment concluded: No eradication activities required (attack unsuccessful)

#### Recovery
-	Device isolation lifted after threat verification complete
-	Systems returned to normal operational status
-	Hardened NSG configurations remain in place as permanent security enhancement

---

### <ins>Post-Incident Activities</ins>
#### Documentation
-	Comprehensive incident notes recorded within Microsoft Sentinel
-	Timeline of events documented with UTC timestamps
-	Technical indicators of compromise cataloged
-	Response actions and remediation steps recorded

#### Incident Closure
-	Incident reviewed for completeness
-	Classification: True Positive - Benign
-	Status: Closed
-	No escalation or external notification required

---

## Root Cause Analysis
### Primary Root Cause
Azure Virtual Machines were deployed with Network Security Group configurations that permitted unrestricted Remote Desktop Protocol (RDP) access from the public internet (0.0.0.0/0). This overly permissive network posture created an attack surface that enabled external threat actors to conduct brute force authentication attempts without network-level restrictions.

### Contributing Factors:
-	Absence of organizational policy requiring NSG hardening for cloud workloads
-	Lack of automated compliance enforcement via Azure Policy
-	Default Azure NSG configurations not aligned with least privilege principles
-	No requirement for Azure Bastion or Just-In-Time (JIT) VM Access for administrative connections

---

## Lessons Learned & Recommendations
### What Worked Well
-	Automated detection through Microsoft Sentinel scheduled query rules
-	Effective log aggregation from Microsoft Defender for Endpoint to Log Analytics Workspace
-	Rapid incident response and containment (under 3 hours from detection to closure)
-	Strong password policies prevented successful credential compromise
-	Entity mapping in Sentinel facilitated efficient investigation workflow

### Areas for Improvement
-	Proactive network hardening should occur at deployment, not post-incident
-	Azure Policy enforcement needed to prevent misconfigured NSGs
-	Consider implementing Azure Bastion to eliminate direct RDP exposure
-	Detection query could be enhanced to identify successful brute force attempts

### Recommendations

| ID | Recommendation | Priority | Owner |
|----|----------------|----------|-------|
| REC-001 | Implement Azure Policy to enforce NSG hardening across all Virtual Machines, prohibiting 0.0.0.0/0 access for management ports (RDP, SSH) | **HIGH** | Cloud Ops |
| REC-002 | Deploy Azure Bastion for all production Virtual Machines to eliminate direct internet exposure for administrative access | **HIGH** | Cloud Arch |
| REC-003 | Enable Just-In-Time (JIT) VM Access in Microsoft Defender for Cloud for time-limited administrative access | **MEDIUM** | SecOps |
| REC-004 | Enhance Sentinel detection query to include correlation for successful authentication following failed attempts (true brute force success) | **MEDIUM** | SOC |
| REC-005 | Implement multi-factor authentication (MFA) requirement for all administrative access to Azure Virtual Machines | **HIGH** | Identity |
| REC-006 | Conduct quarterly review of all NSG configurations to identify and remediate overly permissive rules | **LOW** | Cloud Ops |

---

## Supplemental Appendix
### Indicators of Compromise (IOCs)

| IOC Type | Value | Context |
|----------|-------|---------|
| IPv4 Address | `80.64.18.199` | Attack Source |
| IPv4 Address | `88.214.50.59` | Attack Source |
| Hostname | `corey-win-machi` | Targeted Asset |
| Hostname | `windows-target-1` | Targeted Asset |

---

### Detection Rule Configuration (Sentinel Scheduled Query Rule Setup)
- **Rule Name:** Brute Force Attack Detection
- **Data Source:** DeviceLogonEvents
-	**Query Frequency:** Every 4 hours
-	**Lookback Period:** Last 5 hours
-	**Alert Threshold:** ≥10 failed logon attempts per RemoteIP/DeviceName pair

---

### References
-	NIST SP 800-61 Rev. 3: Incident Response Recommendations and Considerations for Cybersecurity Risk Management
-	MITRE ATT&CK Framework - Credential Access (TA0006)
-	Microsoft Sentinel Documentation: Scheduled Query Rules
-	Microsoft Defender for Endpoint: DeviceLogonEvents Schema
-	Azure Network Security Groups Best Practices

---
