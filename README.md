# Incident Response: Brute Force Attack Detection and Response

---

## Executive Summary
Microsoft Sentinel detected coordinated brute force authentication attempts targeting two Azure Virtual Machines within the organization's cloud infrastructure. The automated detection system identified 171 failed Remote Desktop Protocol (RDP) login attempts originating from two distinct public IP addresses over a five-hour period. The Security Operations Center immediately initiated incident response procedures in accordance with **NIST 800-61** guidelines. 

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
## Technical Analysis
The incident involved coordinated brute force authentication attempts targeting two Azure Virtual Machines. Analysis of DeviceLogonEvents telemetry revealed systematic password guessing behavior characteristic of automated credential stuffing tools.

### Affected Assets

| Device Name | Attack Source IP | Failed Attempts |
|-------------|------------------|-----------------|
| corey-win-machi | 80.64.18.199 | 97 |
| windows-target-1 | 88.214.50.59 | 74 |
| **Total:** | **2 Unique IPs** | **171** |

---

### Detection Mechanism

**Alert Rule Configuration:**
-	**Query Interval:** Every 4 hours
-	**Lookback Period:** Last 5 hours
-	**Threshold:** ≥10 failed logon attempts per RemoteIP/DeviceName pair
-	**Data Source:** DeviceLogonEvents table (Microsoft Defender for Endpoint)
-	**Alert Grouping:** 24-hour consolidation window

---

### KQL Detection Query
```kql
DeviceLogonEvents
| where TimeGenerated >= ago(5h)
| where ActionType == "LogonFailed"
| summarize NumberOfFailures = count() by RemoteIP, ActionType, DeviceName
| where NumberOfFailures >= 10
```

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
### Preparation
-	Incident response procedures documented and accessible
-	Microsoft Sentinel analytics rules configured and operational
-	Microsoft Defender for Endpoint deployed across virtual machine fleet
-	SOC team trained on brute force attack response procedures

---

### Detection & Analysis
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

### Containment, Eradication, and Recovery
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

### Post-Incident Activities
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






---

### **Step 1: Create-Alert-Rule** 
how to create a alert rule in Microsoft Sentinel , go to Microsoft Sentinel, click on your group, click on configuration, click on Analytics, click create with the + beside it , click scheduled query rule
After clicking **"Scheduled query rule"**, you’ll see the **Analytics rule details** tab. Fill in the following fields:

1. **Name**:  
   - Enter a name for your rule, e.g., **"🔥 Brute Force Attack Detection 🔐"**.

2. **Description**:  
   - Add a brief description of what the rule does, e.g.,  
     *"🔍 This rule detects potential brute-force login attempts based on failed sign-ins exceeding a defined threshold."*

3. **Severity**:  
   - Choose a severity level:
     - **Low** 🟢
     - **Medium** 🟡
     - **High** 🔴 (Recommended for brute force detection)

4. **Tactics**:  
   - Select the **MITRE ATT&CK Tactics** related to brute force:
     - **🎯 Initial Access**
     - **🔑 Credential Access**
      
![Screenshot 2025-01-14 103734](https://github.com/user-attachments/assets/f6558c4d-585b-4e63-b787-1cc071cc0ad0)

5. **Rule type**:  
   - Select **Scheduled 🕒**.

6. **Set rule frequency**:  
   - Choose how often the query should run (e.g., **Every 5 minutes ⏱️**).

7. **Set query results to look back**:  
   - Define the time window for the query (e.g., **Last 1 hour ⏳**).

---

### **Step 2: Add the KQL Query**  
In the **Set rule query** step, paste your KQL query to detect brute-force attempts:  

```kql
DeviceLogonEvents
| where TimeGenerated >= ago(5h)
| where ActionType == "LogonFailed"
| summarize NumberOfFailures = count() by RemoteIP, ActionType, DeviceName
| where NumberOfFailures >= 10s
```
![Screenshot 2025-01-14 111832](https://github.com/user-attachments/assets/b1164c0f-6022-444e-a409-43c1d4e9a579)

- 🛠️ This query filters **sign-in logs** for failed login attempts and identifies unusual patterns.  
- 💡 Adjust thresholds based on your environment (e.g., `> 5 failed attempts`).

---

### **Step 3: Define Incident Settings**  
1. **Create incidents based on alert results**: Ensure this is selected ✅.  
2. **Group alerts into incidents**:  
   - Choose **"🧩 Grouped into a single incident if they share the same entities"** to avoid duplicates.

---

### **Step 4: Add Actions and Automation**  
1. Configure **actions** to trigger when the rule is activated:  
   - Add a **Playbook 🛠️** for automated responses, such as:  
     - Blocking an IP 🚫.  
     - Sending an email to your security team 📧.  
     - Triggering a Teams or Slack notification 💬.  

2. Example Playbook: A Logic App that sends an **email notification 📤** to the SOC.

---

### **Step 5: Review and Enable**  
1. **Review everything** to ensure it’s correct:
   - Name 🔖, description 📝, KQL query 📊, frequency ⏱️, and action settings ⚙️.  

2. Click **"Create"** to enable the rule 🎉.  

---

### **Step 6: Validate Your Rule**  
1. Test the rule by simulating a brute-force attack or using sample logs:
   - Run a script that triggers **failed login attempts** (simulated safely) 🧑‍💻.
   - Replay historical logs using KQL 📜.

2. Verify that alerts are generated 🚨 and incidents are grouped as expected ✅.  
---
## 🚫 **Outcome**
- **Attack Status:** Brute force attempts **unsuccessful**.  
- **Recommendations:** Lockdown NSG rules for all VMs and enforce MFA on privileged accounts.

🎉 **Status:** Incident resolved. No further action required.

---
