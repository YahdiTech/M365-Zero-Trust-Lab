 
Project: Enterprise Zero-Trust Cloud Architecture
Architect: [Chukwudi/Yahdi Tech]

Environment: Microsoft 365 E5 / Entra ID / Intune / SharePoint Online

 Executive Summary
In response to the increasing sophistication of identity-based attacks and internal data leaks, I engineered a comprehensive Zero-Trust Security Lab designed to protect mission-critical corporate assets.

This project simulates a high-security corporate environment where "Default Trust" is eliminated. By implementing layered defenses across the Data, Identity, and Device pillars, I have successfully moved the security posture from a vulnerable perimeter-based model to a resilient, identity-centric architecture.

 Key Business Outcomes:

Data Integrity & Confidentiality: Engineered a granular permission structure in SharePoint Online, ensuring that sensitive HR and Payroll data is accessible only to authorized personnel, effectively mitigating "Insider Threat" risks.

Identity Hardening: Eliminated credential-only vulnerabilities by deploying Adaptive MFA through Entra ID Conditional Access. This ensures that even in the event of a password breach, unauthorized access is blocked at the perimeter.

Endpoint Compliance: Secured the physical attack surface by utilizing Microsoft Intune to enforce hardware restrictions, preventing unauthorized data exfiltration via removable storage and blocking "BadUSB" malware vectors.

Threat Visibility: Established a continuous monitoring framework using KQL (Kusto Query Language), providing real-time auditing and rapid incident response capabilities for high-privilege account activities.

TECHNICAL SKILLS DEMONSTRATED:

Governance: Broken Permission Inheritance, Site Collection Administration, Audit Logging.

Identity: Entra ID (Azure AD), Conditional Access Policies, MFA Enforcement.

Management: Microsoft Intune (MEM), Configuration Profiles, Hardware Restriction.

Analytics: KQL Scripting, Log Analytics, Security Monitoring.

Technical Skills Demonstrated:

Identity & Access Management (IAM): * Microsoft Entra ID (Azure AD)

Conditional Access Policies (CAP) * Multi-Factor Authentication (MFA) Enforcement

Break-Glass/Emergency Access Account Management

Data Protection & Governance: * SharePoint Online Site Architecture

Granular Permission Hardening (Breaking Inheritance)

Data Loss Prevention (DLP) Policy Configuration

Endpoint Security: * Microsoft Intune (Endpoint Manager)

Configuration Profiles (Device Hardening)

Removable Storage & USB Restriction Policies

Security Operations (SecOps): * KQL (Kusto Query Language) Scripting

Log Analytics Workspace Management

Continuous Security Monitoring & Auditing


DATA GOVERNANCE
### Security Validation (Audit)
To verify the integrity of the Zero-Trust model, I performed a "Least Privilege" audit. 
* **The Test:** Attempted to access the `Confidential-Payroll` directory using a standard non-admin identity.
* **The Result:** Access was successfully gated at the identity layer, returning a "403 Access Denied" state.
* **The Logic:** This validates that my granular permission hardening is active and effectively prevents internal data exfiltration.
#### Validation Proof:
![Data Governance](Screenshot/SharePoint-Fold<img width="1904" height="942" alt="ShearPoint-Folder-Level-Security" src="https://github.com/user-attachments/assets/a4b2fec7-660a-4f06-8999-5edc28243887" />
er-Level-Security.png)<img width="1765" height="992" alt="Shear Point - Access -Denied - Validation" src="https://github.com/user-attachments/assets/644f3afe-1932-43b1-bbc8-14bb208ce189" /><img width="1913" height="854" alt="Shear Point - Library -View" src="https://github.com/user-attachments/assets/419a9adc-0667-4e62-8791-104ba91fb7ae" />




IDENTITY & ACCESS MANAGEMENT (Microsoft Entra ID)
To secure the "Front Door" of the organization, I engineered a Conditional Access Policy targeting high-privilege access to corporate data.
Identity Challenge: Enforced Multi-Factor Authentication (MFA) for all users accessing the SharePoint Online environment.
Targeted Scope: Specifically scoped the policy to the Office 365 SharePoint Online cloud app to prevent "Lateral Movement" if a standard password is leaked.
Grant Control: Configured the Grant control to require a managed MFA claim, ensuring that only authenticated humans—not automated scripts—can access the HR and Payroll directories.
// Security Logic: How Entra ID evaluates this access
IF (User == "HR_Staff") AND (App == "SharePoint") 
THEN (Require_MFA == TRUE)
ELSE (Block_Access)
####  Technical Evidence:
![Identity & Access Management](screenshots/Entra-HR-MFA<img width="1895" height="939" alt="Entra -HR-MFA Policy" src="https://github.com/user-attachments/assets/a3008a4c-ebf8-41fb-9cad-1d5ac6cf86eb" />
-Policy.png)<img width="1905" height="953" alt="Entra-Log -Capture-Setup" src="https://github.com/user-attachments/assets/c14d326c-f227-488b-9dea-b305dced9990" />


---
ENDPOINT SECURITY & DEVICE HARDENING (Microsoft Intune)
Using Microsoft Intune (MEM), I deployed a "Hardware Lockdown" strategy to mitigate the risk of physical data exfiltration (insider threats) and "BadUSB" malware attacks.
Policy Type: Developed a Settings Catalog profile for Windows 10/11 endpoints.
Removable Storage Block: Disabled all Read and Write permissions for Removable Disk drives. This ensures that even if a malicious USB is plugged into a laptop, the OS will refuse to mount the hardware.
Compliance Integration: Aligned this profile with the organization's Zero-Trust Compliance Policy, ensuring that any device with an enabled USB port is marked as "Non-Compliant" and gated from the network.
By disabling USB mass storage, we effectively close one of the most common "Air-Gap" jump points used in modern cyber-espionage.#### 📸 Technical Evidence:
![Description of Image](screenshots/your-file<img width="1917" height="936" alt="Intune-Policy-Compliance-Setting" src="https://github.com/user-attachments/assets/da42a13f-45a5-4dc8-8969-efce39012b55" />
-name.png)<img width="1906" height="947" alt="Intune-Policy-Summary" src="https://github.com/user-attachments/assets/49b8c261-e29e-4d18-a4af-7d8d808e3b8a" /><img width="1901" height="942" alt="Intune-Windowa-Compliance-Setting" src="https://github.com/user-attachments/assets/d2ed6a1d-1fe5-46a0-8266-68c7173d6a1d" />



---
SECURITY MONITORING & THREAT HUNTING (KQL)
Establish continuous visibility into the environment to detect "Invisible" threats that bypassed the initial gates.
 Technical Implementation: Log Analytics & Kusto Query Language
Security is only as good as its Visibility. I utilized KQL (Kusto Query Language) within the Log Analytics workspace to build a custom monitoring dashboard.
Detection Logic: Created a "Break-Glass" alert system to monitor any sign-in attempts to the emergency Global Admin account.
Audit Trail: Built a query to aggregate all Delete and Permission Change events within the SharePoint HR site, providing a clear audit trail for compliance officers.
Zero-Trust Validation: Used logs to confirm that the "Access Denied" events from my earlier testing were correctly logged as ResultType: 50126 (MFA Failure) or 53003 (Conditional Access Block).
#### 📸 Technical Evidence:
![Description of Image](screenshots/your-file-name.png)<img width="1903" height="576" alt="Emergency-Account-Monitoring-KQL" src="https://github.com/user-attachments/assets/9d1bcc91-c89f-4b93-8d64-829e4f7d56fd"


---

// Custom KQL to monitor sensitive HR Site Access
SigninLogs
| where AppDisplayName contains "SharePoint"
| where ResultType == "0" // Successful Logins
| summarize count() by UserDisplayName, IPAddress, Location
| order by count() desc
