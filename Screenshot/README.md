DATA GOVERNANCE
### Security Validation (Audit)
To verify the integrity of the Zero-Trust model, I performed a "Least Privilege" audit. 
* **The Test:** Attempted to access the `Confidential-Payroll` directory using a standard non-admin identity.
* **The Result:** Access was successfully gated at the identity layer, returning a "403 Access Denied" state.
* **The Logic:** This validates that my granular permission hardening is active and effectively prevents internal data exfiltration.
#### 📸 Validation Proof:
![SharePoint Security Validation](screenshots/SharePoint-Access-Denied-Validation.png)


IDENTITY & ACCESS MANAGEMENT (Microsoft Entra ID)
To secure the "Front Door" of the organization, I engineered a Conditional Access Policy targeting high-privilege access to corporate data.
Identity Challenge: Enforced Multi-Factor Authentication (MFA) for all users accessing the SharePoint Online environment.
Targeted Scope: Specifically scoped the policy to the Office 365 SharePoint Online cloud app to prevent "Lateral Movement" if a standard password is leaked.
Grant Control: Configured the Grant control to require a managed MFA claim, ensuring that only authenticated humans—not automated scripts—can access the HR and Payroll directories.
// Security Logic: How Entra ID evaluates this access
IF (User == "HR_Staff") AND (App == "SharePoint") 
THEN (Require_MFA == TRUE)
ELSE (Block_Access)

ENDPOINT SECURITY & DEVICE HARDENING (Microsoft Intune)
Using Microsoft Intune (MEM), I deployed a "Hardware Lockdown" strategy to mitigate the risk of physical data exfiltration (insider threats) and "BadUSB" malware attacks.
Policy Type: Developed a Settings Catalog profile for Windows 10/11 endpoints.
Removable Storage Block: Disabled all Read and Write permissions for Removable Disk drives. This ensures that even if a malicious USB is plugged into a laptop, the OS will refuse to mount the hardware.
Compliance Integration: Aligned this profile with the organization's Zero-Trust Compliance Policy, ensuring that any device with an enabled USB port is marked as "Non-Compliant" and gated from the network.
By disabling USB mass storage, we effectively close one of the most common "Air-Gap" jump points used in modern cyber-espionage.

SECURITY MONITORING & THREAT HUNTING (KQL)
Establish continuous visibility into the environment to detect "Invisible" threats that bypassed the initial gates.
 Technical Implementation: Log Analytics & Kusto Query Language
Security is only as good as its Visibility. I utilized KQL (Kusto Query Language) within the Log Analytics workspace to build a custom monitoring dashboard.
Detection Logic: Created a "Break-Glass" alert system to monitor any sign-in attempts to the emergency Global Admin account.
Audit Trail: Built a query to aggregate all Delete and Permission Change events within the SharePoint HR site, providing a clear audit trail for compliance officers.
Zero-Trust Validation: Used logs to confirm that the "Access Denied" events from my earlier testing were correctly logged as ResultType: 50126 (MFA Failure) or 53003 (Conditional Access Block).

// Custom KQL to monitor sensitive HR Site Access
SigninLogs
| where AppDisplayName contains "SharePoint"
| where ResultType == "0" // Successful Logins
| summarize count() by UserDisplayName, IPAddress, Location
| order by count() desc
