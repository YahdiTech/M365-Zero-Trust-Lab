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
