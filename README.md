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

 Technical Stack & Skills Demonstrated:

Governance: Broken Permission Inheritance, Site Collection Administration, Audit Logging.

Identity: Entra ID (Azure AD), Conditional Access Policies, MFA Enforcement.

Management: Microsoft Intune (MEM), Configuration Profiles, Hardware Restriction.

Analytics: KQL Scripting, Log Analytics, Security Monitoring.
