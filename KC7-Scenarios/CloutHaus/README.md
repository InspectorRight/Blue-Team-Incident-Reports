# Cloud Threat Hunting Report: Operation Broken Influence
**Lead Incident Analyst:** Nathan J
**Platform Environment:** Azure Data Explorer (KQL Log Analytics)
**Target Organisation:** CloutHause

---

## 1. Executive Summary
On April 3, 2025, CloutHause suffered a targeted Business Email Compromise (BEC) impacting an Influencer Partner. The threat actor initially leveraged open-source intelligence (OSINT) via Instagram to scrape personal data (Mothers maiden name, childhood pets) to target the victim. This was followed by a sophisticated credential-harvesting phishing campaign. Due to MFA being disabled on the corporate account, the attacker successfully logged into the corporate mail server from an external rogue IP infrastructure based in China, initiating internal reconnaissance and unauthorised data access.

---

## 2. Technical Indicators of Compromise (IoCs)
The investigative pipeline isolated the following malicious infrastructure and assets:
*   **Phishing Sender Infrastructure:** `collabs@dior-partners.com`, `noreply@influencer-deals.net`
*   **Credential Harvesting Domain:** `super-brand-offer.com` (Hosted on Attacker IP: `198.51.100.12`)
*   **Linked Attacker Domain Footprint:** `influencer-deals.net`
*   **Attacker Remote Login IP:** `182.45.67.89` (Geolocated to China)
*   **Targeted Corporate Account:** Afomiya Storm (`afomiya_storm@clouthaus.com` / Username: `afstorm`)
*   **Vulnerable Host Asset:** OQPA-DESKTOP (Internal IP: `10.10.0.3`)
*   **Attacker User Agent String:** `Mozilla/5.0 (compatible; MSIE 5.0; Windows NT 5.2; Trident/4.1)` (Legacy Internet Explorer)

---

## 3. Threat Hunting Timeline & Query Logic

### Phase 1: Initial Access & Credential Harvesting
The threat actor dispatched an external spoofed partnership opportunity to the victim. The victim interacted with the embedded link on their local endpoint (`10.10.0.3`) at exactly `2025-04-03T11:20:00Z`.
```kusto
OutboundNetworkEvents

| where url contains "super-brand-offer" and src_ip == "10.10.0.3"
```
*Analysis Finding:* Passive DNS analysis of the landing page exposed a shared hosting footprint connecting multiple spoofed luxury/influencer registration domains to a single malicious IP:
```kusto
PassiveDns
| where ip == "198.51.100.12"
| distinct domain
```

### Phase 2: Unauthorized Authentication & Account Takeover
Exactly one hour after the phishing link interaction (`2025-04-03T12:20:00Z`), an external login was recorded on the enterprise mail server.
```kusto
AuthenticationEvents

| where username == "afstorm" and result == "Successful Login"
| project Timestamp, hostname, src_ip, user_agent, description
```
*Analysis Finding:* The account was highly vulnerable due to `mfa_enabled: False`. The threat actor successfully authenticated from IP `182.45.67.89` utilizing an obfuscated, legacy Internet Explorer user agent string on an archaic Windows NT architecture.

### Phase 3: Lateral Log Traffic Tracking & Exfiltration
Cross-referencing the attacker's source connection IP (`182.45.67.89`) inside network traffic databases exposed targeted malicious exploration paths inside the cloud infrastructure.
```kusto
InboundNetworkEvents
| where src_ip == "182.45.67.89" and url contains "hack"
```
*Analysis Finding:* The actor systematically weaponized the compromised internal session parameters to pivot into secure zones and route outbound exfiltration updates back through their secondary operational domain pool (`noreply@influencer-deals.net`).

---

## 4. MITRE ATT&CK Mapping
*   **Reconnaissance:** Gather Victim Identity Information: Social Media ([T1589.002](https://mitre.org))
*   **Initial Access:** Phishing: Malicious Link ([T1566.002](https://mitre.org))
*   **Credential Access:** Credentials from Web Browsers ([T1555.003](https://mitre.org))
*   **Initial Access:** Valid Accounts: Cloud Accounts ([T1078.004](https://mitre.org))

---

## 5. Defensive Remediation & Mitigations
1.  **Enforce Multi-Factor Authentication (MFA):** Implement a global, non-bypassable conditional access policy requiring hardware or application-based MFA validation across all corporate influencer and partner tiers.
2.  **User Agent Anomalous Baseline Alerts:** Configure SIEM detection rules to immediately alert security operations when high-privilege mail systems receive logins from outdated legacy browsers (e.g., Internet Explorer 5.0 / Windows NT 5.2).
3.  **Geographic Ingestion Barriers:** Establish explicit impossible-travel rules and location-based blocking blocks to reject access attempts originating outside approved domestic operating zones.
