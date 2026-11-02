# References & Architecture: Enterprise SIEM & Log Analysis

This document archives architectural patterns, field normalization models, query syntax specifications, and detection schemas harvested from premier open-source and enterprise SOC tools to guide BeyondLabs development.

---

## 1. References & Sources

1. **Splunk Enterprise & Common Information Model (CIM)**:
   - *Source*: [Splunk Common Information Model (CIM) Documentation](https://docs.splunk.com/Documentation/CIM/latest/User/Overview)
   - *Core Patterns*:
     - Search Processing Language (SPL) pipe architecture: `<base search> | <transformation> | <aggregation> | <formatting>`
     - Field faceting & discovery: Top values, event coverage, and categorical clustering (`Authentication`, `Network Traffic`, `Endpoint`, `Web`).
     - Standard CIM field names: `src`, `dest`, `user`, `action`, `app`, `status`, `duration`, `bytes_in`, `bytes_out`.

2. **Elastic Security & Elastic Common Schema (ECS)**:
   - *Source*: [Elastic Common Schema (ECS) Reference](https://www.elastic.co/guide/en/ecs/current/index.html)
   - *Core Patterns*:
     - Hierarchical dot-notation taxonomy: `source.ip`, `destination.ip`, `destination.port`, `user.name`, `process.name`, `process.command_line`, `event.action`, `event.outcome`.
     - Kibana Query Language (KQL) and ES|QL syntax.
     - Event categorizations: `authentication`, `network`, `process`, `file`, `registry`.

3. **Sigma HQ (Generic Signature Format for SIEM Systems)**:
   - *Source*: [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
   - *Core Patterns*:
     - Standard YAML structure: `title`, `status`, `description`, `references`, `tags`, `logsource`, `detection`, `condition`, `falsepositives`, `level`.
     - Cross-compilation targets: Splunk SPL, Elastic KQL/Lucene, Microsoft Sentinel KQL, QRadar AQL.

4. **Velociraptor**:
   - *Source*: [Velociraptor Knowledge Base](https://docs.velociraptor.app/)
   - *Core Patterns*:
     - Velociraptor Query Language (VQL) forensic queries targeting Event Logs (`Windows.EventLogs.EvtxHunter`), Process execution (`Windows.System.Pslist`), and Network sockets.

---

## 2. Field Normalization Mapping Matrix

| Semantic Concept | BeyondLabs Internal | Splunk CIM | Elastic Common Schema (ECS) | Windows Event Log | Linux Syslog |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Source IP** | `src` / `source_ip` | `src` / `src_ip` | `source.ip` | `IpAddress` / `SourceAddress` | `rhost` / `source` |
| **Destination IP** | `dst` / `destination_ip` | `dest` / `dest_ip` | `destination.ip` | `DestAddress` / `RemoteAddress` | — |
| **Target Port** | `dest_port` | `dest_port` | `destination.port` | `IpPort` / `RemotePort` | `port` |
| **User Account** | `user` | `user` / `src_user` | `user.name` | `TargetUserName` / `SubjectUserName` | `user` / `account` |
| **Process Name** | `process_name` | `process_name` / `app` | `process.name` | `NewProcessName` / `Image` | `process` / `app` |
| **Command Line** | `command_line` | `process_exec` | `process.command_line` | `CommandLine` | — |
| **Event Signature** | `sig` / `headline` | `signature` / `rule_name` | `event.action` / `rule.name` | `Message` / Event Name | `message` |
| **Severity** | `sev` | `severity` (1-4) | `event.severity` (0-100) | `Level` / `Keywords` | `priority` / `facility` |

---

## 3. Cyber Kill-Chain Sequence Model

Chronological threat progression stages used in BeyondLabs automated session reconstruction:
1. **Phase 1: Reconnaissance / Scanning**
   - Indicators: Web path probing (`/wp-admin`, `/.env`, `phpmyadmin`), HTTP 404 floods, port scanning.
   - MITRE ATT&CK: `T1595` (Active Scanning), `T1592` (Gather Victim Host Info).
2. **Phase 2: Initial Access & Credential Attacks**
   - Indicators: SSH authentication failures (`Failed password`), Windows Event ID 4625, password spraying, RDP brute force.
   - MITRE ATT&CK: `T1110` (Brute Force), `T1078` (Valid Accounts), `T1190` (Exploit Public-Facing App).
3. **Phase 3: Execution & Privilege Escalation**
   - Indicators: Base64 encoded PowerShell (`-EncodedCommand`), Windows Event ID 4688 (`cmd.exe`, `powershell.exe`, `wmic.exe`), Windows Event ID 4672 (`SeDebugPrivilege`), Linux `sudo` escalation.
   - MITRE ATT&CK: `T1059.001` (PowerShell), `T1068` (Exploitation for Privilege Escalation), `T1204` (User Execution).
4. **Phase 4: Persistence & Defense Evasion**
   - Indicators: Service installation (`4697`), Scheduled task creation (`4698`), Registry Run keys (`4657`), Security log clearing (`1102`, `104`).
   - MITRE ATT&CK: `T1543.003` (Windows Service), `T1053.005` (Scheduled Task), `T1070.001` (Clear Event Logs).
5. **Phase 5: Command & Control / Exfiltration**
   - Indicators: Periodic HTTPS beaconing (consistent interval/jitter), DNS tunneling queries, large outbound data transfers (`curl`, `bitsadmin`).
   - MITRE ATT&CK: `T1071.001` (Web Protocols), `T1572` (Protocol Tunneling), `T1048` (Exfiltration Over Alternative Protocol).
