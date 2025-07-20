# AZ-500: Microsoft Azure Security Technologies – In-Depth Self‑Study Guide (Intermediate)

---
## 0. Study Strategy & Mindset
**Goal:** Convert intermediate Azure knowledge into *defensible security design & operational skill*.

| Focus | What To Do | Linked References |
|-------|------------|------------------|
| Identity First | Master Conditional Access, risk signals, least privilege with PIM | CA Overview: https://learn.microsoft.com/azure/active-directory/conditional-access/overview  • PIM: https://learn.microsoft.com/azure/active-directory/privileged-identity-management/pim-configure |
| Network Containment | Default deny > explicit allow; private access; centralized egress | NSG Overview: https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview  • Private Endpoint: https://learn.microsoft.com/azure/private-link/private-endpoint-overview |
| Platform Protection | Harden & monitor: Defender for Cloud + encryption strategy | Defender Intro: https://learn.microsoft.com/azure/defender-for-cloud/defender-for-cloud-introduction |
| Detection & Response | Sentinel data onboarding, analytics, automation playbooks | Sentinel Overview: https://learn.microsoft.com/azure/sentinel/overview |
| Governance | Enforce configuration with Policy & initiate remediation | Policy Overview: https://learn.microsoft.com/azure/governance/policy/overview |
| Cost Awareness | Log scope, retention tiers, Defender plan ROI | Monitor Overview: https://learn.microsoft.com/azure/azure-monitor/overview |



---
## 1. Manage Identity & Access (25–30%)
### 1.1 Core Microsoft Entra ID Objects & Architecture
**Concepts:** Tenants, Users, Groups (Security vs M365), Service Principals, App Registrations, Managed Identities.

| Topic | Key Points | Labs / References |
|-------|-----------|------------------|
| Dynamic Groups | Rule syntax, evaluation lag, license-based assignment | Dynamic membership: https://learn.microsoft.com/entra/identity/users/groups-dynamic-membership |
| Managed Identities | System vs User-assigned; secretless auth to Key Vault / Storage | MI Overview: https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/overview |
| App Registration | Redirect URIs, secrets vs certs, delegated vs application perms | Register App Quickstart: https://learn.microsoft.com/entra/identity-platform/quickstart-register-app |

**Practice:** Create user-assigned MI, assign *Key Vault Secrets User* RBAC on a vault, retrieve secret via Azure CLI using MI (no stored secret).

### 1.2 Authentication Methods & Passwordless
**Methods:** FIDO2 Security Keys (phish-resistant), Windows Hello for Business, Authenticator (Number Match), Certificate-based auth, Temporary Access Pass, SMS (weakest). Favor phish-resistant.

- Authentication Methods Overview: https://learn.microsoft.com/entra/identity/authentication/concept-authentication-methods
- FIDO2 Keys: https://learn.microsoft.com/entra/identity/authentication/concept-authentication-methods#fido2-security-keys

**Practice:** Enable FIDO2 policy for a pilot group; register a key; test sign-in.

### 1.3 Self-Service Password Reset (SSPR) & Combined Registration
- Enable for pilot group; configure # methods required, notifications, on-prem writeback (if hybrid).
- Tutorial: https://learn.microsoft.com/entra/identity/authentication/tutorial-enable-sspr

### 1.4 Conditional Access (CA)
**Elements:** Assignments (Users / Apps / Conditions), Controls (Grant & Session). Use *report-only* for safe rollout. Integrate with risk signals, device compliance, and token protection (CAE scenarios).
- Overview: https://learn.microsoft.com/azure/active-directory/conditional-access/overview

**Lab:** Report-only policy requiring MFA for all cloud apps excluding break-glass; review Sign-in logs, then enable.

### 1.5 Identity Protection
**Risk Types:** User risk (credential compromise), Sign-in risk (session anomaly). Policies enforce password reset vs MFA.
- Overview: https://learn.microsoft.com/azure/active-directory/identity-protection/overview-identity-protection
- Risk Signals: https://learn.microsoft.com/entra/identity/identity-protection/concept-identity-protection-risks

### 1.6 Privileged Identity Management (PIM)
Minimize standing privilege: Eligible assignments, approvals, MFA, justification, access reviews.
- Configure PIM: https://learn.microsoft.com/azure/active-directory/privileged-identity-management/pim-configure

**Lab:** Convert permanent Owner to Eligible; require approval; trigger activation.

### 1.7 Access Reviews & Entitlement Management
Automate periodic re-certification of group / role / app assignments. Access Packages for bundled access + lifecycle.
- Access Reviews: https://learn.microsoft.com/azure/active-directory/governance/access-reviews-overview
- Entitlement Mgmt: https://learn.microsoft.com/azure/active-directory/governance/entitlement-management-overview

### 1.8 External Identities (B2B) vs B2C (Awareness)
B2B guest collaboration (invite, CA policies, access reviews) vs B2C customer directory (user flows/custom policies).
- B2B Overview: https://learn.microsoft.com/azure/active-directory/external-identities/what-is-b2b

### 1.9 Application Security & Permissions
Delegate minimal Microsoft Graph permissions; prefer cert creds over long-lived secrets; enforce least privilege.
- Permissions & Consent: https://learn.microsoft.com/entra/identity-platform/permissions-consent-overview

### 1.10 Managed Identities Deep Dive
Use MI to access: Key Vault (RBAC), Storage (Blob Data Reader), Event Hubs; rotate nothing manually.
- Overview (again): https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/overview

---
## 2. Secure Networking (20–25%)
### 2.1 Segmentation & Zero Trust
Assume breach: minimize lateral movement with subnets, NSGs/ASGs, Private Endpoints, Firewall, JIT, Bastion.

### 2.2 Network Security Groups (NSG) & Application Security Groups (ASG)
- NSG Overview: https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview
**Key:** Priority order, first-match, default denies; ASG abstracts IP maintenance.

### 2.3 Azure Firewall
Centralized stateful filtering, FQDN/Application rules, Threat Intel, Premium (TLS inspection, IDPS, URL filtering). Policy hierarchy for scale.
- Firewall Overview: https://learn.microsoft.com/azure/firewall/overview

### 2.4 Web Application Firewall (WAF)
OWASP Core Rule Set; detection vs prevention; custom rules; App Gateway (regional) vs Front Door (global edge + CDN).
- WAF Overview: https://learn.microsoft.com/azure/web-application-firewall/overview

### 2.5 DDoS Protection
Always-on Basic; Standard adds adaptive tuning, telemetry, cost protection.
- DDoS Overview: https://learn.microsoft.com/azure/ddos-protection/ddos-protection-overview

### 2.6 Private Endpoints vs Service Endpoints
| Feature | Private Endpoint | Service Endpoint |
|---------|------------------|------------------|
| Exposure | Private IP in VNet | Public service IP (Azure backbone) |
| DNS | Private DNS zone mapping | Public resolution |
| Restriction | Resource-specific | Service-wide (region) |
| Data Exfil Mitigation | Strong | Limited |
- Private Endpoint: https://learn.microsoft.com/azure/private-link/private-endpoint-overview
- Service Endpoints: https://learn.microsoft.com/azure/virtual-network/virtual-network-service-endpoints-overview

### 2.7 Azure Bastion
Secure browser-based RDP/SSH without exposing ports.
- Overview: https://learn.microsoft.com/azure/bastion/bastion-overview

### 2.8 VPN Gateway & ExpressRoute Security Considerations
- VPN Gateway: https://learn.microsoft.com/azure/vpn-gateway/vpn-gateway-about-vpngateways
- ExpressRoute: https://learn.microsoft.com/azure/expressroute/expressroute-introduction

### 2.9 Just-In-Time (JIT) VM Access
- JIT: https://learn.microsoft.com/azure/defender-for-cloud/just-in-time-access-usage

### 2.10 Network Monitoring & Logging
NSG Flow Logs & Traffic Analytics, Firewall logs, Connection Monitor.
- NSG Flow Logs: https://learn.microsoft.com/azure/network-watcher/network-watcher-nsg-flow-logging-overview

---
## 3. Secure Compute, Storage & Databases (Platform Protection) (20–25%)
### 3.1 VM Security Baselines
Patch (Update Manager), disable password SSH, Defender for Endpoint, Guest Configuration policies, Secure Boot & vTPM (Gen2), Confidential VMs.
- Confidential Computing: https://learn.microsoft.com/azure/confidential-computing/confidential-computing-enclaves

### 3.2 Disk & Data Encryption Layers
| Layer | Tech | Link |
|-------|------|------|
| Platform SSE | Default encryption | https://learn.microsoft.com/azure/virtual-machines/disk-encryption-overview |
| CMK | Disk Encryption Set | https://learn.microsoft.com/azure/virtual-machines/disk-encryption |
| In-guest | Azure Disk Encryption | https://learn.microsoft.com/azure/virtual-machines/disk-encryption-overview |
| Confidential | Enclave / Memory encryption | https://learn.microsoft.com/azure/confidential-computing/confidential-computing-enclaves |

### 3.3 Defender for Cloud Hardening & Plans
Secure Score, recommendations, regulatory compliance, Defender plans (Servers, SQL, Storage, Key Vault, Containers, App Service).
- Intro: https://learn.microsoft.com/azure/defender-for-cloud/defender-for-cloud-introduction
- Secure Score Controls: https://learn.microsoft.com/azure/defender-for-cloud/secure-score-security-controls

### 3.4 Defender for Endpoint Integration
(Delivered via Defender for Servers Plan — EDR, attack surface reduction, automated investigation.)
- Defender Plans: https://learn.microsoft.com/azure/defender-for-cloud/defender-for-cloud-introduction

### 3.5 Container & AKS Security (Awareness Depth)
Image scanning (Defender for Containers), network policies, RBAC, secret management (Key Vault CSI), private clusters.
- Defender for Containers: https://learn.microsoft.com/azure/defender-for-cloud/defender-for-containers-introduction

### 3.6 App Service & Functions Security
Access Restrictions, Private Endpoints, Managed Identity, Key Vault references, HTTPS enforcement.
- App Service Networking: https://learn.microsoft.com/azure/app-service/networking-features
- Key Vault References: https://learn.microsoft.com/azure/app-service/app-service-key-vault-references

### 3.7 Key Vault & Managed HSM
Soft delete + purge protection, RBAC (preferred), private endpoints, logging (AuditEvent), secret rotation policies.
- Overview: https://learn.microsoft.com/azure/key-vault/general/overview
- Soft Delete & Purge: https://learn.microsoft.com/azure/key-vault/general/soft-delete-overview

### 3.8 Storage Security Enhancements
RBAC vs SAS, user delegation SAS, blob immutability (WORM), disable shared key, encryption scopes, Defender for Storage.
- SAS Overview: https://learn.microsoft.com/azure/storage/common/storage-sas-overview
- Immutability: https://learn.microsoft.com/azure/storage/blobs/immutable-policy-configure-version-level-worm
- Disable Shared Key: https://learn.microsoft.com/azure/storage/blobs/storage-account-shared-key-disable
- Defender for Storage: https://learn.microsoft.com/azure/storage/blobs/security-recommendations#defender-for-storage

### 3.9 Database Security
**Azure SQL:** Network isolation (Private Endpoint), Auth (AAD Admin, contained users), TDE (default), Always Encrypted, Dynamic Data Masking, Row-Level Security, Auditing, Defender for SQL.
- Security Overview: https://learn.microsoft.com/azure/azure-sql/database/security-overview
- TDE: https://learn.microsoft.com/azure/azure-sql/database/transparent-data-encryption-tde-overview
- Always Encrypted: https://learn.microsoft.com/azure/azure-sql/database/always-encrypted-azure-sql-overview
- Data Masking: https://learn.microsoft.com/azure/azure-sql/database/dynamic-data-masking-overview
- RLS: https://learn.microsoft.com/azure/azure-sql/database/row-level-security
- Defender for SQL: https://learn.microsoft.com/azure/defender-for-cloud/defender-for-sql-introduction

**Cosmos DB:** RBAC, keys, Private Endpoints, Defender alerts.
- Security: https://learn.microsoft.com/azure/cosmos-db/database-security

### 3.10 Backup & Recovery Security Aspects
Soft delete (Key Vault, storage, backup), geo-redundant replication, encryption of backups. (Concept reinforcement across services.)

---
## 4. Manage Security Operations (25–30%)
### 4.1 Defender for Cloud Operations
Assess posture → prioritize Secure Score remediation → enable Defender plans → workflow automate high severity alerts.
- Intro: https://learn.microsoft.com/azure/defender-for-cloud/defender-for-cloud-introduction

### 4.2 Log Ingestion & Diagnostic Settings
Activity Log vs Resource Logs (KeyVaultAuditEvents, StorageReadWriteDelete), controlled ingestion to workspace.
- Azure Monitor Overview: https://learn.microsoft.com/azure/azure-monitor/overview

### 4.3 Microsoft Sentinel Architecture
Workspace strategy (single vs multi), data connectors, normalization (ASIM), cost control (basic vs analytics tables, retention tiers).
- Overview: https://learn.microsoft.com/azure/sentinel/overview
- Connect Data: https://learn.microsoft.com/azure/sentinel/connect-data-sources

### 4.4 Analytics Rules
Scheduled (KQL + frequency), NRT, Fusion (multi-signal), UEBA anomalies.
- Create Rules: https://learn.microsoft.com/azure/sentinel/tutorial-detect-threats-custom

### 4.5 Incidents & Investigation
Incident grouping, investigation graph, entity mapping, notebooks (MSTICPy) for pivot.
- Incidents: https://learn.microsoft.com/azure/sentinel/respond-incidents

### 4.6 Automation (Playbooks)
Logic Apps to enrich / contain / notify (disable user, isolate host, block IP).
- Playbooks: https://learn.microsoft.com/azure/sentinel/tutorial-respond-threats-playbook
- Logic Apps Overview: https://learn.microsoft.com/azure/logic-apps/logic-apps-overview

### 4.7 Threat Hunting & KQL
Hypothesis-driven queries; adapt gallery hunts; convert recurring hunts to analytics.
- Hunting: https://learn.microsoft.com/azure/sentinel/hunting

### 4.8 UEBA (User & Entity Behavior Analytics)
Behavior baselining for anomalous activities; complement Identity Protection.
- UEBA: https://learn.microsoft.com/azure/sentinel/ueba

### 4.9 Workbooks & Reporting
Visual analytics for posture trend, incident MTTR, coverage gaps.
- Workbooks: https://learn.microsoft.com/azure/sentinel/monitor-your-data-security-workbooks

### 4.10 Incident Response Lifecycle Mapping
Preparation (Policy, CA, PIM) → Detection (Defender alerts) → Analysis (Sentinel) → Containment (playbooks) → Eradication (patch/rotate) → Recovery → Lessons Learned (update controls & analytics).

---
## 5. Governance & Policy Integration
### 5.1 Azure Policy & Initiatives
Effects: Deny / Audit / AuditIfNotExists / DeployIfNotExists / Modify / Append. Initiatives bundle standards (e.g., Azure Security Benchmark).
- Policy Overview: https://learn.microsoft.com/azure/governance/policy/overview
- Effects Detail: https://learn.microsoft.com/azure/governance/policy/concepts/effects
- Remediation: https://learn.microsoft.com/azure/governance/policy/how-to/remediate-resources

### 5.2 Tagging Strategy
Enforce mandatory tags with *Modify*; drive cost, classification, conditional policies.

### 5.3 Regulatory Compliance
Map frameworks in Defender for Cloud; monitor failed controls; custom initiatives for internal baselines.

### 5.4 Blueprint (Legacy) Awareness
Prefer Policy + ARM/Bicep + Deployment Stacks; know transition away from Blueprints.

---
## 6. Data & Key Management / Encryption
Centralize secrets in Key Vault / Managed HSM; enable purge protection; rotate keys & secrets programmatically.
- Key Vault Overview: https://learn.microsoft.com/azure/key-vault/general/overview
- Purge Protection: https://learn.microsoft.com/azure/key-vault/general/soft-delete-overview

| Requirement | Control | Reference |
|-------------|---------|-----------|
| At rest baseline | SSE (platform) | https://learn.microsoft.com/azure/virtual-machines/disk-encryption-overview |
| Customer rotation | CMK + DES | https://learn.microsoft.com/azure/virtual-machines/disk-encryption |
| Column confidentiality | Always Encrypted | https://learn.microsoft.com/azure/azure-sql/database/always-encrypted-azure-sql-overview |
| WORM retention | Blob Immutability | https://learn.microsoft.com/azure/storage/blobs/immutable-policy-configure-version-level-worm |
| Memory isolation | Confidential VMs | https://learn.microsoft.com/azure/confidential-computing/confidential-computing-enclaves |
| Secretless workloads | Managed Identity | https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/overview |

---
## 7. Identity Protection Deep Dive
| Risk | Mitigation | Reference |
|------|------------|-----------|
| User Risk High | Force password reset | https://learn.microsoft.com/azure/active-directory/identity-protection/overview-identity-protection |
| Sign-in Risk Medium+ | CA require MFA | https://learn.microsoft.com/entra/identity/identity-protection/concept-identity-protection-risks |
| Password Spray | Smart lockout + block legacy auth | https://learn.microsoft.com/entra/identity/authentication/concept-authentication-methods |
| Token Replay | CA + token protection (CAE) | https://learn.microsoft.com/azure/active-directory/conditional-access/overview |

Monitor **Risky users**, confirm & remediate or dismiss false positives.

---
## 8. Logging, Monitoring & Cost Optimization
### 8.1 Diagnostic Coverage Checklist
| Resource | Critical Logs | Link |
|----------|---------------|------|
| Key Vault | AuditEvent | https://learn.microsoft.com/azure/key-vault/general/overview |
| Storage | Blob/Queue/File (Read/Write/Delete) | https://learn.microsoft.com/azure/storage/blobs/security-recommendations |
| Firewall | Application / Network / DNAT | https://learn.microsoft.com/azure/firewall/overview |
| NSG | Flow Logs v2 | https://learn.microsoft.com/azure/network-watcher/network-watcher-nsg-flow-logging-overview |
| SQL | Audit + Threat Detection | https://learn.microsoft.com/azure/defender-for-cloud/defender-for-sql-introduction |
| Sentinel | Connector Health | https://learn.microsoft.com/azure/sentinel/connect-data-sources |

### 8.2 Retention Strategy
Hot (interactive KQL) vs Archive (cheap) vs Basic Logs. Apply per-table retention; export rarely queried raw to Storage.

### 8.3 Sample KQL Patterns (Study with Sentinel Hunting Lab)
- Failed privileged sign-ins aggregate
- Mass secret reads in Key Vault
- Bulk blob deletions by single IP
(Practice modifying `TimeGenerated` and adding `summarize` grouping.)
- Hunting: https://learn.microsoft.com/azure/sentinel/hunting

---
## 9. Scenario Mapping (Requirement → Control)
| Requirement | Control |
|-------------|---------|
| Remove public exposure of Storage | Private Endpoint + disable public network |
| Time-bound admin | PIM Eligible + approval |
| Block legacy auth | CA policy (client apps / protocols) |
| JIT RDP/SSH | Defender JIT + Bastion |
| Encrypt disks with customer key | DES + CMK rotation |
| Prevent blob deletion for retention | Immutability Policy |
| Detect anomalous SQL access | Defender for SQL + Sentinel analytics |
| Secretless VM to Key Vault | System-assigned Managed Identity + RBAC |
| Force TLS inbound only | App Service HTTPS Only / Min TLS 1.2 |
| Central egress inspection | Azure Firewall + UDR (0.0.0.0/0) |

---
## 10. Mini Labs Index (All Free Microsoft Docs / Learn)
| # | Lab Goal | Core Docs |
|---|----------|-----------|
| 1 | Conditional Access report-only → enforce | https://learn.microsoft.com/azure/active-directory/conditional-access/overview |
| 2 | PIM role activation workflow | https://learn.microsoft.com/azure/active-directory/privileged-identity-management/pim-configure |
| 3 | Identity Protection risk policies | https://learn.microsoft.com/azure/active-directory/identity-protection/overview-identity-protection |
| 4 | Key Vault hardened (RBAC + purge + PE) | https://learn.microsoft.com/azure/key-vault/general/overview |
| 5 | Hub-Spoke with Azure Firewall | https://learn.microsoft.com/azure/firewall/overview |
| 6 | WAF custom block rule | https://learn.microsoft.com/azure/web-application-firewall/overview |
| 7 | Blob immutability enforcement | https://learn.microsoft.com/azure/storage/blobs/immutable-policy-configure-version-level-worm |
| 8 | Defender secure score remediation | https://learn.microsoft.com/azure/defender-for-cloud/secure-score-security-controls |
| 9 | Sentinel connector + analytics rule | https://learn.microsoft.com/azure/sentinel/connect-data-sources |
| 10 | Sentinel playbook enrichment | https://learn.microsoft.com/azure/sentinel/tutorial-respond-threats-playbook |
| 11 | KQL hunting query adaptation | https://learn.microsoft.com/azure/sentinel/hunting |
| 12 | JIT VM access test | https://learn.microsoft.com/azure/defender-for-cloud/just-in-time-access-usage |
| 13 | Managed Identity to Key Vault | https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/overview |
| 14 | Disk Encryption Set usage | https://learn.microsoft.com/azure/virtual-machines/disk-encryption |
| 15 | Defender for Containers scan | https://learn.microsoft.com/azure/defender-for-cloud/defender-for-containers-introduction |

---
## 11. Common Pitfalls & Avoidance
| Pitfall | Fix | Doc |
|---------|-----|-----|
| Legacy Key Vault access policies | Use RBAC | https://learn.microsoft.com/azure/key-vault/general/overview |
| Over-broad CA lockout | Report-only + exclusions | https://learn.microsoft.com/azure/active-directory/conditional-access/overview |
| Long-lived SAS tokens | User delegation / narrow scope | https://learn.microsoft.com/azure/storage/common/storage-sas-overview |
| Public mgmt ports | Bastion + JIT | https://learn.microsoft.com/azure/bastion/bastion-overview |
| No purge protection | Enable soft delete & purge prot. | https://learn.microsoft.com/azure/key-vault/general/soft-delete-overview |
| Standing admin roles | PIM eligibility | https://learn.microsoft.com/azure/active-directory/privileged-identity-management/pim-configure |
| Excess log ingestion cost | Scope diagnostic settings | https://learn.microsoft.com/azure/azure-monitor/overview |
| Unencrypted customer key req | DES + CMK | https://learn.microsoft.com/azure/virtual-machines/disk-encryption |
| Missing lateral visibility | NSG Flow Logs + Sentinel | https://learn.microsoft.com/azure/network-watcher/network-watcher-nsg-flow-logging-overview |
| Missed secure score drops | Weekly review & alert | https://learn.microsoft.com/azure/defender-for-cloud/secure-score-security-controls |

---
## 12. Final 72‑Hour Checklist
- [ ] CA policies validated (no broad exclusions, MFA enforced)  
- [ ] Break-glass accounts documented & monitored  
- [ ] PIM flow rehearsed (activation + approval logs)  
- [ ] Private Endpoint vs Service Endpoint rationale memorized  
- [ ] 5+ KQL queries executed from memory  
- [ ] Defender Secure Score trend understood (improvement points)  
- [ ] Key Vault purge protection confirmed  
- [ ] Storage immutability policy tested  
- [ ] Sentinel analytic + playbook end-to-end test  
- [ ] Encryption layers mapping (SSE vs CMK vs ADE vs Confidential)  

**Memory Aid (Zero Trust Chain):** *Explicit Verify → Least Privilege → Assume Breach → Encrypt & Protect → Monitor & Respond.*

---
## 13. Glossary (Selected)
| Term | Definition |
|------|------------|
| CA | Conditional Access adaptive policy engine |
| PIM | Just-in-time privileged role activation |
| JIT VM Access | Time-bound NSG opening for mgmt ports |
| Private Endpoint | Private NIC mapping to PaaS resource |
| SSE | Server-side encryption at rest |
| CMK | Customer-managed key in Key Vault / HSM |
| DES | Disk Encryption Set referencing CMK |
| Secure Score | Posture metric in Defender for Cloud |
| ASIM | Normalized schema set in Sentinel |
| UEBA | User & Entity Behavior Analytics |
| Immutability | WORM retention for blobs |
| DCR | Data Collection Rule for AMA ingestion |
| ASG | Application Security Group (NSG abstraction) |
| IDPS | Intrusion Detection & Prevention (Firewall Premium) |
| WAF | Web Application Firewall (OWASP rules) |

---
## 14. Next Steps
1. Execute all 15 mini labs; capture notes & screenshots.  
2. Build a personal *Scenario → Control* flash sheet.  
3. Attempt a timed practice exam; analyze *why* each incorrect answer was wrong.  
4. Revisit weak domains with fresh hands-on (especially Sentinel + KQL).  
5. Sleep well before exam; rely on structured reasoning, not memorization.

**Success Metric:** You can explain *why* each chosen control mitigates a specific risk *and* demonstrate configuration steps from memory.

