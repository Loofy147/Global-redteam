# Incident Response Playbook: Web Application Compromise

**Document Version:** 1.0
**Date:** 2025-10-28
**Playbook Owner:** Head of Security

## 1. Purpose

This playbook provides a structured, actionable guide for responding to a security incident involving the compromise of a web application or API. Its purpose is to ensure a swift, coordinated, and effective response to minimize impact, preserve evidence, and restore services.

**This is a living document and should be reviewed and updated quarterly.**

---

## 2. Phases of Incident Response

This playbook follows the standard NIST framework for incident response:
1.  **Preparation:** Proactive measures taken before an incident occurs.
2.  **Identification:** Detecting and validating a potential security incident.
3.  **Containment:** Limiting the scope and impact of the incident.
4.  **Eradication:** Removing the root cause of the incident.
5.  **Recovery:** Restoring normal operations.
6.  **Post-Mortem & Lessons Learned:** Analyzing the incident to improve future responses.

---

## 3. Playbook: Step-by-Step Actions

### Phase 1: Preparation (Ongoing)

- **[ ] Tools:** Ensure all required tools are available (e.g., access to logs, WAF, server consoles).
- **[ ] Team:** Maintain an up-to-date contact list for the Incident Response Team (IRT).
- **[ ] Training:** Conduct regular IR tabletop exercises and drills.
- **[ ] Baselines:** Establish normal network and application performance baselines.

### Phase 2: Identification

- **Trigger:** An alert is received from monitoring systems (e.g., SIEM, WAF, APM) or a manual report (e.g., bug bounty, customer support).
- **[ ] 1. Acknowledge Alert:** The on-call IR lead acknowledges the alert and starts a new incident log.
- **[ ] 2. Create War Room:** Open a dedicated communication channel (e.g., Slack channel, conference bridge) and invite the core IRT.
- **[ ] 3. Validate Incident:**
    - Analyze logs (application, server, network) to confirm a security incident is occurring.
    - Review monitoring dashboards for anomalies.
    - **Goal:** Confirm the "what, where, when, and how" of the incident. Is it a real threat?
- **[ ] 4. Escalate:** If validated, the IR lead escalates to the full IRT and executive leadership as defined in the communication plan.

### Phase 3: Containment

- **Goal:** Stop the bleeding. Isolate the affected systems to prevent further damage.
- **[ ] 1. Short-Term Containment (Choose one or more):**
    - **[ ] Option A: Isolate Host:** Use security groups or firewall rules to isolate the affected web server(s).
    - **[ ] Option B: Block IP:** Block the attacker's source IP address at the WAF or network edge.
    - **[ ] Option C: Revoke Credentials:** Disable compromised user accounts or revoke API keys.
    - **[ ] Option D: Deploy Virtual Patch:** If the vulnerability is known, apply a temporary rule at the WAF to block exploitation attempts.
- **[ ] 2. Preserve Evidence:**
    - **[ ] Take a snapshot** of the affected server's memory and disk.
    - **[ ] Export relevant logs** to a secure, isolated location.

### Phase 4: Eradication

- **Goal:** Remove the attacker and their tools from the environment.
- **[ ] 1. Identify Root Cause:** Analyze the preserved evidence to determine the exact vulnerability that was exploited (e.g., SQL injection, RCE, compromised credentials).
- **[ ] 2. Remediate Vulnerability:**
    - **[ ] Deploy the code fix** for the identified vulnerability. This is the permanent solution.
    - **[ ] Scan for backdoors** or other persistence mechanisms left by the attacker and remove them.
    - **[ ] Cycle all credentials** associated with the affected system (e.g., database passwords, API keys, admin passwords).

### Phase 5: Recovery

- **Goal:** Safely restore services to normal operation.
- **[ ] 1. Rebuild or Restore:** Rebuild the affected server(s) from a known-good gold image.
- **[ ] 2. Deploy Patched Code:** Deploy the remediated application code to the clean servers.
- **[ ] 3. Monitor:** Intensely monitor the application and underlying systems for any signs of residual attacker activity.
- **[ ] 4. Full Service Restoration:** Once confidence is high, remove containment measures (e.g., unblock IPs, re-enable services) and return the system to full production.

### Phase 6: Post-Mortem & Lessons Learned

- **Goal:** Learn from the incident to improve future security posture.
- **[ ] 1. Schedule Post-Mortem Meeting:** Within 5 business days of incident resolution, conduct a blameless post-mortem.
- **[ ] 2. Create Incident Report:** Document the full timeline, impact, root cause, and actions taken.
- **[ ] 3. Identify Action Items:**
    - What went well?
    - What could be improved?
    - Create JIRA tickets for all follow-up actions (e.g., code fixes, process improvements, new monitoring).
- **[ ] 4. Update Playbook:** Update this playbook with any lessons learned.

---

## 4. Roles & Responsibilities

- **Incident Response Lead:** Overall coordination and decision-making.
- **Security Analyst:** Investigation, forensics, and evidence preservation.
- **DevOps/SRE:** Server and network containment, system recovery.
- **Developer:** Code analysis and vulnerability remediation.
- **Communications Lead:** Internal and external communications.
