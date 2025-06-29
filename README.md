# MyDFIR SOC Analyst challenge

## Objective

I completed a 30-day SOC Analyst Challenge where I used the ELK stack (Elasticsearch, Logstash, and Kibana) to analyze and investigate logs from a virtual machine. Throughout the challenge, I identified and examined various simulated cyber attacks, gaining hands-on experience in threat detection, log correlation, and incident response within a SIEM environment.

<br>

### Skills Learned

🛡️ Log Analysis & Correlation – Interpreted system, network, and application logs to detect suspicious activity.

🔍 Threat Hunting – Proactively searched for indicators of compromise (IOCs) using Kibana visualizations and queries.

🧠 SIEM Proficiency – Gained hands-on experience with the ELK stack (Elasticsearch, Logstash, Kibana) in a security context.

🚨 Attack Detection – Identified and investigated simulated attacks such as brute force attempts, malware infections, and privilege escalation.

🖥️ Incident Response – Practiced triaging and documenting incidents based on log evidence and alert patterns.

🗂️ Data Parsing & Normalization – Used Logstash to ingest and structure raw log data for analysis.

📊 Dashboard Creation – Built and customized Kibana dashboards to monitor system activity and visualize trends.

⏱️ Time-based Analysis – Conducted timeline investigations to trace attacker behavior across different stages.

🧰 Security Use Case Development – Designed basic detection rules and alerts based on observed patterns and behaviors.

<br>

### 🛠️ Tools & Technologies Used

🔎 Elasticsearch – Search and analytics engine for indexing and querying log data.

🔄 Logstash – Data processing pipeline for ingesting, parsing, and transforming logs.

📊 Kibana – Visualization tool for analyzing log data and building dashboards.

📦 Beats (Filebeat / Packetbeat) – Lightweight agents used to forward logs and network data.

🐧 Linux (Ubuntu/Debian VM) – Operating system used to simulate attacks and generate log data.

📝 Syslog / Auditd – System logging and auditing tools used as log sources.

🎯 Kali Linux – Used for simulating attacks and generating malicious traffic.

☁️ VULTR – Cloud infrastructure provider used to host virtual machines and lab environment.

💻 VMware – Local virtualization.

🛡️ SIEM Concepts – Applied Security Information and Event Management techniques in a practical setting.

<br>

## Steps
# Building a SOC + Honeynet in Azure (Live Traffic)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/VULTR%20VPC%20Creation.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%203%20VPC%20IP%20172.31.0.3.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/VPC%20Server%20Specs.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/VPC%20Server%20Specs.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/repositories%20updated.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%203%20Downloaded%20elastic%20search%20via%20CLI.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%203%20Elastic%20search%20install%20confirmation%20and%20version.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%203%20obtaining%20security%20auto%20configuration%20information%20.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%203%20-Elastic%20Search%20.yml%20file.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%203%20-%20Obtaining%20Public%20IP%20address%20149.248.61.82:23%20for%20elastic%20search%20instance.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%203-Adding%20public%20IP%20address%20and%20http%20port.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%204%20-%20Creating%20a%20firewall%20group.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%204-%20Starting%20up%20elastic%20search%20service.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%204%20-%20Downloading%20Kibana%20via%20CLI.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%204%20-%20Kibana%20installed%20and%20version.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%204%20-%20Kibana%20successfully%20installed.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%204%20-%20allowing%20server%20port%20and%20server%20Host%20to%20be%20public%20IP%20instead%20of%20local%20host%20on%20Kibana%20server.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%204%20-%20Kibana%20running%20successfully.png?raw=true)
![image alt]()
## Introduction

In this project, I build a mini honeynet in Azure and ingest log sources from various resources into a Log Analytics workspace, which is then used by Microsoft Sentinel to build attack maps, trigger alerts, and create incidents. I measured some security metrics in the insecure environment for 24 hours, apply some security controls to harden the environment, measure metrics for another 24 hours, then show the results below. The metrics we will show are:

- SecurityEvent (Windows Event Logs)
- Syslog (Linux Event Logs)
- SecurityAlert (Log Analytics Alerts Triggered)
- SecurityIncident (Incidents created by Sentinel)
- AzureNetworkAnalytics_CL (Malicious Flows allowed into our honeynet)

## Architecture Before Hardening / Security Controls
![Architecture Diagram](https://i.imgur.com/aBDwnKb.jpg)

## Architecture After Hardening / Security Controls
![Architecture Diagram](https://i.imgur.com/YQNa9Pp.jpg)

The architecture of the mini honeynet in Azure consists of the following components:

- Virtual Network (VNet)
- Network Security Group (NSG)
- Virtual Machines (2 windows, 1 linux)
- Log Analytics Workspace
- Azure Key Vault
- Azure Storage Account
- Microsoft Sentinel

For the "BEFORE" metrics, all resources were originally deployed, exposed to the internet. The Virtual Machines had both their Network Security Groups and built-in firewalls wide open, and all other resources are deployed with public endpoints visible to the Internet; aka, no use for Private Endpoints.

For the "AFTER" metrics, Network Security Groups were hardened by blocking ALL traffic with the exception of my admin workstation, and all other resources were protected by their built-in firewalls as well as Private Endpoint

## Attack Maps Before Hardening / Security Controls
![NSG Allowed Inbound Malicious Flows](https://i.imgur.com/1qvswSX.png)<br>
![Linux Syslog Auth Failures](https://i.imgur.com/G1YgZt6.png)<br>
![Windows RDP/SMB Auth Failures](https://i.imgur.com/ESr9Dlv.png)<br>

## Metrics Before Hardening / Security Controls

The following table shows the metrics we measured in our insecure environment for 24 hours:
Start Time 2023-03-15 17:04:29
Stop Time 2023-03-16 17:04:29

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 19470
| Syslog                   | 3028
| SecurityAlert            | 10
| SecurityIncident         | 348
| AzureNetworkAnalytics_CL | 843

## Attack Maps Before Hardening / Security Controls

```All map queries actually returned no results due to no instances of malicious activity for the 24 hour period after hardening.```

## Metrics After Hardening / Security Controls

The following table shows the metrics we measured in our environment for another 24 hours, but after we have applied security controls:
Start Time 2023-03-18 15:37
Stop Time	2023-03-19 15:37

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 8778
| Syslog                   | 25
| SecurityAlert            | 0
| SecurityIncident         | 0
| AzureNetworkAnalytics_CL | 0

## Conclusion

In this project, a mini honeynet was constructed in Microsoft Azure and log sources were integrated into a Log Analytics workspace. Microsoft Sentinel was employed to trigger alerts and create incidents based on the ingested logs. Additionally, metrics were measured in the insecure environment before security controls were applied, and then again after implementing security measures. It is noteworthy that the number of security events and incidents were drastically reduced after the security controls were applied, demonstrating their effectiveness.

It is worth noting that if the resources within the network were heavily utilized by regular users, it is likely that more security events and alerts may have been generated within the 24-hour period following the implementation of the security controls.
