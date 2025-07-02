# MyDFIR SOC Analyst Challenge

<br>

## Introduction

Over the course of 30 days, I completed a hands-on SOC Analyst Challenge focused on log analysis, threat detection, and incident response using the ELK Stack (Elasticsearch, Logstash, and Kibana). Working within a simulated SIEM environment hosted on a cloud-based virtual machine, I analyzed system, network, and application logs to detect and investigate various cyber attack scenarios. This included identifying brute force attempts, malware infections, and privilege escalation activities. Throughout the challenge, I gained practical experience in:
Log correlation and threat hunting using Kibana visualizations and queries
Incident triage and documentation based on log evidence and alert patterns
Ingesting and structuring raw logs with Logstash for analysis
Building interactive dashboards and conducting time-based investigations
Developing basic detection rules and security use cases
Tools and technologies used included Ubuntu, Kali Linux, VMware, VULTR, Syslog, and core SIEM concepts—providing a comprehensive, real-world foundation in cybersecurity monitoring and analysis.

<br>

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

🐧 Linux (Ubuntu VM) – Operating system used to simulate attacks and generate log data.

📝 Syslog – System logging and auditing tools used as log sources.

🎯 Kali Linux – Used for simulating attacks and generating malicious traffic.

☁️ VULTR – Cloud infrastructure provider used to host virtual machines and lab environment.

💻 VMware – Local virtualization.

🛡️ SIEM Concepts – Applied Security Information and Event Management techniques in a practical setting.

<br>

## Steps
# 30 Day SOC Analyst Challenge

<p align="center">
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%203%20VPC%20IP%20172.31.0.3.png?raw=true" alt="VPC IP Image" width="24%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/VPC%20Server%20Specs.png?raw=true" alt="Server Specs 1" width="24%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/VPC%20Server%20Specs.png?raw=true" alt="Server Specs 2" width="24%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/VULTR%20VPC%20Creation.png?raw=true" alt="VULTR VPC Creation" width="24%" />
</p>

Cloud Infrastructure Setup

To establish the lab environment, I first configured a VPC (Virtual Private Cloud) on VULTR, defining a custom IPv4 range to ensure proper network segmentation and control. I then provisioned a new virtual machine running Ubuntu 22.04, selecting the following specifications to support high-performance log ingestion and analysis:

80 GB NVMe storage

4 vCPUs

16 GB RAM

6 TB bandwidth

The virtual machine was attached to the previously created VPC, providing a secure and scalable foundation for deploying the ELK stack and simulating real-world cyber attacks.
<br>

![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/repositories%20updated.png?raw=true)
Initial Server Configuration

After provisioning the virtual server, I accessed it via SSH to begin the setup process. The first step was to update the system packages to ensure a secure and stable environment. I executed the following command to update and upgrade all system repositories:
sudo apt-get update && sudo apt-get upgrade -y
With the system fully updated, the server was ready for the installation and configuration of Elasticsearch, the first component of the ELK stack.
<br>

<p align="center">
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%203%20Downloaded%20elastic%20search%20via%20CLI.png?raw=true" alt="Downloaded Elasticsearch via CLI" width="32%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%203%20Elastic%20search%20install%20confirmation%20and%20version.png?raw=true" alt="Elasticsearch Installation Confirmation" width="32%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%203%20obtaining%20security%20auto%20configuration%20information%20.png?raw=true" alt="Security Auto Configuration Info" width="32%" />
</p>

Elasticsearch Installation and Configuration

To begin setting up the ELK stack, I installed Elasticsearch on my Ubuntu virtual machine. I navigated to the official Elasticsearch downloads page, selected the appropriate .deb package for x86_64 architecture, and copied the download link.
Using PowerShell and wget, I initiated the download directly onto the server:
wget elasticsearch-8.15.0-amd64.deb After confirming the successful download with the ls command, I proceeded with the installation: At the time of this project, version 8.15 of Elasticsearch was the latest available. Upon installation, Elasticsearch automatically generated security configuration details, including the superuser password and enrollment tokens. I securely stored this information for use in securing the stack and enabling authentication features.
This marked the foundation for configuring the rest of the ELK stack, beginning with fine-tuning the elasticsearch.yml file and setting up network access.

<Br>

<p align="center">
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%203%20-Elastic%20Search%20.yml%20file.png?raw=true" alt="Elasticsearch YAML Configuration" width="32%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%203%20-%20Obtaining%20Public%20IP%20address%20149.248.61.82:23%20for%20elastic%20search%20instance.png?raw=true" alt="Obtaining Public IP" width="32%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%203-Adding%20public%20IP%20address%20and%20http%20port.png?raw=true" alt="Public IP and Port Configuration" width="32%" />
</p>









![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%204%20-%20Creating%20a%20firewall%20group.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%204-%20Starting%20up%20elastic%20search%20service.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%204%20-%20Downloading%20Kibana%20via%20CLI.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%204%20-%20Kibana%20installed%20and%20version.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%204%20-%20Kibana%20successfully%20installed.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%204%20-%20allowing%20server%20port%20and%20server%20Host%20to%20be%20public%20IP%20instead%20of%20local%20host%20on%20Kibana%20server.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%204%20-%20Kibana%20running%20successfully.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%204%20-%20binaries%20for%20Elastic%20Search%20need%20enrollement%20token.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%204%20-%20Trouble%20shooting%20checking%20if%20services%20are%20active.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%204%20-%20added%20ufw%20to%20allow%205601%20-%20Added%20rule%20to%20firewall%20for%20port%205601.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%204%20-%20added%20enrollment%20token%20for%20Elastic%20search%20and%20now%20verifying%20Kibana.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%204%20-sucessfully%20logged%20in-%20homepage%20of%20Elastic%20search.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%205%20-%20Deployed%20windows%20server.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%205%20-%20Logs%20for%20windows%20server%20.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%207%20-%20Adding%20Fleet%20server.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%207%20-%20configuring%20fleet%20server.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%207%20-%20adding%20fleet%20server%20to%20centralized%20host.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%207%20-%20successfully%20added%20Fleet%20server.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%207%20-%20Installing%20Elastic%20search%20via%20Powershell%20on%20windows%20server.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%207%20Failed%20to%20enroll%20request%20to%20fleet%20server%20.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%207%20-%20successful%20after%20ufw%20allow%208220%20and%20443%20-%20allowing%20correct%20port%20and%20changing%20fleet%20server%20in%20Elastic%20search%20to%208220%20and%20--insecure%20to%20sign%20certificate.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%209%20-%20extracting%20Sysmon%20file%20on%20windows%20server.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%209%20-%20Sysmon%20Config%20file%20.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%209%20Directory%20where%20sysmon%20is%20located%20in%20powershell.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%209%20-%20flags%20for%20installing%20Sysmon.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%209%20-%20Sysmon%20successfully%20running.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%209%20-%20Sysmon%20events%20created.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2010%20-%20Windows%20Sysmon%20integration.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2010%20-%20microsoft%20defender%20logs%20integrated.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2010%20-%20events%20under%20winlog.event_id.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2010%20-%20Now%20able%20to%20see%20logs-%20changed%20firewall%20rule%20for%209200%20on%20VULTR.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2010%20-%20confirmation%20sysmon%20is%20being%20ingested.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2010%2012%2027%20-%20Microsoft%20windows%20defender%20confirmation%20.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2012%20-%20Ubuntu%20server%20install.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2013%20-%20linux%20integration.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2013%20-%20%20adding%20Ubuntu%20Agent.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2013%20-%20filtering%20logs%20for%20Linux%20machine.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2013%20-%20Authentication%20failures%20from%20170.231.48.3%20.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2014%20-%20Failed%20events.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2014%20-%20Defining%20the%20query%20.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2014%20-%20added%20query%20and%20added%20field%20in%20for%20map.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2014%20-%20troubleshot%20by%20adding%20by%20iso%20code%20.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2016%20filtering%20for%20Event%20codes%204625-%20might%20be%20where%20I%20screwed%20up%20space%20after%20colon%20I%20believe.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2016%20-%20First%20alert%20after%20making%20rule.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2016%20-%20Creating%20a%20rule%20to%20see%20failed%20authentiations%20for%20Root.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2016%20-%20Rule%20created.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2016%20-%20Rule%20for%20administrator%20and%204625%20event%20code.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2017%20-%20failed%20RDP%20authentication%20map.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2017%20-%20Creating%20a%20table%20by%20dropping%20filters%20.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2017%20-%20changed%20to%20top%2010%20values%20for%20user.name%20source%20IP%20and%20source%20Geo.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2020%20-%20Installing%20Kali%20Linux.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2020%20-%20Successfully%20SSH%20into%20Mythic%20or%20Kali.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2020%20-%20Mythic%20install%20via%20CLI.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2020%20-%20Made%20Docker%20container%20.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2020%20-%20Able%20to%20access%20Mythic%20login%20screen.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2020%20-%20sucessfully%20logged%20in%20to%20Mytic%20server.png?raw=true)
![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2020%20-%20Mythic%20Dashboard.png?raw=true)


## Conclusion

In this project, a mini honeynet was constructed in Microsoft Azure and log sources were integrated into a Log Analytics workspace. Microsoft Sentinel was employed to trigger alerts and create incidents based on the ingested logs. Additionally, metrics were measured in the insecure environment before security controls were applied, and then again after implementing security measures. It is noteworthy that the number of security events and incidents were drastically reduced after the security controls were applied, demonstrating their effectiveness.

It is worth noting that if the resources within the network were heavily utilized by regular users, it is likely that more security events and alerts may have been generated within the 24-hour period following the implementation of the security controls.
