# MyDFIR SOC Analyst Challenge

<br>

## Introduction

I completed a hands-on SOC Analyst Challenge focused on log analysis, threat detection, and incident response using the ELK Stack (Elasticsearch, Logstash, and Kibana). Working within a simulated SIEM environment hosted on a cloud-based virtual machine, I analyzed system, network, and application logs to detect and investigate various cyber attack scenarios. This included identifying brute force attempts, malware infections, and privilege escalation activities. Throughout the challenge, I gained practical experience in:
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

<br>

<p align="center">
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%203%20-Elastic%20Search%20.yml%20file.png?raw=true" alt="Elasticsearch YAML Configuration" width="32%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%203%20-%20Obtaining%20Public%20IP%20address%20149.248.61.82:23%20for%20elastic%20search%20instance.png?raw=true" alt="Obtaining Public IP" width="32%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%203-Adding%20public%20IP%20address%20and%20http%20port.png?raw=true" alt="Public IP and Port Configuration" width="32%" />
</p>

Elasticsearch .yml Configuration

After completing the installation of Elasticsearch, I configured the elasticsearch.yml file using the nano text editor. In the configuration file, I uncommented and updated the network.host setting to use the server’s public IP address (149.248.61.82) and confirmed that the http.port was set to the default value of 9200. These changes enabled Elasticsearch to accept remote connections, allowing seamless integration with Kibana and other tools. I then saved the file and restarted the Elasticsearch service to apply the new settings.

<br>

![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%204%20-%20Creating%20a%20firewall%20group.png?raw=true)
Implemented SSH Firewall Group for Enhanced Security on VULTR Virtual Machine

I implemented a custom firewall group on VULTR to restrict SSH access exclusively to my personal IP address. By applying this firewall group to my virtual machine, I significantly enhanced its security by limiting remote access and reducing potential attack vectors. This measure effectively prevented unauthorized connections and strengthened the overall security posture of the virtual machine

<br>

![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%204-%20Starting%20up%20elastic%20search%20service.png?raw=true)
Elastic search deployment

I deployed and started the Elasticsearch service using PowerShell by executing key system commands. First, I reloaded the systemd manager configuration with systemctl daemon-reload. Then, I enabled the Elasticsearch service to start on boot using systemctl enable elasticsearch.service. Finally, I started the service with systemctl start elasticsearch.service. To verify that the service was running correctly, I checked its status with systemctl status elasticsearch.service and confirmed it was active and running.

<br>

![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%204%20-%20Downloading%20Kibana%20via%20CLI.png?raw=true)

<br>

<p align="center">
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%204%20-%20Kibana%20installed%20and%20version.png?raw=true" alt="Kibana Installed and Version" width="32%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%204%20-%20Kibana%20successfully%20installed.png?raw=true" alt="Kibana Successfully Installed" width="32%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%204%20-%20allowing%20server%20port%20and%20server%20Host%20to%20be%20public%20IP%20instead%20of%20local%20host%20on%20Kibana%20server.png?raw=true" alt="Kibana Server Host Configuration" width="32%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%204%20-%20Kibana%20running%20successfully.png?raw=true" alt="Kibana Running Successfully" width="32%" />
</p>

Kibana Installation and Configuration

Following the successful setup of Elasticsearch, I proceeded to install Kibana on the same Ubuntu virtual machine to continue building the ELK stack. I visited the official Kibana downloads page and selected the appropriate .deb package for x86_64 architecture. Using PowerShell and the wget command, I downloaded the installer directly to the server by referencing the link for version 8.15.0, which was the latest available at the time. After confirming the download using the ls command, I installed the package with dpkg.
Once installed, Kibana generated its own set of security credentials, including an enrollment token used to establish a secure connection with the Elasticsearch instance. I enrolled Kibana using this token and configured the kibana.yml file to define server host settings and enable encrypted communication. After finalizing the configuration, I started the Kibana service and confirmed it was running and accessible through the browser, completing another essential step in the ELK stack deployment.

<br>

<p align="center">
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%204%20-%20binaries%20for%20Elastic%20Search%20need%20enrollement%20token.png?raw=true" alt="Elasticsearch Binaries for Enrollment Token" width="32%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%204%20-%20Trouble%20shooting%20checking%20if%20services%20are%20active.png?raw=true" alt="Troubleshooting Active Services" width="32%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%204%20-%20added%20ufw%20to%20allow%205601%20-%20Added%20rule%20to%20firewall%20for%20port%205601.png?raw=true" alt="UFW Rule for Port 5601" width="32%" />
</p>

Generating Elasticsearch Enrollment Token for Kibana Access

To enable secure access to Kibana, I first retrieved the Elasticsearch enrollment token specifically scoped for Kibana. I navigated to the Elasticsearch binary directory using cd /usr/share/elasticsearch/bin and listed the available binaries with ls to verify the correct path.
Next, I generated the enrollment token by running the command ./elasticsearch-create-enrollment-token --scope kibana. This created a unique token required for securely connecting Kibana to Elasticsearch.
After copying the generated token, I accessed the Kibana interface via its web address at http://149.248.61.82:5601, where I was prompted to paste the enrollment token. This step successfully established a secure link between Kibana and Elasticsearch, completing the initial authentication setup for the Kibana dashboard.
To make Kibana accessible externally, I added a UFW rule to allow incoming traffic on port 5601, which is the default port used by Kibana. This ensured that I could securely access the Kibana UI from a remote browser.

<br>

<p align="center">
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%204%20-%20added%20enrollment%20token%20for%20Elastic%20search%20and%20now%20verifying%20Kibana.png?raw=true" alt="Enrollment Token and Kibana Verification" width="32%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%204%20-sucessfully%20logged%20in-%20homepage%20of%20Elastic%20search.png?raw=true" alt="Successfully Logged In - Elasticsearch Homepage" width="32%" />
</p>

Completing Kibana Setup with Verification Code and Superuser Authentication

After submitting the enrollment token to connect Kibana to Elasticsearch, I proceeded to retrieve the Kibana verification code required to complete the setup. I navigated to the Kibana binary directory by running cd /usr/share/kibana/bin, then used ls to confirm the available binaries.
To generate the verification code, I executed the ./kibana-verification-code command, which returned a unique six-digit code. This code was then entered into the Kibana web interface to verify the instance.
Following verification, I entered the superuser credentials that were generated during the initial Elasticsearch installation and stored securely earlier in the process. Once authenticated, I successfully accessed the Kibana dashboard—marking the completion of the ELK stack’s core setup.

<br>

<p align="center">
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%205%20-%20Deployed%20windows%20server.png?raw=true" alt="Deployed Windows Server" width="32%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%205%20-%20Logs%20for%20windows%20server%20.png?raw=true" alt="Logs for Windows Server" width="32%" />
</p>

Deployed Windows Server with Remote Desktop Access on VULTR

I provisioned a new cloud-based Windows Server on VULTR, selecting Windows Server 2022 Standard (x64) as the operating system. The server was configured with 1 vCPU, 2 GB of memory, 50 GB SSD storage, and 2 TB of bandwidth, providing a lightweight yet capable environment for remote access and monitoring.
After deployment, I accessed the server using Remote Desktop Protocol (RDP) by entering its public IP address into the Remote Desktop client. Upon connection, I received the login credentials from the VULTR dashboard and successfully authenticated.
With RDP now exposed to the internet, this setup confirms that the Windows Server is live and accessible remotely. I plan to begin capturing and analyzing incoming RDP login attempts as part of a broader effort to monitor external threat activity and study real-world attack behavior.

<br>

<p align="center">
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%207%20-%20Adding%20Fleet%20server.png?raw=true" alt="Adding Fleet Server" width="32%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%207%20-%20configuring%20fleet%20server.png?raw=true" alt="Configuring Fleet Server" width="32%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%207%20-%20adding%20fleet%20server%20to%20centralized%20host.png?raw=true" alt="Adding Fleet Server to Centralized Host" width="32%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%207%20-%20successfully%20added%20Fleet%20server.png?raw=true" alt="Successfully Added Fleet Server" width="32%" />
</p>

Deploying and Connecting a Fleet Server to Elasticsearch

I deployed a new virtual machine on VULTR, selecting Ubuntu 22.04 LTS x64 as the operating system. The server was configured with 1 vCPU, 4 GB of memory, 30 GB NVMe storage, and 4 TB of bandwidth. I named this instance Fleet Server in VULTR, as it will be used to integrate with my Elasticsearch environment.
To connect it to Elasticsearch, I navigated to the Fleet section within Kibana and initiated the process to add a new Fleet Server. I assigned it the same name used in VULTR for consistency and entered the server’s public IP address, https://216.128.181.159, as the host URL.
I then accessed the Fleet Server remotely by launching my Windows Server instance, opening PowerShell, and connecting via SSH using the command ssh root@216.128.181.159. After entering the root password, I successfully logged into the server.

The final step in this phase was to update the system packages. I ran apt-get update && apt-get upgrade -y to ensure the server was fully up to date before proceeding with the Elastic Agent installation.
During the agent enrollment process, I encountered a connection issue. After troubleshooting, I identified that port 9200—used by Elasticsearch—was not open on the ELK server. I resolved this by allowing the port through the firewall with ufw allow 9200. This change enabled a successful connection, and the Elastic Agent was installed and enrolled without any further issues.

<br>

<p align="center">
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%207%20-%20Installing%20Elastic%20search%20via%20Powershell%20on%20windows%20server.png?raw=true" alt="Installing Elasticsearch via PowerShell on Windows Server" width="32%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%207%20Failed%20to%20enroll%20request%20to%20fleet%20server%20.png?raw=true" alt="Failed to Enroll Agent to Fleet Server" width="32%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%207%20-%20successful%20after%20ufw%20allow%208220%20and%20443%20-%20allowing%20correct%20port%20and%20changing%20fleet%20server%20in%20Elastic%20search%20to%208220%20and%20--insecure%20to%20sign%20certificate.png?raw=true" alt="Successful Installation After UFW and --insecure Fix" width="32%" />
</p>

Installing the Elastic Agent on the Windows Server

I began by launching PowerShell as an Administrator on the Windows Server to install the Elastic Agent. During the installation process, I encountered connectivity issues that required troubleshooting.
Initially, I modified the Fleet Server firewall settings to allow traffic on port 8220 by running ufw allow 8220, and also opened port 443. Despite this, the installation still failed due to port conflicts. Upon further investigation, I discovered that the Fleet Server’s expected communication port needed to be changed from 443 to 8220. 
I updated both the Fleet Server configuration and the PowerShell installation command accordingly. After this adjustment, a new error appeared stating that the certificate was signed by an unknown authority. To bypass this, I reran the installation command with the --insecure flag, which allowed the Elastic Agent to install successfully.

<br>

<p align="center">
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%209%20-%20extracting%20Sysmon%20file%20on%20windows%20server.png?raw=true" alt="Extracting Sysmon Files" width="32%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%209%20-%20Sysmon%20Config%20file%20.png?raw=true" alt="Sysmon Config File" width="32%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%209%20Directory%20where%20sysmon%20is%20located%20in%20powershell.png?raw=true" alt="Sysmon Directory in PowerShell" width="32%" />
</p>

<p align="center">
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%209%20-%20flags%20for%20installing%20Sysmon.png?raw=true" alt="Sysmon Install Flags" width="24%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%209%20-%20Sysmon%20successfully%20running.png?raw=true" alt="Sysmon Successfully Running" width="24%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%209%20-%20Sysmon%20events%20created.png?raw=true" alt="Sysmon Event Logs" width="24%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2010%20-%20Windows%20Sysmon%20integration.png?raw=true" alt="Windows Sysmon Integration" width="24%" />
</p>

Installing and Configuring Sysmon on Windows

To begin monitoring detailed system activity, I installed and configured Sysmon (System Monitor) on my Windows Server.
First, I connected to the machine via Remote Desktop Protocol (RDP) and downloaded Sysmon v15.15. After extracting the archive, I verified the presence of the three core binaries: Sysmon.exe, Sysmon64.exe, and SysmonDrv.sys.
Next, I visited GitHub to retrieve a community-recommended Sysmon configuration file. I chose the widely used Olaf Hartong Sysmon config, navigated to the sysmonconfig.xml, selected the raw view, and saved the file into the same directory where the Sysmon binaries were located.
With the setup files in place, I launched PowerShell as Administrator, navigated to the Sysmon directory using cd, and verified the contents with dir. I then installed Sysmon by running .\Sysmon64.exe -i sysmonconfig.xml.
After installation, I confirmed that Sysmon was running by checking the Services panel and opening Event Viewer to verify that logs were actively being generated under the Microsoft-Windows-Sysmon/Operational log.
Sysmon is now successfully installed and integrated with a structured configuration, enabling advanced monitoring and event logging for future threat detection.

<br>

Sysmon
<p align="center">
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2010%20-%20events%20under%20winlog.event_id.png?raw=true" alt="Events Under winlog.event_id" width="32%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2010%20-%20confirmation%20sysmon%20is%20being%20ingested.png?raw=true" alt="Sysmon Ingestion Confirmed" width="32%" />
</p>
Windows Defender
<p align="center">
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2010%20-%20microsoft%20defender%20logs%20integrated.png?raw=true" alt="Microsoft Defender Logs Integrated" width="32%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2010%2012%2027%20-%20Microsoft%20windows%20defender%20confirmation%20.png?raw=true" alt="Windows Defender Ingestion Confirmed" width="32%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2010%20-%20Now%20able%20to%20see%20logs-%20changed%20firewall%20rule%20for%209200%20on%20VULTR.png?raw=true" alt="Logs Visible After Firewall Change" width="32%" />
</p>

Adding Sysmon and Windows Defender Logs to Elastic via Windows Integration

To enhance visibility into endpoint activity, I integrated both Sysmon and Windows Defender logs into my Elastic environment using custom Windows event log settings.
I started by accessing Event Viewer on my Windows Server and navigating to: Applications and Services Logs > Microsoft > Windows > Sysmon > Operational.I opened the Properties panel and copied the channel name:Microsoft-Windows-Sysmon/Operational.

In Kibana, under the Windows integration policy, I added a custom event log with that channel name and labeled the integration clearly for Sysmon. I kept the remaining default settings and saved the changes to the existing policy.
Next, I repeated the process for Windows Defender logs. From Event Viewer, I copied the Defender channel name and created another custom log entry. This time, I specified event IDs 1116, 1117, and 5001, which correspond to real-time threat detection and remediation events. These were also added to the existing Windows integration policy.To ensure all Windows events were being captured, I included the field winlog.event_id: * to collect any event ID that exists, providing broader coverage.
After saving and deploying the changes, I restarted the Elastic Agent via the Services panel on the Windows Server. Initially, I noticed that CPU and memory metrics were showing as "N/A", indicating a connection issue. To resolve this, I modified my VULTR firewall group and allowed TCP port 9200—used by Elasticsearch. Once this was configured, metric data such as CPU and memory began appearing correctly, confirming successful integration and data flow.

<br>

![image alt](https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2012%20-%20Ubuntu%20server%20install.png?raw=true)
Setting Up Ubuntu 24.04 LTS for Authentication Log Monitoring

I deployed a new Ubuntu 24.04 LTS x64 server to collect and analyze authentication logs. After launching the server, I updated the system repositories and packages using apt update && apt upgrade to ensure the environment was fully up to date.
To begin generating log data, I navigated to the /var/log/ directory and used cat auth.log to view the contents of the authentication log. This file captures all login-related events, including failed SSH login attempts, which are critical for monitoring brute-force attacks or unauthorized access attempts.
By intentionally testing failed SSH logins, I confirmed that the system was properly logging authentication failures. These logs will later be ingested into my Elastic Stack for further analysis and correlation.

<br>

<p align="center">
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2013%20-%20linux%20integration.png?raw=true" alt="Linux Integration" width="45%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2013%20-%20%20adding%20Ubuntu%20Agent.png?raw=true" alt="Adding Ubuntu Agent" width="45%" />
</p>
<p align="center">
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2013%20-%20filtering%20logs%20for%20Linux%20machine.png?raw=true" alt="Filtering Logs for Linux Machine" width="45%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2013%20-%20Authentication%20failures%20from%20170.231.48.3%20.png?raw=true" alt="Authentication Failures from IP" width="45%" />
</p>

I deployed an Ubuntu 24.04 LTS server and began the Elastic Agent integration by first connecting via SSH. To prepare the system, I updated the repositories and upgraded existing packages by running sudo apt update && sudo apt upgrade -y. After downloading the Elastic Agent Linux package from the official Elastic downloads page, I extracted the archive using tar -xzf elastic-agent-<version>-linux-x86_64.tar.gz and navigated into the extracted directory.
To enroll the agent with the Fleet Server, I ran the enrollment command with my Fleet Server URL and enrollment token: sudo ./elastic-agent enroll https://216.128.181.159:8220 <ENROLLMENT_TOKEN> --insecure. I included the --insecure flag to bypass certificate validation errors that occurred during enrollment.
Once enrolled, I enabled and started the Elastic Agent service by running sudo systemctl enable elastic-agent followed by sudo systemctl start elastic-agent. I verified the agent’s status using sudo systemctl status elastic-agent to ensure it was running correctly.
Finally, to allow the Fleet Server to communicate with the agent, I updated the firewall rules by adding a UFW rule to allow TCP traffic on port 8220 with the command sudo ufw allow 8220/tcp. After these steps, my Ubuntu server was successfully integrated into the Elastic Stack and ready to send logs to the Fleet Server.

<br>

<p align="center">
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2014%20-%20Failed%20events.png?raw=true" alt="Failed Events" width="23%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2014%20-%20Defining%20the%20query%20.png?raw=true" alt="Defining the Query" width="23%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2014%20-%20added%20query%20and%20added%20field%20in%20for%20map.png?raw=true" alt="Added Query and Field for Map" width="23%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2014%20-%20troubleshot%20by%20adding%20by%20iso%20code%20.png?raw=true" alt="Troubleshot by Adding ISO Code" width="23%" />
</p>
Viewing the maps of where attackers are

I am now able to view security alert logs generated by my Linux machine by applying filters in the Elastic Stack. Specifically, I focus on filtering failed login attempts by user and source IP. To proactively monitor these events, I created an alert rule named Brute Force Activity.
Next, I visualized the geographic locations of these attacks by creating a map. Using Kibana Query Language (KQL), I filtered the map data with queries such as system.auth.ssh.event: * and system.auth.ssh.event: Failed combined with the agent name corresponding to my Linux machine.
To build the map, I added a choropleth layer, using the EMS (Elastic Maps Service) world boundaries as the base. I then selected the appropriate data view and joined it on the field source.geo.country_iso_code to generate a clear, visual representation of where the brute force attempts are occurring globally.

<br>

<p align="center">
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2016%20filtering%20for%20Event%20codes%204625-%20might%20be%20where%20I%20screwed%20up%20space%20after%20colon%20I%20believe.png?raw=true" alt="Filtering for Event Code 4625" width="19%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2016%20-%20First%20alert%20after%20making%20rule.png?raw=true" alt="First Alert After Making Rule" width="19%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2016%20-%20Creating%20a%20rule%20to%20see%20failed%20authentiations%20for%20Root.png?raw=true" alt="Creating Rule for Failed Authentications for Root" width="19%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2016%20-%20Rule%20created.png?raw=true" alt="Rule Created" width="19%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2016%20-%20Rule%20for%20administrator%20and%204625%20event%20code.png?raw=true" alt="Rule for Administrator and Event Code 4625" width="19%" />
</p>

Failed authentication rules for Ubuntu and windows server

I am now focusing on setting up alerts for both my Windows server and Ubuntu machines to enhance monitoring and security. Specifically, I am creating alert rules to detect failed authentication attempts for critical accounts — monitoring failed login attempts from the root user on the Ubuntu server and the Administrator account on the Windows server. These rules will help me quickly identify potential unauthorized access attempts across both environments.

<br>

<p align="center">
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2017%20-%20failed%20RDP%20authentication%20map.png?raw=true" alt="Failed RDP Authentication Map" width="32%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2017%20-%20Creating%20a%20table%20by%20dropping%20filters%20.png?raw=true" alt="Creating a Table by Dropping Filters" width="32%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2017%20-%20changed%20to%20top%2010%20values%20for%20user.name%20source%20IP%20and%20source%20Geo.png?raw=true" alt="Top 10 Values for User, IP, Geo" width="32%" />
</p>

Now its time to do RDP authentications
Next, I created a map visualizing failed RDP authentication attempts, followed by a table filtered to show the top three values for username, timestamp, country, and the count of records.

<br>

<p align="center">
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2020%20-%20Installing%20Kali%20Linux.png?raw=true" alt="Installing Kali Linux" width="48%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2020%20-%20Successfully%20SSH%20into%20Mythic%20or%20Kali.png?raw=true" alt="SSH into Mythic or Kali" width="48%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2020%20-%20Mythic%20install%20via%20CLI.png?raw=true" alt="Mythic Install via CLI" width="48%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2020%20-%20Made%20Docker%20container%20.png?raw=true" alt="Made Docker Container" width="48%" />
</p>

<p align="center">
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2020%20-%20Able%20to%20access%20Mythic%20login%20screen.png?raw=true" alt="Mythic Login Screen" width="48%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2020%20-%20sucessfully%20logged%20in%20to%20Mytic%20server.png?raw=true" alt="Successfully Logged in to Mythic Server" width="48%" />
  <img src="https://github.com/TylerTweedie/MyDFIR-SOC-analyst/blob/main/Day%2020%20-%20Mythic%20Dashboard.png?raw=true" alt="Mythic Dashboard" width="48%" />
</p>

Mythic server

Lastly, I installed Kali Linux and successfully set up Mythic by adding a Docker container. I was able to log in without issues and access the Mythic dashboard. Unfortunately, my VULTR trial expired, which prevented me from moving forward with further deployment.

## Conclusion

This project provided hands-on experience deploying and configuring key components of the ELK stack, integrating security monitoring tools like Sysmon and Elastic Agent, and setting up alerting and visualization for real-time threat detection. Despite some limitations due to trial expirations, I successfully built a foundational environment for centralized log management and security analytics.
