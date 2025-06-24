# SOC-Automation
1.PROBLEM STATEMENT<br>
In today's dynamic cybersecurity landscape, Security Operations Centers (SOCs) are increasingly overwhelmed by the sheer volume and complexity of cyber threats. With the rapid evolution of cyberattacks, ranging from advanced persistent threats (APTs) to sophisticated ransomware and zero-day exploits, SOC teams face significant challenges in effectively detecting, analyzing, and mitigating security incidents.
Traditional SOC operations rely heavily on manual processes for threat investigation, incident correlation, and response execution. These manual workflows are slow, labor-intensive, and prone to human error, making it difficult to keep pace with modern cyber threats. As a result, organizations experience prolonged detection and response times, increasing their exposure to potential data breaches, financial losses, and reputational damage. Additionally, the high volume of security alerts—many of which are false positives—further exacerbates alert fatigue, leading to missed or delayed threat responses.
Moreover, the growing demand for skilled cybersecurity professionals has outpaced the available workforce, making it even more challenging for SOCs to manage the increasing workload. The lack of standardized, automated response mechanisms also limits incident consistency and efficiency, forcing analysts to manually investigate each security event, which is neither scalable nor sustainable in a high-threat environment.

2.METHODOLGY<br>
The development of the SOC Automation Simulation follows a structured and iterative approach to ensure the effective integration of automation into Security Operations Center (SOC) workflows. The methodology consists of multiple phases, including requirement analysis, system design, implementation, testing, and evaluation, each of which plays a crucial role in the system's overall effectiveness.
![image](https://github.com/user-attachments/assets/2db93536-b7b1-4c7e-916c-b6dd5d7d4a0a)

![image](https://github.com/user-attachments/assets/31c274ea-5081-4eba-8da0-5ab2baf82595)<br>
The figure above showcases the DigitalOcean cloud infrastructure used for deploying TheHive and Wazuh services. Each service is hosted on a separate Droplet, a virtual private server provided by DigitalOcean. These droplets have been configured with 8 GB RAM, 2 Intel vCPUs, and 160 GB disk space, ensuring adequate performance for security monitoring and incident response operations.<br>
->TheHive (IP: 143.198.56.201), indicating a recent setup, likely for security incident analysis and case management.<br>
->Wazuh (IP: 143.198.225.10) , serving as a security monitoring and threat detection system.<br>
The DigitalOcean dashboard enables easy management of these deployments, with options to modify settings, scale resources, and monitor performance. This setup is crucial for Security Operations Center (SOC) automation, where TheHive acts as an incident response platform, and Wazuh serves as an intrusion detection and log analysis tool.<br>
![image](https://github.com/user-attachments/assets/61eabfe6-fb67-4261-8105-b41160b36645)<br>
WAZUH dashboard<br>
![image](https://github.com/user-attachments/assets/cd1dd1df-8693-41dd-95e6-208d8ba7438e)<br>
THEHive dashboard<br>
![image](https://github.com/user-attachments/assets/d23bf2a8-6f93-4fdb-b050-45f052be60ec)<br>
The image above displays the Windows Services Manager with the Wazuh Agent actively running on a Windows 10 machine. The service status is marked as "Running" with an "Automatic" startup type, ensuring it starts with the system.<br>
->Wazuh Agent plays a crucial role in endpoint security monitoring, collecting logs, detecting intrusions, and sending security events to the Wazuh Manager for analysis.
The PowerShell window in the background indicates a successful connection to the Wazuh server hosted at 143.198.225.10 (likely a DigitalOcean Droplet).<br>
![image](https://github.com/user-attachments/assets/5ef02901-868a-40df-a52b-2e56ee1ebdca)<br>
The image shows the PowerShell terminal running Mimikatz, a powerful post-exploitation tool often used for extracting credentials, dumping hashes, and performing privilege escalation on Windows systems. 
1.The user navigated to the Mimikatz directory located at: C:\Users\uruc\Downloads\mimikatz_trunk\x64<br>
2.Listed files include:<br>
->omimidrv.sys (Mimikatz driver)<br>
->omimikatz.exe (Main executable)<br>
->omimilib.dll (Library file)<br>
->omimispool.dll (DLL component)<br>
3.The command .\mimikatz.exe was executed, launching the tool successfully.<br>
![image](https://github.com/user-attachments/assets/f1ec82d8-147d-4683-986b-b6e975b4bd60)<br>
The image displays a workflow automation setup in Shuffle, an open-source SOAR (Security Orchestration, Automation, and Response) platform. The workflow integrates Wazuh, VirusTotal, and TheHive to automate the processing of security alerts.
Workflow Breakdown<br>
1.Wazuh-Alerts (Webhook Trigger)<br>
The workflow starts by receiving security alerts from Wazuh, an open-source SIEM (Security Information and Event Management) solution.<br>
2.SHA256Regex (Regex Extraction)<br>
Extracts SHA256 hashes from the alert data using a regular expression (Regex) processor.<br>
3.VirusTotal (Threat Intelligence Check)<br>
The extracted SHA256 hash is sent to VirusTotal, an online malware scanning and threat intelligence service, to check for known malicious indicators.<br>
4.TheHive (Incident Management)<br>
If the hash is flagged as suspicious/malicious, an incident is automatically created in TheHive, a cybersecurity incident response platform.<br>

**Use Case & Importance**<br>
->This workflow automates malware detection and response, reducing manual effort for SOC teams.<br>
->Real-time threat intelligence enhances incident handling efficiency.<br>
->The integration between Wazuh, VirusTotal, and TheHive provides a seamless SOC automation experience.<br>
![image](https://github.com/user-attachments/assets/d47af77d-202b-4384-b682-6ae3675b6249)<br>
The image shows an alert interface in TheHive, a Security Incident Response Platform (SIRP), which is part of a SOC automation workflow. The alert is related to Mimikatz, a well-known tool used for credential dumping in Windows environments.








