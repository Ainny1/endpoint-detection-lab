# 🔐 Endpoint Threat Detection & Response Lab

## 📌 Overview
This project simulates a real-world Security Operations Center (SOC) environment using Splunk and Sysmon to monitor, detect, and analyze endpoint activity.

## 🛠️ Tools Used
- Splunk Enterprise  
- Sysmon  
- Windows Virtual Machine  
- (Optional) Kali Linux  

## 🎯 Objectives
- Monitor endpoint activity  
- Detect suspicious behavior  
- Perform log analysis  
- Create detection rules  
- Simulate incident response workflows  

## 🔍 Use Cases

### Failed Login Detection
Detect brute-force login attempts:
index=wineventlog EventCode=4625

### Successful Login Tracking
index=wineventlog EventCode=4624

### PowerShell Monitoring
Detect suspicious command execution:
powershell

## 🚨 Detection Capabilities
- Brute-force login detection  
- Suspicious process execution  
- PowerShell activity monitoring  
- Endpoint behavior analysis  

## 🧠 Skills Demonstrated
- SIEM (Splunk)  
- Log Analysis  
- Endpoint Security  
- Incident Response  
- Detection Engineering  

## 📸 Screenshots

### Failed Login Detection
<img width="800" height="450" alt="IMG_9717" src="https://github.com/user-attachments/assets/f34dade6-f872-4d85-b39f-7bacdbb6ed6f" />


### PowerShell Activity Monitoring
![PowerShell](powershell-activity.png)

## 📈 Outcome
This lab demonstrates hands-on experience with SIEM tools, endpoint monitoring, and detection workflows aligned with enterprise tools like CrowdStrike Falcon.
