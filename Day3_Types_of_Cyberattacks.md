# 🐛 Day 3: Types of Cyberattacks  
*Part of the [30-Day SOC Level 1 Series](https://medium.com/@0ccupi3R/️️30-days-in-the-soc-️-f70f349b8b1e)*

## 📘 Key Attack Types & Definitions

### **Phishing and Spear Phishing**

📘 **Definition:**  
Phishing is a social engineering technique where attackers impersonate trusted entities to trick users into revealing sensitive information. Spear phishing is a more targeted version aimed at specific individuals or roles within an organization.

🧠 **Example:**  
An employee receives an email that looks like it’s from their bank, asking them to “verify” their account by clicking a link. The link leads to a fake login page that steals credentials. In SIEM, this may appear as a user clicking a suspicious URL flagged by threat intelligence.

*“Phishing is like someone pretending to be your friend to steal your wallet—except it happens through email or messages.”*

### **Malware and Ransomware**

📘 **Definition:**  
Malware refers to any malicious software designed to disrupt, damage, or gain unauthorized access to systems. Ransomware encrypts files and demands payment for decryption.

🧠 **Example:**  
A user downloads a fake PDF attachment that installs a keylogger, silently capturing passwords. In SIEM, this may show up as unusual process creation or outbound traffic to known malicious IPs.

*“Ransomware is like a thief locking your house and asking for money to give you the key.”*

### **Brute Force Login Attempts**

📘 **Definition:**  
Brute force attacks involve systematically guessing passwords until the correct one is found.

🧠 **Example:**  
Authentication logs show 100+ failed login attempts from the same IP within 5 minutes. The SIEM triggers a brute force alert.

*“It’s like trying every key on a keyring until one opens the door.”*

### **Denial of Service (DoS) and Distributed DoS (DDoS)**

📘 **Definition:**  
DoS and DDoS attacks flood a system or network with traffic, making it unavailable to legitimate users.

🧠 **Example:**  
Firewall logs show thousands of requests per second from multiple IPs targeting a single web server.

*“It’s like a crowd blocking the entrance to a store so real customers can’t get in.”*

### **SQL Injection**

📘 **Definition:**  
SQL Injection is a web application attack where malicious SQL code is inserted into input fields to manipulate or access databases.

🧠 **Example:**  
An attacker types `' OR '1'='1` into a login form, bypassing authentication and accessing user data. SIEM may detect this through abnormal query patterns in web logs.

*“It’s like tricking a vending machine into giving you snacks without paying.”*

### **Cross-Site Scripting (XSS)**

📘 **Definition:**  
XSS allows attackers to inject malicious scripts into web pages viewed by other users.

🧠 **Example:**  
A comment box on a website allows JavaScript, which an attacker uses to redirect users to a fake login page.

*“It’s like someone writing a trap into a public notice board that tricks others when they read it.”*

### **Man-in-the-Middle (MITM)**

📘 **Definition:**  
MITM attacks intercept communication between two parties to steal or alter data.

🧠 **Example:**  
An attacker intercepts login credentials sent over an unsecured Wi-Fi network.

*“It’s like someone secretly listening to your phone call and writing down your credit card number.”*

### **Insider Threats**

📘 **Definition:**  
An insider threat involves someone within the organization misusing their access to cause harm.

🧠 **Example:**  
A disgruntled employee downloads sensitive data before leaving the company. SIEM may show large file transfers or access to restricted folders.

*“It’s like a trusted employee stealing from the company vault.”*

### **Suspicious DNS Queries**

📘 **Definition:**  
Attackers often use DNS to communicate with command-and-control servers or exfiltrate data.

🧠 **Example:**  
DNS logs show queries to newly registered domains or domains flagged by threat intelligence feeds.

*“It’s like someone secretly sending coded messages to a remote location.”*

### **Unusual File Access or Modification**

📘 **Definition:**  
Unauthorized access or changes to sensitive files may indicate data theft or malware activity.

🧠 **Example:**  
File integrity monitoring alerts show changes to system files or access to confidential documents by non-privileged users.

*“It’s like someone sneaking into a locked cabinet and rearranging the contents.”*
