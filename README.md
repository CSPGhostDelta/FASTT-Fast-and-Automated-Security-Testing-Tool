# FASTT - Fast and Automated Security Testing Tool
<p align="center">
  <img src="https://github.com/user-attachments/assets/0d693c60-b9b8-4b20-8f0c-e2d06f5375e7" alt="FASTT Logo">
</p>

**FASTT (Fast and Automated Security Testing Tool)** is a web-based vulnerability scanner designed to perform comprehensive security assessments on websites. FASTT aims to identify and evaluate security vulnerabilities by leveraging the OWASP Top 10 2021 security risks and the Common Vulnerability Scoring System (CVSS) v4.0 to assess the severity of detected vulnerabilities. FASTT is built using Python with the Flask framework, providing a robust and scalable architecture. It employs a template-based approach using customizable .py files, allowing users to easily update and extend scan templates to detect new emerging threats.

# Features


# How FASTT Works
### 1. User specify a target website URL to scan.
The scanning process begins when the user provides a website URL as the target for the security assessment. This can be done through the **Scan Targets** page by clicking the **Add Target** button.

![scantargetslight](https://github.com/user-attachments/assets/0868dacd-18c6-4a0e-a312-ee7ad6a1de7b)

After that, user specify the website target by inputting the **Scan Name**, **Target URL**, and **Note** (optional). And then click the **Add Target** button.

![addtargetlight](https://github.com/user-attachments/assets/5a0c9ba8-dac1-4f55-82a1-063d4bb07c7a)

The target will be added on **Scan Targets** page, and user can begin scanning by clicking the **Start** button on the **Actions** column.

![scantargets-addedtarget](https://github.com/user-attachments/assets/daf8c9e1-9334-4eca-8a2f-e846703219dc)

### 2. The scanner crawls & tests parameters for vulnerabilities.
During the scanning process, FASTT will crawl the website first and then proceed to vulnerability scan using templates

![targetscanning](https://github.com/user-attachments/assets/46b66a37-9a91-4d2f-b5b6-a44440b24114)

### 3. Detected issues are ranked based on CVSS v4.0 severity levels.
Once vulnerabilities are identified, FASTT ranks them using the Common Vulnerability Scoring System (CVSS) v4.0. This provides a standardized way to assess the severity of each issue.

### 4. Security reports can be accessed via report dashboard.
FASTT provides a user-friendly dashboard where users can access detailed security reports. These reports include:
- Vulnerability Summary: A high-level overview of detected issues.
- Detailed Findings: Information about each vulnerability, including:
- Description.
- Severity level.
- Affected URLs or parameters.
- Recommendations for remediation.

![targetdetailsfoundvuln](https://github.com/user-attachments/assets/7bfb2c11-72c7-46ec-8574-5639ceb5d266)

# Installation
1. Clone the repository and access the directory.
```
git clone https://github.com/CSPGhostDelta/FASTT-Fast-and-Automated-Security-Testing-Tool.git && cd FASTT-Fast-and-Automated-Security-Testing-Tool/
```
2. Run the **install.sh** script
```
chmod +x install.sh && ./install.sh
```
3. Wait until the installation process finished.

![image](https://github.com/user-attachments/assets/1d740419-9a9e-4821-bff9-aa7b3fdd8cc8)

4. After that, FASTT can be accessed at **https://127.0.0.1/**.

![image](https://github.com/user-attachments/assets/59a1b309-e336-404c-abae-4006d6b825d6)
