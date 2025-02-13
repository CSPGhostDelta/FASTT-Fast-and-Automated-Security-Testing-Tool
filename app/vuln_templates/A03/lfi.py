SCAN_TEMPLATE = {
    'info': {
        'name': 'Local File Inclusion (LFI)',
        'type': 'A03:2021 - Injection',
        'severity': 'Critical',
        'description': (
            'Local File Inclusion (LFI) vulnerabilities occur when an application improperly processes user-supplied input '
            'to include local files from the server’s file system. Attackers can exploit this vulnerability to access sensitive files, retrieve system configurations, '
            'or escalate the attack to Remote Code Execution (RCE) under certain conditions, potentially compromising the entire server.'
        ),
        'cvss_score': '9.8',
        'cvss_metrics': 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H',
        'cwe_code': 'CWE-98: Improper Control of Filename for Include/Require Statement in PHP Program ("PHP Remote File Inclusion")',
        'cve_code': '',
        'full_description': (
            'Local File Inclusion (LFI) is a critical vulnerability that occurs when an application fails to properly validate or sanitize user input before '
            'including files from the server’s local file system. This may allow an attacker to manipulate file path parameters and gain unauthorized access to files '
            'such as `/etc/passwd`, web server configuration files, sensitive application logs, or other system files.'
        ),
        'remediation': (
            'Ensure that all user-supplied input, especially file path parameters, is validated to ensure only valid file names and paths are accepted.'
        ),
    },
    'entry_point': {
        'entry_point_method': 'parameter',
        'paths': [
            '{domain}'
        ],
    },
    'payloads': {
        'payload_type': 'wordlist',
        'payload': ['lfi.txt'] 
    },
    'matcher': {
        'matcher_type': 'http_body',
        'words': [
            '.htpasswd',
            'usr/local/apache',
            'var/log/apache',
            'var/log/httpd',
            'var/log/nginx',
            'var/www/logs',
            'proc/self/environ',
            'Windows\\system32\\',
            'boot.ini',
            'root:x:0:0:', 
            'Linux version',
            'Windows version',
        ]
    },
    'max_scan': 1
}
