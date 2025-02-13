SCAN_TEMPLATE = {
    'info': {
        'name': 'Sensitive Data Exposure via Directory Listing Enabled',
        'type': 'A01:2021 - Broken Access Control',
        'severity': 'Critical',
        'description': 'Found potential sensitive file with extension: {detected_value}',
        'cvss_score': '9.1',
        'cvss_metrics': 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
        'cwe_code': 'CWE-548: Exposure of Information Through Directory Listing',
        'cve_code': '',
        'full_description': (
            'Sensitive data exposure occurs when confidential information such as passwords, financial records, API keys, '
            'or database dumps are stored or transmitted without proper encryption or access controls. '
            'Attackers can exploit exposed data to perform account takeovers, fraud, and further system compromises. '
            'Common causes include misconfigured servers, exposed backups, plaintext storage, and weak cryptographic implementations.'
        ),
        'remediation': (
            'Restrict access to sensitive files and databases using proper authentication and authorization.\n'
            '1. Disable directory listing on the web server\n'
            '2. Move sensitive files outside of web root\n'
            '3. Implement proper access controls\n'
            '4. Use .htaccess or web.config to restrict access\n'
        ),
    },
    'entry_point': {
        'entry_point_method': 'path',
        'path_method': 'single',
        'paths': [
            '{domain}',
        ],
    },
    'payloads': {
        'payload_type': 'wordlist',
        'payload': ['directorylisting.txt']
    },
    'matcher': {
        'matcher_type': 'http_body',
        'type': 'extension',
        'words': [
            '.bak', '.sql', '.log', '.php'
        ]
    },
    'max_scan': 10
}