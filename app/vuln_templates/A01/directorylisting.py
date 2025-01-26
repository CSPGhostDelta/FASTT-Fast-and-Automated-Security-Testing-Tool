SCAN_TEMPLATE = {
    'info': {
        'name': 'Directory Listing Enabled',
        'type': 'A05 - Security Misconfiguration',
        'severity': 'High',
        'description': (
            'Directory Listing is enabled on the target website, allowing unauthorized users to view the contents of directories. '
            'This misconfiguration can expose sensitive files, leading to information disclosure and potential security risks.'
        ),
        'cvss_score': '8.2',
        'cvss_metrics': 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N',
        'cwe_code': 'CWE-548: Exposure of Information Through Directory Listing',
        'cve_code': '',
        'full_description': (
            'Directory Listing occurs when a web server is improperly configured, allowing users to browse and view directory contents that do not have an index file. '
            'This misconfiguration can expose sensitive files such as configuration files, database backups, credentials, logs, and application source code.'
        ),
        'remediation': (
            'Disable Directory Listing in Web Server Configuration'
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
        'words': [
            'Index of',
            'Parent Directory',
            'Last modified',
            'Size',
            'Directory Listing for',
            'Browsing directory',
            'Folder listing',
        ]
    },

    'max_scan': 10
}