SCAN_TEMPLATE = {
    'info': {
        'name': 'PHP Info Disclosure',
        'type': 'A05:2021 - Security Misconfiguration',
        'severity': 'Medium',
        'description': 'Exposure of PHP configuration details via publicly accessible phpinfo() page.',
        'cvss_score': 5.4,
        'cvss_metrics': 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N',
        'cwe_code': 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
        'cve_code': 'N/A',
        'full_description': (
            'The phpinfo() function displays detailed PHP configuration, including loaded modules, environment '
            'variables, file paths, and system details. If exposed publicly, attackers can gather intelligence '
            'to exploit vulnerable extensions, find sensitive file locations, or plan targeted attacks.'
        ),
        'remediation': (
            '1. Remove publicly accessible phpinfo.php files from production servers.\n'
            '2. Disable phpinfo() in php.ini: `disable_functions = phpinfo`.\n'
            '3. Restrict access using authentication or IP whitelisting.\n'
            '4. Regularly scan for and remove debugging tools from live environments.'
        )
    },
    'entry_point': {
        'entry_point_method': 'path',
        'path_method': 'deep',
        'paths': ['{domain}']
    },
    'payloads': {
        'payload_type': 'wordlist',
        'payload': ['phpaths.txt']
    },
    'matcher': {
        'matcher_type': 'http_body',
        'type': 'string',
        'words': [
            'PHP Version',
            'PHP Credits',
            'PHP License'
        ]
    },
    'max_scan': 1
}
