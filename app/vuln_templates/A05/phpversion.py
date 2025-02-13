SCAN_TEMPLATE = {
    'info': {
        'name': 'PHP Version Disclosure',
        'type': 'A05:2021 - Security Misconfiguration',
        'severity': 'Low',
        'description': 'Detected the PHP version ({detected_value}) running on the target server.',
        'cvss_score': 4.3,
        'cvss_metrics': 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N',
        'cwe_code': 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
        'cve_code': 'N/A',
        'full_description': (
            'The web server is disclosing its PHP version via the "X-Powered-By" HTTP header. '
            'This information could help attackers determine whether the server is running a vulnerable PHP version, '
            'potentially allowing them to exploit known vulnerabilities.'
        ),
        'remediation': (
            '1. Disable the "X-Powered-By" header in PHP by setting `expose_php = Off` in php.ini.\n'
            '2. Configure the web server (Apache, Nginx, etc.) to remove or override the header.\n'
            '3. Regularly update PHP to the latest supported version to mitigate known vulnerabilities.'
        )
    },
    'entry_point': {
        'entry_point_method': 'path', 
        'paths': [
            '{domain}'
            ]
    },
    'payloads': {
        'payload_type': 'none'
    },
    'matcher': {
        'matcher_type': 'http_header',
        'type': 'regex',
        'words': ['X-Powered-By'],
        'regex': r'PHP/([\d.]+)'
    },
    'max_scan': 1
}
