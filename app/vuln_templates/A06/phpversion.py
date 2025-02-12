SCAN_TEMPLATE = {
    'info': {
        'name': 'PHP Version Detection',
        'type': 'Information Disclosure',
        'severity': 'Informational',
        'description': 'Detected the PHP version ({detected_value}) running on the target server.',
        'cvss_score': 'N/A',
        'cvss_metrics': 'N/A',
        'cwe_code': 'CWE-200',
        'cve_code': 'N/A',
        'full_description': 'Detected the PHP version ({detected_value}) running on the target server.',
        'remediation': 'N/A'
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
        'words': [
            'X-Powered-By'
            ], 
        'regex': r'PHP/([\d.]+)'  
    },
    'max_scan': 1 
}