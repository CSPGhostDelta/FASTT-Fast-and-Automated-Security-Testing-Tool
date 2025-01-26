SCAN_TEMPLATE = {
    'info': {
        'name': 'Cross-Site Scripting (XSS)',
        'type': 'A03 - Injection',
        'severity': 'High',
        'description': (
            'Cross-Site Scripting (XSS) vulnerabilities occur when an application includes untrusted user input in the web page content '
            'without proper validation or escaping. This allows attackers to inject malicious scripts into web pages viewed by other users.'
        ),
        'cvss_score': '7.4',
        'cvss_metrics': 'CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:R/VC:H/VI:M/VA:L',
        'cwe_code': 'CWE-79: Improper Neutralization of Input During Web Page Generation ("Cross-site Scripting")',
        'cve_code': '',
        'full_description': (
            'Cross-Site Scripting (XSS) vulnerabilities arise when an application fails to properly sanitize or escape user-supplied input, '
            'allowing malicious scripts to be injected into web pages viewed by other users. These scripts can execute in the context of a victim\'s browser, '
            'leading to a variety of potential attacks, such as session hijacking, defacement of the website, redirection to malicious sites, or the '
            'execution of arbitrary commands. XSS attacks can also be used to steal cookies, perform phishing attacks, or escalate into more severe vulnerabilities.'
        ),
        'remediation': (
            'Sanitize User Input. Ensure all user input is sanitized and encoded to prevent the injection of scripts into the web page.'
        ),
    },
    'entry_point': {
        'entry_point_method': 'parameter',
        'paths': [
            '{domain}',
        ],
    },
    'payloads': {
        'payload_type': 'wordlist',
        'payload': ['xss.txt'] 
    },

    'matcher': {
    'words': [
        '<script>', 
        'alert(', 
        'document.cookie', 
        'onerror='
        ]
    },

    'max_scan': 1
}
