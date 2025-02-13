SCAN_TEMPLATE = {
    'info': {
        'name': 'Cross-Site Scripting (XSS)',
        'type': 'A03:2021 - Injection',
        'severity': 'High',
        'description': (
            'Cross-Site Scripting (XSS) vulnerabilities occur when an application includes untrusted user input in the web page content '
            'without proper validation or escaping. This allows attackers to inject malicious scripts into web pages viewed by other users.'
        ),
        'cvss_score': 7.4,
        'cvss_metrics': 'CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:R/VC:H/VI:M/VA:L',
        'cwe_code': 'CWE-79: Improper Neutralization of Input During Web Page Generation ("Cross-site Scripting")',
        'cve_code': 'N/A',
        'full_description': (
            'Cross-Site Scripting (XSS) vulnerabilities arise when an application fails to properly sanitize or escape user-supplied input, '
            'allowing malicious scripts to be injected into web pages viewed by other users. These scripts can execute in the context of a victim\'s browser, '
            'leading to a variety of potential attacks, such as session hijacking, defacement of the website, redirection to malicious sites, or the '
            'execution of arbitrary commands. XSS attacks can also be used to steal cookies, perform phishing attacks, or escalate into more severe vulnerabilities.'
        ),
        'remediation': (
            '1. **Input Validation**: Ensure all user input is validated against strict allowlists.\n'
            '2. **Output Encoding**: Encode user input before rendering it in the browser (e.g., HTML encoding).\n'
            '3. **Use Security Headers**: Implement Content Security Policy (CSP) to prevent inline script execution.\n'
            '4. **Sanitize Inputs**: Use secure libraries like DOMPurify to sanitize HTML content.\n'
            '5. **Avoid Inline JavaScript**: Use external scripts and disable inline script execution where possible.\n'
            '6. **Use HttpOnly and Secure Cookies**: Prevent JavaScript from accessing sensitive cookies.\n'
            '7. **Regularly Update and Patch**: Keep web frameworks and libraries up to date to mitigate known XSS vulnerabilities.'
        ),
    },
    'entry_point': {
        'entry_point_method': 'parameter',
        'paths': ['{domain}']
    },
    'payloads': {
        'payload_type': 'wordlist',
        'payload': ['xss.txt']
    },
    'matcher': {
        'matcher_type': 'http_body',
        'type': 'string',
        'words': [
            '<script>', 
            'alert(', 
            'document.cookie', 
            'onerror='
        ]
    },
    'max_scan': 1
}
