SCAN_TEMPLATE = {
    'info': {
        'name': 'Directory Listing Enabled',
        'type': 'A01:2021 - Broken Access Control',
        'severity': 'Medium',
        'description': (
            'The target web server has Directory Listing enabled, allowing unauthorized users to browse and access files within directories. '
            'This security misconfiguration can expose sensitive files, including configuration files, logs, backups, and source code, '
            'leading to information disclosure and increasing the risk of exploitation.'
        ),
        'cvss_score': 7.5,
        'cvss_metrics': 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N',
        'cwe_code': 'CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory',
        'cve_code': 'N/A',
        'full_description': (
            'Directory Listing occurs when a web server does not have proper access controls in place and lacks an index file (e.g., `index.html` or `index.php`) in a directory. '
            'This allows attackers to list and access files within publicly accessible directories. '
            'Exposed directories may contain sensitive information, such as database dumps, configuration files, application logs, or even source code, '
            'which could be leveraged for further attacks, such as credential theft or application exploitation.'
        ),
        'remediation': (
            '1. **Disable Directory Listing:** Modify the web server configuration to prevent directory indexing.\n'
            '   - **Apache:** Set `Options -Indexes` in `.htaccess` or `httpd.conf`.\n'
            '   - **Nginx:** Use `autoindex off;` in the server block configuration.\n'
            '   - **IIS:** Disable `Directory Browsing` via IIS Manager or `web.config`.\n'
            '2. **Restrict Access to Sensitive Files:** Ensure proper file permissions and access controls are in place.\n'
            '3. **Implement Access Controls:** Restrict directory access using authentication mechanisms if needed.\n'
            '4. **Use an Index File:** Place an `index.html` or `index.php` file in directories to prevent default listing.\n'
            '5. **Regular Security Audits:** Periodically scan for exposed directories and sensitive files.'
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
        'type': 'string',
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
