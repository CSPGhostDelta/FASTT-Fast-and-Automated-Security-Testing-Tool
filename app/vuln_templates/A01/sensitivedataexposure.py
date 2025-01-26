SCAN_TEMPLATE = {
    'info': {
        'name': 'Sensitive Data Exposure',
        'type': 'A01 - Broken Access Control',
        'severity': 'Critical',
        'description': (
            'Sensitive data exposure occurs when an application improperly stores or transmits sensitive information, making it accessible to attackers. '
            'This can lead to data breaches, credential theft, and unauthorized access to private information.'
        ),
        'cvss_score': '9.1',
        'cvss_metrics': 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
        'cwe_code': 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
        'cve_code': '',
        'full_description': (
            'Sensitive data exposure occurs when confidential information such as passwords, financial records, API keys, '
            'or database dumps are stored or transmitted without proper encryption or access controls. '
            'Attackers can exploit exposed data to perform account takeovers, fraud, and further system compromises. '
            'Common causes include misconfigured servers, exposed backups, plaintext storage, and weak cryptographic implementations.'
        ),
        'remediation': (
            'Restrict access to sensitive files and databases using proper authentication and authorization.\n'

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
            '.7z', '.7zip', '.action', '.backup', '.bat', '.bmp', '.box', '.bz', '.bz2', '.c', '.cfg', '.cfm', '.class', '.conf', '.config', '.csproj', '.dat',
            '.data', '.db', '.deb', '.default', '.desktop', '.dist', '.dll', '.do', '.doc', '.docb', '.docm', '.docx', '.dot', '.dotm', '.dotx', '.dsa', '.example',
            '.exe', '.fcgi', '.gem', '.go', '.gpg', '.gzip', '.HTM', '.htm', '.java', '.jhtml', '.jks', '.jpeg', '.jsa', '.jsx', '.kbx', '.kdb', '.kdbx',
            '.keystore', '.lnk', '.log', '.lst', '.lua', '.mdb', '.nsf', '.numbers', '.odf', '.odp', '.ods', '.odt', '.old', '.one', '.ori', '.orig', '.ost',
            '.ovpn', '.page', '.pages', '.password', '.pcap', '.pem', '.phar', '.php2', '.php3', '.php4', '.php5', '.php6', '.php7', '.phps', '.pht', '.phtml',
            '.ph_', '.pl', '.pot', '.potm', '.potx', '.pps', '.ppsm', '.ppsx', '.ppt', '.pptm', '.pptx', '.prn', '.properties', '.pst', '.pub', '.pwd', '.py.bak',
            '.pyc', '.rbc', '.reg', '.rpm', '.rsa', '.rtf', '.sav', '.save', '.sh', '.shtml', '.sldm', '.sldx', '.source', '.sqlite3', '.src', '.swp', '.tif',
            '.tiff', '.vm', '.vpn', '.wbk', '.xla', '.xlam', '.xlm', '.xls', '.xlsb', '.xlsm', '.xlsx', '.xlt', '.xltm', '.xltx', '.xps', '.yaml', '.yml',
            '.ashx', '.asmx', '.asp', '.aspx', '.axd', '.bak', '.cgi', '.css', '.csv', '.gz', '.html', '.inc', '.inc.php', '.ini', '.jar', '.js', '.json',
            '.jsp', '.md', '.min.js', '.pdf', '.php', '.php.bak', '.png', '.py', '.rar', '.rb', '.sql', '.sqlite', '.swf', '.tar', '.tar.gz', '.tgz', '.tmp',
            '.txt', '.war', '.xml', '.zip', '_inc.php'
        ]
    },
    
    'max_scan': 10
}
