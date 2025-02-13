SCAN_TEMPLATE = {
    'info': {
        'name': 'SQL Injection',
        'type': 'A03:2021 - Injection',
        'severity': 'Critical',
        'description': (
            'SQL Injection occurs when an attacker manipulates an application’s SQL queries through unsanitized user input. '
            'This allows attackers to gain unauthorized access to sensitive data, modify database contents, '
            'perform administrative operations on the database, or even execute arbitrary commands on the server.'
        ),
        'cvss_score': '9.8',
        'cvss_metrics': 'CVSS:4.0/AV:N/AC:L/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
        'cwe_code': 'CWE-89: Improper Neutralization of Special Elements used in an SQL Command (''SQL Injection'')',
        'cve_code': '',
        'full_description': (
            'SQL Injection (SQLi) is a vulnerability that allows attackers to manipulate SQL queries in an unsafe application, '
            'usually by injecting malicious SQL code into input fields (e.g., search boxes, login forms, etc.).'
        ),
        'remediation': (
            'Use Prepared Statements with Parameterized Queries. Always validate, sanitize, and escape user inputs. '
            'For added security, use Web Application Firewalls (WAFs) and implement database permissions to limit data access.'
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
        'payload': ['sqlinjection.txt']
    },
    'matcher': {
        'matcher_type': 'http_body',
        'words': [
            'SQL syntax error',
            'MySQL',
            'ORA-',
            'Warning: mysql_',
            'Microsoft OLE DB Provider for SQL Server',
            'ODBC SQL Server Driver',
            'SQLServer',
            'Unclosed quotation mark',
            'PostgreSQL',
            'SQLite',
            'syntax near',
            'unexpected end of SQL command',
            'You have an error in your SQL syntax',
            'MySQL query error',
            'Division by zero',
            'Internal Server Error',
            'supplied argument is not a valid MySQL result resource',
            'subquery returns more than 1 row',
            'unterminated quoted string at or near'
        ]
    },
     'max_scan': 1
}
