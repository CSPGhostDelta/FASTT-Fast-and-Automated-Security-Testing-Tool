import re
from app.celery_worker import celery
from flask import Blueprint, jsonify, render_template, redirect, url_for
from app.database import db, Target, Vulnerability
import logging
import os
import time
import importlib
import importlib.util
import requests
from datetime import datetime
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

scanner_app = Blueprint('scanner', __name__)

logger = logging.getLogger('scanner')
logger.setLevel(logging.DEBUG)
file_handler = logging.FileHandler('scanner.log')
file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

def get_all_templates():
    templates = []
    templates_dir = "app/vuln_templates"
    for root, dirs, files in os.walk(templates_dir):
        for file in files:
            if file.endswith(".py") and file != "__init__.py": 
                templates.append(os.path.join(root, file))
    
    if not templates:
        logger.warning("No templates found in the directory.")
    
    return templates

def import_module(module_path):
    try:
        module_name = os.path.basename(module_path).replace('.py', '')
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if not hasattr(module, 'SCAN_TEMPLATE'):
            raise ValueError(f"Missing SCAN_TEMPLATE in {module_path}")
        return module
    except Exception as e:
        logger.error(f"Error importing module {module_path}: {e}")
        return None

def validate_scan_template(template_module):
    required_sections = {
        'info': ['name', 'type', 'severity', 'description'],
        'entry_point': ['entry_point_method']
    }

    if not hasattr(template_module, 'SCAN_TEMPLATE'):
        raise ValueError(f"Template {template_module} does not have a SCAN_TEMPLATE")

    template = template_module.SCAN_TEMPLATE

    if 'info' not in template:
        raise ValueError("Missing 'info' section in SCAN_TEMPLATE")
    
    info = template['info']
    for key in required_sections['info']:
        if key not in info:
            raise ValueError(f"Missing required key '{key}' in info section")

    if 'entry_point' not in template:
        raise ValueError("Missing 'entry_point' section in SCAN_TEMPLATE")
    
    entry_point = template['entry_point']
    if 'entry_point_method' not in entry_point:
        raise ValueError("Missing 'entry_point_method' in entry_point section")
    
    method = entry_point['entry_point_method']
    if method not in ['parameter', 'path']:
        raise ValueError(f"Invalid entry_point_method: {method}")

    
    if method == 'parameter' and 'paths' not in entry_point:
        raise ValueError("Missing 'paths' for parameter method")
    
    if method == 'path' and 'paths' not in entry_point:
        raise ValueError("Missing 'paths' for path method")

    if 'payloads' not in template:
        raise ValueError("Missing 'payloads' section in SCAN_TEMPLATE")
    
    payloads = template['payloads']
    if 'payload_type' not in payloads or 'payload' not in payloads:
        raise ValueError("Missing 'payload_type' or 'payload' in payloads section")
    
    if payloads['payload_type'] not in ['single', 'wordlist']:
        raise ValueError("Invalid payload_type. Must be 'single' or 'wordlist'")

    if payloads['payload_type'] == 'wordlist' and not isinstance(payloads['payload'], list):
        raise ValueError("For 'wordlist' payload_type, 'payload' must be a list")

    if payloads['payload_type'] == 'single' and not isinstance(payloads['payload'], str):
        raise ValueError("For 'single' payload_type, 'payload' must be a string")

def add_vulnerability(scan_info, endpoint, target):
    if isinstance(target, int):
        target = Target.query.get(target)
    if not target:
        raise ValueError(f"Target with ID {target} not found")

    existing_vuln = Vulnerability.query.filter(
        Vulnerability.name == scan_info['name'],
        Vulnerability.endpoint == endpoint,
        Vulnerability.scan_name == target.name
    ).first()

    if existing_vuln:
        logger.info(f"Vulnerability already exists: {endpoint}")
        return existing_vuln

    try:
        from uuid import uuid4
        unique_id = str(uuid4())

        vulnerability = Vulnerability(
            id=unique_id,
            name=scan_info['name'],
            vulnerability_type=scan_info['type'],
            details=scan_info.get('description', 'N/A'),
            severity=scan_info['severity'],
            cvss_score=scan_info.get('cvss_score', 'N/A'),
            cvss_metrics=scan_info.get('cvss_metrics', 'N/A'),
            endpoint=endpoint,
            scan_name=target.name,
            full_description=scan_info.get('full_description', 'N/A'),
            remediation=scan_info.get('remediation', 'N/A'),
            cwe_code=scan_info.get('cwe_code', 'N/A'),
            cve_code=scan_info.get('cve_code', 'N/A')
        )
        
        db.session.add(vulnerability)
        db.session.commit()
        return vulnerability

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding vulnerability: {e}")
        return None

def requests_retry_session(
    retries=3,
    backoff_factor=0.3,
    status_forcelist=(500, 502, 504)
    ):
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session = requests.Session()
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def crawl_website(domain, target_name, report_dir, depth=3, max_urls=500):
    visited = set()
    to_crawl = [(domain, 0)]
    discovered_resources = {
        'urls': set(),
        'paths': set(['/']),
        'parameters': {},
        'parameter_details': {}
    }
    
    target_crawl_dir = os.path.join(report_dir, f"{target_name}_crawl_results")
    os.makedirs(target_crawl_dir, exist_ok=True)

    urls_file = os.path.join(target_crawl_dir, "discovered_urls.txt")
    parameters_file = os.path.join(target_crawl_dir, "discovered_parameters.txt")
    parameter_details_file = os.path.join(target_crawl_dir, "parameter_details.txt")

    session = requests_retry_session()
    
    while to_crawl and len(discovered_resources['urls']) < max_urls:
        current_url, current_depth = to_crawl.pop(0)
        
        if current_url in visited or current_depth > depth:
            continue
        
        visited.add(current_url)
        
        try:
            response = session.get(current_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            discovered_resources['urls'].add(current_url)
            
            parsed_url = urlparse(current_url)
            path = parsed_url.path
            if path and path != '/':
                discovered_resources['paths'].add(path)
            
            if parsed_url.query:
                params = parsed_url.query.split('&')
                for param in params:
                    param_parts = param.split('=')
                    param_name = param_parts[0]
                    param_value = param_parts[1] if len(param_parts) > 1 else ''
                    parameter_path = f"{parsed_url.path}?{param_name}="
                    
                    if param_name not in discovered_resources['parameters']:
                        discovered_resources['parameters'][param_name] = set()
                    discovered_resources['parameters'][param_name].add(parameter_path)
                    
                    if param_name not in discovered_resources['parameter_details']:
                        discovered_resources['parameter_details'][param_name] = {
                            'sources': set(),
                            'values': set(),
                            'source_urls': []
                        }
                    
                    discovered_resources['parameter_details'][param_name]['sources'].add(current_url)
                    discovered_resources['parameter_details'][param_name]['values'].add(param_value)
                    discovered_resources['parameter_details'][param_name]['source_urls'].append(current_url)

            for link in soup.find_all('a', href=True):
                absolute_url = urljoin(current_url, link['href'])
                parsed_absolute_url = urlparse(absolute_url)
                
                if parsed_absolute_url.netloc == urlparse(domain).netloc:
                    to_crawl.append((absolute_url, current_depth + 1))
        
        except Exception as e:
            logger.error(f"Crawl error for {current_url}: {e}")
    
    # Write URLs
    with open(urls_file, 'w') as f:
        for path in sorted(discovered_resources['paths']):
            if not path.startswith('/'):
                path = f'/{path}'
            f.write(f"{path}\n")
    
    # Write Parameters
    with open(parameters_file, 'w') as f:
        for param in sorted(discovered_resources['parameters']):
            for path in sorted(discovered_resources['parameters'][param]):
                f.write(f"{path}\n")
    
    # Write Parameter Details
    with open(parameter_details_file, 'w') as f:
        for param in sorted(discovered_resources['parameter_details']):
            details = discovered_resources['parameter_details'][param]
            
            f.write(f"Parameter: {param}\n")
            f.write(f"Sources: {len(details['sources'])} URLs\n")
            
            sorted_values = sorted(details['values'], key=str)
            f.write(f"Unique Values: {set(sorted_values)}\n")
            f.write(f"Total Occurrences: {len(details['source_urls'])}\n")
            
            sorted_urls = sorted(details['source_urls'])
            
            f.write("Source URLs: \n")
            for url in sorted_urls:
                f.write(f"{url}, \n")
            f.write("\n")
    


    
    logger.info(f"Discovered {len(discovered_resources['parameters'])} unique parameters")
    
    return list(discovered_resources['urls']), {
        'urls': urls_file,
        'parameters': parameters_file,
        'parameter_details': parameter_details_file
    }

def save_crawled_urls(urls, target_name, report_dir):
    os.makedirs(report_dir, exist_ok=True)
    
    filename = f"crawled_urls_{target_name.replace(' ', '_')}.txt"
    file_path = os.path.join(report_dir, filename)

    with open(file_path, 'w') as file:
        for url in urls:
            file.write(url + '\n')
    
    logger.info(f"Crawled URLs saved to {file_path}")

def normalize_url(url):
    parsed_url = urlparse(url)
    normalized_url = parsed_url._replace(query='').geturl()
    return normalized_url

def perform_scan(domain, template_module, target, total_templates, current_template_index, scan_start_time, report_dir):
    validate_scan_template(template_module)

    scan_info = template_module.SCAN_TEMPLATE['info']
    payload_info = template_module.SCAN_TEMPLATE['payloads']
    entry_point = template_module.SCAN_TEMPLATE['entry_point']
    matcher = template_module.SCAN_TEMPLATE.get('matcher', {})
    matcher_type = matcher.get('matcher_type', '')
    matcher_words = matcher.get('words', [])
    max_scan = template_module.SCAN_TEMPLATE.get('max_scan', 5)

    payloads = []
    if payload_info['payload_type'] == 'wordlist':
        wordlist_path = os.path.join('app/vuln_templates/resources/wordlist', payload_info['payload'][0])
        if os.path.exists(wordlist_path):
            with open(wordlist_path, 'r') as f:
                payloads = [line.strip() for line in f]
    elif payload_info['payload_type'] == 'single':
        payloads = [payload_info['payload']]

    urls_file_path = os.path.join(report_dir, f"{target.name}_crawl_results", "discovered_urls.txt")
    discovered_urls = []
    if os.path.exists(urls_file_path):
        with open(urls_file_path, 'r') as f:
            discovered_urls = [line.strip() for line in f]

    if not discovered_urls:
        discovered_urls = [domain]

    method = entry_point['entry_point_method']
    session = requests_retry_session()

    paths = entry_point.get('paths', ['{domain}'])
    paths = [path.format(domain=domain) for path in paths]

    logger.info(f"Scanning {scan_info['name']} (Total payloads: {len(payloads)})")
    vulnerabilities_found = False

    def check_vulnerability(endpoint, extra_details=None, headers=None, template=None):
        try:
            response = session.get(endpoint, timeout=10, headers=headers)
            
            if response.status_code != 200:
                logger.info(f"Skipping {endpoint} due to non-200 status code: {response.status_code}")
                return False
            
            response_headers = {k: v for k, v in response.headers.items()}
            response_body = response.text
            matched_words = []
            matched_regex = []

            logger.info(f"Response Headers: {response_headers}")

            matcher = template['matcher']
            matcher_type = matcher.get('matcher_type', '')
            matcher_words = matcher.get('words', [])
            matcher_regex = matcher.get('regex', None)

            def check_matches(content, words, regex):
                matches = []
                for word in words:
                    if word.lower() in content.lower():
                        matches.append(f"Matched word: {word}")

                if regex:
                    regex_matches = re.findall(regex, content)
                    for match in regex_matches:
                        matches.append(f"Regex match: {match}")
                return matches

            if matcher_type == 'http_header':
                header_content = ' '.join(response_headers.values())
                matched_words.extend(check_matches(header_content, matcher_words, matcher_regex))
            elif matcher_type == 'http_body':
                matched_words.extend(check_matches(response_body, matcher_words, matcher_regex))

            if matched_words:
                detected_value = "unknown"
                if matcher_regex:
                    version_match = re.search(matcher_regex, header_content, re.IGNORECASE)
                    if version_match:
                        detected_value = version_match.group(1)
                
                description = template['info']['description'].format(detected_value=detected_value)

                logger.warning(f"WARNING - {description} for {endpoint}")

                vulnerability_details = scan_info.copy()
                if extra_details:
                    vulnerability_details.update(extra_details)
                
                vulnerability_details.update({
                    'matched_words': matched_words,
                    'matched_regex': matched_regex,
                    'response_status': response.status_code,
                    'response_headers': response_headers ,
                    'response_preview': response_body[:1000],
                    'description': description
                })
                
                add_vulnerability(vulnerability_details, endpoint, target)
                logger.info(f"Stopping scan for {template['info']['name']} template due to matches found")
                return True

        except requests.RequestException as e:
            logger.warning(f"Request error for {endpoint}: {e}")
        
        return False
    
    try:
        if method == 'path':
            path_method = entry_point.get('path_method', 'single')
            
            def scan_paths(paths_to_scan):
                nonlocal vulnerabilities_found
                
                template_vulnerability_count = 0
                
                for path in paths_to_scan:
                    if template_vulnerability_count >= max_scan:
                        logger.info(f"Reached maximum vulnerabilities ({max_scan}) for {scan_info['name']}")
                        break

                    base_endpoint = path.rstrip('/')
                    logger.info(f"Checking base path: {base_endpoint}")
                    
                    if not payloads:
                        if check_vulnerability(base_endpoint):
                            vulnerabilities_found = True
                            template_vulnerability_count += 1
                            continue

                    if payloads:
                        for payload in payloads:
                            if template_vulnerability_count >= max_scan:
                                break
                            
                            full_endpoint = f"{base_endpoint}/{payload}"
                            logger.info(f"Checking path with payload: {full_endpoint}")
                            
                            try:
                                response = session.get(full_endpoint, timeout=10)
                                
                                if response.status_code == 200:
                                    matched_words = [
                                        word for word in matcher_words 
                                        if word.lower() in response.text.lower()
                                    ]

                                    if matched_words:
                                        logger.warning(f"WARNING - Potential vulnerability found at {full_endpoint}")
                                        
                                        vulnerability_details = scan_info.copy()
                                        vulnerability_details.update({
                                            'matched_words': matched_words,
                                            'response_status': response.status_code,
                                            'matcher_type': matcher_type,
                                            'endpoint': full_endpoint,
                                            'payload': payload,
                                            'response_preview': response.text[:1000]
                                        })
                                        
                                        add_vulnerability(vulnerability_details, full_endpoint, target)
                                        
                                        vulnerabilities_found = True
                                        template_vulnerability_count += 1

                            except requests.RequestException as e:
                                logger.warning(f"Request error for {full_endpoint}: {e}")

                return template_vulnerability_count

            if path_method in ['single', 'multiple', 'crawled']:
                scan_paths(paths)

        elif method == 'parameter':
            parameters_file_path = os.path.join(report_dir, f"{target.name}_crawl_results", "discovered_parameters.txt")
            discovered_parameters = []
            if os.path.exists(parameters_file_path):
                with open(parameters_file_path, 'r') as f:
                    discovered_parameters = [line.strip() for line in f]

            for param_path in discovered_parameters:
                base_url = f"{domain.rstrip('/')}/{param_path.split('?')[0].lstrip('/')}"
                param_name = param_path.split('?')[-1]

                for payload in payloads:
                    injected_url = f"{base_url}?{param_name}={payload}"
                    logger.info(f"Scanning parameter: {injected_url}")

                    try:
                        response = session.get(injected_url, timeout=10)
                        
                        if response.status_code == 200:
                            matched_words = [
                                word for word in matcher_words 
                                if word.lower() in response.text.lower()
                            ]

                            if matched_words:
                                logger.warning(f"WARNING - Potential vulnerability found at {injected_url}")
                                
                                vulnerability_details = scan_info.copy()
                                vulnerability_details.update({
                                    'matched_words': matched_words,
                                    'response_status': response.status_code,
                                    'matcher_type': matcher_type,
                                    'endpoint': injected_url,
                                    'parameter': param_name,
                                    'payload': payload,
                                    'response_preview': response.text[:1000]
                                })
                                
                                add_vulnerability(vulnerability_details, injected_url, target)
                                
                                vulnerabilities_found = True
                                break 

                    except requests.RequestException as e:
                        logger.warning(f"Request error for {injected_url}: {e}")

    except Exception as e:
        logger.error(f"Error during scanning template {scan_info['name']}: {e}")
        vulnerabilities_found = False

    if vulnerabilities_found:
        logger.info(f"Vulnerabilities found in template: {scan_info['name']}")
    else:
        logger.info(f"No vulnerabilities found for template: {scan_info['name']}")

    elapsed_time = time.time() - scan_start_time
    logger.info(f"Scanning completed for {scan_info['name']}! Time elapsed: {elapsed_time:.2f} seconds")

    return vulnerabilities_found
        
@celery.task(name='perform_scan')
def perform_scan_task(target_id):
    from app.init import create_app
    app = create_app()
    with app.app_context():
        try:
            target = Target.query.get_or_404(target_id)
            scan_name = f"reports_for_{target.name}"
            report_dir = os.path.join('app/reports', scan_name)
            os.makedirs(report_dir, exist_ok=True)
            
            log_filename = f"log_for_{target.name}.log"
            scan_log_path = os.path.join(report_dir, log_filename)
            scan_logger = logging.getLogger(scan_name)
            scan_logger.setLevel(logging.DEBUG)

            file_handler = logging.FileHandler(scan_log_path)
            file_handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            file_handler.setFormatter(formatter)
            
            scan_logger.handlers.clear()
            scan_logger.addHandler(file_handler)
            
            global logger
            original_logger = logger
            logger = scan_logger

            scan_start_time = time.time()
            start_datetime = datetime.fromtimestamp(scan_start_time)

            logger.info(f"-- Running vulnerability Scan for {target.name} on {start_datetime.strftime('%Y-%m-%d')} at {start_datetime.strftime('%H:%M:%S')}")

            target.status = "Scanning"
            target.scan_progress = 0 
            db.session.commit()

            logger.info(f"Starting crawl for target: {target.name}")
            logger.info("Crawling Websites")
            discovered_urls, crawl_files = crawl_website(target.domain, target.name, report_dir)
            
            target.scan_progress = 30
            db.session.commit()
            
            logger.info(f"Crawl results saved in {crawl_files['urls']}")
            logger.info("Crawling completed.")
            templates = get_all_templates()
            if not templates:
                target.status = "Scan Error"
                db.session.commit()
                logger.warning("No templates to execute. Exiting scan.")
                return

            logger.info("Checking templates")
            logger.info(f"{len(templates)} templates found")

            total_templates = len(templates)
            vulnerability_count = 0

            for i, template_path in enumerate(templates, start=1):
                try:
                    progress_increment = 70 / total_templates
                    current_progress = 30 + (i * progress_increment)
                    
                    target.scan_progress = current_progress
                    db.session.commit()

                    template_module = import_module(template_path)
                    if not template_module:
                        logger.warning(f"Skipping template {template_path}")
                        continue

                    vulnerability_found = perform_scan(
                        target.domain, 
                        template_module, 
                        target, 
                        total_templates, 
                        i, 
                        scan_start_time, 
                        report_dir
                    )
                    
                    if vulnerability_found:
                        vulnerability_count += 1
                        logger.info(f"Vulnerability found in template {template_path}")

                except Exception as template_error:
                    logger.error(f"Error during scan with template {template_path}: {template_error}")
                    continue
                
            scan_end_time = time.time()
            end_datetime = datetime.fromtimestamp(scan_end_time)

            target.scan_progress = 100
            target.status = "Completed"
            db.session.commit()

            logger.info(f"Scan Completed! Scan started at {start_datetime.strftime('%H:%M:%S')} and ends at {end_datetime.strftime('%H:%M:%S')}")
            
            scan_report(report_dir, target, scan_name, scan_start_time)
            
        except Exception as e:
            logger.error(f"Scan task failed for target {target_id}: {e}")
            target.status = "Scan Error"
            target.scan_progress = 0
            db.session.commit()
        finally:
            logger = original_logger
            
def scan_report(report_dir, target, scan_name, scan_start_time):
    summary_filename = f"{target.name}_scan_summary.txt"
    summary_path = os.path.join(report_dir, summary_filename)
    vulnerabilities = Vulnerability.query.filter_by(scan_name=target.name).all()
    
    with open(summary_path, 'w') as summary_file:
        summary_file.write(f"Scan Summary for {target.name}\n")
        summary_file.write("=" * 50 + "\n")
        summary_file.write(f"Target Domain: {target.domain}\n")
        summary_file.write(f"Scan Start Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(scan_start_time))}\n")
        summary_file.write(f"Scan End Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))}\n")
        summary_file.write(f"Total Vulnerabilities Found: {len(vulnerabilities)}\n\n")
        
        summary_file.write("Vulnerability Details:\n")
        for vuln in vulnerabilities:
            summary_file.write(f"- {vuln.name} (Severity: {vuln.severity})\n")
            summary_file.write(f"  Endpoint: {vuln.endpoint}\n")
            summary_file.write(f"  Description: {vuln.details}\n\n")

@scanner_app.route('/start_scan/<int:target_id>', methods=['POST'])
def start_scan(target_id):
    perform_scan_task.delay(target_id)
    return redirect(url_for('targets.target', target_id=target_id))

@scanner_app.route('/scan_status/<int:target_id>', methods=['GET'])
def scan_status(target_id):
    target = Target.query.get_or_404(target_id)
    return jsonify({
        'status': target.status,
        'progress': target.scan_progress,
    })

@scanner_app.route('/results/<int:target_id>', methods=['GET'])
def view_results(target_id):
    target = Target.query.get_or_404(target_id)
    vulnerabilities = Vulnerability.query.filter_by(scan_name=target.name).all()
    return render_template('results.html', target=target, vulnerabilities=vulnerabilities)

def severity_color(severity, mode='border'):
    severity = severity.lower() if severity else ''
    color_map = {
        'critical': {
            'border': '#dc3545',
            'background': 'rgba(220, 53, 69, 0.1)',
            'text': '#dc3545'
        },
        'high': {
            'border': '#fd7e14',
            'background': 'rgba(253, 126, 20, 0.1)',
            'text': '#fd7e14'
        },
        'medium': {
            'border': '#ffc107',
            'background': 'rgba(255, 193, 7, 0.1)',
            'text': '#ffc107'
        },
        'low': {
            'border': '#28a745',
            'background': 'rgba(40, 167, 69, 0.1)',
            'text': '#28a745'
        },
        'info': {
            'border': '#17a2b8',
            'background': 'rgba(23, 162, 184, 0.1)',
            'text': '#17a2b8'
        }
    }
    
    default = {
        'border': '#6c757d',
        'background': 'rgba(108, 117, 125, 0.1)',
        'text': '#6c757d'
    }
    
    selected_color = color_map.get(severity, default)
    return selected_color.get(mode, selected_color['border'])

@scanner_app.route('/vulnerability_details/<string:vuln_id>')
def vulnerability_details(vuln_id):
    vulnerability = Vulnerability.query.get_or_404(vuln_id)
    return render_template(
        'details.html', 
        vulnerability=vulnerability, 
        severity_color=severity_color
    )