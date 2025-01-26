import os
import re
from datetime import datetime
from flask import Blueprint, render_template, session, redirect, url_for
from app.database import User, Target

history_app = Blueprint("history", __name__, template_folder="../templates", static_folder="../static")

@history_app.route('/homedashboard/history/')
def history():
    if "username" not in session:
        return redirect(url_for("app.login"))

    current_user = User.query.filter_by(username=session['username']).first()
    if not current_user:
        return redirect(url_for("app.login"))

    user_targets = Target.query.filter_by(user_id=current_user.id).all()

    scan_histories = []

    for target in user_targets:
        report_dir = f'reports_for_{target.name}'
        full_report_path = os.path.join('app/reports', report_dir)

        # Check if report directory exists
        if not os.path.exists(full_report_path):
            continue

        summary_files = [
            f for f in os.listdir(full_report_path) 
            if f.endswith('_scan_summary.txt')
        ]
        
        if not summary_files:
            continue

        summary_file = os.path.join(full_report_path, summary_files[0])
        
        try:
            with open(summary_file, 'r') as f:
                content = f.read()
                
                domain = re.search(r'Target Domain: (.*)', content)
                domain = domain.group(1).strip() if domain else target.domain
                
                start_match = re.search(r'Scan Start Time: (.*)', content)
                end_match = re.search(r'Scan End Time: (.*)', content)
                
                if not (start_match and end_match):
                    continue
                
                start_time = datetime.strptime(start_match.group(1).strip(), "%Y-%m-%d %H:%M:%S")
                end_time = datetime.strptime(end_match.group(1).strip(), "%Y-%m-%d %H:%M:%S")
                
                scan_start = start_time.strftime("%d %B, %Y - %H:%M:%S %p")
                scan_end = end_time.strftime("%d %B, %Y - %H:%M:%S %p")
                target_date = start_time.strftime("%d %B, %Y")
                
                time_diff = end_time - start_time
                total_seconds = int(time_diff.total_seconds())
                scan_time_elapsed = f"{total_seconds} seconds ({time_diff})"
                
                scan_histories.append({
                    'name': target.name,
                    'domain': domain,
                    'target_date': target_date,
                    'scan_start': scan_start,
                    'scan_end': scan_end,
                    'scan_time_elapsed': scan_time_elapsed,
                    'status': target.status
                })
        
        except Exception as e:
            print(f"Error processing {summary_file}: {e}")
    
    scan_histories.sort(key=lambda x: datetime.strptime(x['scan_start'], "%d %B, %Y - %H:%M:%S %p"), reverse=True)
    
    return render_template('history.html', targets=scan_histories)