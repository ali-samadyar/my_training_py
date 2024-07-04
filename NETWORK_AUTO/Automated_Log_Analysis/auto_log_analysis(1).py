from datetime import datetime
import os


def parse_firewall_log(line):
    parts = line.strip().split(' | ')

    log_entry = {
        'type': 'firewall',
        'timestamp': datetime.strptime(parts[0], "%Y-%m-%d %H:%M:%S"),
        'action': parts[1],
        'src_ip': parts[2].split('=')[1],
        'dst_ip': parts[3].split('=')[1],
        'proto': parts[4].split('=')[1],
        'sport': int(parts[5].split('=')[1]),
        'dport': int(parts[6].split('=')[1])
    }
    return log_entry


def ids_log_analysis(line):
    date, time, *rest = line.split(' ', 2)
    timestamp = f'{date} {time}'
    message = line.split('[ALERT]')[1].split('from')[0].strip()
    source_ip = line.split('[ALERT]')[1].split('from')[1].strip()
    log_entry = {
        'type': 'ids',
        'timestamp': timestamp,
        'mesaage': message,
        'source_ip': source_ip

    }
    return log_entry


def auth_log_analysis(line, year=None):
    month, day, time, *rest = line.split()
    if year is None:
        year = datetime.now().year

    timestamp_str = f'{year} {month} {day} {time}'
    timestamp = datetime.strptime(timestamp_str, '%Y %b %d %H:%M:%S')

    status = line.split(': ')[1].split()[0]
    src_ip = line.split('from')[1].split()[0]
    username = line.split('from')[0].split()[-1]

    log_entry = {
        'type': 'auth',
        'timestamp': timestamp,
        'status': status,
        'user': username,
        'src_ip': src_ip,
        'port': 22
    }
    return log_entry


def identify_incidents(parsed_log):
    incidents = []
    for log in parsed_log:
        if log['type'] == 'firewall' and log['action'] == 'DENY':
            incidents.append({
                'type': 'Firewall Deny',
                'timestamp': log['timestamp'],
                'details': f"Connection denied from {log['src_ip']} to {log['dst_ip']}",
                'priority': 'low'
            })
        elif log['type'] == 'ids':
            incidents.append({
                'type': 'IDS Alert',
                'timestamp': log['timestamp'],
                'details': f"{log['mesaage']} from {log['source_ip']}",
                'priority': 'high'
            })
        elif log['type'] == 'auth' and log['status'] == 'Failed':
            incidents.append({
                'type': 'Failed Login',
                'timestamp': log['timestamp'],
                'details': f"Failed login attempt for user {log['user']} from {log['src_ip']}",
                'priority': 'medium'
            })

    generate_report(incidents)
    return incidents


def generate_report(incidents):
    report = []
    path = '***********ADD_PATH***********'
    file_name = f"Security-Daily-Report[{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}].txt"
    with open(os.path.join(path, file_name), 'w') as report_file:
        report = "Daily Security Incident Report\n"
        report += "==============================\n\n"
        for incident in incidents:
            report += f"Type: {incident['type']}\n"
            report += f"Time: {incident['timestamp']}\n"
            report += f"Details: {incident['details']}\n"
            report += f"Priority: {incident['priority']}\n\n"
        report_file.write(report)
    return report


def main():
    firewall_log_path = '***********ADD_PATH***********'
    ids_log_path = '***********ADD_PATH***********'
    auth_log_path = '***********ADD_PATH***********'
    parsed_logs = []
    with open(firewall_log_path, 'r') as firewall_log, open(ids_log_path, 'r') as ids_log, open(auth_log_path, 'r') as auth_log:
        for line in firewall_log:
            parsed_entry = parse_firewall_log(line)
            if parsed_entry:
                parsed_logs.append(parsed_entry)
        for line in ids_log:
            parsed_entry = ids_log_analysis(line)
            if parsed_entry:
                parsed_logs.append(parsed_entry)
        for line in auth_log:
            parsed_entry = auth_log_analysis(line)
            if parsed_entry:
                parsed_logs.append(parsed_entry)
    identify_incidents(parsed_logs)


if __name__ == "__main__":
    main()
