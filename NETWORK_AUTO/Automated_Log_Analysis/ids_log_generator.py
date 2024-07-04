import random
from datetime import datetime, timedelta

# Sample Log: 2024-07-04 13:15:14 [ALERT] Suspected brute force attack from 164.22.81.83

def generate_ids_log(num_entries, output_file):
    alert_types = [
        "Potential SQL injection attempt",
        "Possible XSS attack detected",
        "Unusual port scan activity",
        "Suspected brute force attack",
        "Potential DDoS attack identified"
    ]

    with open(output_file, 'w') as f:
        start_time = datetime.now()
        for _ in range(num_entries):
            timestamp = start_time.strftime("%Y-%m-%d %H:%M:%S")
            alert = random.choice(alert_types)
            src_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

            log_entry = f"{timestamp} [ALERT] {alert} from {src_ip}\n"
            f.write(log_entry)

            start_time += timedelta(seconds=random.randint(30, 300))


generate_ids_log(100, '12.2.1-ids.txt')
