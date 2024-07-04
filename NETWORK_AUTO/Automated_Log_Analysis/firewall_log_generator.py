from datetime import datetime, timedelta
import random

# Sample format: "2023-07-04 15:30:45 | ALLOW | src=192.168.1.5 | dst=10.0.0.1 | proto=TCP | sport=54321 | dport=80"

start_time = datetime.now()
actions = ["ALLOW", "DENY"]
protocols = ["TCP", "UDP", "ICMP"]


with open('12.1.1-firewall_log.txt', 'w') as firewall_log:
    for i in range(100):
        timestamp = (start_time + timedelta(seconds=i, minutes=i)
                     ).strftime('%Y-%m-%d %H:%M:%S')
        action = random.choice(actions)
        src_ip = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
        dst_ip = f"10.0.0.{random.randint(1,254)}"
        proto = random.choice(protocols)
        sport = random.randint(1024, 65535)
        dport = random.choice([80, 443, 22, 3389, 8080])
        log_entry = f"{timestamp} | {action} | src={src_ip} | dst={dst_ip} | proto={proto} | sport={sport} | dport={dport}\n"
        firewall_log.write(log_entry)
