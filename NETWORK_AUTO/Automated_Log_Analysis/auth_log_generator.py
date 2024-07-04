import random
from datetime import datetime, timedelta

# Sample Log: Nov 17 12:59:28 server sshd[3165]: Failed password for invalid user john from 175.98.178.11 port 5919 ssh2


def generate_auth_log(num_entries, output_file):
    months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
              'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    usernames = ['admin', 'root', 'user', 'guest', 'john', 'alice', 'bob']
    status = ['Failed', 'Accepted']

    with open(output_file, 'w') as f:
        start_time = datetime.now()
        for _ in range(num_entries):
            month = random.choice(months)
            day = random.randint(1, 28)
            time = start_time.strftime("%H:%M:%S")
            server = "server"
            pid = random.randint(1000, 9999)
            auth_status = random.choice(status)
            user = random.choice(usernames)
            src_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            port = random.randint(1024, 65535)

            log_entry = f"{month} {day} {time} {server} sshd[{pid}]: {auth_status} password for {'invalid user ' if auth_status == 'Failed' else ''}{user} from {src_ip} port {port} ssh2\n"
            f.write(log_entry)

            start_time += timedelta(seconds=random.randint(1, 60))


generate_auth_log(200, '12.3.1-auth_log.txt')
