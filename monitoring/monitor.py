"""
    Query System to retrieve info about resource usage and who is using the resource (only GPUs)

    ```
[
  {
    "day": 1,
    "month": 5,
    "year": 2019,
    "hour": 14,
    "minute": 19,
    "sec": 30,
    "hostname": "power92.server.mila.quebec",
    "gpus": [
      {
        "timestamp": "2019/05/01 14:19:30.662",
        "pid": "104523",
        "process_name": "python",
        "gpu_name": "Tesla V100-SXM2-16GB",
        "used_gpu_memory [MiB]": "663",
        "gpu_bus_id": "00000004:04:00.0",
        "gpu_uuid": "GPU-016b348f-3447-d57f-672a-9144fd65ae30",
        "gpu_serial": "0324117166425",
        "memory_used [MiB]": "673",
        "utilization_memory [%]": "0",
        "utilization_gpu [%]": "0",
        "memory_total [MiB]": "16130"
      },
      {
        "timestamp": "2019/05/01 14:19:30.663",
        "pid": "104523",
        "process_name": "python",
        "gpu_name": "Tesla V100-SXM2-16GB",
        "used_gpu_memory [MiB]": "663",
        "gpu_bus_id": "00000004:05:00.0",
        "gpu_uuid": "GPU-6d5d201f-d34e-70e2-0a6b-e16c7aea6a30",
        "gpu_serial": "0324317007486",
        "memory_used [MiB]": "673",
        "utilization_memory [%]": "0",
        "utilization_gpu [%]": "0",
        "memory_total [MiB]": "16130"
      }
    ],
    "PID": "104523",
    "USER": "delaunap",
    "%CPU": "0.0",
    "%MEM": "0.4",
    "C": "0",
    "ELAPSED": "02:38:21",
    "PPID": "104473",
    "RSS": "2455360",
    "TIME": "00:00:05",
    "VSZ": "23516352",
    "COMMAND": "python"
  }

]
    ```
"""

import subprocess
import json
import copy
import socket
import datetime


def parse_csv_to_dict(data, sep=','):
    data = data.split('\n')
    data = [list(filter(lambda x: len(x.strip()) > 0, line.split(sep))) for line in data]

    header = data[0]
    data = data[1:]

    result = []

    for row in data:
        entry = {}
        for name, value in zip(header, row):
            value = value.strip()
            if value:
                entry[name.strip()] = value

        if entry:
            result.append(entry)

    return result


def make_gpu_db(data):
    result = {}
    for gpu_status in data:
        result[gpu_status['uuid']] = gpu_status
    return result


def get_process_info(pid):
    cmd = f'ps -o "pid,user,%cpu,%mem,c,etime,ppid,rss,time,vsz,comm" -p {pid}'
    print(cmd)
    return subprocess.check_output(cmd, shell=True).decode('utf-8')


notuser_users = {
    'systemd+',
    'message+',
    'syslog',
    'daemon',
    'munge',
    'www-data',
    'statd'
}


def cmd_get_all_process_pid():
    cmd = f'ps -eo "user,pid,comm" | grep -v root'
    print(cmd)
    return subprocess.check_output(cmd, shell=True).decode('utf-8')


status_query = \
    'timestamp,utilization.gpu,utilization.memory,count,memory.total,memory.used,gpu_serial,gpu_uuid,gpu_bus_id'


def cmd_get_gpu_info():
    cmd = f'nvidia-smi --query-gpu={status_query} --format=csv,nounits -u'
    print(cmd)
    return subprocess.check_output(cmd, shell=True).decode('utf-8')


pid_query = 'timestamp,pid,name,gpu_name,used_memory,gpu_bus_id,gpu_uuid,gpu_serial'


def cmd_get_gpu_pid():
    cmd = f'nvidia-smi --query-compute-apps={pid_query} --format=csv,nounits -u'
    print(cmd)
    return subprocess.check_output(cmd, shell=True).decode('utf-8')


def parse_cpuset(data):
    data = data.strip()
    gpu_sets = data.split(',')
    cpu_count = 0

    for gpu_set in gpu_sets:
        try:
            b, u = gpu_set.split('-')
            cpu_count += int(u) - int(b) + 1
        except Exception as e:
            cpu_count += 1

    return {'total_requested': cpu_count, 'cpu_set': data}


def parse_cpuacct(data):
    data = data.strip()
    cpu_usage_per_core = {}
    for cpu_id, cpu_usage in enumerate(data.split(' ')):
        if cpu_usage != '0':
            cpu_usage_per_core[str(cpu_id)] = cpu_usage
    return cpu_usage_per_core


def parse_devices(data):
    return data.strip()


def parse_memory_used(data):
    return data.strip()


def parse_memory_limit(data):
    return data.strip()


cgroup_regex = r'\/slurm.*'
cgroup_constraint_set = {'cpuset', 'cpu,cpuacct', 'devices', 'memory'}
cgroup_constraint = [
    ('cpuset'       , 'cpuset.effective_cpus', parse_cpuset),
    ('cpu,cpuacct'  , 'cpuacct.usage_percpu', parse_cpuacct),
    ('devices'      , 'devices.allow', parse_devices),
    ('memory'       , 'memory.usage_in_bytes', parse_memory_used),
    ('memory'       , 'memory.limit_in_bytes', parse_memory_limit)
]


def get_slurm_cg(cgroup_file):
    for row in cgroup_file:
        data = row.split(':')
        if data[2].startswith('/slurm'):
            return list(filter(lambda x: len(x.strip()) > 0, data[2].split('/')))


def get_cgroup_config(pid):
    """
    12  :cpuset         :/slurm_power92/uid_1500000082/job_68543/step_0
    5   :devices        :/slurm_power92/uid_1500000082/job_68543/step_0
    4   :cpu,cpuacct    :/slurm_power92/uid_1500000082/job_68543/step_0/task_0
    3   :memory         :/slurm_power92/uid_1500000082/job_68543/step_0/task_0
    """

    cgroup_file = open(f'/proc/{pid}/cgroup', 'r').read().split('/n')
    slurm_cg_all = get_slurm_cg(cgroup_file)

    slurm_cg = '/'.join(slurm_cg_all[0:3])

    cgroup_config = {}

    for cname, cfile, parser in cgroup_constraint:
        cgroup_data = f'/sys/fs/cgroup/{cname}/{slurm_cg}/{cfile}'

        try:
            with open(cgroup_data, 'r') as file:
                data = file.read()
                cgroup_config[cfile] = parser(data)

        except Exception as e:
            cgroup_config[cfile] = str(e)

    return cgroup_config


def insert_cgroup_config(pid, process_report):
    try:
        cgroup_config = get_cgroup_config(pid)

        for k, v in cgroup_config.items():
            nk = k.replace('.', '_')
            if nk in process_report:
                print('OVERRIDING DATA')

            process_report[nk] = v
    except FileNotFoundError as e:
        process_report['cgroup_error'] = e.filename


def filter_pids(all_pids):
    filtered = []

    for pid in all_pids:
        if pid['USER'] not in notuser_users:
            filtered.append(pid)

    return filtered


def make_report():
    # Get GPU overall usage
    raw_gpus = make_gpu_db(parse_csv_to_dict(cmd_get_gpu_info()))

    # Get GPU usage per process
    raw_pids = parse_csv_to_dict(cmd_get_gpu_pid())

    # Get All CPU Jobs
    # This does not work
    # we need to process tree
    raw_allpids = filter_pids(parse_csv_to_dict(cmd_get_all_process_pid(), ' '))
    for data in raw_allpids:
        raw_pids.append({
            "pid": data['PID'],
            "process_name": data['COMMAND'],
        })
    # <<<<

    gpu_stat_cpy = [
        'memory.used [MiB]',
        'utilization.memory [%]',
        'utilization.gpu [%]',
        'memory.total [MiB]'
    ]

    processed_pid = {}
    report = []
    today = datetime.date.today()
    day, month, year = today.day, today.month, today.year

    for process in raw_pids:
        pid = process['pid']
        gid = process.get('gpu_uuid')

        # Process is already using another GPU
        process_report = None
        if pid in processed_pid:
            process_report = processed_pid[pid]
        else:
            process_report = dict()
            insert_cgroup_config(pid, process_report)

            now = datetime.datetime.now().time()
            h, m, s = now.hour, now.minute, now.second

            process_report['day'] = day
            process_report['month'] = month
            process_report['year'] = year
            process_report['hour'] = h
            process_report['minute'] = m
            process_report['sec'] = s

            process_report['hostname'] = socket.gethostname()
            process_report['gpus'] = []
            try:
                pinfo = parse_csv_to_dict(get_process_info(pid), sep=' ')[0]

                for k, v in pinfo.items():
                    process_report[k] = v

                # Only append at the end when nothing bad happened
                processed_pid[pid] = process_report
                report.append(process_report)

            except subprocess.CalledProcessError as e:
                process_report['get_process_info_error'] = e.returncode

        # if a GPU was detected add the GPU info
        if gid:
            process_gpu = copy.deepcopy(process)
            ginfo = raw_gpus[gid]

            for k in gpu_stat_cpy:
                nk = k.replace('.', '_')
                process_gpu[nk] = ginfo[k]

            process_report['gpus'].append(process_gpu)

    return raw_gpus, raw_pids, report


if __name__ == '__main__':
    from pymongo import MongoClient
    import argparse

    # 172.16.38.50
    parser = argparse.ArgumentParser()
    parser.add_argument('--mongodb', default='mongodb://172.16.38.50:27017')
    parser.add_argument('--no-print', action='store_true', default=False)
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--daemon', action='store_true')
    parser.add_argument('--check-every', default=1, help='second')
    parser.add_argument('--push-every', default=60, help='second')

    args = parser.parse_args()

    for k, v in vars(args).items():
        print(f'{k:>30}:{v}')

    raw_gpus, raw_pids, report = make_report()

    if not args.no_print:
        print(json.dumps(raw_gpus, indent=2))
        print(json.dumps(raw_pids, indent=2))
        print(json.dumps(report, indent=2))

    if len(report) > 0 and not args.dry_run:
        client = MongoClient(args.mongodb)
        db = client.usage_reports
        db.data.insert_many(report)
        client.close()
