#!/usr/bin/env python3

"""
    Query System to retrieve info about resource usage and who is using the resource (only GPUs)

    ```
[
  {
    "pid": "107664",
    "name": "bash",
    "user": "delaunap",
    "children": {
      "111107": "vi",
      "107733": "python",
      "60202": "python",
      "59794": "python"
    },
    "cgroup": {
      "cpuset_effective_cpus": {
        "total_requested": 4,
        "cpu_set": "4-7"
      },
      "cpuacct_usage_percpu": {
        "4": "22286403972",
        "5": "29442837182",
        "6": "20747031952",
        "7": "24572310962"
      },
      "devices_allow": "[Errno 13] Permission denied: '/sys/fs/cgroup/devices/slurm_power92/uid_1500000082/job_68543/devices.allow'",
      "memory_usage_in_bytes": "2065039360",
      "memory_limit_in_bytes": "8589934592"
    },
    "gpus": [
      {
        "timestamp": "2019/05/02 13:19:11.218",
        "pid": "107733",
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
    "errors": {},
    "hostname": "power92.server.mila.quebec",
    "timestamp": "2019-05-02 13:19:11.220055"
  }
]
    ```
"""

import subprocess
import json
import copy
import socket
import datetime
import time
import psutil
import traceback

notuser_users = frozenset({
    'systemd+',
    '_chrony',
    'mail',
    'message+',
    'syslog',
    'daemon',
    'munge',
    'www-data',
    'statd',
    'root',
    'systemd-resolve',
    'avahi',
    'messagebus',
    'colord',
    'lp',
    'kernoops',
    'whoopsie',
    'rtkit',
    'mpd',
    'gdm',
    'systemd-timesync',
    'systemd-network'
})


class ParentProcess:
    def __init__(self, pid, name, username, children):
        self.pid = pid
        self.name = name
        self.user = username
        self.children = children
        self.cgroup = None
        self.gpus = None
        self.errors = {}
        self.hostname = socket.gethostname()
        self.system = {}

    def to_dict(self, to_str=str):
        return {
            'pid': self.pid,
            'name': self.name,
            'user': self.user,
            'children': self.children,
            'cgroup': self.cgroup,
            'gpus': self.gpus,
            'errors': self.errors,
            'hostname': self.hostname,
            'timestamp': to_str(datetime.datetime.now()),
            'system': self.system
        }

    def add_system_info(self):
        proc = psutil.Process(int(self.pid))

        with proc.oneshot():
            cpu = psutil.cpu_times()
            self.system['cpu%'] = proc.cpu_percent()

            ptimes = proc.cpu_times()
            self.system['cpu_user'] = ptimes[0]
            self.system['cpu_sys'] = ptimes[1]
            self.system['cpu_child_user'] = ptimes[2]
            self.system['cpu_child_sys'] = ptimes[3]

            self.system['user'] = cpu.user
            self.system['iowait'] = cpu.iowait
            self.system['system'] = cpu.system

            try:
                mem = proc.memory_full_info()
                self.system['mem_rss'] = mem.rss
                self.system['mem_vms'] = mem.vms
                self.system['mem_uss'] = mem.uss

            except psutil.AccessDenied:
                self.errors['psutil'] = str(traceback.format_exc())

    def add_cgroup(self):
        try:
            cgroup_config = get_cgroup_config(self.pid)
            if cgroup_config is None:
                return

            self.cgroup = {}

            for k, v in cgroup_config.items():
                nk = k.replace('.', '_')
                self.cgroup[nk] = v

        except Exception:
            self.errors['cgroup_error'] = str(traceback.format_exc())



def get_parent(proc):
    parent = proc.parent()

    if parent is None:
        return parent

    if parent.username() in notuser_users:
        return None

    return parent


def find_top_most_parent(proc, processes, children, children_to_parent):
    parent = get_parent(proc)

    if parent is None:
        for c in children:
            children_to_parent[c] = str(proc.pid)

        return ParentProcess(
            pid=str(proc.pid),
            username=proc.username(),
            children=children,
            name=proc.name()
        )
    else:
        if proc.pid in processes:
            processes.pop(proc.pid)

        children[str(proc.pid)] = proc.name()
        return find_top_most_parent(parent, processes, children, children_to_parent)


def make_process_trees():
    """ return a list of all the processes as a tree"""
    processes = []
    pids = dict()

    # make a clean list of user processes
    for proc in psutil.process_iter(attrs=['pid', 'name', 'username', 'ppid']):
        if proc.username() in notuser_users:
            continue

        processes.append(proc)
        pids[proc.pid] = proc

    # Make Tree of processes
    clean_list = []
    children_to_parent = {}
    parent_accessor = {}

    while len(pids) > 0:
        (pid, proc) = pids.popitem()
        parent = find_top_most_parent(proc, pids, {}, children_to_parent)

        if parent.pid in parent_accessor:
            oparent = parent_accessor[parent.pid]
            oparent.children.update(parent.children)

        elif parent.user not in notuser_users:
            clean_list.append(parent)
            parent_accessor[parent.pid] = parent

            parent.add_cgroup()
            parent.add_system_info()

    return children_to_parent, clean_list, parent_accessor


class ProcessDatabase:

    def __init__(self):
        a, b, c = make_process_trees()
        self.children_to_parent = a
        self.process_list = b
        self.get_parent_object = c

    def get_parent_process(self, pid):
        ppid = self.children_to_parent.get(pid, pid)
        return self.get_parent_object[ppid]

    def make_report(self):
        return [proc.to_dict() for proc in self.process_list]


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
    #print(cmd)
    return subprocess.check_output(cmd, shell=True).decode('utf-8')


def cmd_get_all_process_pid():
    cmd = f'ps -eo "user,pid,comm" | grep -v root'
    #print(cmd)
    return subprocess.check_output(cmd, shell=True).decode('utf-8')


status_query = \
    'timestamp,utilization.gpu,utilization.memory,count,memory.total,memory.used,gpu_serial,gpu_uuid,gpu_bus_id'


def cmd_get_gpu_info():
    cmd = f'nvidia-smi --query-gpu={status_query} --format=csv,nounits -u'
    # print(cmd)
    return subprocess.check_output(cmd, shell=True).decode('utf-8')


pid_query = 'timestamp,pid,name,gpu_name,used_memory,gpu_bus_id,gpu_uuid,gpu_serial'


def cmd_get_gpu_pid():
    cmd = f'nvidia-smi --query-compute-apps={pid_query} --format=csv,nounits -u'
    # print(cmd)
    return subprocess.check_output(cmd, shell=True).decode('utf-8')


def cmd_get_slurm_job_info(jid):
    cmd = f'squeue -j {jid} -O tres-alloc:255.,tres-per-node:255.,command::255. -h'
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
cgroup_constraint_set = {'cpuset', 'cpu,cpuacct', 'memory'}
cgroup_constraint = [
    ('cpuset'       , 'cpuset.effective_cpus', parse_cpuset),
    ('cpu,cpuacct'  , 'cpuacct.usage_percpu', parse_cpuacct),
    ('memory'       , 'memory.usage_in_bytes', parse_memory_used),
    ('memory'       , 'memory.limit_in_bytes', parse_memory_limit)
]


def get_slurm_cg(cgroup_file):
    # /slurm_hostname/uid_XXXXX/job_XXXX/

    for row in cgroup_file:
        data = row.split(':')
        if data[2].startswith('/slurm'):
            return list(filter(lambda x: len(x.strip()) > 0, data[2].split('/')))


def get_slurm_job_request(jid):
    line = cmd_get_slurm_job_info(jid)
    tres_alloc = line[:255]
    tres_node = line[255:255 * 2]
    command = line[255 * 2:]

    resources = {
        'tres_per_node': tres_node.strip(),
        'command': command.strip()
    }

    for res in tres_alloc.split(','):
        k, v = res.split('=')
        resources[k.strip()] = v.strip()

    return resources


def get_cgroup_config(pid):
    """
    12  :cpuset         :/slurm_power92/uid_1500000082/job_68543/step_0
    4   :cpu,cpuacct    :/slurm_power92/uid_1500000082/job_68543/step_0/task_0
    3   :memory         :/slurm_power92/uid_1500000082/job_68543/step_0/task_0
    """

    cgroup_file = open(f'/proc/{pid}/cgroup', 'r').read().split('\n')
    slurm_cg_all = get_slurm_cg(cgroup_file)

    uid = slurm_cg_all[1].split('_')[1]
    job = slurm_cg_all[2].split('_')[1]

    slurm_cg = '/'.join(slurm_cg_all[0:2])
    cgroup_config = {
        'uid': uid,
        'job': job,
    }

    for cname, cfile, parser in cgroup_constraint:
        cgroup_data = f'/sys/fs/cgroup/{cname}/{slurm_cg}/{cfile}'

        try:
            with open(cgroup_data, 'r') as file:
                data = file.read()
                cgroup_config[cfile] = parser(data)

        except Exception as e:
            cgroup_config[f'{cfile}_error'] = str(traceback.format_exc())

    # Get Slurm info
    try:
        cgroup_config['slurm'] = get_slurm_job_request(job)

    except Exception as e:
        cgroup_config['slurm_error'] = str(traceback.format_exc())

    return cgroup_config


def insert_cgroup_config(pid, process_report):
    try:
        cgroup_config = get_cgroup_config(pid)

        cgroup_config2 = {}
        process_report['cgroup'] = cgroup_config2

        for k, v in cgroup_config.items():
            nk = k.replace('.', '_')
            cgroup_config2[nk] = v

    except Exception:
        process_report['errors']['cgroup'] = str(traceback.format_exc())


def filter_pids(all_pids):
    filtered = []

    for pid in all_pids:
        if pid['USER'] not in notuser_users:
            filtered.append(pid)

    return filtered


def make_report():
    # Get all CPU Jobs
    process_db = ProcessDatabase()

    # Get GPU overall usage
    try:
        raw_gpus = make_gpu_db(parse_csv_to_dict(cmd_get_gpu_info()))

        # Get GPU usage per process
        raw_pids = parse_csv_to_dict(cmd_get_gpu_pid())
    except Exception as e:
        print(traceback.format_exc())
        raw_gpus = []
        raw_pids = []

    gpu_stat_cpy = [
        'memory.used [MiB]',
        'utilization.memory [%]',
        'utilization.gpu [%]',
        'memory.total [MiB]'
    ]

    # For all processes using GPUs update the parent process with the info
    for process in raw_pids:
        pid = process['pid']
        gid = process.get('gpu_uuid')

        process_report = process_db.get_parent_process(pid)
        if process_report.gpus is None:
            process_report.gpus = []

        # if a GPU was detected add the GPU info
        if gid:
            process_gpu = copy.deepcopy(process)
            ginfo = raw_gpus[gid]

            for k in gpu_stat_cpy:
                nk = k.replace('.', '_')
                process_gpu[nk] = ginfo[k]

            process_report.gpus.append(process_gpu)

    return raw_gpus, raw_pids, process_db.make_report()


class Chrono:
    start = 0
    end = 0

    def __enter__(self):
        self.start = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            raise exc_type

        self.end = time.time()

    @property
    def val(self):
        return self.end - self.start


def daemon(args):
    to_be_pushed = []
    last_push_time = time.time()
    last_report_time = 0

    client = MongoClient(args.mongodb)
    db = client.usage_monitor
    health = db.health
    collections = db.ts

    if not args.dry_run:
        health.update_one(
            {'hostname': socket.gethostname()},
            {
                '$set': {
                    'hostname': socket.gethostname(),
                    'push_every': args.push_every,
                    'daemon': args.daemon,
                    'alive': True,
                    'check_every': args.check_every,
                    'last_alive': str(datetime.datetime.utcnow()),
                    'errors': [],
                    'heart': 1
                }
            }, upsert=True)

    while True:
        try:
            now = time.time()
            report = []

            # Time to check the node again
            if now - last_report_time > args.check_every:
                last_report_time = time.time()
                raw_gpus, raw_pids, report = make_report()

                if not args.no_print:
                    print(json.dumps(raw_gpus, indent=2))
                    print(json.dumps(raw_pids, indent=2))
                    print(json.dumps(report, indent=2))

            # if a report was generated add to the pending reports
            if report:
                to_be_pushed.extend(report)

            # Time to push to DB
            if now - last_push_time > args.push_every or not args.daemon:
                if len(to_be_pushed) > 0 and not args.dry_run:
                    health.update_one(
                        {'hostname': socket.gethostname()},
                        {
                            '$set': {
                                'heart': time.time()
                            }
                        }
                    )
                    collections.insert_many(to_be_pushed)
                    print(f'Inserting {len(to_be_pushed)}')

                to_be_pushed = []
                last_push_time = time.time()

            if not args.daemon:
                client.close()
                break

            # do not use 100% of the processor
            time.sleep(0.01)

        except KeyboardInterrupt:
            break

        except Exception as e:
            if not args.dry_run:
                health.update_one(
                    {'hostname': socket.gethostname()},
                    {
                        '$push': {'errors': str(traceback.format_exc())}
                    }
                )

    if not args.dry_run:
        health.update_one(
            {'hostname': socket.gethostname()},
            {
                '$set': {
                    'alive': False,
                    'last_died': str(datetime.datetime.utcnow()),
                    'heart': 0
                }
            }
        )


if __name__ == '__main__':
    from pymongo import MongoClient
    import argparse
    psutil.cpu_percent()

    # 172.16.38.50
    parser = argparse.ArgumentParser()
    parser.add_argument('--mongodb', default='mongodb://172.16.38.50:27017')
    parser.add_argument('--no-print', action='store_true', default=False)
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--daemon', action='store_true')
    parser.add_argument('--check-every', type=int, default=5, help='second')
    parser.add_argument('--push-every', type=int, default=60, help='second')

    opt = parser.parse_args()

    for k, v in vars(opt).items():
        print(f'{k:>30}:{v}')

    daemon(opt)

