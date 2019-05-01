"""
    Query System to retrieve info about resource usage and who is using the resource (only GPUs)

    ```
        {
          "hostname": "power92.server.mila.quebec",
          "gpus": [
            {
              "timestamp": "2019/05/01 10:16:13.645",
              "pid": "101215",
              "process_name": "python",
              "gpu_name": "Tesla V100-SXM2-16GB",
              "used_gpu_memory [MiB]": "663",
              "gpu_bus_id": "00000004:04:00.0",
              "gpu_uuid": "GPU-016b348f-3447-d57f-672a-9144fd65ae30",
              "gpu_serial": "0324117166425"
            },
            {
              "timestamp": "2019/05/01 10:16:13.646",
              "pid": "101215",
              "process_name": "python",
              "gpu_name": "Tesla V100-SXM2-16GB",
              "used_gpu_memory [MiB]": "663",
              "gpu_bus_id": "00000004:05:00.0",
              "gpu_uuid": "GPU-6d5d201f-d34e-70e2-0a6b-e16c7aea6a30",
              "gpu_serial": "0324317007486"
            }
          ],
          "timestamp": "2019-05-01 10:16:13.649564",
          "PID": "101215",
          "USER": "delaunap",
          "%CPU": "0.0",
          "%MEM": "0.4",
          "C": "0",
          "ELAPSED": "01:32:19",
          "PPID": "101166",
          "RSS": "2453824",
          "TIME": "00:00:05",
          "VSZ": "23514176",
          "COMMAND": "python"
        }
    ```
"""

import subprocess
import json
import copy
import socket
import datetime
from typing import List, Dict


def parse_csv_to_dict(data, sep=',') -> List[Dict[str, str]]:
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


def make_report():
    raw_gpus = make_gpu_db(parse_csv_to_dict(cmd_get_gpu_info()))
    raw_pids = parse_csv_to_dict(cmd_get_gpu_pid())

    gpu_stat_cpy = ['memory.used [MiB]', 'utilization.memory [%]', 'utilization.gpu [%]']

    processed_pid = {}
    report = []
    today = datetime.date.today()
    day, month, year = today.day, today.month, today.year

    for process in raw_pids:
        pid = process['pid']
        gid = process['gpu_uuid']

        # Process is already using another GPU
        process_report = None
        if pid in processed_pid:
            process_report = processed_pid[pid]
        else:
            process_report = dict()
            processed_pid[pid] = process_report
            report.append(process_report)

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
            pinfo = parse_csv_to_dict(get_process_info(pid), sep=' ')[0]

            for k, v in pinfo.items():
                process_report[k] = v

        # Add GPU info
        process_gpu = copy.deepcopy(process)
        ginfo = raw_gpus[gid]

        for k in gpu_stat_cpy:
            process[k] = ginfo[k]

        process_report['gpus'].append(process_gpu)

    return raw_gpus, raw_pids, report


if __name__ == '__main__':
    from pymongo import MongoClient
    import argparse

    # 172.16.38.50
    parser = argparse.ArgumentParser()
    parser.add_argument('--mongodb', default='mongodb://172.16.38.50:27017')
    parser.add_argument('--no-print', action='store_true', default=False)
    args = parser.parse_args()

    for k, v in vars(args).items():
        print(f'{k:>30}:{v}')

    raw_gpus, raw_pids, report = make_report()

    if not args.no_print:
        print(json.dumps(raw_gpus, indent=2))
        print(json.dumps(raw_pids, indent=2))
        print(json.dumps(report, indent=2))

    if len(report) > 0:
        client = MongoClient(args.mongodb)
        db = client.usage_reports
        db.data.insert_many(report)
        client.close()
