from benchutils.statstream import StatStream
from collections import defaultdict
from pymongo import MongoClient
import json


gpu_metrics = [
    'memory_used [MiB]',
    'utilization_memory [%]',
    'utilization_gpu [%]',
    'memory_total [MiB]'
]

cgroup_metrics = [
    'memory_limit_in_bytes',
    'memory_usage_in_bytes'
    # 'devices_allow',
]

system_metrics = [
    "cpu%",
    "cpu_user",
    "cpu_sys",
    "cpu_child_user",
    "cpu_child_sys",
    "user",
    "iowait",
    "system",
    "mem_rss",
    "mem_vms",
    "mem_uss"
]


def acc_gpu(report, key, value):
    if value is None:
        #print('no gpu?')
        return

    gpu_count = len(value)
    report['gpu_count'].update(gpu_count)

    for gpu in value:
        for k in gpu_metrics:
            v = gpu.get(k)
            if v:
                report[f'gpu_{k}'].update(float(v))
            else:
                print(f'Missing value for {k}')


def default_acc(report, key, value):
    if value is None:
        return

    acc = report[key]
    value = float(value)
    acc.update(value)


def acc_children(report, key, value):
    """
    "children": {
        "111107": "vi",
        "107733": "python",
        "65719": "python",
        "59794": "python"
      },
    """
    report["children_count"].update(len(value))


def acc_system(report, key, value):
    for metric in system_metrics:
        val = value.get(metric)
        if val:
            report[f'system_{metric}'].update(float(val))


def acc_cgroup(report, key, value):
    """
    "cgroup":{
        "cpuset_effective_cpus": {
          "total_requested": 4,
          "cpu_set": "4-7"
        },
        "cpuacct_usage_percpu": {
          "4": "24953153148",
          "5": "32997757400",
          "6": "25034003872",
          "7": "29122557948"
        },
        "devices_allow": "",
        "memory_usage_in_bytes": "2064384000",
        "memory_limit_in_bytes": "8589934592"
      }
    """
    if value is None:
       return 

    val = float(value['cpuset_effective_cpus']['total_requested'])
    report['requested_cpu_count'].update(val)

    val = value['cpuacct_usage_percpu']
    for k, usage in val.items():
        report['cpuacct_usage'].update(float(usage))

    for metric in cgroup_metrics:
        val = float(value[metric])
        report[f'cgroup_{metric}'].update(val)


metrics = {
    'gpus': acc_gpu,
    'children': acc_children,
    'cgroup': acc_cgroup,
    'system': acc_system
}


def usage_per_user(observations):
    user_util_dict = dict()
    use_util = []

    for obs in observations:
        obs['_id'] = str(obs['_id'])
        # print(json.dumps(obs, indent=2))

        username = obs['user']

        user_report = defaultdict(lambda: StatStream(drop_first_obs=0))
        user_report['user'] = username

        if username in user_util_dict:
            user_report = user_util_dict[username]
        else:
            user_util_dict[username] = user_report
            use_util.append(user_report)

        for k, accumulator in metrics.items():

            val = obs.get(k)
            accumulator(user_report, k, val)

    return use_util


def implode_statstream(usage_report):
    final_report = []

    for user_usage in usage_report:
        user_report = defaultdict(lambda: 0)

        for k, v in user_usage.items():
            if isinstance(v, StatStream):
                if k == 'memory_total [MiB]':
                    user_report[f'avg_{k}'] = v.avg
                else:
                    user_report[f'avg_{k}'] = v.avg
                    user_report[f'sd_{k}'] = v.sd
                    user_report[f'min_{k}'] = v.min
                    user_report[f'max_{k}'] = v.max
            else:
                user_report[k] = v

        final_report.append(user_report)

    return final_report


def to_csv(report):
    if len(report) <= 0:
        return [], []

    rows = []
    header = list(report[0].keys())
    for h in report:
        if len(h.keys()) > len(header):
            header = h.keys()


    for data in report:
        row = []
        for k in header:
            row.append(data[k])
        rows.append(row)

    return header, rows


if __name__ == '__main__':

    import pandas as pd
    import argparse

    # 172.16.38.50
    parser = argparse.ArgumentParser()
    parser.add_argument('--mongodb', default='mongodb://172.16.38.50:27017')
    parser.add_argument('--no-print', action='store_true', default=False)
    parser.add_argument('--delete-observed', action='store_true', default=False)
    args = parser.parse_args()

    client = MongoClient(args.mongodb)
    db = client.usage_reports
    collection = db.data

    data = collection.find()
    usage_report = usage_per_user(data)
    #print(usage_report)
    usage_report = implode_statstream(usage_report)
    print(usage_report)
    header, data = to_csv(usage_report)

    for h in header:
        print(h)

    df = pd.DataFrame(data, columns=header)
    df.to_csv('full_report.csv', index=False)

    selected_cols = [
        'user',
        'avg_gpu_count', 'avg_gpu_memory_used [MiB]', 'avg_gpu_utilization_memory [%]', 'avg_gpu_memory_total [MiB]',
        'avg_gpu_utilization_gpu [%]',
        'avg_children_count', 'avg_requested_cpu_count',    # 'avg_cpuacct_usage',
        # 'avg_cpuacct_usage_s',
        # 'avg_cgroup_memory_limit_in_bytes', 'avg_cgroup_memory_usage_in_bytes',
        'avg_system_cpu_child_user', 'avg_system_cpu_child_sys',
        # 'avg_cgroup_memory_limit_in_mib', 'avg_cgroup_memory_usage_in_mib'
    ]

    pd.set_option('display.max_rows', 500)
    pd.set_option('display.max_columns', 500)
    pd.set_option('display.width', 120)
    #print(df)

    ns = 1000 * 1000 * 1000
    mio = 1024 * 1024
    try:
        df.loc[:, 'avg_cgroup_memory_limit_in_mib'] = df['avg_cgroup_memory_limit_in_bytes'] / mio
        df.loc[:, 'avg_cgroup_memory_usage_in_mib'] = df['avg_cgroup_memory_usage_in_bytes'] / mio
        df.loc[:, 'avg_cpuacct_usage_s'] = df['avg_cpuacct_usage'] / ns
        selected_cols.append('avg_cpuacct_usage_s')
        selected_cols.append('avg_cgroup_memory_limit_in_mib')
        selected_cols.append('avg_cgroup_memory_usage_in_mib')
    except Exception as e:
        print(e)

    try:
        df = df[selected_cols]

        df.to_csv('reduced_report.csv', index=False)
        print(df)
    except Exception as e:
        print(e)

    if args.delete_observed:
        collection.drop()

