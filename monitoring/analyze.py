from benchutils.statstream import StatStream
from collections import defaultdict

gpu_metrics = [
    'memory_used [MiB]',
    'utilization_memory [%]',
    'utilization_gpu [%]',
    'memory_total [MiB]'
]


def acc_gpu(report, key, value):
    gpu_count = len(value)
    report['gpu_count'].update(gpu_count)

    for gpu in value:
        for k in gpu_metrics:
            v = gpu.get(k)
            if v:
                report[k].update(float(v))


def default_acc(report, key, value):
    acc = report[key]
    value = float(value)
    acc.update(value)


metrics = {
    'gpus': acc_gpu,
    'VSZ': default_acc,
    'RSS': default_acc,
    '%MEM': default_acc,
    '%CPU': default_acc
}


def usage_per_user(observations):
    user_util_dict = dict()
    use_util = []

    for obs in observations:
        username = obs['USER']

        user_report = defaultdict(lambda: StatStream(drop_first_obs=0))
        user_report['USER'] = username

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
        user_report = defaultdict(lambda: StatStream(drop_first_obs=0))

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
    rows = []
    header = list(report[0].keys())

    for data in report:
        row = []
        for k in header:
            row.append(data[k])
        rows.append(row)

    return header, rows


if __name__ == '__main__':
    from pymongo import MongoClient
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
    usage_report = implode_statstream(usage_report)

    header, data = to_csv(usage_report)

    for line in data:
        print(line)

    df = pd.DataFrame(data, columns=header)
    print(df)
    df.to_csv('report.csv', index=False)

    if args.delete_observed:
        collection.drop()

