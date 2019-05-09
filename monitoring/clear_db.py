import argparse
from pymongo import MongoClient


parser = argparse.ArgumentParser()
parser.add_argument('--mongodb', default='mongodb://172.16.38.50:27017')
parser.add_argument('--no-print', action='store_true', default=False)
parser.add_argument('--delete-observed', action='store_true', default=False)
args = parser.parse_args()

client = MongoClient(args.mongodb)
db = client.usage_monitor
health = db.health
collections = db.ts

collections.drop()
