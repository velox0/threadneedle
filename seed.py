import redis

r = redis.Redis(host="localhost", port=6379)

ips = [
    "1.1.1.1",
    "8.8.8.8"
]

for ip in ips:
    r.lpush("targets", ip)

print("queued")
