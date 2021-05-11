#!/usr/bin/env python3

from common import EC2Environment, CREATE, eprint
import time, json, os, atexit
from datetime import date


# Note: this script will run for ~8 minutes and incur costs of about $ 0.02

FILE = "../../target/release/vpncloud"
VERSION = "2.2.0"
REGION = "eu-central-1"

env = EC2Environment(
    region = REGION, 
    node_count = 2, 
    instance_type = "m5.large", 
    use_spot = True, 
    max_price = "0.08", # USD per hour per VM
    vpncloud_version = VERSION,
    vpncloud_file = FILE,
    cluster_nodes = True,
    subnet = CREATE, 
    keyname = CREATE
)


CRYPTO = ["plain", "aes256", "aes128", "chacha20"]


class PerfTest:
    def __init__(self, sender, receiver):
        self.sender = sender
        self.receiver = receiver
        self.sender_ip_vpncloud = "10.0.0.1"
        self.receiver_ip_vpncloud = "10.0.0.2"

    @classmethod
    def from_ec2_env(cls, env):
        return cls(env.nodes[0], env.nodes[1])

    def run_ping(self, dst, size):
        eprint(f"\tRunning ping {dst} with size {size} ...")
        return self.sender.ping(dst=dst, size=size, count=30000, interval=0.001)

    def run_iperf(self, dst):
        eprint(f"\tRunning iperf on {dst} ...")
        self.receiver.start_iperf_server()
        time.sleep(0.1)
        result = self.sender.run_iperf(dst=dst, duration=30)
        self.receiver.stop_iperf_server()
        return result

    def start_vpncloud(self):
        eprint("\tSetting up vpncloud on receiver")
        self.receiver.start_vpncloud(ip=f"{self.receiver_ip_vpncloud}/24")
        eprint("\tSetting up vpncloud on sender")
        self.sender.start_vpncloud(peers=[f"{self.receiver.private_ip}:3210"], ip=f"{self.sender_ip_vpncloud}/24")
        time.sleep(1.0)

    def stop_vpncloud(self):
        self.sender.stop_vpncloud(wait=False)
        self.receiver.stop_vpncloud(wait=True)

    def run(self):
        print()
        self.start_vpncloud()
        throughput = self.run_iperf(self.receiver_ip_vpncloud)["throughput"]
        print(f"Throughput: {throughput / 1_000_000.0} MBit/s")
        native_ping_100 = self.run_ping(self.receiver.private_ip, 100)["rtt_avg"]
        ping_100 = self.run_ping(self.receiver_ip_vpncloud, 100)["rtt_avg"]
        print(f"Latency 100: +{(ping_100 - native_ping_100)*1000.0/2.0} µs")
        native_ping_1000 = self.run_ping(self.receiver.private_ip, 1000)["rtt_avg"]
        ping_1000 = self.run_ping(self.receiver_ip_vpncloud, 1000)["rtt_avg"]
        print(f"Latency 1000: +{(ping_1000 - native_ping_1000)*1000.0/2.0} µs")
        self.stop_vpncloud()

keyfile = "key.pem"
assert not os.path.exists(keyfile)
with open(keyfile, 'x') as fp:
    fp.write(env.privatekey)
os.chmod(keyfile, 0o400)
print(f"SSH private key written to {keyfile}")
atexit.register(lambda : os.remove(keyfile))
print()
print("Nodes:")
for node in env.nodes:
    print(f"\t {env.username}@{node.public_ip}\tprivate: {node.private_ip}")
print()

perf = PerfTest.from_ec2_env(env)

try:
    perf.run()
except Exception as e:
    eprint(f"Exception: {e}")
    print("Press ENTER to shut down")
    input()

eprint("done.")