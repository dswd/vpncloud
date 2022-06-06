#!/usr/bin/env python3

from common import EC2Environment, CREATE, eprint
import time, json
from datetime import date


# Note: this script will run for ~8 minutes and incur costs of about $ 0.02

FILE = "../../target/release/vpncloud"
VERSION = "2.3.0"
REGION = "eu-central-1"

env = EC2Environment(
    region = REGION, 
    node_count = 2, 
    instance_type = "m5.large", 
    use_spot = False, 
    max_price = "0.08", # USD per hour per VM
    vpncloud_version = VERSION,
    vpncloud_file = FILE,
    cluster_nodes = True,
    subnet = CREATE, 
    keyname = CREATE
)


CRYPTO = ["plain", "aes256", "aes128", "chacha20"]


class PerfTest:
    def __init__(self, sender, receiver, meta):
        self.sender = sender
        self.receiver = receiver
        self.sender_ip_vpncloud = "10.0.0.1"
        self.receiver_ip_vpncloud = "10.0.0.2"
        self.meta = meta

    @classmethod
    def from_ec2_env(cls, env):
        meta = {
            "region": env.region,
            "instance_type": env.instance_type,
            "ami": env.ami,
            "version": env.vpncloud_version
        }
        return cls(env.nodes[0], env.nodes[1], meta)

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

    def run_suite(self, dst):
        return {
            "iperf": self.run_iperf(dst),
            "ping_100": self.run_ping(dst, 100),
            "ping_500": self.run_ping(dst, 500),
            "ping_1000": self.run_ping(dst, 1000),
        }

    def start_vpncloud(self, crypto=None):
        eprint("\tSetting up vpncloud on receiver")
        self.receiver.start_vpncloud(crypto=crypto, ip=f"{self.receiver_ip_vpncloud}/24")
        eprint("\tSetting up vpncloud on sender")
        self.sender.start_vpncloud(crypto=crypto, peers=[f"{self.receiver.private_ip}:3210"], ip=f"{self.sender_ip_vpncloud}/24")
        time.sleep(1.0)

    def stop_vpncloud(self):
        self.sender.stop_vpncloud(wait=False)
        self.receiver.stop_vpncloud(wait=True)

    def run(self):
        eprint("Testing native network")
        results = {
            "meta": self.meta,
            "native": self.run_suite(self.receiver.private_ip)
        }
        for crypto in CRYPTO:
            eprint(f"Running with crypto {crypto}")
            self.start_vpncloud(crypto=crypto)
            res = self.run_suite(self.receiver_ip_vpncloud)
            self.stop_vpncloud()
            results[str(crypto)] = res
        results['results'] = {
            "throughput_mbits": dict([
                (k, results[k]["iperf"]["throughput"] / 1000000.0) for k in ["native"] + CRYPTO
            ]),
            "latency_us": dict([
                (k, dict([
                    (str(s), (results[k]["ping_%s" % s]["rtt_avg"] - results["native"]["ping_%s" % s]["rtt_avg"])*1000.0/2.0) for s in [100, 500, 1000]
                ])) for k in CRYPTO
            ])
        }
        return results

perf = PerfTest.from_ec2_env(env)

start = time.time()
results = perf.run()
duration = time.time() - start

results["meta"]["duration"] = duration

name = f"measurements/{date.today().strftime('%Y-%m-%d')}_{VERSION}_perf.json"
eprint(f'Storing results in {name}')
with open(name, 'w') as fp:
    json.dump(results, fp, indent=2)
eprint("done.")
