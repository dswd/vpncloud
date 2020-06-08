#!/usr/bin/env python3

import boto3
import atexit
import paramiko
import io
import time
import threading
import re
import json
import base64
import sys
from datetime import date


# Note: this script will run for ~8 minutes and incur costs of about $ 0.02

REGION = "eu-central-1"
AMI = "ami-0a02ee601d742e89f"
USERNAME = "ec2-user"
INSTANCE_TYPE = "m5.large"
SPOT = True
MAX_PRICE = "0.08" # USD per hour per VM

VERSION = "1.4.0"

USERDATA = """#cloud-config
packages:
  - iperf3
runcmd:
  - wget https://github.com/dswd/vpncloud/releases/download/v{version}/vpncloud_{version}.x86_64.rpm -O /tmp/vpncloud.rpm
  - yum install -y /tmp/vpncloud.rpm
""".format(version=VERSION)

MAX_WAIT = 300

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def run_cmd(connection, cmd):
    _stdin, stdout, stderr = connection.exec_command(cmd)
    out = stdout.read().decode('utf-8')
    err = stderr.read().decode('utf-8')
    code = stdout.channel.recv_exit_status()
    if code:
        raise Exception("Command failed", code, out, err)
    else:
        return out, err


class EC2Environment:
    def __init__(self):
        self.vpc = None
        self.igw = None
        self.rtb = None
        self.subnet = None
        self.sg = None
        self.key_pair = None
        self.rsa_key = None
        self.placement_group = None
        self.sender = None
        self.receiver = None
        self.sender_request = None
        self.receiver_request = None
        self.sender_ssh = None
        self.receiver_ssh = None
        try:
            eprint("Setting up resources...")
            self.setup()
            self.wait_until_ready()
            eprint("Setup done")
        except:
            eprint("Error, shutting down")
            self.terminate()
            raise

    def setup(self):
        ec2 = boto3.resource('ec2', region_name=REGION)
        ec2client = boto3.client('ec2', region_name=REGION)

        self.vpc = ec2.create_vpc(CidrBlock='172.16.0.0/16')
        eprint("\tCreated VPC {}".format(self.vpc.id))
        self.vpc.create_tags(Tags=[{"Key": "Name", "Value": "vpncloud-perf-test"}])
        self.vpc.wait_until_available()
        ec2client.modify_vpc_attribute(VpcId=self.vpc.id, EnableDnsSupport={'Value': True})
        ec2client.modify_vpc_attribute(VpcId=self.vpc.id, EnableDnsHostnames={'Value': True})

        self.igw = ec2.create_internet_gateway()
        eprint("\tCreated Internet Gateway {}".format(self.igw.id))
        self.igw.attach_to_vpc(VpcId=self.vpc.id)

        self.rtb = self.vpc.create_route_table()
        eprint("\tCreated Routing table {}".format(self.rtb.id))
        self.rtb.create_route(DestinationCidrBlock='0.0.0.0/0', GatewayId=self.igw.id)

        self.subnet = ec2.create_subnet(CidrBlock='172.16.1.0/24', VpcId=self.vpc.id)
        eprint("\tCreated Subnet {}".format(self.subnet.id))
        self.rtb.associate_with_subnet(SubnetId=self.subnet.id)

        self.sg = ec2.create_security_group(GroupName='SSH-ONLY', Description='only allow SSH traffic', VpcId=self.vpc.id)
        eprint("\tCreated security group {}".format(self.sg.id))
        self.sg.authorize_ingress(CidrIp='0.0.0.0/0', IpProtocol='tcp', FromPort=22, ToPort=22)
        self.sg.authorize_ingress(CidrIp='172.16.1.0/24', IpProtocol='icmp', FromPort=-1, ToPort=-1)
        self.sg.authorize_ingress(CidrIp='172.16.1.0/24', IpProtocol='tcp', FromPort=0, ToPort=65535)
        self.sg.authorize_ingress(CidrIp='172.16.1.0/24', IpProtocol='udp', FromPort=0, ToPort=65535)

        self.key_pair = ec2.create_key_pair(KeyName='vpncloud-perf-test-keypair')
        eprint("\tCreated key pair {}".format(self.key_pair.name))
        self.rsa_key = paramiko.RSAKey.from_private_key(io.StringIO(self.key_pair.key_material))
        self.placement_group = ec2.create_placement_group(GroupName="vpncloud-test-placement", Strategy="cluster")
        eprint("\tCreated placement group {}".format(self.placement_group.name))
        if SPOT:
            response = ec2client.request_spot_instances(
                SpotPrice = MAX_PRICE,
                Type = "one-time",
                InstanceCount = 2,
                LaunchSpecification = {
                    "ImageId": AMI,
                    "InstanceType": INSTANCE_TYPE,
                    "KeyName": self.key_pair.name,
                    "UserData": base64.b64encode(USERDATA.encode("ascii")).decode('ascii'),
                    "BlockDeviceMappings": [
                        {
                            "DeviceName": "/dev/xvda",
                            "Ebs": {
                                "DeleteOnTermination": True,
                                "VolumeType": "gp2",
                                "VolumeSize": 8,
                            }
                        }
                    ],
                    "NetworkInterfaces": [
                        {
                            'SubnetId': self.subnet.id,
                            'DeviceIndex': 0,
                            'AssociatePublicIpAddress': True,
                            'Groups': [self.sg.group_id]
                        }
                    ],
                    "Placement": {
                        'GroupName': self.placement_group.name
                    }
                }
            )
            sender, receiver = response['SpotInstanceRequests']
            self.sender_request = sender['SpotInstanceRequestId']
            self.receiver_request = receiver['SpotInstanceRequestId']
            eprint("\tCreated spot instance requests {} and {}".format(self.sender_request, self.receiver_request))
            eprint("\tWaiting for spot instance requests")
            waited = 0
            while waited < MAX_WAIT:
                time.sleep(1.0)
                response = ec2client.describe_spot_instance_requests(SpotInstanceRequestIds=[self.sender_request])
                sender = response['SpotInstanceRequests'][0]
                response = ec2client.describe_spot_instance_requests(SpotInstanceRequestIds=[self.receiver_request])
                receiver = response['SpotInstanceRequests'][0]
                if 'InstanceId' in sender:
                    self.sender = ec2.Instance(sender['InstanceId'])
                if 'InstanceId' in receiver:
                    self.receiver = ec2.Instance(receiver['InstanceId'])
                if self.sender and self.receiver:
                    break
            if waited >= MAX_WAIT:
                raise Exception("Waited too long")
        else:
            self.sender, self.receiver = ec2.create_instances(
                ImageId=AMI,
                InstanceType=INSTANCE_TYPE,
                MaxCount=2,
                MinCount=2,
                NetworkInterfaces=[
                    {
                        'SubnetId': self.subnet.id,
                        'DeviceIndex': 0,
                        'AssociatePublicIpAddress': True,
                        'Groups': [self.sg.group_id]
                    }
                ],
                Placement={
                    'GroupName': self.placement_group.name
                },
                UserData=USERDATA,
                KeyName='vpncloud-perf-test-keypair'
            )
        eprint("\tCreated EC2 instances {} and {}".format(self.sender.id, self.receiver.id))
        eprint("\tWaiting for instances to start...")
        self.sender.wait_until_running()
        self.receiver.wait_until_running()
        self.sender.reload()
        self.receiver.reload()

    def wait_until_ready(self):
        waited = 0
        eprint("\tWaiting for SSH to be ready...")
        while waited < MAX_WAIT:
            try:
                if not self.sender_ssh:
                    self.sender_ssh = self._connect(self.sender)
                if not self.receiver_ssh:
                    self.receiver_ssh = self._connect(self.receiver)
                break
            except:
                pass
            time.sleep(1.0)
            waited += 1
        eprint("\tWaiting for instances to finish setup...")
        while waited < MAX_WAIT:
            try:
                run_cmd(self.sender_ssh, 'test -f /var/lib/cloud/instance/boot-finished')
                run_cmd(self.receiver_ssh, 'test -f /var/lib/cloud/instance/boot-finished')
                break
            except:
                pass
            time.sleep(1.0)
            waited += 1
        if waited >= MAX_WAIT:
            raise Exception("Waited too long")

    def terminate(self):
        eprint("Deleting resources...")
        if self.sender_ssh:
            self.sender_ssh.close()
        if self.receiver_ssh:
            self.receiver_ssh.close()
        if self.sender:
            eprint(self.sender.id)
            self.sender.terminate()
        if self.receiver:
            eprint(self.receiver.id)
            self.receiver.terminate()
        if self.sender:
            self.sender.wait_until_terminated()
        if self.receiver:
            self.receiver.wait_until_terminated()
        if self.sender_request or self.receiver_request:
            ec2client = boto3.client('ec2', region_name=REGION)
        if self.sender_request:
            eprint(self.sender_request)
            ec2client.cancel_spot_instance_requests(SpotInstanceRequestIds=[self.sender_request])
        if self.receiver_request:
            eprint(self.receiver_request)
            ec2client.cancel_spot_instance_requests(SpotInstanceRequestIds=[self.receiver_request])
        if self.placement_group:
            self.placement_group.delete()
        if self.key_pair:
            eprint(self.key_pair.name)
            self.key_pair.delete()
        if self.sg:
            eprint(self.sg.id)
            self.sg.delete()
        if self.subnet:
            eprint(self.subnet.id)
            self.subnet.delete()
        if self.rtb:
            eprint(self.rtb.id)
            self.rtb.delete()
        if self.igw:
            eprint(self.igw.id)
            self.igw.detach_from_vpc(VpcId=self.vpc.id)
            self.igw.delete()
        if self.vpc:
            eprint(self.vpc.id)
            self.vpc.delete()

    def _connect(self, instance):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=instance.public_dns_name, username=USERNAME, pkey=self.rsa_key, timeout=1.0, banner_timeout=1.0)
        return client


class PerfTest:
    def __init__(self, sender_ssh, sender_ip, receiver_ssh, receiver_ip):
        self.sender_ssh = sender_ssh
        self.sender_ip = sender_ip
        self.receiver_ssh = receiver_ssh
        self.receiver_ip = receiver_ip
        self.sender_ip_vpncloud = "10.0.0.1"
        self.receiver_ip_vpncloud = "10.0.0.2"

    @classmethod
    def from_ec2_env(cls, env):
        return cls(env.sender_ssh, env.sender.private_ip_address, env.receiver_ssh, env.receiver.private_ip_address)

    def run_sender(self, cmd):
        return run_cmd(self.sender_ssh, cmd)

    def run_receiver(self, cmd):
        return run_cmd(self.receiver_ssh, cmd)

    def run_ping(self, dst, size):
        eprint("\tRunning ping {} with size {} ...".format(dst, size))
        (out, _) = self.run_sender('sudo ping {dst} -c 30000 -i 0.001 -s {size} -U -q'.format(dst=dst, size=size))
        match = re.search(r'([\d]*\.[\d]*)/([\d]*\.[\d]*)/([\d]*\.[\d]*)/([\d]*\.[\d]*)', out)
        ping_min = float(match.group(1))
        ping_avg = float(match.group(2))
        ping_max = float(match.group(3))
        match = re.search(r'(\d*)% packet loss', out)
        pkt_loss = float(match.group(1))
        return {
            "rtt_min": ping_min,
            "rtt_max": ping_max,
            "rtt_avg": ping_avg,
            "pkt_loss": pkt_loss
        }

    def run_iperf(self, dst):
        eprint("\tRunning iperf on {} ...".format(dst))
        self.run_receiver('iperf3 -s -D')
        time.sleep(0.1)
        (out, _) = self.run_sender('iperf3 -c {dst} -t 30 --json'.format(dst=dst))
        self.run_receiver('killall iperf3')
        data = json.loads(out)
        return {
            "throughput": data['end']['streams'][0]['receiver']['bits_per_second'],
            "cpu_sender": data['end']['cpu_utilization_percent']['host_total'],
            "cpu_receiver": data['end']['cpu_utilization_percent']['remote_total']
        }

    def run_suite(self, dst):
        return {
            "iperf": self.run_iperf(dst),
            "ping_100": self.run_ping(dst, 100),
            "ping_500": self.run_ping(dst, 500),
            "ping_1000": self.run_ping(dst, 1000),
        }

    def start_vpncloud(self, mtu=8800, crypto=None):
        eprint("\tSetting up vpncloud on receiver")
        crypto_str = " --shared-key test --crypto {}".format(crypto) if crypto else ""
        args = "-t tap --daemon -l 3210 --no-port-forwarding" + crypto_str
        self.run_receiver("sudo vpncloud {args} --ifup 'ifconfig $IFNAME {ip}/24 mtu {mtu} up'".format(args=args, mtu=mtu, ip=self.receiver_ip_vpncloud))
        eprint("\tSetting up vpncloud on sender")
        self.run_sender("sudo vpncloud {args} -c {peer}:3210 --ifup 'ifconfig $IFNAME {ip}/24 mtu {mtu} up'".format(args=args, mtu=mtu, ip=self.sender_ip_vpncloud, peer=self.receiver_ip))
        time.sleep(1.0)

    def stop_vpncloud(self):
        self.run_sender("sudo killall vpncloud")
        self.run_receiver("sudo killall vpncloud")
        time.sleep(3.0)

    def run(self):
        eprint("Testing native network")
        results = {
            "meta": {
                "region": REGION,
                "instance_type": INSTANCE_TYPE,
                "ami": AMI,
                "version": VERSION
            },
            "native": self.run_suite(self.receiver_ip)
        }
        for crypto in [None, "aes256", "chacha20"]:
            eprint("Running with crypto {}".format(crypto or "plain"))
            self.start_vpncloud(mtu=8800, crypto=crypto)
            res = self.run_suite(self.receiver_ip_vpncloud)
            self.stop_vpncloud()
            results[str(crypto or "plain")] = res
        results['results'] = {
            "throughput_mbits": dict([
                (k, results[k]["iperf"]["throughput"] / 1000000.0) for k in ["native", "plain", "aes256", "chacha20"]
            ]),
            "latency_us": dict([
                (k, dict([
                    (str(s), (results[k]["ping_%s" % s]["rtt_avg"] - results["native"]["ping_%s" % s]["rtt_avg"])*1000.0/2.0) for s in [100, 500, 1000]
                ])) for k in ["plain", "aes256", "chacha20"]
            ])
        }
        return results



env = EC2Environment()
atexit.register(lambda: env.terminate())

perf = PerfTest.from_ec2_env(env)

start = time.time()
results = perf.run()
duration = time.time() - start

results["meta"]["duration"] = duration

name = "{date}_{version}_perf.json".format(date=date.today().strftime('%Y-%m-%d'), version=VERSION)
eprint('Storing results in {}'.format(name))
with open(name, 'w') as fp:
    json.dump(results, fp, indent=2)
eprint("done.")