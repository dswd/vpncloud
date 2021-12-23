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
import os
from datetime import date

MAX_WAIT = 300
CREATE = "***CREATE***"

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

def upload(connection, local, remote):
    ftp_client=connection.open_sftp()
    ftp_client.put(local, remote)
    ftp_client.close()

class SpotInstanceRequest:
    def __init__(self, id):
        self.id = id
    def __str__(self):
        return str(self.id)


class Node:
    def __init__(self, instance, connection):
        self.instance = instance
        self.connection = connection
        self.private_ip = instance.private_ip_address
        self.public_ip = instance.public_ip_address

    def run_cmd(self, cmd):
        return run_cmd(self.connection, cmd)

    def start_vpncloud(self, ip=None, crypto=None, password="test", device_type="tun", listen="3210", mode="normal", peers=[], claims=[]):
        args = [
            "--daemon", 
            "--no-port-forwarding", 
            "-t {}".format(device_type),
            "-m {}".format(mode),
            "-l {}".format(listen),
            "--password '{}'".format(password)
        ]
        if ip:
            args.append("--ip {}".format(ip))
        if crypto:
            args.append("--algo {}".format(crypto))
        for p in peers:
            args.append("-c {}".format(p))
        for c in claims:
            args.append("--claim {}".format(c))
        args = " ".join(args)
        self.run_cmd("sudo vpncloud {}".format(args))

    def stop_vpncloud(self, wait=True):
        self.run_cmd("sudo killall vpncloud")
        if wait:
            time.sleep(3.0)

    def ping(self, dst, size=100, count=10, interval=0.001):
        (out, _) = self.run_cmd('sudo ping {dst} -c {count} -i {interval} -s {size} -U -q'.format(dst=dst, size=size, count=count, interval=interval))
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

    def start_iperf_server(self):
        self.run_cmd('iperf3 -s -D')
        time.sleep(0.1)

    def stop_iperf_server(self):
        self.run_cmd('killall iperf3')

    def run_iperf(self, dst, duration):
        (out, _) = self.run_cmd('iperf3 -c {dst} -t {duration} --json'.format(dst=dst, duration=duration))
        data = json.loads(out)
        return {
            "throughput": data['end']['streams'][0]['receiver']['bits_per_second'],
            "cpu_sender": data['end']['cpu_utilization_percent']['host_total'],
            "cpu_receiver": data['end']['cpu_utilization_percent']['remote_total']
        }
    

def find_ami(region, owner, name_pattern, arch='x86_64'):
    ec2client = boto3.client('ec2', region_name=region)
    response = ec2client.describe_images(Owners=[owner], Filters=[
        {'Name': 'name', 'Values': [name_pattern]}, 
        {'Name': 'architecture', 'Values': ['x86_64']}
    ])
    try:
        image = max(response['Images'], key=lambda i: i['CreationDate'])
        return image['ImageId']
    except ValueError:
        return None


class EC2Environment:
    def __init__(self, vpncloud_version, region, node_count, instance_type, vpncloud_file=None, use_spot=True, max_price=0.1, ami=('amazon', 'amzn2-ami-hvm-*'), username="ec2-user", subnet=CREATE, keyname=CREATE, privatekey=CREATE, tag="vpncloud", cluster_nodes=False):
        self.region = region
        self.node_count = node_count
        self.instance_type = instance_type
        self.use_spot = use_spot
        self.max_price = str(max_price)
        if isinstance(ami, tuple):
            owner, name = ami
            self.ami = find_ami(region, owner, name)
            assert self.ami
        else:
            self.ami = ami
        self.username = username
        self.vpncloud_version = vpncloud_version
        self.vpncloud_file = vpncloud_file
        self.cluster_nodes = cluster_nodes
        self.resources = []
        self.instances = []
        self.connections = []
        self.nodes = []
        self.subnet = subnet
        self.tag = tag
        self.keyname = keyname
        self.privatekey = privatekey
        self.rsa_key = None
        try:
            eprint("Setting up resources...")
            self.setup()
            self.wait_until_ready()
            for i in range(0, self.node_count):
                self.nodes.append(Node(self.instances[i], self.connections[i]))
            eprint("Setup done")
            atexit.register(lambda : self.terminate())
            eprint()
        except:
            eprint("Error, shutting down")
            self.terminate()
            raise

    def track_resource(self, res):
        self.resources.append(res)
        eprint("\t{} {}".format(res.__class__.__name__, res.id if hasattr(res, "id") else ""))
        if hasattr(res, "create_tags") and not hasattr(res, "name"):
            res.create_tags(Tags=[{"Key": "Name", "Value": self.tag}])

    def setup_vpc(self):
        ec2 = boto3.resource('ec2', region_name=self.region)
        ec2client = boto3.client('ec2', region_name=self.region)

        vpc = ec2.create_vpc(CidrBlock='172.16.0.0/16')
        self.track_resource(vpc)
        vpc.wait_until_available()
        ec2client.modify_vpc_attribute(VpcId=vpc.id, EnableDnsSupport={'Value': True})
        ec2client.modify_vpc_attribute(VpcId=vpc.id, EnableDnsHostnames={'Value': True})

        igw = ec2.create_internet_gateway()
        self.track_resource(igw)
        igw.attach_to_vpc(VpcId=vpc.id)

        rtb = vpc.create_route_table()
        self.track_resource(rtb)
        rtb.create_route(DestinationCidrBlock='0.0.0.0/0', GatewayId=igw.id)

        subnet = ec2.create_subnet(CidrBlock='172.16.1.0/24', VpcId=vpc.id)
        self.track_resource(subnet)
        rtb.associate_with_subnet(SubnetId=subnet.id)

        self.subnet = subnet.id


    def setup(self):
        ec2 = boto3.resource('ec2', region_name=self.region)
        ec2client = boto3.client('ec2', region_name=self.region)

        if self.subnet == CREATE:
            self.setup_vpc()
        else:
            eprint("\tUsing subnet {}".format(self.subnet))

        vpc = ec2.Subnet(self.subnet).vpc

        sg = ec2.create_security_group(GroupName='SSH-ONLY', Description='only allow SSH traffic', VpcId=vpc.id)
        self.track_resource(sg)
        sg.authorize_ingress(CidrIp='0.0.0.0/0', IpProtocol='tcp', FromPort=22, ToPort=22)
        sg.authorize_ingress(CidrIp='172.16.1.0/24', IpProtocol='icmp', FromPort=-1, ToPort=-1)
        sg.authorize_ingress(CidrIp='172.16.1.0/24', IpProtocol='tcp', FromPort=0, ToPort=65535)
        sg.authorize_ingress(CidrIp='172.16.1.0/24', IpProtocol='udp', FromPort=0, ToPort=65535)

        if self.keyname == CREATE:
            key_pair = ec2.create_key_pair(KeyName="{}-keypair".format(self.tag))
            self.track_resource(key_pair)
            self.keyname = key_pair.name
            self.privatekey = key_pair.key_material
        self.rsa_key = paramiko.RSAKey.from_private_key(io.StringIO(self.privatekey))

        placement = {}
        if self.cluster_nodes:
            placement_group = ec2.create_placement_group(GroupName="{}-placement".format(self.tag), Strategy="cluster")
            self.track_resource(placement_group)
            placement = { 'GroupName': placement_group.name }
        
        userdata = """#cloud-config
packages:
  - iperf3
  - socat
"""
        if not self.vpncloud_file:
            userdata += """
runcmd:
  - wget https://github.com/dswd/vpncloud/releases/download/v{version}/vpncloud_{version}.x86_64.rpm -O /tmp/vpncloud.rpm
  - yum install -y /tmp/vpncloud.rpm
""".format(version=self.vpncloud_version)
        
        if self.use_spot:
            response = ec2client.request_spot_instances(
                SpotPrice = self.max_price,
                Type = "one-time",
                InstanceCount = self.node_count,
                LaunchSpecification = {
                    "ImageId": self.ami,
                    "InstanceType": self.instance_type,
                    "KeyName": key_pair.name,
                    "UserData": base64.b64encode(userdata.encode("ascii")).decode('ascii'),
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
                            'SubnetId': self.subnet,
                            'DeviceIndex': 0,
                            'AssociatePublicIpAddress': True,
                            'Groups': [sg.group_id]
                        }
                    ],
                    "Placement": placement
                }
            )
            requests = []
            for req in response['SpotInstanceRequests']:
                request = SpotInstanceRequest(req['SpotInstanceRequestId'])
                self.track_resource(request)
                requests.append(request)
            eprint("Waiting for spot instance requests")
            waited = 0
            self.instances = [None] * len(requests)
            while waited < MAX_WAIT:
                time.sleep(1.0)
                for i, req in enumerate(requests):
                    response = ec2client.describe_spot_instance_requests(SpotInstanceRequestIds=[req.id])
                    data = response['SpotInstanceRequests'][0]
                    if 'InstanceId' in data:
                        self.instances[i] = ec2.Instance(data['InstanceId'])
                        self.track_resource(self.instances[i])
                if min(map(bool, self.instances)):
                    break
            if waited >= MAX_WAIT:
                raise Exception("Waited too long")
        else:
            self.instances = ec2.create_instances(
                ImageId=self.ami,
                InstanceType=self.instance_type,
                MaxCount=self.node_count,
                MinCount=self.node_count,
                NetworkInterfaces=[
                    {
                        'SubnetId': self.subnet,
                        'DeviceIndex': 0,
                        'AssociatePublicIpAddress': True,
                        'Groups': [sg.group_id]
                    }
                ],
                Placement=placement,
                UserData=userdata,
                KeyName=key_pair.name
            )
            for instance in self.instances:
                self.track_resource(instance)

    def wait_until_ready(self):
        waited = 0
        eprint("Waiting for instances to start...")
        for instance in self.instances:
            instance.wait_until_running()
            instance.reload()
        eprint("Waiting for SSH to be ready...")
        self.connections = [None] * len(self.instances)
        while waited < MAX_WAIT:
            for i, instance in enumerate(self.instances):
                if self.connections[i]:
                    continue
                try:
                    self.connections[i] = self._connect(instance)
                except:
                    pass
            if min(map(bool, self.connections)):
                break
            time.sleep(1.0)
            waited += 1
        eprint("Waiting for instances to finish setup...")
        ready = [False] * len(self.connections)
        while waited < MAX_WAIT:
            for i, con in enumerate(self.connections):
                if ready[i]:
                    continue
                try:
                    run_cmd(con, 'test -f /var/lib/cloud/instance/boot-finished')
                    ready[i] = True
                except:
                    pass
            if min(map(bool, ready)):
                break
            time.sleep(1.0)
            waited += 1
        if waited >= MAX_WAIT:
            raise Exception("Waited too long")
        if self.vpncloud_file:
            eprint("Uploading vpncloud binary")
            for con in self.connections:
                upload(con, self.vpncloud_file, 'vpncloud')
                run_cmd(con, 'chmod +x vpncloud')
                run_cmd(con, 'sudo mv vpncloud /usr/bin/vpncloud')


    def terminate(self):
        if not self.resources:
            return
        eprint("Closing connections...")
        for con in self.connections:
            if con:
                con.close()
        self.connections = []
        eprint("Terminating instances...")
        for instance in self.instances:
            instance.terminate()
        for instance in self.instances:
            eprint("\t{}".format(instance.id))
            instance.wait_until_terminated()
        self.instances = []
        eprint("Deleting resources...")
        ec2client = boto3.client('ec2', region_name=self.region)
        for res in reversed(self.resources):
            eprint("\t{} {}".format(res.__class__.__name__, res.id if hasattr(res, "id") else ""))
            if isinstance(res, SpotInstanceRequest):
                ec2client.cancel_spot_instance_requests(SpotInstanceRequestIds=[res.id])
            if hasattr(res, "attachments"):
                for a in res.attachments:
                    res.detach_from_vpc(VpcId=a['VpcId'])
            if hasattr(res, "delete"):
                res.delete()
        self.resources = []

    def _connect(self, instance):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=instance.public_dns_name, username=self.username, pkey=self.rsa_key, timeout=1.0, banner_timeout=1.0)
        return client
