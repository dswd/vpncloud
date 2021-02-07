#!/usr/bin/env python3

from common import EC2Environment, CREATE
import atexit, argparse, os

REGION = "eu-central-1"

VERSION = "2.1.0"


parser = argparse.ArgumentParser(description='Create a test setup')
parser.add_argument('--instancetype', default='t3a.nano', help='EC2 instance type')
parser.add_argument('--version', default=VERSION, help='VpnCloud version to use')
parser.add_argument('--count', '-c', dest="count", type=int, default=2, help='Number of instance to create')
parser.add_argument('--cluster', action="store_true", help='Cluster instances to get reliable throughput')
parser.add_argument('--subnet', help='AWS subnet id to use (empty = create new one)')
parser.add_argument('--keyname', help='Name of AWS keypair to use (empty = create new one)')
parser.add_argument('--keyfile', default="key.pem", help='Path of the private key file')


args = parser.parse_args()

privatekey = None
if args.keyname:
    with open(args.keyfile, 'r') as fp:
        privatekey = fp.read()

opts = {}
if os.path.exists(args.version):
    opts["vpncloud_file"] = args.version
    opts["vpncloud_version"] = None
else:
    opts["vpncloud_version"] = args.version

setup = EC2Environment(
    region = REGION, 
    node_count = args.count, 
    instance_type = args.instancetype, 
    cluster_nodes = args.cluster,
    subnet = args.subnet or CREATE, 
    keyname = args.keyname or CREATE,
    privatekey = privatekey,
    **opts
)

if not args.keyname:
    assert not os.path.exists(args.keyfile)
    with open(args.keyfile, 'x') as fp:
        fp.write(setup.privatekey)
    os.chmod(args.keyfile, 0o400)
    print("SSH private key written to {}".format(args.keyfile))
    atexit.register(lambda : os.remove(args.keyfile))
    print()

print("Nodes:")
for node in setup.nodes:
    print("\t {}@{}\tprivate: {}".format(setup.username, node.public_ip, node.private_ip))
print()

print("Press ENTER to shut down")
input()