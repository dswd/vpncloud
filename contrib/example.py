#!/usr/bin/env python3

from common import EC2Environment, CREATE
import time

setup = EC2Environment(
    region = "eu-central-1", 
    node_count = 2, 
    instance_type = 't3a.nano', 
    vpncloud_version = "2.1.0"
)

sender = setup.nodes[0]
receiver = setup.nodes[1]

sender.start_vpncloud(ip="10.0.0.1/24")
receiver.start_vpncloud(ip="10.0.0.2/24", peers=["{}:3210".format(sender.private_ip)])
time.sleep(1.0)

sender.ping("10.0.0.2")

sender.stop_vpncloud()
receiver.stop_vpncloud()