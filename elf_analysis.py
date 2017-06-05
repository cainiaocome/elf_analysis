#!/usr/bin/env python3
# encoding: utf8

# 目前只在本机上使用，需要docker和wireshark，以及docker和wireshark的python库 
# docker-py
# pyshark

import os
import sys
import time
import traceback
import json
import argparse
import random
import threading
from pprint import pprint

def main():
    import docker
    import pyshark
    import shutil
    import concurrent.futures._base

    argparser = argparse.ArgumentParser()
    argparser.add_argument('-f', '--file', type=str, required=True, help='elf file to analysis')
    args = argparser.parse_args()

    elffilepath = os.path.abspath( args.file )
    elffilename = os.path.basename( args.file )
    in_docker_elffilepath = '/tmp/{}'.format( elffilename )
    # elf info done

    client = docker.from_env()
    container = client.containers.run( 'strace', 'sleep 30', detach=True )
    # container started, and we have 3 minutes to test elf

    cmd = 'docker cp {} {}:{}'.format( elffilepath, container.id, in_docker_elffilepath )
    os.system( cmd )

    container.exec_run( 'chmod +x {}'.format( in_docker_elffilepath ) )
    container.exec_run( in_docker_elffilepath, detach=True )
    # elf started in docker

    dns_query_set = set()
    connections = set()
    def pkt_callback( pkt ):
        if hasattr( pkt, 'dns' ):
            if pkt.dns.qry_name not in dns_query_set:
                print( 'dns  ' + pkt.dns.qry_name )
                dns_query_set.add( pkt.dns.qry_name )
        else:
            try:
                protocol =  pkt.transport_layer
                src_addr = pkt.ip.src
                src_port = pkt[pkt.transport_layer].srcport
                dst_addr = pkt.ip.dst
                dst_port = pkt[pkt.transport_layer].dstport
                connection = (protocol, src_addr, src_port, dst_addr, dst_port)

                if connection not in connections:
                    print ( '%s  %s:%s --> %s:%s' % (protocol, src_addr, src_port, dst_addr, dst_port) )
                    connections.add( connection )
            except AttributeError as e:
                #ignore packets that aren't TCP/UDP or IPv4
                pass

    livecap = pyshark.LiveCapture( interface='docker0' )

    try:
        livecap.apply_on_packets( pkt_callback, timeout=30 )
    except concurrent.futures._base.TimeoutError:
        pass

if __name__ == '__main__':
    main()
