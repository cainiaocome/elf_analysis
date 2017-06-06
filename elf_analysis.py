#!/usr/bin/env python3
# encoding: utf8

# 目前只在本机上使用，需要docker和wireshark，以及docker和wireshark的python库 
# docker-py
# pyshark
# 还有一个自制的docker image...速度太慢，git没法push，等找到好的机会push上来

import os
import sys
import time
import traceback
import json
import argparse
import random
import threading
from pprint import pprint

def start_thread_as_daemon(target, args):
    t = threading.Thread( target=target, args=args )
    t.daemon = True
    t.start()
    return t

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
    container = client.containers.run( 'pythonwithstrace', 'sleep 180', detach=True )
    # container started, and we have 3 minutes to test elf

    cmd = 'docker cp {} {}:{}'.format( elffilepath, container.id, in_docker_elffilepath )
    os.system( cmd )

    container.exec_run( 'chmod +x {}'.format( in_docker_elffilepath ) )
    container.exec_run( in_docker_elffilepath, detach=True )
    # elf started in docker

    def process_monitor( container ):
        # p[0]: user
        # p[1]: pid
        # p[-1]: exe
        old_process_list = container.top( ps_args='aux' )['Processes']
        while True:
            now_process_list = container.top( ps_args='aux' )['Processes']
            new_process_list = [ p for p in now_process_list if p[1] not in [ o[1] for o in old_process_list ] ]
            for p in new_process_list:
                print( 'process', '-->', p[0], p[1], p[-1] )
            old_process_list = now_process_list
    start_thread_as_daemon( process_monitor, args=[ container, ] )

    dns_query_set = set()
    connections = set()
    def pkt_callback( pkt ):
        if hasattr( pkt, 'dns' ):
            if pkt.dns.qry_name not in dns_query_set and hasattr( pkt.dns, 'resp_class' ):
                if hasattr( pkt.dns, 'a' ):
                    print( 'dns  ', pkt.dns.qry_name, '-->', pkt.dns.a )
                    dns_query_set.add( pkt.dns.qry_name )
                else:
                    pprint( 'unhandled dns query, check mannualy' ) 
        else:
            try:
                protocol = pkt.transport_layer
                src_addr = pkt.ip.src
                src_port = pkt[pkt.transport_layer].srcport
                dst_addr = pkt.ip.dst
                dst_port = pkt[pkt.transport_layer].dstport
                connection = (protocol, src_addr, src_port, dst_addr, dst_port)

                if connection not in connections:
                    print ( '%s  %s:%s --> %s:%s' % connection )
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
