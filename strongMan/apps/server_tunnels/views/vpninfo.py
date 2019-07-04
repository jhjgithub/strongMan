# -*- coding: utf-8 -*-

# https://gist.github.com/SamuelDudley/40ea891c7f1fd0221bc0b25e185fe8c6

from __future__ import unicode_literals

import os
import socket
import fcntl
import struct
import vici
import multiprocessing
import collections
import time
from collections import OrderedDict
from datetime import timedelta, datetime
import logging
import psutil
import platform

from django.contrib import messages
from django.shortcuts import render
from django_tables2 import RequestConfig

from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.http import HttpResponse

#from strongMan.apps.pools.models import Pool
#from strongMan.helper_apps.vici.wrapper.exception import ViciException
#from .. import tables
#from strongMan.helper_apps.vici.wrapper.wrapper import ViciWrapper

# Create your views here.

logger = logging.getLogger('default')


def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915,  struct.pack('256s', ifname[:15]))[20:24])


def convert_size(size, precision=2):
    suffixes = ['B', 'KB', 'MB', 'GB', 'TB']
    suffixIndex = 0
    while size > 1024 and suffixIndex < 4:
        # increment the index of the suffix
        suffixIndex += 1
        #apply the division
        size = size/1024.0

    return "%.*f %s" % (precision, size, suffixes[suffixIndex])


def convert_time(seconds, granularity=2):
    intervals = (
        ('d', 86400),    # 60 * 60 * 24
        ('h', 3600),    # 60 * 60
        ('m', 60),
        ('s', 1),
        )

    result = []

    for name, count in intervals:
        value = seconds // count
        if value:
            seconds -= value * count
            if value == 1:
                name = name.rstrip('s')
            result.append("{}{}".format(value, name))

    return ', '.join(result[:granularity])


def convert_time_new(sec):
    seconds_to_minute = 60
    seconds_to_hour = 60 * seconds_to_minute
    seconds_to_day = 24 * seconds_to_hour

    days = sec / seconds_to_day
    sec %= seconds_to_day

    hours = sec / seconds_to_hour
    sec %= seconds_to_hour

    minutes = sec / seconds_to_minute
    sec %= seconds_to_minute

    seconds = sec

    #print("%dD, %dH, %dm, %ds" % (days, hours, minutes, seconds))
    print("%d Days %d:%d:%d" % (days, hours, minutes, seconds))


class VState(object):
    """holds the VPN state"""
    def __init__(self):
        self.alive = True
        self.session = vici.Session()
        self.conns = []
        self.active_conns = []
        self.target_conns = ['rw-ikev2']
        #self.users = {}


class StrongSwan(object):
    def __init__(self,  queue=None):
        self.state = VState()
        self.get_possible_connections()

    def process_control_connection_in(self):
        '''handle incoming mavlink packets'''
        pass

    def inc_user_usage(self, summary, username):
        users = summary['userinfo']
        usage = 0

        if username in users:
            users[username] += 1
        else:
            users[username] = 1

    def get_sa_info(self, summary, name, sa):
        si = {'child-sas': {}}
        uid = sa['uniqueid']
        try:
            #print("SA: ", sa)
            #msg.append('name: \t%s' % name)

            si['name'] = name
            age = sa['established']
            now = datetime.now()
            now = now.replace(microsecond=0)
            si['date'] = now - timedelta(seconds=int(age))
            si['age'] = age
            si['state'] = sa['state']
            si['local'] = sa['local-host']
            si['remote'] = sa['remote-host']
            si['remote-vips'] = sa['remote-vips']
            rid = ''
            if 'remote-eap-id' in sa:
                rid = sa['remote-eap-id']
            elif 'remote-id' in sa:
                rid = sa['remote-id']

            si['login-id'] = rid
            self.inc_user_usage(summary, rid)

        except Exception as e:
            print(e)
            pass

        try:
            child = sa['child-sas']
            for child_key in child:
                c = {}
                ch = child[child_key]
                #print("Child SA", child)
                #msg.append("  Child SA: %s" % child_key)

                c['uniqueid'] = ch['uniqueid']
                c['reqid'] = ch['reqid']
                c['bytes-in'] = ch['bytes-in']
                c['bytes-out'] = ch['bytes-out']

                si['child-sas'][child_key] = c

        except Exception as e:
            print('tunnel not connected at child level!')
            print(e)
            pass

        summary['sa-details'][uid] = si

    def get_sa_summary(self, summary):
        state = self.state
        #sas = state.session.list_sas()
        for vpn_conn in state.session.list_sas():
            #print("!!!!", vpn_conn)
            for name, sa in vpn_conn.items():
                self.get_sa_info(summary, name, sa)

    def connection_up(self, key):
        state = self.state
        print('up: ', key)
        sa = OrderedDict()
        sa['child'] = key
        sa['timeout'] = '2000'
        sa['loglevel'] = '0'
        rep = state.session.initiate(sa)
        rep.next()
        rep.close()

        #TODO: handle errors, log?

    def connection_down(self, key):
        state = self.state
        print('down: ', key)
        sa = OrderedDict()
        sa['ike'] = key
        sa['timeout'] = '2000'
        sa['loglevel'] = '0'
        rep = state.session.terminate(sa)
        rep.next()
        rep.close()


    def get_possible_connections(self):
        '''reset and repopulate possible connections based on /etc/ipsec.conf'''
        state = self.state
        state.conns = []
        for conn in state.session.list_conns():
            for key in conn:
                state.conns.append(key)

        #print('p',state.conns)

    def get_active_connections(self):
        state = self.state
        state.active_conns = []

        for conn in state.session.list_sas():
            for key in conn:
                state.active_conns.append(key)

        #print('a', state.active_conns)

    def is_alive(self):
        return self.state.alive


def get_net_usage():
    usage = psutil.net_io_counters(pernic=True)
    ifaces = psutil.net_if_addrs()
    tsent = 0
    trecv = 0
    eth0_ip = ""
    for k, v in ifaces.items():
        if k == 'lo':
            continue

        ip = v[0].address
        if k == 'eth0':
            eth0_ip = ip

        data = usage[k]
        nic = usage[k]
        tsent += nic.bytes_sent
        trecv += nic.bytes_recv

        #sent = convert_size(nic.bytes_sent)
        #recv = convert_size(nic.bytes_recv)
        #print("%s: IP: %s, Sent: %s, Recv: %s" % (k, ip, sent, recv))

    total = convert_size(tsent + trecv)
    tsent = convert_size(tsent)
    trecv = convert_size(trecv)
    #print("Network Usage: Sent: %s, Recv: %s" % (tsent, trecv))

    return {'total': total, 'tsent': tsent, 'trecv': trecv, 'eth0_ip': eth0_ip}


def get_cpu_usage():
    cpu = psutil.cpu_percent(interval=None)
    #cpu = psutil.cpu_percent(interval=2)
    #print("CPU Usage: %s" % (cpu))

    return cpu


def get_mem_usage():
    mem = psutil.virtual_memory()
    total = convert_size(mem.total)
    available = convert_size(mem.available)
    used = convert_size(mem.used)
    free = convert_size(mem.free)
    #print("Mem Usage: %s, Available: %s, Used: %s, Free: %s" % (total, available, used, free))
    return {'total': total, 'available': available, 'used': used, 'free': free}


def get_disk_usage():
    disk = psutil.disk_usage('/')
    total = convert_size(disk.total)
    used = convert_size(disk.used)
    free = convert_size(disk.free)
    #print("Disk Usage: %s, Used: %s(%.1f%%), Free: %s" % (total, used, disk.percent, free))
    return {'total': total, 'used': used, 'free': free}


def get_boot_time():
    bt = psutil.boot_time()
    bt_str = datetime.fromtimestamp(bt).strftime("%Y-%m-%d %H:%M:%S")
    #print("Boot Time: %s" % (bt_str))
    return bt_str


def sa_summary():
    summary = {'summary': {'conns': 0, 'sas': 0}, 'sa-details': {}, 'userinfo': {}}

    try:
        #make a strongSwan control object
        VPN = StrongSwan()

        if VPN.is_alive() is False:
            raise Exception

        #VPN.process_control_connection_in()

        VPN.get_possible_connections()
        ac = len(VPN.state.conns)
        at = 0

        #if ac > 0:
        #    VPN.get_active_connections()
        #    at = len(VPN.state.active_conns)
        #    print("###", VPN.state.active_conns)
        #    print("@@@", at)
        #if at > 0:
        #    VPN.get_sa_summary(summary)

        VPN.get_sa_summary(summary)

        # sorting
        s = summary['sa-details']
        s1 = OrderedDict(sorted(s.items(), key=lambda t: t[1]['date'], reverse=True))
        #s1 = OrderedDict(sorted(s.items(), key=lambda t : t[1]['date']))
        at = len(s1)
        summary['sa-details'] = s1

        summary['summary'] = {'conns': ac, 'sas': at}

        u = summary['userinfo']
        u1 = OrderedDict(sorted(u.items(), key=lambda t: t[0], reverse=False))
        summary['userinfo'] = u1

    except Exception as e:
        print(e)
        pass

    return summary


def get_string(s):
    return s.decode()


def sa_summary_html():
    msg = []
    summary = {}

    try:
        summary = sa_summary()
        netusage = get_net_usage()
        cpuusage = get_cpu_usage()
        memusage = get_mem_usage()
        diskusage = get_disk_usage()
        bt = get_boot_time()


        #msg.append("<h2><span> <p> System Infomation </p> </h2>")
        msg.append("<table class=\"tunnel-header\" width=400> <thead> <tr>")
        msg.append("<th >System Summary</th></thead></table>")

        msg.append("<table class=\"tunnel\" width=1100> <thead> <tr>")
        msg.append("<th scope=\"cols\" width=150>Host(IP)</th>")
        msg.append("<th scope=\"cols\" width=300>Traffic(In/Out)</th>")
        msg.append("<th scope=\"cols\" width=100>CPU</th>")
        msg.append("<th scope=\"cols\" width=150>Memory(Free)</th>")
        msg.append("<th scope=\"cols\" width=150>Disk(Free)</th>")
        msg.append("<th scope=\"cols\" widht=150>Boot Date</th></tr></thead><tbody><tr>")

        hname = platform.node()
        msg.append("<td scope=\"row\">%s<br>%s</td>" % (hname, netusage['eth0_ip']))
        msg.append("<td scope=\"row\">%s<br>(Sent:%s Revc:%s) </td>" % (netusage['total'], netusage['tsent'], netusage['trecv']))
        msg.append("<td scope=\"row\">%d %%</td>" % cpuusage)
        msg.append("<td scope=\"row\">%s<br>%s</td>" % (memusage['total'], memusage['free']))
        msg.append("<td scope=\"row\">%s<br>%s</td>" % (diskusage['total'], diskusage['free']))
        msg.append("<td scope=\"row\">%s</td>" % bt)
        msg.append("</tr></tbody></table>")

        s = summary['summary']

        msg.append("<h3></h3>")
        msg.append("<table class=\"tunnel-header\" width=400> <thead> <tr>")
        msg.append("<th >Tunnel Summary</th></thead></table>")

        msg.append("<table class=\"tunnel\" width=400> <thead> <tr>")
        msg.append("<th scope=\"cols\" width=200>Configurations</th>")
        msg.append("<th scope=\"cols\" widht=200>Active Tunnels</th></tr></thead><tbody><tr>")
        msg.append("<td scope=\"row\">%d</td>" % s['conns'])
        msg.append("<td scope=\"row\">%d</td></tr></tbody></table>" % s['sas'])

        u = summary['userinfo']
        msg.append("<h3></h3>")
        msg.append("<table class=\"tunnel-header\" width=400> <thead> <tr>")
        msg.append("<th>Login Summary</th></thead></table>")
        msg.append("<table class=\"tunnel\" width=400> <thead> <tr>")
        msg.append("<th scope=\"cols\" width=200>User</td>")
        msg.append("<th scope=\"cols\" width=200>Login Count</td></tr><tbody><tr>")

        for name, cnt in u.items():
            msg.append("<tr>")
            msg.append("<td scope=\"row\">{}</td>".format(name.decode()))
            msg.append("<td scope=\"row\">{}</td>".format(cnt))
            msg.append("</tr>")

        msg.append("</tbody></table>")

        msg.append("<h3></h3>")
        msg.append("<table class=\"tunnel-header\" width=400> <thead> <tr>")
        msg.append("<th>Active Tunnel Information</th></thead></table>")

        msg.append("<table class=\"tunnel\" width=1100> <thead><tr>")
        msg.append("<th scope=\"cols\" width=100>ID</th>")
        msg.append("<th scope=\"cols\" width=200>User</th>")
        msg.append("<th scope=\"cols\" width=400>Date</th>")
        msg.append("<th scope=\"cols\" width=200>Config</th>")
        #msg.append("<th scope=\"cols\" width=350px>State</th>")
        msg.append("<th scope=\"cols\" width=200>Local</th>")
        msg.append("<th scope=\"cols\" width=200>Remote</th>")
        msg.append("<th scope=\"cols\" width=200>VIP(s)</th>")
        msg.append("<th scope=\"cols\" width=300>In Bytes</th>")
        msg.append("<th scope=\"cols\" width=300>Out Bytes</th>")
        msg.append("<th scope=\"cols\" width=300>Age</th>")
        msg.append("</tr></thead><tbody>")

        d = summary['sa-details']
        #print(d)
        for uid, details in d.items():
            msg.append("<tr>")
            msg.append("<td scope=\"row\" >{}</td>".format(get_string(uid)))
            msg.append("<td scope=\"row\" >{}</td>".format(get_string(details['login-id'])))
            msg.append("<td scope=\"row\" >{}</td>".format(details['date']))
            msg.append("<td scope=\"row\" >{}</td>".format(details['name']))
            #msg.append("<td scope=\"row\" >" % details['state'])
            msg.append("<td scope=\"row\" >{}</td>".format(get_string(details['local'])))
            msg.append("<td scope=\"row\" >{}</td>".format(get_string(details['remote'])))
            _vip = get_string(details['remote-vips'][0])
            msg.append("<td scope=\"row\" >{}</td>".format(_vip))

            bytin = 0
            bytout = 0

            for cname, cdetails in details['child-sas'].items():
                #print("  child SA: \t%s" % cname)
                #print("  unique id: \t%s" % cdetails['uniqueid'])
                #print("  req id: \t%s" % cdetails['reqid'])
                #print("  bytes-in: \t%s" % cdetails['bytes-in'])
                #print("  bytes-out: \t%s" % cdetails['bytes-out'])
                bytin += int(cdetails['bytes-in'])
                bytout += int(cdetails['bytes-out'])

            msg.append("<td scope=\"row\">%s</td>" % convert_size(bytin))
            msg.append("<td scope=\"row\">%s</td>" % convert_size(bytout))
            msg.append("<td scope=\"row\">%s</td>" % convert_time(int(details['age'])))
            msg.append("</tr>")

        msg.append("</tbody></table>")
        #msg.append("</body> ")
        #msg.append("</html>")
    except Exception as e:
        logger.error("except: %s", str(e))
        pass

    html_string = '\r\n'.join(msg)

    return html_string


class OverviewHandler(object):
    def __init__(self, request):
        self.request = request
        self.ENTRIES_PER_PAGE = 50

    def handle(self):
        try:
            return self._render()
        #except ViciException as e:
        except Exception as e:
            messages.warning(self.request, str(e))

    def _render(self):
        h = ""
        try:
            h = sa_summary_html()
        except Exception as e:
            logger.error(e)

        return render(self.request, 'server_tunnels/tunnels1.html', {'msg': h})
