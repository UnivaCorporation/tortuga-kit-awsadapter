#!/usr/bin/env python3

import itertools
import json
import os
import random
import socket
import subprocess
import sys
import tempfile
import time

# Default settings
operating_system = 'debian'
cloud_provider = 'aws'
installerIpAddress = None
installerHostName = None
port = None
dns_search = None
override_dns_domain = False
dns_options = None
dns_nameservers = []
dns_domain = None
insertnode_request = None


### SETTINGS


class ReqMixin:
    class NotFound(Exception):
        pass

    class InvalidCredentials(Exception):
        pass

    def req(self, u, h=None, d=None):
        _req = getattr(
            self, '_req_py{}'.format(self._get_py_maj()))
        return _req(u, h, d)

    def _get_py_maj(self):
        return sys.version_info[0]

    def _req_py2(self, u, h=None, d=None):
        import urllib2
        req = urllib2.Request(u)
        if h:
            for k, v in h.items():
                req.add_header(k, v)
        try:
            if d:
                res = urllib2.urlopen(req, d)
            else:
                res = urllib2.urlopen(req)
        except urllib2.HTTPError as ex:
            if ex.code == 404:
                raise self.NotFound(str(ex))
            elif ex.code == 401:
                raise self.InvalidCredentials()
            raise
        if res.code != 200:
            raise Exception('Unable to read URL: {}'.format(u))
        return res.read()

    def _req_py3(self, u, h=None, d=None):
        from urllib import request, error
        req = request.Request(u)
        if isinstance(d, str):
            d = d.encode()
        if h:
            for k, v in h.items():
                req.add_header(k, v)
        try:
            if d:
                res = request.urlopen(req, d)
            else:
                res = request.urlopen(req)
        except error.HTTPError as ex:
            if ex.code == 404:
                raise self.NotFound(str(ex))
            elif ex.code == 401:
                raise self.InvalidCredentials()
            raise
        if res.code != 200:
            raise Exception('Unable to read URL: {}'.format(u))
        return res.read().decode()


class ProviderBase(ReqMixin):
    def __init__(self):
        self.bootstrapper = None

    def set_bootstrapper(self, b):
        self.bootstrapper = b

    def get_node_name(self):
        raise NotImplementedError()

    def get_node_metadata(self):
        return {}


class BootstrapperBase(ReqMixin):
    def __init__(self, cloud_provider_helper, installer_hostname,
                 installer_ip_address, port, override_dns_domain=None,
                 dns_domain=None, dns_search=None, dns_options=None,
                 dns_nameservers=None, insertnode_request=None):
        self.cloud_provider_helper = cloud_provider_helper
        self.cloud_provider_helper.set_bootstrapper(self)
        self.installer_hostname = installer_hostname
        self.installer_ip_address = installer_ip_address
        self.port = port
        self.override_dns_domain = override_dns_domain
        self.dns_domain = dns_domain
        self.dns_search = dns_search
        self.dns_options = dns_options
        self.dns_nameservers = dns_nameservers
        self.insertnode_request = insertnode_request

    def run(self):
        self.cfg_dns()
        self.add_node()
        self.disable_selinux()
        self.install_puppet()
        self.boot_puppet()

    def cfg_dns(self):
        if not self.installer_ip_address:
            raise Exception('Installer hostname not set')
        if not self.installer_ip_address:
            raise Exception('Installer IP address not set')
        with open('/etc/hosts', 'a+') as fp:
            fp.write('{}\t{}\n'.format(
                self.installer_ip_address, self.installer_hostname))
        if self.override_dns_domain:
            with open('/etc/resolv.conf', 'w') as fp:
                fp.write('# Created by Tortuga\n')
                if self.dns_search:
                    fp.write('search {}}\n'.format(self.dns_search))
                if self.dns_options:
                    fp.write('options {}\n'.format(self.dns_options))
                if not self.dns_nameservers:
                    raise Exception("DNS nameservers not set")
                if not isinstance(self.dns_nameservers, list):
                    raise Exception("DNS nameservers must be a list")
                for ns in self.dns_nameservers:
                    fp.write('nameserver {}\n'.format(ns))
                if not self.dns_domain:
                    raise Exception("DNS domain not set")
                fqdn = '{}.{}'.format(
                    socket.getfqdn().split('.', 1)[0],
                    self.dns_domain
                )
                self.try_cmd(
                    'hostnamectl set-hostname --static {}'.format(fqdn))

    def add_node(self):
        if not self.insertnode_request:
            print("No insertnode_request, skipping add_node")
            return
        if not self.installer_ip_address:
            raise Exception("Installer IP address not set")
        self.try_cmd("mkdir -p /etc/pki/ca-trust/source/anchors/")
        self.try_cmd(
            "curl http://{}:8008/ca.pem > "
            "/etc/pki/ca-trust/source/anchors/tortuga-ca.pem".format(
                self.installer_ip_address)
        )
        self.try_cmd("update-ca-trust")
        d = {
            'node_details': {
                'name': self.cloud_provider_helper.get_node_name(),
                'metadata': self.cloud_provider_helper.get_node_metadata(),
            }
        }
        print('Instance details: ' + json.dumps(d))
        u = 'https://{}:{}/v1/node-token/{}'.format(
            self.installer_hostname, self.port, self.insertnode_request)
        h = {
            'Content-Type': 'application/json'
        }
        for i in range(5):
            try:
                print('Add node: {}'.format(u))
                res = self.req(u, h=h, d=json.dumps(d))
                break
            except self.InvalidCredentials:
                raise Exception('Invalid Tortuga credentials')
            except self.NotFound:
                raise Exception('Tortuga URI not found')
            except Exception as ex:
                print(str(ex))
                time.sleep(2 ** (i + 1))
        else:
            raise Exception('Unable to communicate with Tortuga')
        print(json.load(res))

    def disable_selinux(self):
        self.try_cmd('setenforce permissive')

    def install_puppet(self):
        raise NotImplementedError()

    def boot_puppet(self):
        self.try_cmd('touch /tmp/puppet_bootstrap.log')
        cmd = (
            '/opt/puppetlabs/bin/puppet agent'
            ' --logdest /tmp/puppet_bootstrap.log'
            ' --no-daemonize'
            ' --onetime --server {}'
            ' --waitforcert 120'.format(self.installer_hostname)
        )
        self.try_cmd(cmd, good_return_values=(0, 2), time_limit=10 * 60)

    def try_cmd(self, command, good_return_values=(0,), retry_limit=0,
                time_limit=0, max_sleep_time=15000, sleep_interval=2000):
        total_sleep_time = 0
        for retries in itertools.count(0):
            returned = subprocess.Popen(command, shell=True).wait()
            if returned in good_return_values or \
                    retries >= retry_limit or total_sleep_time >= time_limit:
                return returned
            seed = min(max_sleep_time, sleep_interval * 2 ** retries)
            sleep_for = (seed / 2 + random.randint(0, seed / 2)) / 1000.0
            total_sleep_time += sleep_for
            time.sleep(sleep_for)


class AwsProvider(ProviderBase):
    def get_node_name(self):
        return self._get_inst_data('/local-hostname')

    def get_node_metadata(self):
        return {
            'ec2_instance_id': self._get_inst_data('/instance-id'),
            'ec2_ipaddress': self._get_inst_data('/local-ipv4'),
        }

    def _get_inst_data(self, path):
        u = 'http://169.254.169.254/latest/meta-data' + path
        for i in range(5):
            try:
                print('Get instance data: {}'.format(u))
                return self.req(u)
            except self.NotFound:
                raise
            except Exception as ex:
                print(ex)
                time.sleep(2 ** (i + 1))
        else:
            raise Exception('Unable to communicate with metadata service')


class AzureProvider(ProviderBase):
    def get_node_name(self):
        if self.bootstrapper.override_dns_domain:
            return socket.getfqdn() + "." + self.bootstrapper.dns_domain
        else:
            return socket.gethostname() + "." + \
                   self.bootstrapper.installer_hostname.split('.', 1)[1]

    def get_node_metadata(self):
        instance_name = self._get_inst_data('/compute/name')
        try:
            scale_set_name = self._get_inst_data(
                '/compute/vmScaleSetName')
            instance_id = int(instance_name.rsplit('_', 1)[1])
        except:
            instance_id = instance_name
            scale_set_name = ""
        return {
            'instance_id': instance_id,
            'private_ip': self._get_inst_data(
                '/network/interface/0/ipv4/ipAddress/0/privateIpAddress'),
            'scale_set_name': scale_set_name,
        }

    def _get_inst_data(self, path):
        u = ('http://169.254.169.254/metadata/instance{}'
               '?api-version=2019-04-30&format=text'.format(path))
        h = {
            'Metadata': 'true'
        }
        for i in range(5):
            try:
                print('Get instance data: {}'.format(u))
                return self.req(u, h)
            except self.NotFound:
                raise
            except Exception as ex:
                print(ex)
                time.sleep(2 ** (i + 1))
        else:
            raise Exception('Unable to communicate with metadata webservice')


class GcpProvider(ProviderBase):
    def get_node_name(self):
        return self._get_inst_data('/hostname')

    def get_node_metadata(self):
        return {
            'instance_name': self._get_inst_data('/name')
        }

    def _get_inst_data(self, path):
        u = 'http://169.254.169.254/computeMetadata/v1/instance' + path
        h = {
            'Metadata-Flavor': 'Google'
        }
        for i in range(5):
            try:
                print('Get instance data: {}'.format(u))
                return self.req(u, h=h)
            except self.NotFound:
                raise
            except Exception as ex:
                print(ex)
                time.sleep(2 ** (i + 1))
        else:
            raise Exception('Unable to communicate with metadata webservice')


class CentOsBootstrapper(BootstrapperBase):
    def install_puppet(self):
        if self._is_installed('puppet-agent'):
            return
        if not self._is_installed('git'):
            self._install('git')
        pkg = 'puppet5-release'
        if not self._is_installed(pkg):
            ver = self._get_major_ver()
            u = ('http://yum.puppetlabs.com/puppet5/'
                   '{}-el-{}.noarch.rpm'.format(pkg, ver))
            result = self.try_cmd('rpm -ivh {}'.format(u),
                                      retry_limit=5)
            if result != 0:
                raise Exception('Unable to install package: {}'.format(pkg))
        self._install('puppet-agent')

    def _get_major_ver(self):
        result = self.try_cmd(
            'rpm --query --queryformat %{VENDOR} system-release |'
            ' grep --quiet --ignore-case Amazon'
        )
        if result == 0:
            # amazon linuxv2
            self.try_cmd(
                'awk -F: \'{ print $6 }\' /etc/system-release-cpe |'
                'grep --quiet \'^2$\''
            )
            if result == 0:
                return 7
            return 6
        import platform
        vals = platform.dist()
        return vals[1].split('.')[0]

    def _install(self, pkg, opts=None, retries=10):
        cmd = ['yum']
        if opts:
            cmd.append(opts)
        cmd.extend(['-y', 'install', pkg])
        result = self.try_cmd(' '.join(cmd), retry_limit=retries)
        if result != 0:
            raise Exception('Error installing package: {}'.format(pkg))

    def _is_installed(self, pkg):
        return self.try_cmd('rpm -q --quiet {}'.format(pkg)) == 0


class DebianBootstrapper(BootstrapperBase):
    def install_puppet(self):
        if self._is_installed('puppet-agent'):
            return
        pkg = 'puppet5-release'
        if not self._is_installed(pkg):
            ver = self._get_ver()
            u = 'http://apt.puppetlabs.com/{}-{}.deb'.format(pkg, ver)
            tmptuple = tempfile.mkstemp()
            try:
                retval = self.try_cmd(
                    'wget --tries 5 --retry-connrefused --timeout 120'
                    ' --random-wait --quiet {} --output-document {}'.format(
                        u, tmptuple[1])
                )
                if retval != 0:
                    raise Exception(
                        'Unable to download package: {}'.format(pkg))
                cmd = 'dpkg --install %s' % (tmptuple[1])
                retval = self.try_cmd(cmd)
                if retval != 0:
                    raise Exception(
                        'Error installing package: {}'.format(pkg))
            finally:
                os.close(tmptuple[0])
                os.unlink(tmptuple[1])
            self.try_cmd('apt-get update')

        self._install('puppet-agent')
        self.try_cmd('systemctl disable puppet.service')
        self.try_cmd('systemctl stop puppet.service')

    def _get_ver(self):
        import platform
        vals = platform.dist()
        if vals[0].lower() == 'debian':
            cmd = 'dpkg --status tzdata|grep Provides|cut -f2 -d\'-\''
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)
            codename = None
            while True:
                buf = p.stdout.readline()
                if not buf:
                    break
                codename = str(buf.rstrip(), 'utf-8')
            retval = p.wait()
            if retval != 0:
                raise Exception('Error: unable to determine Debian version')
        else:
            # Ubuntu reports the codename through platform.dist()
            codename = vals[2]
        return codename

    def _install(self, pkg, retries=10):
        cmd = 'apt-get --assume-yes install {}'.format(pkg)
        result = self.try_cmd(cmd, retry_limit=retries)
        if result != 0:
            raise Exception('Error installing package: {}'.format(pkg))

    def _is_installed(self, pkg):
        return self.try_cmd(
            'dpkg -l {} 2>/dev/null | grep -q ^ii'.format(pkg)) == 0


BOOTSTRAPPERS = {
    'centos': CentOsBootstrapper,
    'debian': DebianBootstrapper
}


PROVIDERS = {
    'aws': AwsProvider,
    'azure': AzureProvider,
    'gcp': GcpProvider,
}


if __name__ == '__main__':
    Bootstrapper = BOOTSTRAPPERS[operating_system]
    Provider = PROVIDERS[cloud_provider]
    bs = Bootstrapper(
        Provider(),
        installerHostName,
        installerIpAddress,
        port,
        override_dns_domain=override_dns_domain,
        dns_domain=dns_domain,
        dns_search=dns_search,
        dns_options=dns_options,
        dns_nameservers=dns_nameservers,
        insertnode_request=insertnode_request
    )
    bs.run()
