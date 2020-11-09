#!/usr/bin/env python

import itertools, json, os, random, socket, subprocess, sys, tempfile, time

operating_system = 'centos'
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

    def req(self, u, h={}, d=None):
        return getattr(self, '_req_py{}'.format(self._get_py_maj()))(u, h, d)

    def _get_py_maj(self):
        return sys.version_info[0]

    def _req_py2(self, u, h={}, d=None):
        import urllib2
        req = urllib2.Request(u)
        for k, v in h.items():
            req.add_header(k, v)
        try:
            res = urllib2.urlopen(req, data=d if d else None)
        except urllib2.HTTPError as ex:
            if ex.code == 404:
                raise self.NotFound(str(ex))
            elif ex.code == 401:
                raise self.InvalidCredentials()
            raise
        if res.code != 200:
            raise Exception('Unable to read URL: {}'.format(u))
        return res.read()

    def _req_py3(self, u, h={}, d=None):
        from urllib import request, error
        req = request.Request(u)
        d = d.encode() if isinstance(d, str) else d
        for k, v in h.items():
            req.add_header(k, v)
        try:
            res = request.urlopen(req, data=d if d else None)
        except error.HTTPError as ex:
            if ex.code == 404:
                raise self.NotFound(str(ex))
            elif ex.code == 401:
                raise self.InvalidCredentials()
            raise
        if res.code != 200:
            raise Exception('Unable to read URL: {}'.format(u))
        return res.read().decode()


class ProvBase(ReqMixin):
    def __init__(self):
        self.bootstrapper = None

    def set_bootstrapper(self, b):
        self.bootstrapper = b

    def get_node_name(self):
        raise NotImplementedError()

    def get_node_metadata(self):
        return {}


class BootstrapperBase(ReqMixin):
    cert_loc = "/etc/pki/ca-trust/source/anchors"
    cert_ext = "pem"
    cert_update_cmd = "update-ca-trust"

    def __init__(self, provider, inst_hname, inst_ip, port,
                 override_dns_domain=None, dns_domain=None, dns_search=None,
                 dns_opts=None, dns_nameservers=None, insertnode_req=None):
        self.provider = provider
        self.provider.set_bootstrapper(self)
        self.inst_hname = inst_hname
        self.inst_ip = inst_ip
        self.port = port
        self.override_dns_domain = override_dns_domain
        self.dns_domain = dns_domain
        self.dns_search = dns_search
        self.dns_opts = dns_opts
        self.dns_nameservers = dns_nameservers
        self.insertnode_req = insertnode_req

    def run(self):
        self.cfg_dns()
        self.add_node()
        self.dis_selinux()
        self.inst_puppet()
        self.boot_puppet()

    def cfg_dns(self):
        if not self.inst_ip:
            raise Exception('Installer hostname not set')
        if not self.inst_ip:
            raise Exception('Installer IP address not set')
        with open('/etc/hosts', 'a+') as fp:
            fp.write('{}\t{}\n'.format(
                self.inst_ip, self.inst_hname))
        if self.override_dns_domain:
            with open('/etc/resolv.conf', 'w') as fp:
                fp.write('# Created by Tortuga\n')
                if self.dns_search:
                    fp.write('search {}\n'.format(self.dns_search))
                if self.dns_opts:
                    fp.write('options {}\n'.format(self.dns_opts))
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
        else:
            with open('/etc/resolv.conf', 'r') as fp:
                data = fp.read().strip().split('\n')
            data = ['# Rewritten by Tortuga'] + data
            ns_line = \
                next((l for l in data if l.startswith('nameserver ')), None)
            if ns_line is not None:
                data.insert(data.index(ns_line),
                            'nameserver {}'.format(installerIpAddress))
            with open('/etc/resolv.conf', 'w') as fp:
                fp.write("\n".join(data))

    def add_node(self):
        if not self.insertnode_req:
            print("No insertnode_request, skipping add_node")
            return
        if not self.inst_ip:
            raise Exception("Installer IP address not set")
        self.add_installer_cert()
        d = {
            'node_details': {
                'name': self.provider.get_node_name(),
                'metadata': self.provider.get_node_metadata(),
            }
        }
        print('Instance details: ' + json.dumps(d))
        u = 'https://{}:{}/v1/node-token/{}'.format(
            self.inst_hname, self.port,
            self.insertnode_req.decode())
        h = {'Content-Type': 'application/json'}
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
        print(json.loads(res))

    def add_installer_cert(self):
        self.try_cmd("mkdir -p {}".format(self.cert_loc))
        self.try_cmd("curl http://{}:8008/ca.pem > {}/tortuga-ca.{}".format(
            self.inst_ip, self.cert_loc, self.cert_ext)
        )
        self.try_cmd(self.cert_update_cmd)

    def dis_selinux(self):
        self.try_cmd('setenforce permissive')

    def inst_puppet(self):
        raise NotImplementedError()

    def boot_puppet(self):
        self.try_cmd('touch /tmp/puppet_bootstrap.log')
        cmd = ('/opt/puppetlabs/bin/puppet agent'
               ' --logdest /tmp/puppet_bootstrap.log --no-daemonize'
               ' --splay --splaylimit 3m --onetime'
               ' --server {} --waitforcert 120'.format(self.inst_hname))
        self.try_cmd(cmd, valid_return=(0, 2), time_limit=10 * 60)

    def try_cmd(self, cmd, valid_return=(0,), retries=0, time_limit=0,
                max_sleep=15000, sleep_int=2000):
        sleep = 0
        for r in itertools.count(0):
            rv = subprocess.Popen(cmd, shell=True).wait()
            if rv in valid_return:
                return rv
            if retries is not None and r >= retries:
                return rv
            if time_limit is not None and sleep >= time_limit:
                return rv

            seed = min(max_sleep, sleep_int * 2 ** r)
            sleep_for = (seed / 2 + random.randint(0, seed / 2)) / 1000.0
            sleep += sleep_for
            time.sleep(sleep_for)


class AwsProv(ProvBase):
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


class AzureProv(ProvBase):
    def get_node_name(self):
        if self.bootstrapper.override_dns_domain:
            return socket.getfqdn() + "." + self.bootstrapper.dns_domain
        else:
            return socket.gethostname() + "." + \
                   self.bootstrapper.inst_hname.split('.', 1)[1]

    def get_node_metadata(self):
        instance_name = self._get_inst_data('/compute/name')
        try:
            scale_set_name = self._get_inst_data('/compute/vmScaleSetName')
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
        h = {'Metadata': 'true'}
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


class GcpProv(ProvBase):
    def get_node_name(self):
        return self._get_inst_data('/hostname')

    def get_node_metadata(self):
        return {'instance_name': self._get_inst_data('/name')}

    def _get_inst_data(self, path):
        u = 'http://169.254.169.254/computeMetadata/v1/instance' + path
        h = {'Metadata-Flavor': 'Google'}
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
    def inst_puppet(self):
        if self._is_installed('puppet-agent'):
            return
        if not self._is_installed('git'):
            self._install('git')
        pkg = 'puppet6-release'
        if not self._is_installed(pkg):
            ver = self._get_major_ver()
            u = 'http://yum.puppetlabs.com/puppet6/{}-el-{}.noarch.rpm'.format(
                pkg, ver)
            result = self.try_cmd('rpm -ivh {}'.format(u), retries=5)
            if result != 0:
                raise Exception('Unable to install package: {}'.format(pkg))
        self._install('puppet-agent')

    def _get_major_ver(self):
        result = self.try_cmd(
            'rpm --query --queryformat %{VENDOR} system-release | '
            'grep --quiet --ignore-case Amazon'
        )
        if result == 0:
            # amazon linuxv2
            self.try_cmd(
                'awk -F: \'{ print $6 }\' /etc/system-release-cpe | '
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
        result = self.try_cmd(' '.join(cmd), retries=retries)
        if result != 0:
            raise Exception('Error installing package: {}'.format(pkg))

    def _is_installed(self, pkg):
        return self.try_cmd('rpm -q --quiet {}'.format(pkg)) == 0


class DebianBootstrapper(BootstrapperBase):
    cert_loc = "/usr/local/share/ca-certificates"
    cert_ext = "crt"
    cert_update_cmd = "update-ca-certificates"

    def inst_puppet(self):
        if self._is_installed('puppet-agent'):
            return
        pkg = 'puppet6-release'
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
        result = self.try_cmd(cmd, retries=retries)
        if result != 0:
            raise Exception('Error installing package: {}'.format(pkg))

    def _is_installed(self, pkg):
        return self.try_cmd(
            'dpkg -l {} 2>/dev/null | grep -q ^ii'.format(pkg)) == 0


BOOTSTRAPPERS = {'centos': CentOsBootstrapper, 'debian': DebianBootstrapper}
PROVIDERS = {'aws': AwsProv, 'azure': AzureProv, 'gcp': GcpProv}


if __name__ == '__main__':
    bs = BOOTSTRAPPERS[operating_system](
        PROVIDERS[cloud_provider](),
        installerHostName,
        installerIpAddress,
        port,
        override_dns_domain=override_dns_domain,
        dns_domain=dns_domain,
        dns_search=dns_search,
        dns_opts=dns_options,
        dns_nameservers=dns_nameservers,
        insertnode_req=insertnode_request
    )
    bs.run()
