# Copyright 2008-2018 Univa Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


class tortuga_kit_awsadapter::management::package {
  require tortuga::packages

  include tortuga::config

  ensure_packages(['unzip'], {'ensure' => 'installed'})

  if $::osfamily == 'RedHat' {
    if versioncmp($::operatingsystemmajrelease, '5') > 0 and
        versioncmp($::operatingsystemmajrelease, '7') < 0 {
      # gcc is required only on RHEL/CentOS 6 to compile gevent
      ensure_packages(['gcc'], {'ensure' => 'installed'})

      exec { 'install_gevent_for_rhel_6':
        path    => ["${tortuga::config::instroot}/bin", '/bin', '/usr/bin'],
        command => "${tortuga::config::instroot}/bin/pip install 'gevent<1.2.0'",
        unless  => "${tortuga::config::instroot}/bin/pip freeze | grep -q gevent==",
        require => Package['gcc'],
      }
    }

    # Package in EPEL recently renamed from 'python-boto' to 'python2-boto'
    $pkgs = ['python2-boto']

    ensure_packages($pkgs, {'ensure' => 'installed'})
  }
}

class tortuga_kit_awsadapter::management::post_install {
  include tortuga_kit_awsadapter::config

  require tortuga_kit_awsadapter::management::package

  tortuga::run_post_install { 'tortuga_kit_awsadapter_management_post_install':
    kitdescr  => $tortuga_kit_awsadapter::config::kitdescr,
    compdescr => $tortuga_kit_awsadapter::management::compdescr,
  }
}

class tortuga_kit_awsadapter::management::config {
  require tortuga::installer::apache
  require tortuga_kit_awsadapter::management::post_install

  include tortuga::config

  $instroot = $tortuga::config::instroot

  if versioncmp($::operatingsystemmajrelease, '7') < 0 {
    file { '/etc/rc.d/init.d/awsspotd':
      content => template('tortuga_kit_awsadapter/awsspotd.sysv.erb'),
      mode    => '0755',
    }
    -> exec { 'install awsspotd initscript':
      command => '/sbin/chkconfig --add awsspotd',
      unless  => '/sbin/chkconfig --list awsspotd',
    }
  } elsif versioncmp($::operatingsystemmajrelease, '7') >= 0 {
    # Install systemd service file on RHEL/CentOS 7.x

    file { '/usr/lib/systemd/system/awsspotd.service':
      content => template('tortuga_kit_awsadapter/awsspotd.service.erb'),
      mode    => '0644',
    } ~>
    exec { 'refresh_after_installing_awsspotd_service':
      command     => '/bin/systemctl daemon-reload',
      refreshonly => true,
    }
  }

  file { '/etc/sysconfig/awsspotd':
      source => 'puppet:///modules/tortuga_kit_awsadapter/awsspotd.sysconfig',
  }
}

class tortuga_kit_awsadapter::management::service {
  require tortuga_kit_awsadapter::management::config

  if versioncmp($::operatingsystemmajrelease, '7') < 0 {
    $svcname = 'awsspotd'
  } else {
    $svcname = 'awsspotd.service'
  }

  service { $svcname:
    # ensure     => running,
    # enable     => true,
    hasstatus  => true,
    hasrestart => true,
  }
}

class tortuga_kit_awsadapter::management {
  include tortuga_kit_awsadapter::config

  $compdescr = "management-${tortuga_kit_awsadapter::config::major_version}"

  contain tortuga_kit_awsadapter::management::package
  contain tortuga_kit_awsadapter::management::post_install
  contain tortuga_kit_awsadapter::management::config
  contain tortuga_kit_awsadapter::management::service

  Class['tortuga_kit_awsadapter::management::config'] ~>
    Class['tortuga_kit_awsadapter::management::service']

  Class['tortuga_kit_awsadapter::management::post_install'] ~>
    Class['tortuga_kit_base::installer::webservice::server']
}
