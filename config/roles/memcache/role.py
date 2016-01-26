# -*- coding: utf-8 -*-
#
# Copyright (C) 2015, 2016 Red Hat, Inc.
#
# Authors:
# Stephen Gallagher <sgallagh@redhat.com>
# Nils Philippsen <nils@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# This role provides a memory object caching service
# It is deployed inside of a Docker container

import os
from rolekit.server.rolebase import RoleBase
from rolekit.server.rolebase import RoleDeploymentValues
from rolekit import async
from rolekit.dbus_utils import SystemdJobHandler
from rolekit.config import SYSTEMD_UNITS
from rolekit.errors import COMMAND_FAILED
from rolekit.errors import RolekitError
from rolekit.logger import log
from rolekit.server.settings import RoleSetting
from rolekit.server.io.systemd import enable_units
from rolekit.server.io.systemd import SystemdContainerServiceUnit

MEMCACHED_DOCKER_IMAGE = "fedora/memcached"

MEMCACHED_ENVIRONMENT_FILE = "/etc/sysconfig/memcached"
MEMCACHED_DEFAULT_PORT = 11211

MiB_SIZE = 1024 * 1024
GiB_SIZE = MiB_SIZE * 1024


def _cache_size_default():
    # Do a late import of psutil. This will only get
    # used during a deployment, so we don't need to
    # have it as a dependency for rolekit itself
    import psutil

    # Get the total number of bytes in local system memory
    total_ram = psutil.virtual_memory().total

    # If 25% of the available memory is less than 1GB, use
    # that for the cache.
    return int(min(total_ram / 4 / MiB_SIZE, GiB_SIZE / MiB_SIZE))

def _cache_size_constraint(cache_size):
    # Do a late import of psutil. This will only get
    # used during a deployment, so we don't need to
    # have it as a dependency for rolekit itself
    import psutil

    return cache_size < psutil.virtual_memory().total / MiB_SIZE

def _threads_constraint(threads):
    # Up to four threads should be safe on any platform
    # More than that should be limited by the available CPUs
    return 0 < threads <= max(4, os.cpu_count())


class Role(RoleBase):

    ### The following properties/settings are defined/set up in RoleBase.
    ### Role-specific (default) values are set here.

    # version of the *role* (not the services it provides)
    version = 1

    # A list of systemd services that must be started with
    # this role. Empty list by default, so no need to set it.
    # services = []

    # A list of packages that must be installed by the package manager to be
    # able to deploy and run this role. These will be installed before the
    # role-specific deployment takes place, so it can contain packages needed
    # for deployment as well as runtime.
    packages = ['memcached', 'docker', 'python3-docker-py', 'python3-psutil']

    # The 'ports' and/or 'services' will be opened automatically as part of
    # deployment and associated with the default firewall zone of the system.
    # Ports can be single ports or ranges and are formatted as
    # "<port>[-<endport>]/<protocol>", services are the names of services in
    # firewalld.
    firewall = {'ports': [
        "{}/{}".format(MEMCACHED_DEFAULT_PORT, proto)
        for proto in ('tcp', 'udp')]}

    # Maximum number of instances of this role that can be instantiated
    # on a single host.

    # Until we work out how to set multiple firewall ports, this will
    # provide a single instance.
    max_instances = 1

    ### These settings are specific to memcached.

    # RoleSetting supports callables for computed defaults.
    cache_size = RoleSetting(
        int, default=_cache_size_default, constraint=_cache_size_constraint,
        help="How many megabytes to allocate for the cache. If this is "
             "unspecified, the default will be 1 GB or 25% of the total RAM "
             "on the system, whichever is smaller.")

    # How many concurrent connections are allowed?
    # Default: 1024 (from upstream recommendations)
    connections = RoleSetting(
        int, default=1024, constraint=lambda x: 0 < x <= 65536,
        help="Maximum number of concurrent connections.")

    threads = RoleSetting(
        int, default=4, constraint=_threads_constraint,
        help="Number of threads used for memcached. "
             "It is not recommended to change this value.")

    # Initialize role
    # def __init__(self, name, directory, *args, **kwargs):
    #     # Always invoke the base class constructor if overriding __init__()
    #     super(Role, self).__init__(name, directory, *args, **kwargs)
    #
    #     # Role-specific initialization goes here, if any
    #     ...


    # Deploy code
    def do_deploy_async(self, sender=None):
        log.debug9("TRACE: do_deploy_async")
        # Run whatever series of actions are needed to deploy
        # this role in a meaningful way.
        #
        import docker

        # Create a container for memcached and launch that
        log.debug2("Enabling the Docker container manager")

        # Enable and start the docker service
        enable_units(['docker.service'])

        log.debug2("Starting the Docker container manager")
        with SystemdJobHandler() as job_handler:
            job_path = job_handler.manager.StartUnit(
                    "docker.service", "replace")
            job_handler.register_job(job_path)

            job_results = yield job_handler.all_jobs_done_future()
            if any(
                    x for x in job_results.values()
                    if x not in ("skipped", "done")):
                details = ", ".join(
                    "{}: {}".format(*item) for item in job_results.items())
                raise RolekitError(
                    COMMAND_FAILED,
                    "Starting docker.service failed: {}".format(details))

        log.debug2("Pulling {} image from Docker Hub".format(
            MEMCACHED_DOCKER_IMAGE))
        dockerclient = docker.Client(
                base_url=docker.utils.utils.DEFAULT_UNIX_SOCKET, version='auto')

        # First, pull down the latest version of the memcached container
        dockerclient.pull(MEMCACHED_DOCKER_IMAGE, tag="latest")

        log.debug2("Creating systemd service unit")
        # Generate a systemd service unit for this container
        container_unit = SystemdContainerServiceUnit(
            image_name = MEMCACHED_DOCKER_IMAGE,
            container_name = "memcached_{}".format(self.name),
            desc="memcached docker container - {}".format(self.name),
            env = {
                "MEMCACHED_CACHE_SIZE": str(self.cache_size),
                "MEMCACHED_CONNECTIONS": str(self.connections),
                "MEMCACHED_THREADS": str(self.threads)
            },
            ports = ("{0}:{0}/tcp".format(MEMCACHED_DEFAULT_PORT),
                     "{0}:{0}/udp".format(MEMCACHED_DEFAULT_PORT))
        )
        container_unit.write()

        # Make systemd load this new unit file
        log.debug2("Running systemd daemon-reload")
        with SystemdJobHandler() as job_handler:
            job_handler.manager.Reload()

        # Return the target information
        target = RoleDeploymentValues(self.get_type(), self.get_name(),
                                      "Memory Cache")
        target.add_required_units(['memcached_{}.service'.format(self.name)])

        log.debug9("TRACE: exiting do_deploy_async")
        yield target

    # Redeploy code
    def do_redeploy_async(self, sender=None):
        # Run whatever series of actions are needed to update the
        # role with a new high-level configuration.
        # Note: This should be configuration of the role itself,
        # not configuration of data held by the role. That should
        # be managed by the standard tools for interacting with
        # the role.

        # For this role, we can just run the decommission routine
        # and then the deploy routine again.
        yield async.call_future(self.do_decommission_async(sender))

        # Invoke the deploy routine again
        # Discard the target return; we don't need it
        yield async.call_future(self.do_deploy_async(sender))

        # Success
        yield None


    # Decommission code
    def do_decommission_async(self, force=False, sender=None):
        # Remove the container unit
        # Nothing else needs to happen here; the image is
        # removed as part of the role stop() operation
        path = "{}/memcached_{}.service".format(SYSTEMD_UNITS, self.name)
        try:
            os.unlink(path)
        except FileNotFoundError:
            # If the file wasn't there, this is probably part of a
            # redeploy fixing a failed initial deployment.
            pass

        yield None


    # Update code
    def do_update_async(self, sender=None):
        # If this role requires any special processing during an
        # update (other than simply updating the packages),
        # run them here.
        #
        # Always yield None at the end or return a RolekitError exception
        # yield None

        # Remove this line for real roles
        raise NotImplementedError()
