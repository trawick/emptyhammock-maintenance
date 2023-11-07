#!/usr/bin/env python
from __future__ import print_function

from datetime import datetime, timedelta
import json
import logging
from logging.config import dictConfig
import os
import re
import shutil
import subprocess
import tempfile
import time

import click
from croniter import croniter
import pytz
import requests
import yaml

from e_ood import (
    Analyzer, AvailablePackageVersions, InstalledPackageVersions,
    PackageVersionClassifications
)


MAX_CACHED_CONFIG_AGE_SECS = 4 * 60 * 60


class RunnerException(Exception):
    pass


class Runner(object):

    def __init__(self, logger, inventory_path, playbooks_path):
        self.logger = logger
        self.inventory = inventory_path
        self.playbooks_path = playbooks_path

    def check_output(self, server, task_name, args):
        self.logger.debug('%s %s args: %r', server, task_name, args)
        output = subprocess.check_output(args)
        self.logger.debug('Output from %s %s: %r', server, task_name, output)
        return output

    def get_hostname(self, server):
        output = subprocess.check_output([
            'ansible-inventory',
            '-i', self.inventory,
            '--list',
        ]).decode('utf-8')
        data = json.loads(output)
        return data[server]['hosts'][0]

    def ping(self, server):
        self.mod(server, 'ping')

    def playbook(self, server, playbook_name, data=None):
        playbook = os.path.join(self.playbooks_path, playbook_name)
        data = data or {}
        data['selected_host'] = server

        variables = []
        for k, v in data.items():
            variables.append('-e')
            variables.append('%s=%s' % (k, v))

        output = subprocess.check_output([
                'ansible-playbook',
                '-i', self.inventory,
            ] + variables + [
            playbook,
        ]).decode('utf-8')
        self.logger.debug('Output from %s: %r', playbook, output)
        m = re.match(
            r'^.*ok=(\d+)\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)\s+',
            output, re.MULTILINE | re.DOTALL
        )
        if not m:
            msg = 'Could not understand result of running playbook %s on %s: %r' % (
                playbook, server, output
            )
            self.logger.critical(msg)
            raise RunnerException(msg)
        ok, changed, unreachable, failed = map(int, m.groups())
        self.logger.debug(
            'Status of running playbook %s on %s: %s/%s/%s/%s',
            playbook, server,
            ok, changed, unreachable, failed
        )
        if unreachable or failed:
            msg = 'Server was unreachable or a task failed, running playbook %s on %s: %r' % (
                playbook, server, output
            )
            self.logger.critical(msg)
            raise RunnerException(msg)
        return output

    def mod(self, server, mod, mod_args=None, become=False):
        args = [
            'ansible',
            '-i', self.inventory,
            server,
            '-m', mod,
        ]
        if mod_args is not None:
            args.append('-a')
            args.append(mod_args)
        if become:
            args.append('-b')

        output = subprocess.check_output(args).decode('utf-8')
        self.logger.debug(
            'Output of running %s(%s) on %s: %r',
            mod, mod_args, server, output
        )

        m = re.match(r'^.* (?:SUCCESS|CHANGED) => (.*)$', output, re.MULTILINE | re.DOTALL)
        if m:
            return json.loads(m.group(1))

        m = re.match(r'^.* CHANGED \| rc=0 >>(.*)$', output, re.MULTILINE | re.DOTALL)
        if m:
            return m.group(1)

        msg = 'Could not understand result of running %s(%s) on %s: %r' % (
            mod, mod_args, server, output
        )
        self.logger.critical(msg)
        raise RunnerException(msg)

    def fetch_file(self, server, src, dest):
        result = self.mod(server, 'fetch', 'flat=yes src=%s dest=%s' % (
            src, dest
        ))
        if 'dest' not in result:
            logging.error(
                'File %s does not exist for %s or cannot be accessed, skipping...',
                src, server
            )
            try:
                os.remove(dest)
            except OSError:
                pass
            return False
        return True


MAINTENANCE_CONFIG = '/etc/emptyhammock-maintenance.yml'

STATUS_FILE = 'maintenance-status.json'
status = json.loads(open(STATUS_FILE).read())


def is_due(task_name, when, last_performed, now, window_size=None):
    assert croniter.is_valid(when)
    last_success = datetime.fromtimestamp(last_performed, pytz.utc)
    run_times = croniter(when, last_success)
    next_run = run_times.get_next(datetime)
    perform = now >= next_run
    logging.debug('%s: %s > %s?  %s', task_name, now, next_run, perform)
    if perform and window_size:
        # check that the current time is within the specified window
        # e.g., if reboot time is 1 a.m. with window size 15 minutes and we didn't run
        # for some reason until 2 a.m., the reboot can't be performed now
        run_times = croniter(when, now)
        prev_run = run_times.get_prev(datetime)
        delta = now - prev_run
        if delta > window_size:
            logging.debug(
                '%s cannot be run because window %s has been exceeded '
                '(should have run %s ago at %s)',
                task_name, window_size, delta, prev_run
            )
            perform = False
    return perform


class MaintenanceTask(object):
    """
    Abstract base class for some kind of server maintenance task.
    """
    _must_override = ('task_name', 'nickname', 'rule_key', 'when_key')
    task_name = None  # Printable/log-able name for the task; must override
    nickname = None  # short name for user to identify specific task to run; must override
    rule_key = None  # rule dictionary key for this task's rules; must override
    when_key = None  # status dictionary key for this task's status; must override

    # override with timedelta IFF task must be performed within a time delta from
    # scheduled execution; this can be used to prevent the task running at an
    # arbitrary time of day if the maintenance service is off-line during the
    # scheduled time
    window_size = None

    # In what order does this task run compared with other tasks?
    RUN_VERY_FIRST = 10
    RUN_FIRST = 20
    RUN_MIDDLE = 30
    RUN_LAST = 40
    RUN_VERY_LAST = 50

    order = RUN_MIDDLE  # default: don't care what order

    def __init__(self, server, rules, scratch_dir, config_dir, backup_dir):
        """
        Initialize maintenance task for use with a particular server.

        :param server: Nickname of server within Ansible inventory file
        :param rules: Rules for all tasks for this server.
        :param scratch_dir: Per-server directory for scratch space.
        :param config_dir: Per-server directory for storing configuration.
        :param backup_dir: Per-server directory for retaining server backups.
        """
        for attr in self._must_override:
            if getattr(self, attr, None) is None:
                raise NotImplementedError('Attribute "%s" must be set by %s' % (
                    attr, type(self)
                ))

        self.all_server_rules = rules
        self.server = server
        self.scratch_dir = scratch_dir
        self.config_dir = config_dir
        self.backup_dir = backup_dir

    @classmethod
    def prepare(cls, config_dir):
        """
        Perform initialization for the maintenance task, prior to processing any
        particular servers.

        Example:  A maintenance task needs to download data to be used repeatedly
        when performing maintenance on particular servers.  It implements this
        class method to download that data and store it in the configuration
        directory.

        :param config_dir: global (not server-specific) configuration directory
        :return: nothing
        """
        pass

    def get_task_rules(self):
        """
        Get the rules for this task, for the server being processed.

        :return: Dictionary of rules for this task.
        """
        return self.all_server_rules[self.rule_key]

    def is_due(self, now):
        """
        Determine if this task needs to be performed for the server, based on
        the current time, the server rules for this task, and an optional
        window size associated with the task.

        :param now: the current time
        :return: boolean
        """
        task_rules = self.all_server_rules[self.rule_key]
        try:
            when = task_rules['when']
        except TypeError:
            # XXX legacy configuration format used with ApplyOSMaintenanceTask
            #     and RebootTask
            when = task_rules
        return is_due(
            self.task_name,
            when,
            status[self.server][self.when_key], now,
            window_size=self.window_size
        )

    def perform_if_needed(self, runner, dry_run, now):
        """
        Perform this task if:
        * the server has defined rules for the task AND
        * the task is due AND
        * this isn't a dry run

        :param runner: Runner object, for performing actions on the server
        :param dry_run: Whether or not this is a dry run to see what would be
            performed
        :param now: The current time
        :return: nothing
        """
        # check dry_run last, in order to record any log messages for prior
        # operations
        if self.rule_key in self.all_server_rules:
            rules = self.get_task_rules()
            if self.is_due(now):
                if not dry_run:
                    self.perform(runner, rules)

    def perform(self, runner, rules):
        """
        Perform the maintenance task unconditionally.  Applicability has
        already been determined.

        :param runner: Runner object, for performing actions on the server
        :param rules: A dictionary with the server's rules for this task.
        :return: nothing
        """
        raise NotImplementedError('perform must be implemented by %s' % type(self))

    def was_performed(self):
        """
        Record that the task has been performed on this server.

        :return: nothing
        """
        status[self.server][self.when_key] = int(time.time())


# See http://avilpage.com/2017/06/auto-register-subclasess-without-metaclass.html
# (until Python 3.6's __init_subclass__())
def subclasses(cls, registry=None):
    if registry is None:
        registry = set()

    subs = cls.__subclasses__()

    for sub in subs:
        if sub in registry:
            return
        registry.add(sub)
        yield sub
        for sub in subclasses(sub, registry):
            yield sub


def get_task_classes(nickname=None):
    matching_classes = [
        cls
        for cls in subclasses(MaintenanceTask)
        if nickname is None or nickname == cls.nickname
    ]
    return sorted(
        matching_classes,
        key=lambda c: c.order
    )


class DatabaseBackupTask(MaintenanceTask):
    task_name = 'DB backup'
    nickname = 'backupdb'
    rule_key = 'db_backup'
    when_key = 'db_backup_when'

    def perform(self, runner, rules):
        if not self.backup_dir.endswith('/'):
            self.backup_dir += '/'
        dump_name = '/tmp/%s.gz' % rules['database']
        runner.playbook(self.server, 'dump_db_and_fetch.yml', {
            'dump_filename': dump_name,
            'database': rules['database'],
            'backup_dir': self.backup_dir,
        })
        self.was_performed()


class DirectoryBackupTask(MaintenanceTask):
    task_name = 'Directory backup'
    nickname = 'backupdirectory'
    rule_key = 'directory_backup'
    when_key = 'directory_backup_when'

    def backup_remote_path(self, runner, hostname, remote_path, local_dir=None, via_sudo=False):
        if not remote_path.endswith('/'):
            remote_path = remote_path + '/'
        if not local_dir:
            local_dir = os.path.basename(os.path.dirname(remote_path))
        local_path = os.path.join(self.backup_dir, local_dir)
        if not os.path.exists(local_path):
            os.makedirs(local_path)
        local_path += '/'  # must end in slash
        extra_rsync_args = ['--rsync-path=sudo rsync'] if via_sudo else []
        rsync = [
            'rsync',
            '-arvz',
            '-delete',
            '-e', 'ssh',
        ] + extra_rsync_args + [
            '%s:%s' % (hostname, remote_path),
            local_path
        ]
        runner.check_output(self.server, 'copying %s' % remote_path, rsync)

    def perform(self, runner, rules):
        hostname = runner.get_hostname(self.server)
        for remote_path in rules['paths']:
            self.backup_remote_path(runner, hostname, remote_path)
        self.was_performed()


class DockerVolumeBackupTask(DirectoryBackupTask):
    task_name = 'Docker volume backup'
    nickname = 'backupdockervolume'
    rule_key = 'docker_volume_backup'
    when_key = 'docker_volume_backup_when'

    def perform(self, runner, rules):
        ok = True
        hostname = runner.get_hostname(self.server)
        for volume_name in rules['volume_names']:
            output = runner.playbook(self.server, 'inspect_docker_volume.yml', {
                'volume_name': volume_name,
            })
            m = re.search(r'\\"Mountpoint\\": \\"([^"]+)\\"', output)
            if m:
                mount_point = m.group(1)
                self.backup_remote_path(
                    runner, hostname, mount_point, local_dir=volume_name,
                    via_sudo=True
                )
            else:
                logging.error(
                    'Docker volume mountpoint could not be found in %s', output
                )
                ok = False
        if ok:
            self.was_performed()


class CertbotRefreshTask(MaintenanceTask):
    task_name = 'Renew'
    nickname = 'renewcert'
    rule_key = 'certbot'
    when_key = 'certbot_renew_when'

    def perform(self, runner, rules):
        result = runner.mod(self.server, 'command', rules['command'], become=True)
        ok = True
        if rules['not_due_output'] in result:
            logging.info('Certificate is not due for renewal')
        elif rules['renewed_output'] in result:
            logging.info('Certificate was renewed')
        else:
            logging.error(
                'Output of certbot on %s is not understood: %r',
                self.server, result
            )
            ok = False
        if ok:
            self.was_performed()


class VirtualenvTask(MaintenanceTask):
    task_name = 'Check Python package versions'
    nickname = 'virtualenv'
    rule_key = 'check_python_package_versions'
    when_key = 'check_python_packages_when'

    IGNORED = (
        'emptyhammock-article',
        'emptyhammock-contact',
        'emptyhammock-out-of-date-django',
        'emptyhammock-simple-plugins',
        'emptyhammock-time',
        'html5lib',
        'pkg-resources',
        'stacktraces',
    )

    USER_AGENT = 'emptyhammock-maintenance'

    PYPI_CACHE_SECONDS = 60 * 60 * 6

    @classmethod
    def prepare(cls, config_dir):
        if not os.path.exists('.db_url'):
            return
        db_filename = os.path.join(config_dir, 'db.yaml')

        rv = requests.get(open('.db_url').read().strip('\n'), headers={
            'User-Agent': cls.USER_AGENT,
        })
        assert rv.status_code == 200
        with open(db_filename, 'w') as f:
            f.write(rv.text)

    def perform(self, runner, rules):
        list_command = rules['list_command']
        src_file = '/tmp/python-packages.txt'
        dest_file = os.path.join(self.config_dir, 'python-packages.txt')
        command_line = '{} {}'.format(
            list_command, src_file,
        )
        result = runner.mod(self.server, 'command', command_line, become=True)
        if re.match('^\n+$', result):
            ok = runner.fetch_file(
                self.server, src_file, dest_file,
            )
            if ok:
                env_packages = InstalledPackageVersions.from_freeze_file(dest_file)
                yaml_db = os.path.join(self.config_dir, '..', 'db.yaml')
                version_db = PackageVersionClassifications(
                    yaml_db=open(yaml_db) if os.path.exists(yaml_db) else None
                )
                with AvailablePackageVersions(
                    max_cache_time_seconds=self.PYPI_CACHE_SECONDS
                ) as version_info:
                    analyzer = Analyzer(env_packages, version_info, version_db)
                    result = analyzer.analyze(
                        ignored_packages=self.IGNORED
                    )
                output = result.render()
                if output:
                    print('Out of date packages for %s:' % self.server)
                    print()
                    print(output)
                    logging.info('Out of date packages: %s', output)
        else:
            logging.error(
                'Output of %s on %s is not understood: %r',
                list_command, self.server, result
            )
            ok = False
        if ok:
            self.was_performed()


class CheckOSMaintenanceTask(MaintenanceTask):
    task_name = 'Check for fixes'
    nickname = 'availosfixes'
    rule_key = 'check_for_available_os_fixes'
    when_key = 'check_os_fixes_when'

    def perform(self, runner, rules):
        command_line = 'apt list --upgradable 2>/dev/null'
        result = runner.mod(self.server, 'shell', command_line, become=True)
        if 'Listing...\n' not in result:
            logging.error(
                'Output of "%s" on %s is not understood: %r',
                command_line, self.server, result
            )
            return
        threshold = int(rules['threshold'])
        lines = [
            line
            for line in result.split('\n')
            if line not in (
                '',
                'Listing...',
                'WARNING: apt does not have a stable CLI interface. Use with caution in scripts.'
            )
        ]
        if len(lines) > threshold:
            print('Out of date OS packages for %s:' % self.server)
            print('\n'.join(lines))
        self.was_performed()


class ApplyOSMaintenanceTask(MaintenanceTask):
    task_name = 'Apply'
    nickname = 'osfixes'
    rule_key = 'maintenance_apply_when'
    when_key = 'maintenance_apply_when'

    def perform(self, runner, rules):
        runner.playbook(self.server, 'full-upgrade.yml')
        self.was_performed()


class RebootTask(MaintenanceTask):
    task_name = 'Reboot'
    nickname = 'reboot'
    rule_key = 'maintenance_reboot_when'
    when_key = 'maintenance_reboot_when'
    # reboot can't happen at an arbitrary point AFTER the due time
    window_size = timedelta(minutes=30)

    # The server may be rebooting as soon as this task runs, so any subsequent
    # tasks would fail.
    order = MaintenanceTask.RUN_VERY_LAST

    def perform(self, runner, rules):
        runner.playbook(self.server, 'reboot-if-needed.yml')
        self.was_performed()


class CheckRebootTask(MaintenanceTask):
    task_name = 'Check reboot'
    nickname = 'check_reboot'
    rule_key = 'check_reboot'
    when_key = 'maintenance_check_reboot_when'

    def perform(self, runner, rules):
        filename = '/var/run/reboot-required'
        command_line = f'ls -l {filename} 2>/dev/null || true'
        result = runner.mod(self.server, 'shell', command_line)
        if filename in result:
            print(f'Server {self.server} needs to be rebooted.')
        self.was_performed()


class RunCommandTask(MaintenanceTask):
    task_name = "Run custom command"
    nickname = "run_custom_command"
    rule_key = "run_custom_command"
    when_key = "run_custom_command_when"

    def perform(self, runner, rules):
        command = rules["command"]
        # An exception will be logged by runner.mod() if the command exits with
        # non-zero status.  Since this is run via the shell, we force the shell
        # exit status to be zero so that we propagate the output of the command
        # and avoid logging an exception.
        result = runner.mod(self.server, "shell", command + "; exit 0", become=True)
        result = result.strip()
        if result:
            print(f"Output of {command}:\n{result}")
        self.was_performed()


def perform_maintenance_tasks(
        task_classes, runner, dry_run, server, scratch_dir, backup_dir,
        rules_filename, config_dir
):
    rules = yaml.load(open(rules_filename), Loader=yaml.FullLoader)
    logging.debug('Rules for %s: %r', server, rules)

    server_status = status[server]

    now = datetime.utcnow().replace(tzinfo=pytz.utc)

    for task_class in task_classes:
        if task_class.when_key not in server_status:
            server_status[task_class.when_key] = 0  # never performed
        task = task_class(server, rules, scratch_dir, config_dir, backup_dir)
        task.perform_if_needed(runner, dry_run, now)


def maintain_server(task_classes, runner, scratch_dir, backup_dir, config_dir, dry_run, server):
    logging.info('Processing %s', server)
    config_yml = os.path.join(config_dir, 'config.yml')
    try:
        st = os.stat(config_yml)
        refresh = int(st.st_mtime) < (int(time.time()) - MAX_CACHED_CONFIG_AGE_SECS)
        if refresh:
            logging.debug('Existing %s is too old, refreshing', config_yml)
            os.remove(config_yml)
        else:
            logging.debug('Using existing %s', config_yml)
    except OSError:
        logging.debug('%s not found or cannot be accessed, downloading', config_yml)
        refresh = True

    if refresh:
        ok = runner.fetch_file(server, MAINTENANCE_CONFIG, config_yml)
        if not ok:
            return

    perform_maintenance_tasks(
        task_classes, runner, dry_run, server, scratch_dir, backup_dir,
        config_yml, config_dir
    )


@click.command()
@click.argument('backup-dir', type=click.Path(exists=True, file_okay=False, writable=True))
@click.argument('log-dir', type=click.Path(exists=True, file_okay=False, writable=True))
@click.argument('config-cache-dir', type=click.Path(exists=True, file_okay=False, writable=True))
@click.option('--dry-run', is_flag=True)
@click.option('--debug', is_flag=True, help='Enable debug logging to console')
@click.option('--server', help='Perform maintenance only for this server')
@click.option('--task', help='Perform only this maintenance task')
@click.option(
    '--configuration', help='Path to directory with inventory and server list'
)
def main(
    backup_dir,
    log_dir,
    config_cache_dir,
    dry_run,
    debug,
    server=None,
    task=None,
    configuration=None
):
    log_config = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'detailed':  {
                'format': '%(asctime)s %(levelname)-8s %(message)s'
            },
        },
        'handlers': {
            'console': {
                'level': 'DEBUG' if debug else 'WARNING',
                'class': 'logging.StreamHandler',
            },
            'file': {
                'level': 'DEBUG',
                'class': 'logging.handlers.RotatingFileHandler',
                'filename': os.path.join(log_dir, 'maintain.log'),
                'formatter': 'detailed',
                'mode': 'a',
                'maxBytes': 10 * 1024 * 1024,
                'backupCount': 10,
            }
        },
        'root': {
            'handlers': ['console', 'file'],
            'level': 'DEBUG',
        },
    }
    dictConfig(log_config)

    task_classes = get_task_classes(task)
    for task_class in task_classes:
        task_class.prepare(config_cache_dir)

    configuration = configuration or '.'
    inventory_path = os.path.join(configuration, 'inventory')
    servers_path = os.path.join(configuration, 'servers.yml')

    runner = Runner(logging, inventory_path, './playbooks')

    servers = yaml.load(open(servers_path), Loader=yaml.FullLoader)['servers']
    if server:
        servers = filter(lambda x: x['name'] == server, servers)

    found = -1
    for found, server_data in enumerate(servers):
        server = server_data['name']
        transient = server_data.get('transient', False)
        scratch_dir = tempfile.mkdtemp()

        if server not in status:
            status[server] = {}

        try:
            runner.ping(server)
        except subprocess.CalledProcessError as ex:
            log_args = ['Could not ping server %s (%s)', server, ex.output]
            if transient:
                logging.debug(*log_args)
            else:
                logging.exception(*log_args)
        else:
            try:
                maintain_server(
                    task_classes,
                    runner, scratch_dir, os.path.join(backup_dir, server),
                    os.path.join(config_cache_dir, server), dry_run, server
                )
            except Exception:  # noqa
                logging.exception('Bad stuff happened maintaining server %s', server)
        shutil.rmtree(scratch_dir)
    assert found >= 0, 'No servers were found'

    if not dry_run:
        with open(STATUS_FILE, 'w') as f:
            f.write(json.dumps(status))


if __name__ == '__main__':
    main()
