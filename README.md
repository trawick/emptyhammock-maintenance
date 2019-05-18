# Maintenance

"Maintenance bot" implementation

## Design

### Overview

A key objective is to minimize duplicate configuration.  This is implemented
largely by having the individual projects store configuration information on
the server, in a well-known location examined by maintenance code, which
only needs to be able to connect to the server and fetch the maintenance
configuration in order to perform the appropriate maintenance tasks.

### Supported Features

* Apply system maintenance
* Perform system reboot during reboot window
* Backup databases and directories and Docker volumes
* Maintain Let's Encrypt certificates
* Analyze Python dependency versions

### Project code

This has the following responsibilities:

* Set up the maintenance user (with ssh key) so that the maintenance bot can
  access the system.
* Store a maintenance configuration file on the server.  This file describes to
  maintenance code which specific tasks need to be performed, as well as
  any necessary configuration details.

### Maintenance code

* Fetch maintenance configuration file from the server(s) for each 
  maintained project.
* Perform necessary tasks.
* Save output of the tasks, save server and maintenance state.

## Setting up maintenance server

```bash
$ sudo apt install aptitude virtualenv postfix python-dev
$ virtualenv -p /usr/bin/python2.7 env
$ . env/bin/activate
$ pip install -r requirements.txt
```

Copy `maintenance-status.json` from another machine or initialize the file
with contents `{}` (empty JSON dictionary).

Create a `maintain.sh` script or similar that changes to the git checkout,
activates the virtualenv, and runs `maintain.py`.

Run the script at intervals from cron.  Configure cron to use a monitored
e-mail address for reports.

Copy `servers.yml.sample` to `servers.yml` and `inventory.sample` to `inventory`
and configure for your servers.

### [`emptyhammock-out-of-date-django`](https://github.com/trawick/emptyhammock-out-of-date-django)

If you have access to a server running this code, place the URL, including
access key, in a file called `.db_url`.

## Setting up snapshots on maintenance server

### Installing zfs-auto-snapshot on Ubuntu versions prior to 17.04

See https://askubuntu.com/questions/322541/activate-zfs-snapshots for installing
from source.  Don't try to add the repository referenced in one of the answers.

### Setting up snapshotting rules

Edit `setup_auto_snapshot.sh` and then run it via `sudo`.  The purpose is to
disable auto-snapshotting on all datasets except for `emptyhammock`.

## Configuring the servers to maintain

Provide `servers.yml` and the Ansible `inventory` file, either in the working
directory of `maintain.py` or in a separate directory, to be named with the
`--configuration` command-line argument.

### Details for maintaining a server

* Add the server to the Ansible `inventory`.
* Update `servers.yml` to list the server.
  * Optionally set the attribute `transient` to `yes` if the server is not
    always active.  This will suppress messages every 15 minutes while the
    server is inactive.
* From the maintenance bot id, ssh to the server once to verify and check
  the host key, if Ansible will use ssh for the connection.
