<!--
title: "Kerio Connect monitoring with Netdata"
custom_edit_url: https://github.com/netdata/netdata/edit/master/collectors/python.d.plugin/kerio_connect/README.md
sidebar_label: "kerio_connect"
-->

# Kerio Connect monitoring with Netdata

Monitors one or more Kerio Connect servers depending on configuration. Servers can be either local or remote.

## Requirements

Example nginx configuration can be found in 'python.d/nginx.conf'

It produces following charts:

1.  **Up Time**

    -   requests

2.  **Storage**

    -   requests

## Configuration

Edit the `python.d/kerio_connect.conf` configuration file using `edit-config` from the your agent's [config
directory](/docs/step-by-step/step-04.md#find-your-netdataconf-file), which is typically at `/etc/netdata`.

```bash
cd /etc/netdata   # Replace this path with your Netdata config directory, if different
sudo ./edit-config python.d/kerio_connect.conf
```

Needs `url`, `user` and `password`.

Here is an example for local server:

```yaml
update_every : 10
priority     : 90100

local:
  url     : 'http://localhost/'
  user    : 'admin'
  pass    : 'secret'
```

---