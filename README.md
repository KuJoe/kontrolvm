# kontrolvm
A simple self-hosted PHP + SQLite3 control panel for Linux KVM clusters, nodes, and guests.

## User Management

 - Create user accounts
 - Delete user accounts
 - Update user details (username, email, status, password)
 - Cloudflare Turnstile invisible CAPTCHA

## Node Management

 - Add nodes to the cluster
 - Delete nodes from the cluster
 - Edit node details (hostname, IP address, SSH port, status, etc.)
 - Get node statistics (CPU, RAM, disk usage, etc.)
 - Update node statistics
 - Enable/disable nodes

## VM Management

 - Create VMs
 - Edit VM details (name, hostname, IP address, resources, etc.)
 - Start, stop, restart, shut down VMs
 - Delete VMs
 - Mount/unmount ISO images to VMs
 - Set I/O limits for VMs
 - Configure NIC speed for VMs
 - Enable/disable VNC for VMs
 - HTML5 + VNC Console
 - Reset VNC passwords
 - Change disk and network drivers for VMs
 - Set boot order for VMs

## Cluster Management

 - Add clusters
 - Delete clusters
 - Enable/disable clusters

## Other Features

 - Add ISOs
 - Manage IP addresses (add, delete, reserve, unreserve)
 - Get total resources (CPU, disk, RAM, VMs, nodes)