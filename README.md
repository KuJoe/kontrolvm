![KontrolVM Logo](https://kontrolvm.com/logo.png)  

A simple self-hosted PHP + SQLite3 control panel for Linux KVM clusters, nodes, and guest VMs.

[**DEMO**](https://demo.kontrolvm.com)  

*This is mostly a tour of the control panel and not functional at this time.  
All of the current assets and UI are placeholders, I'll find somebody to design a better looking UI in the near future.*

#### Table of Contents  
- [Features](#features)  
    - [User Management](#user-management)  
    - [Node Management](#node-management)  
    - [VM Management](#vm-management)  
    - [Cluster Management](#cluster-management)  
    - [Other Features](#other-features)  
- [Requirements](#requirements)  
- [KontrolVM Installation](#kontrolvm-installation)  
- [Linux KVM Node Setup](#linux-kvm-node-setup)  

##

# Features
### User Management

 - ✅Create user accounts
 - ✅Delete user accounts
 - ✅Update user details (username, email, status, password)
 - ✅Cloudflare Turnstile invisible CAPTCHA
 - 🚧Multifactor Authentication
 - 🚧User permissions/levels
 - 🚧Password reset
 - 🚧Notifications

### Node Management

 - ✅Add nodes to the cluster
 - ✅Remove nodes from the cluster
 - ✅Edit node details (hostname, IP address, SSH port, status, etc.)
 - ✅Get node statistics (CPU, RAM, disk usage, etc.)
 - ✅Update node statistics
 - ✅Enable/disable nodes
 - 🚧Import existing Linux KVM nodes
 - 🚧Setup multiple virtual networks (i.e. VLANs, public, private, etc...)

### VM Management

 - ✅Create VMs
 - ✅Edit VM details (name, hostname, IP address, resources, etc.)
 - ✅Start, stop, restart, shut down VMs
 - ✅Delete VMs
 - ✅Mount/unmount ISO images to VMs
 - ✅Set I/O limits for VMs
 - ✅Configure NIC speed for VMs
 - ✅Enable/disable VNC for VMs
 - ✅HTML5 + VNC Console
 - ✅Reset VNC passwords
 - ✅Change disk and network drivers for VMs
 - ✅Set boot order for VMs
 - 🚧Adjusting VM resources (CPU, RAM, disk space, etc...)
 - 🚧Adding and removing disks
 - 🚧Adding and removing NICs
 - 🚧Backup/Restore/Snapshot VMs
 - 🚧Migrate VMs between nodes/clusters
 - 🚧IP Management (DHCP, vSwitch, etc...)
 - 🚧Display VM resource usage + history
 - 🚧Bandwidth accounting/monitoring
 - 🚧Expiring VNC access

### Cluster Management

 - ✅Add clusters
 - ✅Delete clusters
 - ✅Enable/disable clusters
 - 🚧Load balancing
 - 🚧Resource based deployment

### Other Features

 - ✅Add ISOs
 - ✅Get total resources (CPU, disk, RAM, VMs, nodes)
 - 🚧Manage IP addresses (add, delete, reserve, unreserve)
 - 🚧Logging and alerting
 - 🚧Automated backups of SQLite3 database
 - 🚧Automatic updates of KontrolVM + Nodes

# Requirements

 - PHP 8.x (tested on PHP 8.1 and 8.2)
 - SQLite3

# KontrolVM Installation

 1. ~~Download the [latest release](https://github.com/KuJoe/kontrolvm/releases).~~
 2. Extract the files and upload them to your web directory.  
	 *OPTIONAL: Update the config.php file if needed.*
 3. Navigate to the install.php file in your browser to run the installer.  
	 ***NOTE: Save the username and password generated in this file for later.***

# Linux KVM Node Setup
*At this time only AlmaLinux 9, RockyLinux 9, and CentOS Stream 9 have been tested and are supported. We will add more server OS options later.*
Login to your Linux KVM node and run the following command as root:

    COMMAND COMING SOON