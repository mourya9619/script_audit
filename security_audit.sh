#!/bin/bash

# security_audit.sh
# A script to automate security audits and server hardening on Linux servers.

# Function to audit user and group settings
audit_users_and_groups() {
    echo "Auditing users and groups..."
    # List all users
    cut -d: -f1 /etc/passwd
    # Check for users with UID 0 (root)
    awk -F: '($3 == 0) {print $1}' /etc/passwd
}

# Function to audit file permissions
audit_file_permissions() {
    echo "Auditing file and directory permissions..."
    # Find world-writable files
    find / -type f -perm -o+w -exec ls -l {} \;
}

# Main function
main() {
    echo "Starting security audit..."
    audit_users_and_groups
    audit_file_permissions
    echo "Security audit completed."
}

# Execute main function
main

audit_users_and_groups() {
    echo "Auditing users and groups..."

    # List all users
    echo "Users:"
    cut -d: -f1 /etc/passwd

    # List all groups
    echo "Groups:"
    cut -d: -f1 /etc/group

    # Check for users with UID 0 (root)
    echo "Users with UID 0 (root privileges):"
    awk -F: '($3 == 0) {print $1}' /etc/passwd

    # Identify users without passwords
    echo "Users without passwords:"
    awk -F: '($2 == "") {print $1}' /etc/shadow

    # Check for weak passwords (if the `cracklib-check` utility is installed)
    if command -v cracklib-check &> /dev/null; then
        echo "Checking for weak passwords:"
        cut -d: -f1 /etc/passwd | while read user; do
            passwd=$(grep "^$user:" /etc/shadow | cut -d: -f2)
            echo "$user:$passwd" | cracklib-check
        done
    else
        echo "cracklib-check is not installed, skipping weak password check."
    fi
}

audit_file_permissions() {
    echo "Auditing file and directory permissions..."

    # Find world-writable files
    echo "World-writable files:"
    find / -type f -perm -o+w -exec ls -l {} \; 2>/dev/null

    # Check for .ssh directories with insecure permissions
    echo "Checking .ssh directory permissions:"
    find /home -type d -name ".ssh" -exec ls -ld {} \; 2>/dev/null | awk '$1 !~ /^drwx------/ {print $0}'

    # Report files with SUID/SGID bits set
    echo "Files with SUID/SGID bits set:"
    find / -perm /6000 -exec ls -l {} \; 2>/dev/null
}
audit_services() {
    echo "Auditing running services..."

    # List all running services
    echo "Running services:"
    service --status-all 2>/dev/null | grep '+' | awk '{print $4}'

    # Ensure critical services are running
    echo "Checking critical services:"
    for service in sshd iptables; do
        if systemctl is-active --quiet $service; then
            echo "$service is running."
        else
            echo "$service is NOT running!"
        fi
    done

    # Check for services listening on non-standard ports
    echo "Services listening on non-standard ports:"
    ss -tuln | awk '$5 !~ /:(22|80|443)$/ {print $1, $4, $5}'
}
audit_firewall_and_network() {
    echo "Auditing firewall and network security..."

    # Check if firewall is active
    if systemctl is-active --quiet ufw || systemctl is-active --quiet iptables; then
        echo "Firewall is active."
    else
        echo "Firewall is NOT active!"
    fi

    # List open ports and associated services
    echo "Open ports:"
    ss -tuln | awk '{print $1, $4, $5}'
}
main() {
    echo "Starting security audit..."

    audit_users_and_groups
    audit_file_permissions
    audit_services
    audit_firewall_and_network

    echo "Security audit completed."
}

main

