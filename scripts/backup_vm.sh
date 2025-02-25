#!/bin/bash

# Configuration (adjust as needed)
DISABLE_SUSPEND=0

if [ $# -ne 2 ]; then
  echo "Usage: $0 <vm_name> <backup_file_name>"
  exit 1
fi

VM_NAME="$1"
BACKUP_NAME="$2"
BACKUP_DIR="/home/kontrolvm/kvm_backups"
TEMP_DIR="/home/kontrolvm/backups_tmp"
VM_TEMP_DIR="$TEMP_DIR/$VM_NAME"
mkdir -p "$BACKUP_DIR"
mkdir -p "$TEMP_DIR"
mkdir -p "$VM_TEMP_DIR"
vm_state=$(virsh domstate "$VM_NAME")
echo "Starting backup."
if [[ "$vm_state" == "running" ]] && [[ "$DISABLE_SUSPEND" -eq 0 ]]; then
	virsh suspend "$VM_NAME"
	backup_type="suspended"
elif [[ "$vm_state" == "running" ]] && [[ "$DISABLE_SUSPEND" -eq 1 ]]; then
	backup_type="online"
elif [[ "$vm_state" == "shut off" ]]; then # Correct check for "shut off" state
	backup_type="offline"
else
	echo "VM '$VM_NAME' backup failed: Unknown state."
	exit 1
fi
disks=$(virsh dumpxml "$VM_NAME" | xmllint --xpath '//disk[not(@device="cdrom")]/source/@file' -)
for disk in $disks; do
	disk=$(echo "$disk" | awk -F'"' '{print $2}')		
	disk_name=$(basename "$disk")
	echo "Backing up $disk_name"
	backup_file="$BACKUP_DIR/${BACKUP_NAME}.tar.gz"
	cp "$disk" "$VM_TEMP_DIR/$disk_name"
	echo "$disk_name backed up."
done
echo "Backing up XML file."
vm_xml_file="/home/kontrolvm/xmls/${VM_NAME}.xml"
/usr/bin/virsh dumpxml "$VM_NAME" --security-info > "$VM_TEMP_DIR/$VM_NAME.xml"
echo "Creating compressed backup file."
tar -czvf "$backup_file" -C "$TEMP_DIR" "$VM_NAME"
echo "Compressed backup file created."
rm -rf "$VM_TEMP_DIR"
if [[ "$backup_type" == "suspended" ]]; then
	virsh resume "$VM_NAME"
fi

echo "VM '$VM_NAME' backup completed."