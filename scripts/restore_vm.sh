#!/bin/bash

# Configuration (adjust as needed)
BACKUP_DIR="/home/kontrolvm/kvm_backups"
DISK_LOCATION="/home/kontrolvm/data"
XML_DIR="/home/kontrolvm/xmls"
TEMP_DIR="/home/kontrolvm/backups_tmp/"
mkdir -p "$TEMP_DIR"

# Check for required arguments
if [ $# -ne 3 ]; then
  echo "Usage: $0 <backup_file.tar.gz> <new_vm_name> <vnc_port>"
  exit 1
fi

BACKUP_FILE_ARG="$1"
NEW_VM_NAME="$2"
VNC_PORT_NAME="$3"

# Check if the argument includes the full path or just the filename
if [[ "$BACKUP_FILE_ARG" == /* ]]; then # Check if it starts with a / (full path)
  BACKUP_FILE="$BACKUP_FILE_ARG"
else
  BACKUP_FILE="$BACKUP_DIR/$BACKUP_FILE_ARG" # Prepend BACKUP_DIR
fi

OLD_VM_NAME=$(basename "$BACKUP_FILE" | cut -d '.' -f 1 | cut -d '_' -f 1) # Extract before timestamp
VM_TEMP_DIR="$TEMP_DIR/$OLD_VM_NAME"

# Check if the backup file exists
if [ ! -f "$BACKUP_FILE" ]; then
  echo "Error: Backup file '$BACKUP_FILE' not found."
  exit 1
fi

# Extract the archive
tar -xzf "$BACKUP_FILE" -C "$TEMP_DIR"

# Find the disk image file(s) and the XML file
disk_image_files=$(find "$VM_TEMP_DIR" -type f -name "*.img" -o -name "*.qcow2")
vm_xml_file=$(find "$VM_TEMP_DIR" -name "*.xml") # Find the XML file

# Check if the XML file and any disk images were found
if [ -z "$vm_xml_file" ] || [ -z "$disk_image_files" ]; then
    echo "Error: XML configuration file or disk image files not found in the archive."
    rm -rf "$VM_TEMP_DIR"
    exit 1
fi

# Loop through the disk images and restore them
disk_counter=1  # Counter for disk numbering
for disk_image_file in $disk_image_files; do
    disk_name=$(basename "$disk_image_file")
    disk_path_new="$DISK_LOCATION/${NEW_VM_NAME}-disk${disk_counter}.${disk_name##*.}" # Use NEW_VM_NAME and numbered disks

    # Restore the disk image (copy or convert if needed)
    if [[ "$disk_name" == *.qcow2 ]]; then
        cp "$disk_image_file" "$disk_path_new"
    elif [[ "$disk_name" == *.img ]]; then  # Assuming .img is raw format
        qemu-img convert -f raw -O qcow2 "$disk_image_file" "$disk_path_new"
    else
        echo "Unknown disk format: $disk_name. Skipping."
        continue
    fi

    echo "Disk '$disk_name' restored to '$disk_path_new'."
    disk_counter=$((disk_counter + 1)) # Increment disk counter
done

# Build and define the new XML file
NEW_XML_FILE="$XML_DIR/$NEW_VM_NAME.xml"
sed "s/$OLD_VM_NAME/$NEW_VM_NAME/" "$vm_xml_file" > "$NEW_XML_FILE"
NEW_UUID=$(uuidgen)
sed -i "s/<uuid>.*<\/uuid>/<uuid>$NEW_UUID<\/uuid>/" "$NEW_XML_FILE"
sed -i "s/type='vnc' port='\([0-9]*\)'/type='vnc' port='$VNC_PORT_NAME'/g" "$NEW_XML_FILE"
NEW_MAC=$(printf "%02x:%02x:%02x:%02x:%02x:%02x" $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)))
NEW_MAC=$(echo "$NEW_MAC" | sed 's/:\(.\)$/:\1/')
sed -i "s/address='[0-9a-fA-F:]*'/address='$NEW_MAC'/" "$NEW_XML_FILE"
virsh define "$NEW_XML_FILE"
virsh start "$NEW_VM_NAME"

# Clean up the temporary directory
rm -rf "$VM_TEMP_DIR"

echo "VM '$NEW_VM_NAME' restored."