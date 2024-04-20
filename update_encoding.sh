#!/bin/bash

# Find necessary files
file_path="$(find /opt/yara-validator/ -iname 'yara_validator.py')"
py_path="$(find /opt/yara-validator/ -iname 'setup.py')"

# Output found paths
echo "File path: $file_path"
echo "Setup.py path: $py_path"

# Check if the files exist
if [[ ! -f "$file_path" || ! -f "$py_path" ]]; then
    echo "Error: Required file does not exist - $file_path or $py_path"
    exit 1
fi

# Extract directory from file path
dir_path="$(dirname "$py_path")"
echo "Directory path: $dir_path"

# Check and modify setup.py if necessary
if ! grep -q "version = '0.1b0'" "$py_path"; then
    sed -i "s/version = 'v0.1b'/version = '0.1b0'/" "$py_path"
fi

if ! grep -q "zip_safe=False" "$py_path"; then
    sed -i "/setup(/a \    zip_safe=False," "$py_path"
fi

# Check and modify yara_validator.py if necessary
if ! grep -q "encoding='utf-8'" "$file_path"; then
    sed -i "/open(.*'r'/ s/open(\(.*\)'r'/open(\1'r', encoding='utf-8'/" "$file_path"
fi

# Initialize retries
retries=3
success=false

for (( i=0; i<retries; i++ )); do
    # Change to the directory where setup.py is located
    cd "$dir_path"
    
    # Build and install
    if python3 $py_path build && python3 $py_path install; then
        # Try to import the module to verify it's correctly installed
        if python3 -c "import yara_validator" &> /dev/null; then
            success=true
            echo "Yara-validator installed and verified successfully in $container_name."
            break
        else
            echo "Attempt $(($i + 1)) to import yara-validator failed after installation."
        fi
    else
        echo "Attempt $(($i + 1)) failed to install yara-validator."
    fi

    sleep 2  # Wait before retrying
done

if ! $success; then
    echo "Failed to install or verify yara-validator after $retries attempts."
    exit 1
fi
