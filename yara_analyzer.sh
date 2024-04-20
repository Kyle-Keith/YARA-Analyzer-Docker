#!/bin/bash

bar_size=40
bar_char_done="#"
bar_char_todo="-"
bar_percentage_scale=2
counter=0
container_name="centos_temp"
image_name="centos:7"
error_log="errors.log"
report_file="$host_dir/report.log"
git_yara="https://github.com/VirusTotal/yara/archive/v4.0.2.tar.gz"
git_openssl="https://www.openssl.org/source/openssl-1.1.1k.tar.gz"
git_yara_python="https://github.com/VirusTotal/yara-python.git"
git_yara_validator="https://github.com/CIRCL/yara-validator.git"

function show_progress {
    current="$1"
    total="$2"

    # calculate the progress in percentage 
    percent=$(bc <<< "scale=$bar_percentage_scale; 100 * $current / $total" )
    # The number of done and todo characters
    done=$(bc <<< "scale=0; $bar_size * $percent / 100" )
    todo=$(bc <<< "scale=0; $bar_size - $done" )

    # build the done and todo sub-bars
    done_sub_bar=$(printf "%${done}s" | tr " " "${bar_char_done}")
    todo_sub_bar=$(printf "%${todo}s" | tr " " "${bar_char_todo}")

    # Clear screen
    clear

    # output the bar
    echo -ne "\rProgress : [${done_sub_bar}${todo_sub_bar}] ${percent}%"
    echo ""
    if [ $total -eq $current ]; then
        echo -e "\nDONE"
    fi
}

function creating_docker_container() {
    local max_attempts=2
    local attempt=1
    local host_dir="$PWD/files"

    # Pull CentOS Docker image
    docker pull $image_name > /dev/null
    rm -rf "$host_dir/*"
    mkdir -p "$host_dir"

    while [ ${attempt} -le ${max_attempts} ]; do
        echo "Attempt ${attempt} to create Docker container '${container_name}' from image '${image_name}'..."

        # Start the container with a command that keeps it alive
        if docker run -d --name "${container_name}" -v "$host_dir:/files" "${image_name}" /bin/sh -c "while true; do sleep 30; done" ; then
            echo "Docker container '${container_name}' created successfully."
            return 0
        else
            echo "Error creating Docker container '${container_name}'. Attempting to remove..."
            docker rm -f "${container_name}" 
            ((attempt++))
            echo "Retrying..."
        fi
    done

    echo "Failed to create Docker container after ${max_attempts} attempts."
    return 1
}

function Installing_dependencies() {
    local packages=("kernel-devel-$(uname -r)" "kernel-headers-$(uname -r)" "git" "perl-core" "pcre-devel" "gcc" "wget" "zlib-devel" "file" "python3" "python3-devel" "python3-pip" "automake" "libtool" "make" "gcc-c++" "epel-release")
    local retries=3
    local success=false
    for (( i=0; i<retries; i++ )); do
        if docker exec "$container_name" sh -c "yum install -y ${packages[*]} && yum update -y && yum upgrade -y && CFLAGS='-fno-strict-aliasing'"; then
            success=true
            for package in "${packages[@]}"; do
                if ! docker exec "$container_name" rpm -q $package > /dev/null; then
                    echo "Verification failed for $package."
                    success=false
                    break
                fi
            done
            if $success; then
                break
            fi
        else
            echo "Attempt $(($i + 1)) failed to install dependencies in $container_name."
            sleep 2
        fi
    done
    if ! $success; then
        echo "Failed to install dependencies after $retries attempts."
        return 1
    fi
    echo "Dependencies installed and verified successfully in $container_name."
}


function Installing_OpenSSL() {
    local retries=3
    local success=false
    for (( i=0; i<retries; i++ )); do
        if docker exec "$container_name" sh -c "cd /opt/ && curl -O $git_openssl && \
                                                tar -zxvf openssl-1.1.1k.tar.gz && \
                                                cd openssl-1.1.1k && \
                                                ./config --prefix=/usr --openssldir=/etc/ssl --libdir=lib no-shared zlib-dynamic && make && make install"; then
            if docker exec "$container_name" openssl version | grep -q '1.1.1k'; then
                success=true
                break
            else
                echo "OpenSSL version check failed."
            fi
        else
            echo "Attempt $(($i + 1)) failed to install OpenSSL in $container_name."
            sleep 2
        fi
    done
    if ! $success; then
        echo "Failed to install and verify OpenSSL after $retries attempts."
        return 1
    fi
    echo "OpenSSL installed and verified successfully in $container_name."
}

function Installing_yara() {
    local retries=3
    local success=false
    for (( i=0; i<retries; i++ )); do
        if docker exec "$container_name" sh -c "pip3 install yara"; then
            if docker exec "$container_name" pip3 show yara > /dev/null; then
                success=true
                break
            else
                echo "Yara verification failed."
            fi
        else
            echo "Attempt $(($i + 1)) failed to install yara in $container_name."
            sleep 2
        fi
    done
    if ! $success; then
        echo "Failed to install and verify yara after $retries attempts."
        return 1
    fi
    echo "Yara installed and verified successfully in $container_name."
}

function Installing_yara_python() {
    local retries=3
    local success=false
    for (( i=0; i<retries; i++ )); do
        if docker exec "$container_name" sh -c "pip3 install yara-python"; then
            if docker exec "$container_name" pip3 show yara-python > /dev/null; then
                success=true
                break
            else
                echo "Yara-python verification failed."
            fi
        else
            echo "Attempt $(($i + 1)) failed to install yara-python in $container_name."
            sleep 2
        fi
    done
    if ! $success; then
        echo "Failed to install and verify yara-python after $retries attempts."
        return 1
    fi
    echo "Yara-python installed and verified successfully in $container_name."
}

function Installing_yara_validator() {
    local retries=3

    # Clone the yara-validator repository with retry logic
    local success=false
    for (( i=0; i<retries; i++ )); do
        if docker exec "$container_name" sh -c "cd /opt && git clone $git_yara_validator"; then
            success=true
            break
        else
            echo "Attempt $(($i + 1)) failed to clone yara-validator from $git_yara_validator."
            sleep 2
        fi
    done
    if ! $success; then
        echo "Failed to clone yara-validator after $retries attempts."
        return 1
    fi

    # Copy the update_encoding script to the container
    if ! cp "$PWD/update_encoding.sh" "$PWD/files/"; then
        echo "Failed to copy update_encoding.sh to $container_name."
        return 1
    fi

    # Change permissions and run the script with retry logic
    docker exec "$container_name" /bin/bash -c "mv /files/update_encoding.sh /opt/" && \
    success=false
    for (( i=0; i<retries; i++ )); do
        if docker exec "$container_name" chmod +x /opt/update_encoding.sh && \
            docker exec "$container_name" /bin/bash -c "/opt/update_encoding.sh"; then
            success=true
            break
        else
            echo "Attempt $(($i + 1)) failed to execute update_encoding.sh in $container_name."
            sleep 2
        fi
    done
    if ! $success; then
        echo "Failed to execute update_encoding.sh after $retries attempts."
        return 1
    fi

}


function Injecting_python_script() {
    echo "Creating script.py and inserting the provided Python script into $yara_dir/script.py..."

    # Ensure error log exists
    if [[ ! -f "$error_log" ]]; then
        touch "$error_log"
    fi

    # Check for script.py in the current working directory
    if [[ ! -f "$PWD/script.py" ]]; then
        echo "Error: script.py is not found in the current directory." | tee -a "$error_log"
        return 1
    fi

    # Copy the script.py into the container's specified directory
    if !  cp "$PWD/script.py" "$PWD/files/script.py"; then
        echo "Failed to copy script.py to $container_name:/opt/" | tee -a "$error_log"
        return 1
    fi
    
    if ! docker exec "$container_name" sh -c "mv /files/script.py /opt/"; then
        echo "Failed to copy script.py to $container_name:/opt/" | tee -a "$error_log"
        return 1
    fi

    # Update permissions inside the container
    if ! docker exec "$container_name" chmod +x /opt/script.py; then
        echo "Failed to set execute permissions on the script inside the container." | tee -a "$error_log"
        return 1
    fi

    echo "Successfully copied and updated script.py in $container_name:/opt/"

    # Verify the script was copied successfully
    if ! docker exec "$container_name" test -f "/opt/script.py"; then
        echo "Failed to verify that script.py exists inside the container." | tee -a "$error_log"
        return 1
    else
        echo "Python script created successfully inside the container."
    fi
}


function running_analysis() {

    # Extract the host directory for the /files mount
    host_dir=$(docker inspect "$container_name" --format='{{range .Mounts}}{{if eq .Destination "/files"}}{{.Source}}{{end}}{{end}}')
    host_dir=$(echo "$host_dir" | tr -d '",')  # Clean the output
    export host_dir
    echo "Debug: Container Name - $container_name"
    echo "Debug: Host Directory - $host_dir"
    echo "Debug: PWD - $PWD"
    echo "Debug: YARA Directory - $yara_dir"

    if [ -n "$host_dir" ]; then
        echo "Found host directory for /files: $host_dir"
        if [ "$host_dir" != "$PWD/$yara_dir" ]; then
            echo "Clearing any previous YARA rules"
            rm -rf $host_dir/*  # Correct the path and remove the quotes around the glob
            mkdir -p "$host_dir/rules/"
            echo "Moving YARA rules from $PWD/$yara_dir to $host_dir"
            cp -rf "$PWD/$yara_dir/"* "$host_dir/rules/"  # Ensure copying directly to $host_dir
            if [ $? -eq 0 ]; then
                echo "YARA rules moved successfully."
            else
                echo "Failed to move YARA rules."
                return 1
            fi
        else
            echo "Container home directory is same as the yara directory"
        fi
    else
        echo "Did not find a mount for /files in container $container_name."
        return 1
    fi

    # Ensure the script is executable and then run it within the container
    output=$(docker exec "$container_name" sh -c "python3 /opt/script.py /files/")
    echo "$output"
}

function container_cleanup() {
    # Attempt to get a container and set 'container_name'
    get_container
    local status=$?

    # If no container is found and it's not treated as an error, skip cleanup
    if [ $status -ne 0 ]; then
        echo "No container selected or found, skipping cleanup."
        return 0  # Return success since this is an expected situation
    fi

    echo "Cleaning up container: $container_name"

    # Stop the container
    if docker kill "$container_name"; then
        echo "Container '$container_name' stopped successfully."
    else
        echo "Could not stop container '$container_name'. It may already be stopped."
    fi

    # Remove the container
    if docker rm -f "$container_name"; then
        echo "Container '$container_name' removed successfully."
    else
        echo "Could not remove container '$container_name'. It may already be removed."
    fi
}


function get_yara_dir() {
    local install_dir
    local directories
    local index

    # List only directories using ls
    directories=($(ls -d */))  # */ pattern lists directories only, removing the final slashes
    # If no directories found, return an error
    if [ ${#directories[@]} -eq 0 ]; then
        echo "No directories found in the current working directory."
        return 1
    fi

    while true; do
        echo "Available Directories:"
        # Remove trailing slashes and list directories with indices for user selection
        for i in "${!directories[@]}"; do
            echo "$((i+1)). ${directories[i]%/}"  # Remove trailing slash for display
        done
        # Ask user to select the directory by index
        read -p "Select the directory where the YARA rules are located: " index
        ((index--))  # Adjust index because array is zero-based
        if [[ index -lt 0 || index -ge ${#directories[@]} ]]; then
            echo "Invalid selection. Please try again."
        else
            break
        fi
    done

    yara_dir="${directories[index]%/}"  # Use only the name of the directory, remove trailing slash
    export yara_dir
    # Verify if directory contains any .yara or .yar files
    files_found=$(find "$PWD/${yara_dir}" -type f \( -iname "*.yara" -o -iname "*.yar" \))

    if [ -z "$files_found" ]; then
        echo "No .yara or .yar files found in $yara_dir. Please try again."
    else
        echo "Selected directory: $yara_dir"
    fi
}

function exporting_docker_image() {
    local container_name="$1"  # The name of the Docker image to export
    local tar_file="$container_name.tar"    # The path to the output .tgz file
    # Commit changes to container
    rm -rf "$PWD/files/*"
    docker commit "$container_name" "$container_name:latest"

    echo "Exporting Docker image '$container_name' to '$tar_file'..."
    
    # Save the Docker image to a tar file and compress it using gzip
    docker save -o "$container_name.tar" "$container_name:latest"
    
    if [ $? -eq 0 ]; then
        echo "Docker image '$container_name' has been successfully exported to '$tar_file'."
    else
        echo "Failed to export Docker image '$container_name'."
        return 1
    fi
}

function display_report() {

    echo "==================== YARA Analysis Report ===================="

    # Check if the report file exists
    if [[ -f "$PWD/files/$report_file" ]]; then
        # Display the contents of the report file
        echo "Rules are combined separated into $host_dir/{Valid,Broken,Repaired}/{valid,broke,repaired}.yara for easy collection"
        cat "$PWD/files/$report_file"
    else
        echo "No report file found at $host_dir$report_file."
    fi

    echo "============================================================="
}

function check_docker_container_status() {
    local container_name="$1" # Take container_name as an argument

    # Check if the Docker container exists
    container_exists=$(docker ps -a --format '{{.Names}}' | grep "^${container_name}$")
    if [ -z "$container_exists" ]; then
        echo "Container '${container_name}' does not exist."
        # Option to create the container or exit the script
        read -p "Would you like to create the container? (y/n): " create_choice
        if [[ $create_choice == "y" ]]; then
            # Placeholder for container creation command
            create_yara_docker_image
        else
            echo "Exiting script."
            exit 1
        fi
    else
        echo "Container '${container_name}' exists."
        # Check if the container is already running
        container_status=$(docker inspect --format '{{.State.Status}}' "$container_name")
        if [ "$container_status" == "running" ]; then
            echo "Container '${container_name}' is already running."
        else
            echo "Container '${container_name}' is not running. Starting it..."
            docker start "$container_name"
            # Check if the container started successfully
            if [ $? -eq 0 ]; then
                echo "Container '${container_name}' started successfully."
            else
                echo "Failed to start container '${container_name}'."
            fi
        fi
    fi
}


function get_container() {
    echo "Available Docker Containers:"
    IFS=$'\n'  # Set Internal Field Separator to new line for proper array handling
    containers=($(docker ps --format "{{.Names}}"))  # Store container names in an array

    if [ ${#containers[@]} -eq 0 ]; then
        echo "No running Docker containers found."
        return 1  # Optionally change this to return 0 if you don't want to treat this as an error
    fi

    for i in "${!containers[@]}"; do
        echo "$((i+1)). ${containers[i]}"
    done

    read -p "Select the number of the container you want to use: " index
    container_name=${containers[$((index-1))]}

    if [ -z "$container_name" ]; then
        echo "Invalid selection."
        return 1
    fi
    export container_name
}


######################### MAIN FUNCTIONS ##############################################

function create_yara_docker_image() {
    echo "Creating a new YARA Docker image..."
    local function_list=( Installing_dependencies Installing_OpenSSL Installing_yara  Installing_yara_python Installing_yara_validator Injecting_python_script )
    local total_steps=${#function_list[@]}
    yara_dir="files"
    touch "${error_log}"

    echo "Creating docker container" >> "${error_log}"
    creating_docker_container 2>> "${error_log}"
    status=$?
    if [ $status -ne 0 ]; then
        echo "Error: $func failed with status $status."
        # Handle the error, e.g., exit or continue
        echo "ERROR $status, Check errors.log for fatal error"
        exit 1
    fi

    sleep 10
    show_progress $counter $total_steps
    # Iterate through the function list
    for func in "${function_list[@]}"; do

        echo "$func" >> "${error_log}"
        echo "$func"
        echo "This may take awhile..."
        $func 1> /dev/null 2>> "${error_log}"

        ((counter++))
        show_progress $counter $total_steps

        # Capture the exit status of the last command
        status=$?
        if [ $status -ne 0 ]; then
            echo "Error: $func failed with status $status."
            # Handle the error, e.g., exit or continue
            echo "ERROR $status, Check errors.log for fatal error"
            exit 1
        fi
    done
    read -p "Would you like to export the container? (y/n): " choice
    if [[ $choice == "y" ]]; then
        exporting_docker_image $container_name
    fi
}

function yara_analysis() {
    local function_list=(running_analysis)
    local total_steps=${#function_list[@]}
    local counter=0

    # Assuming get_yara_dir and get_container are implemented correctly
    get_container
    get_yara_dir
    check_docker_container_status "$container_name"

    if [ $? -ne 0 ]; then
        echo "Docker container $container_name is not running properly, exiting."
        return 1
    fi

    shopt -s lastpipe
    show_progress $counter $total_steps
    
    # Iterate through the function list
    for func in "${function_list[@]}"; do
        sleep 1

        echo "Executing $func..." >> "${error_log}"
        echo "$func"
        $func 1> /dev/null 2>> "${error_log}"

       ((counter++))
        show_progress $counter $total_steps

        status=$?
        if [ $status -ne 0 ]; then
            echo "Error: $func failed with status $status."
            # Handle the error, e.g., exit or continue
            echo "ERROR $status, Check errors.log for fatal error"
            exit 1
        fi
    done

    display_report
}

function export_image() {
    local function_list=( exporting_docker_image )    
    local total_steps=${#function_list[@]}

    # Prompt the user
    get_container
    check_docker_container_status "$container_name"

    # Iterate through the function list
    for func in "${function_list[@]}"; do

        echo "$func" >> "${error_log}"
        echo "$func"
        $func $container_name 1> /dev/null 2>> "${error_log}"
        
        sleep 1
                # Capture the exit status of the last command
        status=$?
        if [ $status -ne 0 ]; then
            echo "Error: $func failed with status $status."
            # Handle the error, e.g., exit or continue
            echo "ERROR $status, Check errors.log for fatal error"
            exit 1
        fi
    done
}

function Kill_image() {
    local function_list=(container_cleanup)
    local total_steps=${#function_list[@]}

    # Iterate through the function list
    for func in "${function_list[@]}"; do

        echo "$func" >> "${error_log}"
        echo "$func"
        
        $func 2>> "${error_log}"
        # Capture the exit status of the last command
        status=$?
        if [ $status -ne 0 ]; then
            echo "Error: $func failed with status $status."
            # Handle the error, e.g., exit or continue
            echo "ERROR $status, Check errors.log for fatal error"
            exit 1
        fi
    done
    sleep 10

    exit 1

}


function import_and_run_docker_image() {
    
    IFS=$'\n'  # Set Internal Field Separator to new line for proper array handling
    files=($(ls | grep *.tar))  # Store container names in an array

    if [ ${#files[@]} -eq 0 ]; then
        echo "No running Docker containers found."
        return 1  # Optionally change this to return 0 if you don't want to treat this as an error
    fi

    for i in "${!files[@]}"; do
        echo "$((i+1)). ${files[i]}"
    done

    read -p "Select the number of the .tar file of the Docker image: " index
    image_name=${files[$((index-1))]}


    # Check if the .tar file exists
    if [ ! -f "$image_name" ]; then
        echo "The specified .tar file does not exist."
        return 1
    fi

    # Check if any matching images exist and store the count
    image_count=$(docker images "$image_name" -q | wc -l)

    if [ "$image_count" -eq 0 ]; then
        echo "No duplicate Docker images found for $image_name."
    else
        echo "Removing Docker images for $image_name..."
        docker rmi $(docker images "$image_name" -q)
    fi
    
    # Load the Docker image from the .tar file
    echo "Loading Docker image from $PWD/$image_name..."
    docker load -i "$PWD/$image_name"
    if [ $? -ne 0 ]; then
        echo "Failed to load Docker image." >> "${error_log}"
        return 1
    fi

    # Run the Docker container using the global image name
    echo "Running the Docker container from image $container_name..."
    mkdir $PWD/files
    docker run -d --name "$container_name" -v "$PWD/files:/files" "$container_name:latest"  /bin/sh -c "while true; do sleep 30; done"
    if [ $? -eq 0 ]; then
        echo "Docker container '$container_name' is mounted at $PWD/files."
    else
        echo "Failed to run the Docker container."  >> "${error_log}"
        return 1
    fi
}

function main() {
    rm -f $error_log
    touch $error_log
    echo "Starting setup..."
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        echo "Docker is not installed. Please install Docker first."
        exit 1
    fi
    export DOCKER_HOST=unix:///var/run/docker.sock

    while true; do
        echo "Please ensure that the files that you want to analyze are in a folder inside the SAME directory of this script"
        echo "Select an option:"
        echo "1) Create a new YARA Docker image *Requires Internet"
        echo "2) Run YARA checker using existing image"
        echo "3) Export Docker current image"
        echo "4) Delete Docker image"
        echo "5) Import Docker Image"
        echo "6) Exit"
        read -p "Enter option [1-6]: " option

        case $option in
            1)
                create_yara_docker_image 
                ;;
            2)
                yara_analysis
                ;;
            3)
                export_image
                ;;
            4)
                Kill_image
                ;;
            5)
                import_and_run_docker_image 
                ;;
            6)
                echo "Exiting..."
                break
                ;;
            *)
                echo "Invalid option. Try again"
                ;;
        esac
    done
}

main 