README: YARA Docker Image Creation and Analysis Tool

This Bash script is designed to streamline the creation of Docker containers for YARA rule analysis, manage dependencies, and execute Python scripts within the Docker environment. It provides a comprehensive solution for users looking to validate and analyze YARA rules efficiently.
Features:

    Automated Docker container setup for YARA rule analysis.
    Dependency management for YARA, OpenSSL, and related tools.
    Integration with YARA validator and YARA Python library.
    Option to run analysis, create a new Docker image, or use existing images for YARA rule checks.
    Container and image management functionalities.

Prerequisites:

    Docker is installed on the host machine.
    Bash shell environment.
    Internet connection for downloading dependencies and Docker images.
    Place the YARA rules in the same directory as the three scripts. 

Usage Instructions:

    Starting the Script: Run the script in your terminal with bash script_name.sh.

    Select an Option: The script prompts you with multiple options:
        1) Create a new YARA Docker image: Set up a new Docker container specifically for YARA rule analysis, installing all necessary dependencies.
        2) Run the YARA checker using an existing image: Use an already created Docker container to analyze YARA rules.
        3) Export the Docker image 
        4) Delete Docker image: Remove an existing Docker container used for YARA analysis.
        5) Import Docker Image: Import a Docker image from a .tar file and run YARA rule checks using this image.
        6) Exit: Terminate the script execution.

    Follow On-screen Prompts: Depending on the chosen option, you may need to enter additional information, such as the directory containing YARA rules or the name of the Docker container.

    Analysis and Reports: For options involving YARA rule analysis, the script will execute the analysis and provide a report upon completion, indicating the status of the rules (valid, broken, repaired).

    Cleanup: If you choose to delete a Docker image or container, the script will handle the cleanup process.

Additional Information:

    Error Handling: The script logs errors to an errors.log file. If any step fails, refer to this log for more details.
    Exporting Docker Images: After creating a Docker image, you have the option to export it to a .tgz file for sharing or future use.
    Customization: Advanced users can modify the script variables (e.g., bar_size, container_name) at the beginning of the script to customize the Docker environment and progress bar appearance.

Troubleshooting:

    Ensure Docker is correctly installed and running on your system.
    Verify that the script.py Python script is present in the same directory as the Bash script.
    Check the errors.log file for detailed error messages if any operation fails.

Contributing:

Feedback and contributions to improve this script are welcome. Please follow standard GitHub procedures for forking the repository, making changes, and submitting pull requests.
