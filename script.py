import os
import sys
import yara_validator
import re


class YaraSource:
    # Existing attributes and methods here...

    def to_string(self):
        # This method should return the rule as a string
        return self.source  # Adjust 'source' to the actual attribute holding the rule text

def yara_rule_parser(file_path):
    """Function to return all YARA rules from a file as a list."""
    rules = []  # List to store all the rules
    if not os.path.isfile(file_path):
        return rules  # Return an empty list if the file doesn't exist
    with open(file_path, 'r', encoding='utf-8') as file:
        rule_lines = []
        for line in file:
            line_stripped = line.strip()
            if line_stripped.startswith('//'):
                continue  # Skip comment lines
            if 'rule ' in line_stripped:
                if rule_lines:
                    rules.append(''.join(rule_lines).strip())  # Store the complete rule in the list
                    rule_lines = []  # Reset for the next rule
            rule_lines.append(line)
        if rule_lines:
            rules.append(''.join(rule_lines).strip())  # Add the last rule if any
    return rules

def cleanup_files(directory):
    """Deletes specific files and any file that doesn't have the .yara extension in the given directory and its subdirectories,
    except for report.log."""
    excluded_file = 'report.log'
    files_to_remove = {'valid.yara', 'repaired.yara', 'broken.yara', 'none.yara'}
    valid_extension = '.yara'

    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if file == excluded_file:
                continue  # Skip the excluded file
            if file in files_to_remove or not file.endswith(valid_extension):
                os.remove(file_path)
                print(f"Deleted: {file_path}")

def append_to_summary_file(directory, content):
    """Append content to a file, ensuring it uses UTF-8 encoding."""
    # Check if the content is a YaraSource object or another non-string type
    if isinstance(content, YaraSource):
        try:
            # Assuming 'source' is the attribute holding the rule text
            content = content.source  
        except AttributeError:
            # Handle the case where 'source' attribute does not exist
            content = "Unable to retrieve YARA rule content"
    elif not isinstance(content, str):
        # Fallback for any other non-string content
        content = str(content)

    with open(directory, 'a', encoding='utf-8') as summary_file:
        summary_file.write(content + "\n\n")

def clean_yara_file_v2(yara_file_content):
    lines = yara_file_content.split('\n')
    fields = ["meta:", "strings:", "condition:"]
    # List to hold the cleaned file content
    cleaned_content = []
    item = []
    
    # Flags to handle indentation and rule parsing
    in_rule = False

    for line in lines:
        is_special_comment = any(keyword in line for keyword in ["STATUS:", "ORIGINAL:", "Error:"])
        
        if line.lstrip().startswith('//') and not is_special_comment:
            # Remove leading comment slashes for lines that are not special comments
            line_content = line.lstrip('//').lstrip()
        else:
            line_content = line
        
        # Check for rule start or end
        if line_content.startswith('rule'):
            in_rule = True
            item.append(line_content)
        elif line_content.startswith('}') and in_rule:
            in_rule = False
            item.append(line_content)
            cleaned_content.append('\n'.join(item))
            item = []  # Reset item for the next rule
        elif in_rule:
            if any(field == line_content.strip() for field in fields):
                line_content = line_content.strip()
                item.append(' ' * 4 + line_content)
            else:
                # Normal lines within a rule
                line_content = line_content.strip()
                item.append(' ' * 8 + line_content)
        else:
            # Lines outside rules are not indented
            cleaned_content.append(' ' * 8 + line_content)  # Directly append to cleaned_content

    return cleaned_content


def count_yara_rules_and_find_imports(directory, exclude_filename=None):
    """Counts YARA rules and finds unique imports from all YARA files in a directory, returning results as a dictionary."""
    rule_count = 0
    unique_imports = set()
    rule_pattern = re.compile(r'^\s*rule\s+\w+')  # Pattern to find lines starting with 'rule'
    import_pattern = re.compile(r'^\s*import\s+(\S+)')  # Pattern to find lines starting with 'import'
    valid_extensions = ('.yara', '.yar')
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(valid_extensions):
                file_path = os.path.join(root, file)
                if exclude_filename and file == exclude_filename:
                    continue
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        if rule_pattern.match(line):
                            rule_count += 1
                        match = import_pattern.match(line)
                        if match:
                            unique_imports.add(match.group(1))
    
    return {'item1': rule_count, 'item2': list(unique_imports)}


#################################### MAIN ##############################################

def process_yara_files(root_dir):
    batch_size = 100
    dirs = {'valid': 'valid', 'broken': 'broken', 'repaired': 'repaired'}
    rule_names = {
        "valid": [],
        "broken": [],
        "repaired": []
    }
    
    # Initial count of total rules before processing
    results = count_yara_rules_and_find_imports(os.path.join(root_dir, "rules"))

    for key in dirs:
        os.makedirs(os.path.join(root_dir, dirs[key]), exist_ok=True)
        with open(os.path.join(root_dir, dirs[key] + '/' + dirs[key] + '.yara'), 'w', encoding='utf-8') as file:
            file.write("")

    unique_rules = set()
    temp_file_path = os.path.abspath("temp_batch_yara.yara")
    validator = yara_validator.YaraValidator(auto_clear=True)
    duplicate_rules = 0

    excluded_files = {'valid.yara', 'repaired.yara', 'broken.yara', 'test.yara'}

    with open(temp_file_path, 'w', encoding='utf-8') as temp_file:
        temp_file.write('')
    for dp, dn, filenames in os.walk(root_dir):
        for f in filenames:
            if f in excluded_files:
                continue  # Skip the specified files
            if f.endswith(('.yara', '.yar')):
                file_path = os.path.join(dp, f)
                for rule in yara_rule_parser(file_path):
                    rule_hash = hash(rule)
                    if rule_hash not in unique_rules:
                        unique_rules.add(rule_hash)
                        with open(temp_file_path, 'a', encoding='utf-8') as temp_file:
                            temp_file.write(rule + "\n")
                        if len(unique_rules) % batch_size == 0:
                            validator = yara_validator.YaraValidator(auto_clear=False)
                            validator.add_rule_file(temp_file_path, 'namespace_1')
                            valid, broken, repaired = validator.check_all()
                            for rule in valid:
                                append_to_summary_file(os.path.join(root_dir, dirs['valid'] + '/' + dirs['valid'] + '.yara'), rule)
                            for rule in broken:
                                append_to_summary_file(os.path.join(root_dir, dirs['broken'] + '/' + dirs['broken'] + '.yara'), rule)
                            for rule in repaired:
                                append_to_summary_file(os.path.join(root_dir, dirs['repaired'] + '/' + dirs['repaired'] + '.yara'), rule)
                            open(temp_file_path, 'w').close()  # Clear the file after processing
                    else:
                        duplicate_rules += 1

    if len(unique_rules) % batch_size != 0:
        validator = yara_validator.YaraValidator(auto_clear=False)
        validator.add_rule_file(temp_file_path, 'namespace_1')
        valid, broken, repaired = validator.check_all()
        for rule in valid:
            append_to_summary_file(os.path.join(root_dir, dirs['valid'] + '/' + dirs['valid'] + '.yara'), rule)
        for rule in broken:
            append_to_summary_file(os.path.join(root_dir, dirs['broken'] + '/' + dirs['broken'] + '.yara'), rule)
        for rule in repaired:
            append_to_summary_file(os.path.join(root_dir, dirs['repaired'] + '/' + dirs['repaired'] + '.yara'), rule)

    os.remove(temp_file_path)

    # Clean the output files
    for key in dirs:
        pattern = re.compile(r'^rule\s+(\w+)\s*{', re.IGNORECASE)
        yara_file = os.path.join(root_dir, dirs[key] + '/' + dirs[key] + '.yara')
        
        # Read the existing content from the YARA file
        if os.path.exists(yara_file):
            with open(yara_file, 'r', encoding='utf-8') as file:
                yara_file_content = file.read()

            # Clean the YARA file content
            cleaned_content = clean_yara_file_v2(yara_file_content)
            # Write the cleaned content back to the file
            for rule in cleaned_content:
                match = pattern.match(rule)
                if match:
                    rule_name = match.group(1) + ".yara"
                    rule_names[key].append(rule_name)
                    yara_file_path = os.path.join(root_dir, dirs[key] + '/' + rule_name)
                    with open(yara_file_path, 'w', encoding='utf-8') as file:
                        for i in results['item2']:
                            file.write(f"import {i}\n")
                        file.write(rule)
                else:
                    print(f"No match found for rule: {rule.encode('utf-8', 'ignore').decode('utf-8')}")
        else:
            # Create the file if it does not exist
            with open(yara_file, 'w', encoding='utf-8') as file:
                file.write("")

    # Assuming 'dirs' is a dictionary mapping keys to subdirectory names
    with open(os.path.join(root_dir, "report.log"), 'w', encoding='utf-8') as report_file:
        # Assuming 'results' has been previously defined with the output of count_yara_rules_and_find_imports
        report_file.write(f"Total Initial Rule count: {results['item1']}\n")
        report_file.write(f"Total Duplicate Rule count: {duplicate_rules}\n")

        # Iterate through each key and corresponding subdirectory, excluding the 'rules' directory
        for key, subdir in dirs.items():
            if subdir == 'rules':
                continue
            dir_path = os.path.join(root_dir, subdir)
            exclude_filename = subdir + ".yara"
            # Cleanup extra files
            # Obtain rule count from each specific subdirectory, excluding the file that matches subdir + ".yara"
            subdir_results = count_yara_rules_and_find_imports(dir_path, exclude_filename=exclude_filename)
            # Write only the numeric rule count ('item1') to the report file
            report_file.write(f"{key.capitalize()} rules count: {subdir_results['item1']}\n")


if __name__ == "__main__":
    root_dir = "/files" if len(sys.argv) <= 1 else sys.argv[1]
    process_yara_files(root_dir)
