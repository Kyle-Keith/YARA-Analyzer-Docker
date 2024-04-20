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
    fields = ["meta:","strings:", "condition:"]
    # List to hold the cleaned file content
    body = []
    
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
            body.append(line_content)
        elif line_content.startswith('}') and in_rule:
            in_rule = False
            body.append( line_content)
        elif in_rule:
            if any(field == line_content.strip() for field in fields):
                line_content =line_content.strip()
                body.append(' ' * 4 + line_content)
            else:
                # Normal lines within a rule
                line_content =line_content.strip()
                body.append(' ' * 8 + line_content)
        else:
            # Lines outside rules are not indented
            body.append(' ' * 8 + line_content)

    # Join all lines to form the cleaned content
    cleaned_content = '\n'.join(body)
    return cleaned_content


def count_yara_rules_in_directory(directory):
    """Counts YARA rules based on lines strictly starting with 'rule' declarations in all YARA files in a directory."""
    rule_count = 0
    rule_pattern = re.compile(r'^\s*rule\s+\w+')  # Pattern to find lines that start with 'rule' followed by whitespace and an identifier
    valid_extensions = ('.yara', '.yar')
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(valid_extensions):
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        if rule_pattern.match(line):
                            rule_count += 1
    return rule_count

#################################### MAIN ##############################################

def process_yara_files(root_dir):
    batch_size = 100
    dirs = {'valid': 'valid', 'broken': 'broken', 'repaired': 'repaired'}

    # Initial count of total rules before processing
    total_initial_rules = count_yara_rules_in_directory(root_dir + "/rules/")
    
    for key in dirs:
        os.makedirs(os.path.join(root_dir, dirs[key] ), exist_ok=True)
        with open(os.path.join(root_dir, dirs[key] + '/' + dirs[key] + '.yara'), 'w', encoding='utf-8') as file:
            file.write(f"\n")

    unique_rules = set()
    temp_file_path = os.path.abspath("temp_batch_yara.yara")
    validator = yara_validator.YaraValidator(auto_clear=True)
    duplicate_rules = 0

    for file_path in [os.path.join(dp, f) for dp, dn, filenames in os.walk(root_dir) for f in filenames if f.endswith(('.yara', '.yar'))]:
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
        yara_file_path = os.path.join(root_dir, dirs[key] + '/' + dirs[key] + '.yara')
        # Read the existing content from the YARA file
        if os.path.exists(yara_file_path):
            with open(yara_file_path, 'r', encoding='utf-8') as file:
                yara_file_content = file.read()

            # Clean the YARA file content
            cleaned_content = clean_yara_file_v2(yara_file_content)

            # Write the cleaned content back to the file
            with open(yara_file_path, 'w', encoding='utf-8') as file:
                file.write(cleaned_content)
        else:
            # Create the file if it does not exist
            with open(yara_file_path, 'w', encoding='utf-8') as file:
                file.write("")

    with open(os.path.join(root_dir, "report.log"), 'w', encoding='utf-8') as report_file:
        report_file.write(f"Total Initial Rule count: {total_initial_rules}\n")
        report_file.write(f"Total Duplicate Rule count: {duplicate_rules}\n")
        for key, subdir in dirs.items():
            dir_path = os.path.join(root_dir, subdir)
            rule_count = count_yara_rules_in_directory(dir_path)  # Count rules in each specific subdirectory
            report_file.write(f"{key.capitalize()} rules count: {rule_count}\n")


if __name__ == "__main__":
    root_dir = "/files" if len(sys.argv) <= 1 else sys.argv[1]
    process_yara_files(root_dir)