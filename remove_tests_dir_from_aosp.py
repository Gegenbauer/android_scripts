#!/usr/bin/env python3

# remove tests directory from Android Studio iml file.
# remove lines contains isTestSource="true"

def remove_tests_dir_from_iml(iml_file_path):
    """Removes lines containing isTestSource="true" from the given iml file.\n
    Save original file as iml_file_path.bak before modifying.
    Args:
        iml_file_path (str): The path to the iml file.
    """
    try:
        # Read the original iml file
        with open(iml_file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()

        # Create a backup of the original file
        with open(iml_file_path + '.bak', 'w', encoding='utf-8') as backup_file:
            backup_file.writelines(lines)

        # Filter out lines containing isTestSource="true"
        filtered_lines = [line for line in lines if 'isTestSource="true"' not in line]

        # Write the filtered lines back to the iml file
        with open(iml_file_path, 'w', encoding='utf-8') as file:
            file.writelines(filtered_lines)

        print(f"Removed test directories from {iml_file_path} and created a backup at {iml_file_path}.bak")
    except Exception as e:
        print(f"Error processing {iml_file_path}: {e}")
        
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python remove_tests_dir.py <path_to_iml_file>")
        sys.exit(1)

    iml_file_path = sys.argv[1]
    remove_tests_dir_from_iml(iml_file_path)