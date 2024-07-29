import json
import argparse


# EXAMPLE: python3 json_2_sql.py.py /tmp/cpanel_import_d0LDqv/backup-7.29.2024_13-22-32_s51nesto/mysql.sql-auth.json /tmp/cpanel_import_d0LDqv/backup-7.29.2024_13-22-32_s51nesto/mysql.sql-auth.sql

def main():
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Generate SQL statements from a JSON file.")
    parser.add_argument('json_file', help="Path to the JSON file")
    parser.add_argument('output_file', help="Path to the output SQL file")
    
    args = parser.parse_args()
    
    json_file_path = args.json_file
    output_file_path = args.output_file
    
    # Load the JSON data
    with open(json_file_path) as f:
        data = json.load(f)
    
    # Open the output SQL file
    with open(output_file_path, 'w') as sql_file:
        for db, hosts in data.items():
            # Skip databases without underscores in their name
            if '_' not in db:
                continue
    
            for host, details in hosts.items():
                # Skip localhost entries
                if host == 'localhost':
                    continue
                
                auth_plugin = details.get('auth_plugin', 'mysql_native_password')
                pass_hash = details.get('pass_hash')
    
                if pass_hash:
                    # Generate the SQL statement with `%` as the hostname
                    sql = f"""
CREATE USER IF NOT EXISTS '{db}'@'%' IDENTIFIED WITH {auth_plugin} BY '{pass_hash}';
GRANT ALL PRIVILEGES ON `{db}`.* TO '{db}'@'%';
"""
                    # Write the SQL statement to the file
                    sql_file.write(sql)

if __name__ == "__main__":
    main()
