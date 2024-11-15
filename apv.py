import argparse
import subprocess
import json
import datetime
from textwrap import fill
from tabulate import tabulate
from itertools import zip_longest
import glob
import os
import zipfile
import time
from func.export import export_json, export_csv_table


def run_bloodhound(domain, username, password):
    try:
        result = subprocess.run(f'cd logs && bloodhound-python -d {domain} -u {username} -p {password} -c ACL --zip',
                                shell=True)
        print(result.stderr)  # Print any errors
    except Exception as e:
        print(f"Error running command: {e}")


def get_zip_file():
    """
    Returns the latest BloodHound zip file created.
    """
    zip_files = glob.glob('.\\logs\\*_BloodHound.zip')
    if not zip_files:
        return None
    zip_files.sort(key=os.path.getmtime)
    return zip_files[-1]


def wmic_query():
    query1 = "wmic useraccount get name,sid"
    query2 = "wmic group get name,sid"
    try:
        # Run both commands
        result1 = subprocess.run(query1, shell=True, capture_output=True, text=True)
        result2 = subprocess.run(query2, shell=True, capture_output=True, text=True)

        # Process result1 and result2 to skip the header line
        result1_lines = result1.stdout.strip().splitlines()[1:]  # Skip the first line
        result2_lines = result2.stdout.strip().splitlines()[1:]  # Skip the first line

        # Join the remaining lines
        combined_result = "\n".join(result1_lines + result2_lines)

        return combined_result
    except Exception as e:
        print(f"Error running command: {e}")


def wmic_query_sep(i):
    if i == 0:
        query = "wmic useraccount get name,sid"
        try:
            result = subprocess.run(query, shell=True, capture_output=True, text=True)
            return result.stdout.strip()
        except Exception as e:
            print(f"Error running command: {e}")
    elif i == 1:
        query = "wmic group get name,sid"
        try:
            result = subprocess.run(query, shell=True, capture_output=True, text=True)
            return result.stdout.strip()
        except Exception as e:
            print(f"Error running command: {e}")


def compare_sid(v, sids):
    # sids = get_sid()
    for user, sid in sids.items():
        if sid in v:
            return user


def get_sid(result):
    # result = str(wmic_query(1))
    lines = result.split("\n")
    dic = {}
    # white_list = ["Administrator", "IT-Help01", "AD-02"]
    # list = ["Print Operators", "Backup Operators", "Replicator", "Remote Desktop Users", "Network Configuration Operators", "Performance Monitor Users", "Performance Log Users", "Distributed COM Users", "IIS_IUSRS", "Cryptographic Operators", "Event Log Readers", "Certificate Service DCOM Access", "RDS Remote Access Servers", "RDS Endpoint Servers", "RDS Management Servers", "Hyper-V Administrators", "Access Control Assistance Operators", "Remote Management Users", "Server Operators", "Account Operators", "Pre-Windows 2000 Compatible Access", "Incoming Forest Trust Builders", "Windows Authorization Access Group", "Terminal Server License Servers", "Cert Publishers", "RAS and IAS Servers", "Allowed RODC Password Replication Group", "Denied RODC Password Replication Group"]
    list = []
    # list = ["Administrators","Backup-SYNC"]
    for line in lines[1:]:
        if line.strip():  # ignore empty lines
            parts = line.split()
            sid = parts[-1]
            user = " ".join(parts[0:-1])
            if user not in list:
                # if user in white_list:
                dic[user] = sid
    return dic


def extract_ace_data(user, data, principal_sid, permission):
    arr0 = []
    arr1 = []
    dic = {}
    for key, value in data.items():
        for item in value:
            if 'Aces' in item and 'Properties' in item:
                s = item["Properties"]["name"]
                s1 = s.split("@")
                if user == s1[0]:
                    for ace in item['Aces']:
                        # if ace['PrincipalType'] == "User" and ace["PrincipalSID"] == principal_sid and ace['RightName'] == permission:
                        if ace['RightName'] == permission:
                            value = ace["PrincipalSID"]
                            user0 = compare_sid(value, get_sid(str(wmic_query_sep(0))))
                            user1 = compare_sid(value, get_sid(str(wmic_query_sep(1))))
                            if user0 not in arr0 and user0 is not None:
                                arr0.append(user0)
                                dic["user"] = arr0
                            elif user1 not in arr1 and user1 is not None:
                                arr1.append(user1)
                                dic["group"] = arr1
    return dic


def read_json(part):
    zip_file = get_zip_file()
    filename = os.path.basename(zip_file)
    date = filename.split('_')[0]
    try:
        with zipfile.ZipFile(zip_file, 'r') as zip_ref:
            with zip_ref.open(f'{date}{part}', 'r') as f:
                content = f.read()
                if not content.strip():  # Check if the file is empty or contains only whitespace
                    print("File is empty or contains only whitespace")
                    return
                data = json.loads(content)
                return data

    except FileNotFoundError:
        print("File not found")
    except json.JSONDecodeError as e:
        print("Error parsing JSON:", e)
    except Exception as e:
        print("An error occurred:", e)


def result_table(passed, header, width=100):
    # Wrap text in each column to the specified width
    passed_wrapped = [fill(item, width=width) if item else '' for item in passed]

    # Create the table with two columns
    table = [p for p in zip_longest(passed_wrapped, fillvalue='')]

    # Print the table
    if len(passed) > 0:
        print(tabulate(table, headers=[header], tablefmt="grid"))
        return tabulate(table, headers=[header], tablefmt="grid")
    return ""


def export_result(current_time, str, table):
    f_name = f"APV_{current_time}.txt"
    with open(f".\\results\\{f_name}", "a+") as f:
        if str != "":
            f.write(str)
        if len(table) > 1:
            f.write(table)

def execute(dic, permission):
    if len(dic) != 0:
        try:
            arr0 = dic.get('user')
            # export_result(current_time, str(count) + "." + user + ":\n", result_table(arr0, "GenericAll") + "\n")
            result_table(arr0, permission)
            export_json(arr0, permission, name,secured_object_type, 'user')
        except:
            pass
        try:
            arr1 = dic.get('group')
            # export_result(current_time, "", result_table(arr1, "GenericAll") + "\n")
            result_table(arr1, permission)
            export_json(arr1, permission, name, secured_object_type, 'group')
        except:
            pass

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Run BloodHound')
    parser.add_argument('-d', '--domain', required=True, help='Domain to target')
    parser.add_argument('-u', '--username', required=True, help='Username to use')
    parser.add_argument('-p', '--password', required=True, help='Password to use')
    args = parser.parse_args()

    new_path = ".\\logs"
    if not os.path.exists(new_path):
        os.makedirs(new_path)
    new_path2 = ".\\results"
    if not os.path.exists(new_path2):
        os.makedirs(new_path2)
    #user
    # run_bloodhound(args.domain, args.username, args.password)
    sids = get_sid(str(wmic_query_sep(0)))
    data = read_json("_users.json")
    count = 0
    print("\n")
    secured_object_type = "user"
    current_time = datetime.datetime.now().strftime('%d%m%Y_%H%M%S')
    for name, sid in sids.items():
        count = count + 1
        principal_sid = sid
        print(str(count) + "." + name)

        dic = extract_ace_data(name.upper(), data, sid, "ForceChangePassword")
        execute(dic, "ForceChangePassword")

        dic = extract_ace_data(name.upper(), data, sid, "GenericAll")
        execute(dic, "GenericAll")

        dic = extract_ace_data(name.upper(), data, sid, "GenericWrite")
        execute(dic, "GenericWrite")

        dic = extract_ace_data(name.upper(), data, sid, "WriteDACL")
        execute(dic, "WriteDACL")

        dic = extract_ace_data(name.upper(), data, sid, "AllExtendedRights")
        execute(dic, "AllExtendedRights")

    export_csv_table()

    '''
    #run_bloodhound(args.domain, args.username, args.password)
    sids = get_sid(str(wmic_query(1)))
    data = read_json("_groups.json")
    #print(data["data"][0]["Properties"]["name"])
    count = 0
    print("\n")
    current_time = datetime.datetime.now().strftime('%d%m%Y_%H%M%S')
    for user, sid in sids.items():
        count = count + 1
        principal_sid = sid
        print("\n" + str(count) + "." + user)

        arr = extract_ace_data(user.upper(), data, sid, "GenericWrite", 1)
        #export_result(current_time, str(count) + "." + user + ":\n",result_table(arr, "GenericWrite") + "\n")

        arr = extract_ace_data(user.upper(),data, sid, "GenericAll", 1)
        #export_result(current_time, "", result_table(arr, "GenericAll") + "\n")

        arr = extract_ace_data(user.upper(),data, sid, "WriteDacl", 1)
        #export_result(current_time, "", result_table(arr, "WriteDacl") + "\n")
    '''
