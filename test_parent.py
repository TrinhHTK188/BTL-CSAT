from datetime import datetime, time as datetime_time
import subprocess
import psutil
from pymongo import MongoClient
from scapy.all import *
import socket

client = MongoClient('mongodb://localhost:27017')
db = client['Test']
domain_collection = db['Test_domain']
ip_collection = db['Test_IP']


def domain_correct(domain):
    parts = domain.split(".")
    result = ".".join(parts[-2:])
    if result.endswith("."):
        result = result[:-1]
    return result


def domain_to_app(domain):
    query = {'Domain': domain}
    result = domain_collection.find_one(query)

    if result:
        app = result.get('App')
        return app
    else:
        domain1 = domain_correct(domain)
        query1 = {'Domain': domain1}
        result1 = domain_collection.find_one(query1)
        if result1:
            app1 = result1.get('App')
            return app1
        else:
            return "Không xác định ứng dụng"


def ip_to_app(ip_address):
    query = {'IP': ip_address}
    result = ip_collection.find_one(query)

    if result:
        app = result.get('App')
        return app
    else:
        return "Không xác định ứng dụng"


def domain_to_ip(domain_name):
    try:
        ip_address = socket.gethostbyname(domain_name)
        return ip_address
    except socket.gaierror:
        return "Không thể tìm thấy địa chỉ IP cho tên miền."


def run_subprocess(command):
    process = subprocess.Popen(
        command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    return process.returncode, out, err


def terminate_process_and_children(pid):
    try:
        parent_process = psutil.Process(pid)
        children = parent_process.children(recursive=True)

        for child in children:
            child.terminate()

        psutil.wait_procs(children, timeout=5)
        parent_process.terminate()
        parent_process.wait(5)

        print(f"Terminated parent process (PID {pid}) and its children.")
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
        print(f"Error terminating process (PID {pid}): {e}")


def stop_processes_by_connection(target_address):
    processes = psutil.process_iter(['pid', 'name', 'connections'])

    for process in processes:
        try:
            for conn in process.info['connections']:
                if target_address in conn.raddr:
                    pid = process.info['pid']
                    terminate_process_and_children(pid)
                    print(f"Terminated processes connected to {
                          target_address} (PID {pid})")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass


def is_within_allowed_time():
    current_time = datetime.now().time()
    start_time = datetime_time(7, 0)
    end_time = datetime_time(21, 0)
    return start_time <= current_time <= end_time


def kill_processes(App):
    try:
        all_processes = psutil.process_iter()

        for process in all_processes:
            try:
                if App in process.name():
                    process.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

    except Exception as e:
        print(f"Lỗi: {e}")


def dns_packet_handler(packet):
    if DNS in packet and packet.qr == 0:
        domain = packet[DNS].qd.qname.decode('utf-8')
        if domain.endswith("."):
            domain = domain[:-1]

        app = domain_to_app(domain)
        if app != "Không xác định ứng dụng":
            ip_addr = domain_to_ip(domain)
            if (ip_addr != "Không thể tìm thấy địa chỉ IP cho tên miền."):
                if (ip_to_app(ip_addr) == "Không xác định ứng dụng"):
                    ip_collection.insert_one({'App': app, 'IP': ip_addr})
            if is_within_allowed_time():
                stop_processes_by_connection(ip_addr)
            print(f"{domain} : {app}")
        else:
            ip_address = domain_to_ip(domain)
            if ip_address != "Không thể tìm thấy địa chỉ IP cho tên miền.":
                app_from_ip = ip_to_app(ip_address)
                if app_from_ip != "Không xác định ứng dụng":
                    # Thêm domain vào csdl
                    domain_collection.insert_one(
                        {'App': app_from_ip, 'Domain': domain})
                    if is_within_allowed_time():
                        stop_processes_by_connection(ip_address)
                    print(f"{domain} : {ip_address} : {app_from_ip}")
                else:
                    print(f"{domain} : Không xác định ứng dụng")
            else:
                print(f"{domain} : Không xác định ứng dụng")


# Bắt gói tin DNS
sniff(filter="udp and port 53", prn=dns_packet_handler)
