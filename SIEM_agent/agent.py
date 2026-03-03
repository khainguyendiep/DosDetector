import socket
import os 
import time
import subprocess
import select
from file_read_backwards import FileReadBackwards

HOST_IP = "10.0.2.4"
PORT = 4000
LOG_FILE = "/var/log/auth.log"
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as soc:
    soc.connect((HOST, PORT))
    linuxProcess = subprocess.Popen(['tail','-F',LOG_FILE], stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    p = select.poll()
    p.register(linuxProcess.stdout)
    while True:
        if p.poll(500): # Each 500ms call process 1 time. If new log is wrote, send it to server
            newLog = linuxProcess.stdout.readline()
            if newLog:
                soc.sendall(newLog.strip())
        
