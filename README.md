# DOSDETECTOR
---
## Introduction
- This project has been created to dectect Dos (Denial of services) attacks for Windows and Linux devices. The core component of this code relies on [pcap library](https://www.tcpdump.org/manpages/pcap.3pcap.html).
---
## Main idea
- Using pcap library to capture packets on the socket, then measuring time per DOSTIMETHRESHOLD to determine attack threshold.
In this project, I tried to simulate a Dos attack and measured that 15000 packets (DOSPACKETTHRESHOLD) per 10 seconds (DOSTIMETHRESHOLD) is a reasonable numbers.
---
## Installation
### HTTPS Clone
- Open the Powershell/Terminal and typing:
```bash 
# Clone DosDetector repository
clone https://github.com/khainguyendiep/DosDetector
# Navigate to the cloned directory
cd DosDetector
```
---
### For Windows
- We need to compile to excuted file on Windows by using minGW, so you have to install [mingGW](https://www.mingw-w64.org/downloads/) first.
- Then we install [npcap installer](https://npcap.com/#download) to pcap library can be work smoothly.
- Typing this command the compile the code:
```bash
# Compile the code
x86_64-w64-mingw32-g++ main.cpp -o main.exe \
-I./npcap-sdk/Include \
-L./npcap-sdk/Lib/x64 \
-lwpcap -lws2_32 -static-libgcc -static-libstdc++
```
---
### For Linux
- Install g++:
```bash
sudo apt install build-essential gdb
```
- Install pcap library:
```bash
sudo apt install libpcap-dev
```
- Open the terminal and move to folder has been cloned and typing on the terminal:
```bash
# Compile the code
exec "!g++ -std=c++17 -Wall % -o %< -lpcap"
```
---
### Running
- Running the executed file that was just created.
- Choosing an network card you want to use.
- Waiting for Dos attack.
---
## License
- MIT license 
