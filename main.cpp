#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <chrono>

#if defined(_WIN32)
    #include <winsock2.h>
    #pragma comment(lib, "ws2_32.lib") 
#else
	#include <sys/socket.h>
    #include <unistd.h>
#endif
const long long DOSPACKETTHRESHOLD = 15000; // packets
const double DOSTIMETHRESHOLD = 10000; //milisecond

struct DosDetectorState{
	pcap_t *handle;
	std::chrono::steady_clock::time_point timeBegin = std::chrono::steady_clock::now();
	std::chrono::steady_clock::time_point timeEnd = std::chrono::steady_clock::now();
	long long packetNumber = 0;
	long long countCapturedPacket = 0;
};
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	DosDetectorState *state = (DosDetectorState*)args;
	state->packetNumber++;
	state->countCapturedPacket++;
	printf("Captured %lld packets\n", state->packetNumber);
	if(state->countCapturedPacket == DOSPACKETTHRESHOLD){
			state->timeEnd = std::chrono::steady_clock::now();
			std::chrono::milliseconds elapsedTime = std::chrono::duration_cast<std::chrono::milliseconds>(state->timeEnd - state->timeBegin);
			if(elapsedTime.count() <= DOSTIMETHRESHOLD){
				printf("The computer got a Dos attack.\n");
				pcap_breakloop(state->handle);
			}
		printf("Elapsed time: %ld\n", elapsedTime.count());
		state->timeBegin = std::chrono::steady_clock::now(); // if there is not a Dos a attack, setting new time-counter
		state->countCapturedPacket = 0;
	}
}

bool listAllDevs(pcap_if_t *alldevsp, char *listDev[], int &countDevs){
	for(pcap_if_t *d = alldevsp; d != NULL; d = d->next){
		bool hasIP = false;
		// finding ipv4 of a device by iterating a linked list of addresses (include ipv6, ipv4, MAC address... without any order)
		for(pcap_addr_t *a = d->addresses; a != NULL; a = a->next){
			if(a->addr->sa_family == AF_INET){
				hasIP = true;
				break;
			}
		}
		if(hasIP == true){
			countDevs++;
			listDev[countDevs] = d->name;
			printf("[%d] - %s - %s\n", countDevs, d->name, d->description);
		}
	}
	if(countDevs == 0) return false;
	return true;
}
char* choosingDev(pcap_if_t *alldevsp, char *listDevs[]){
	int countDevs = 0;	
	if(listAllDevs(alldevsp, listDevs, countDevs) == false){
		printf("No devices available.\n");
		return listDevs[0];
	}
	printf("Choose one device:\n");
	int devOrderNumber = 0;
	while(true){
		scanf("%d", &devOrderNumber);
		if(devOrderNumber <= countDevs){
			break;
		}
		else{
			printf("Please choosing available number.\n"); 
		}
	}
	return listDevs[devOrderNumber];
}

int main(){
	printf("Start detect\n");
	DosDetectorState state;
	pcap_t *handle;
	bpf_u_int32 mask; // netmask of sniffing device
	bpf_u_int32 net;
	struct bpf_program fp; // the complied filter expression
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevsp = NULL;
	char *listDevs[1000];
	
	//const char *filter_expression[] ={(tcp[tcpflags] & tcp-syn != 0) or udp or icmp"};
	//tcpflags is located in the 13th byte of the TCP header (counting from 0).
	//tcp-syn has a value of 2 (00000010).
	const char *filter_expression[] ={"(tcp[13] & 2 != 0) or udp or icmp"};

	if(pcap_findalldevs(&alldevsp, errbuf) != 0){
		printf("Finding netword card error!!!");
		return (2);
	}
	
	//choosing device
	dev = choosingDev(alldevsp, listDevs);
	
	// pcap_lookupnet() is used to determine the IPv4 network number and mask associated with the network device device.
	if(pcap_lookupnet(dev, &net, &mask, errbuf) != 0){
		printf("Can't get netmask for the device\n");
		return(2);
	}
	/* pcap_t *pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf);
	*  device is name of device
	*  snaplen is length of length of the packet to be captured
	*  promisc (Promiscuous Mode) with:
	**  	0 is Network cards only accept packets specifically addressed to your computer (and broadcast packets). They ignore packets from other users. 
	**  	1 is The network card will "grab" all packets p(double)(state->timeEnd - state->timeBegin)assing through the cable, including packets not intended for it.
	*  to_ms (read timeout): The unit is milliseconds (ms). It specifies the time the kernel waits to gather enough packets before returning the data to your handler function.
	*
	*/	
	
	handle = pcap_open_live(dev, BUFSIZ, 0, 1000000, errbuf);
	if(handle == NULL){
		printf("Can't open device\n");
		return (2);
	}
	
	/* int pcap_compile(pcap_t *p, struct bpf_program *fp, const char *str, int optimize, bpf_u_int32 netmask);
	 * pcap_t * p: This is the session management pointer for the packet capture you created earlier using the pcap_open_live function.
	 * struct bpf_program *fp: This is the "destination". After the function finishes running, the compiled machine code will be saved to this structure variable.
	 * const char *str: This is the rules what you want to capture in the captured packet.
	 * int optimize: accelerate compile code.a
	 * bpf_u_int32 netmask: netmask of listening network card (the mask parameter of pcap_lookupnet)
	*/
	
	if(pcap_compile(handle, &fp, *filter_expression, 1, mask) != 0){
		printf("Couldn't parse filter\n");
		return (2);	
	}
	
	if(pcap_setfilter(handle, &fp) != 0){
		printf("Couldn't install filter");
		return (2);
	}
	
	state.handle = handle;
	state.timeBegin = std::chrono::steady_clock::now();
	pcap_loop(handle, -1, got_packet, (u_char*)&state);
	printf("Detected sucessfully");
	pcap_close(handle);
	return(0);
}
