#include <stdio.h>
#include <pcap.h>
#include <signal.h>

pcap_t *handle;

static void mycb(u_char *user,
    const struct pcap_pkthdr *h, const u_char *packet)
{
    static int count = 1;
    printf("Packet %d:\n", count);
    printf("    user: %x\n", user);
    printf("    h: %x\n", h);
    printf("    h->ts: %d.%d\n", h->ts.tv_sec, h->ts.tv_usec);
    printf("    h->caplen: %d\n", h->caplen);
    printf("    h->len: %d\n", h->len);
    printf("    packet: %x\n", packet);

    if(count >= 3) {
        pcap_breakloop((pcap_t*)user);
    } else {
        count += 1;
    }
}

void terminate_pcap(int signum)
{
   pcap_breakloop(handle);
}

int main(int argc, char *argv[])
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	bpf_u_int32 net;
	bpf_u_int32 mask;
	char filter_exp[] = "port 23";
	char filter_exp2[] = "port 22";
	struct pcap_pkthdr header;
	const u_char *packet;
	int pcap_loop_ret;
	signal(SIGINT, terminate_pcap);

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	printf("Device: %s\n", dev);
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Can't get netmask for device %s\n", dev);
		net = 0;
	}
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	printf("Capture port 23 packets\n");
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	/* Grab a packet */
	/* start the loop of capture, loop 5 times */
	pcap_loop_ret = pcap_loop(handle, 5, mycb, (u_char*)handle);
	printf("pcap_loop break: %d\n", pcap_loop_ret);

	printf("Capture port 22 packets!\n");
	pcap_compile(handle, &fp, filter_exp2, 0, net);
	pcap_setfilter(handle, &fp);
	pcap_loop_ret = pcap_loop(handle, 5, mycb, (u_char*)handle);
	printf("pcap_loop returned: %d\n", pcap_loop_ret);
	/* And close the session */
	pcap_close(handle);
	return(0);
}
