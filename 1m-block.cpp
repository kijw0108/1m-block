#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnet.h>
#include <string.h>
#include <queue>

#define CharNum 39
using namespace std;

int getChartoNum(char x)
{
	if('0' <= x && x <= '9')return x - '0';
	if('A' <= x && x <= 'Z')return x - 'A' + 10;
	if('a' <= x && x <= 'z')return x - 'a' + 10;
	if(x == '.')return 36;
	if(x == '-')return 37;
	if(x == '/')return 38;
	return -1;
}

struct Trie
{
	Trie* go[CharNum];
	Trie* failure;
	bool isExist;

	Trie() {
		fill(go, go + CharNum, nullptr);
		failure = nullptr;
		isExist = false;
	}
	~Trie() {
		for (int i = 0; i < CharNum; i++)if (go[i])delete go[i];
	}

	void insert(const char* key) {
		if (*key == 0) {
			isExist = true;
			return;
		}
		int next = getChartoNum(*key);
		if (!go[next])go[next] = new Trie;
		go[next]->insert(key + 1);
	}
};

char method[9][8] = {"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"};
char block_address[100], block_site[100], input_char;
int block_address_cnt = 0, block_site_cnt = 0;
int method_len[9] = {3, 4, 4, 3, 6, 7, 7, 5, 5};
Trie* root;

void getFailure()
{
	queue<Trie*> qu;
	root->failure = root;
	qu.push(root);
	while (!qu.empty()) {
		Trie* current = qu.front();
		qu.pop();
		for (int i = 0; i < CharNum; i++) {
			Trie* next = current->go[i];
			if (!next)continue;
			if (current == root)next->failure = root;
			else {
				Trie* destination = current->failure;
				while (destination != root && !destination->go[i])destination = destination->failure;
				if (destination->go[i])destination = destination->go[i];
				next->failure = destination;
			}
			if (next->failure->isExist)next->isExist = true;
			qu.push(next);
		}
	}
}

bool beBlocked(char* c)
{
	Trie* current = root;
	bool toreturn = false;
	for (int j = 0; c[j]; j++) {
		if(current == root)block_address_cnt = 0;
		int next = getChartoNum(c[j]);
		if(next == -1) {
			block_address_cnt = 0;
			continue;
		}
		block_address[block_address_cnt] = c[j];
		block_address_cnt++;
		while (current != root && !current->go[next])current = current->failure;
		if (current->go[next])current = current->go[next];
		if (current->isExist) {
			toreturn = true;
			break;
		}
	}
	return toreturn;
}

void usage()
{
	printf("syntax: 1m-block <site list file>\n");
	printf("sample: 1m-block top-1m.txt\n");
}

static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	int ret;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		/*
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
		*/
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		/*
		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
		*/
	}

	/*
	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
		printf("payload_len=%d\n", ret);

	fputc('\n', stdout);
	*/

	return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa), cur_len = 0;
	unsigned char *packet;
	int ret = nfq_get_payload(nfa, &packet);
	if (ret >= 0) {
		struct libnet_ipv4_hdr* Ip = (struct libnet_ipv4_hdr*)packet;
		if(Ip->ip_p != IPPROTO_TCP)return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
		cur_len += (Ip->ip_hl << 2);
		
		struct libnet_tcp_hdr *Tcp = (struct libnet_tcp_hdr*)(packet + cur_len);
		cur_len += (Tcp->th_off << 2);
		
		char* http = (char*)(packet + cur_len);
		int http_len = strlen(http);
		
		bool flag = true;
		for(int i = 0; i < http_len; i++) {
			for(int j = 0; j < 9; j++) {
				if(i + method_len[j] >= http_len)continue;
				if(strncmp(http + i, method[j], method_len[j]) == 0) {
					flag = false;
					http = (char*)(http + method_len[j]);
					http_len = strlen(http);
					break;
				}
			}
			if(!flag)break;
		}
		if(flag)return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
		
		if(beBlocked(http)) {
			printf("Blocked ");
			for(int i = 0; i < block_address_cnt; i++) {
				printf("%c", block_address[i]);
			}
			printf(" complete!\n");
			return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
		}
	}
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	if(argc != 2) {
		usage();
		return -1;
	}
	
	root = new Trie;
	
	FILE *fp = fopen(argv[1], "r");
	while(input_char != EOF) {
		input_char = getc(fp);
		if(input_char == '\n') {
			block_site[block_site_cnt] = 0;
			root->insert(block_site);
			block_site_cnt = 0;
		}
		else if(input_char == ',')block_site_cnt=0;
		else {
			block_site[block_site_cnt] = input_char;
			block_site_cnt++;
		}
	}
	
	getFailure();
	
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			// printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);
	delete root;

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}

