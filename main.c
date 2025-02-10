#include <asm-generic/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <sys/types.h>
#include <netdb.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct tcphdr_p{
        unsigned int src_ip;
        unsigned int dest_ip;
        unsigned char reserved;
        unsigned char protocol;
        unsigned short tcp_len;
};

unsigned short checksum(unsigned short* ptr, int nbytes){
        long sum;
        short answer;
        unsigned short oddbyte;
        sum=0;
        while(nbytes>1){
                sum+=*ptr++;
                nbytes-=2;
        }
        if(nbytes==1){
                oddbyte=0;
                *((u_char*)&oddbyte)=*(u_char*)ptr;
                sum+=oddbyte;
        }

        sum = (sum>>16)+(sum&0xffff);
        sum=sum+(sum>>16);
        answer=(short)~sum;
        return answer;
}

char* construct_packet(int dest_port){
        char *datagram = malloc(4096);
        memset(datagram, 0, 4096);
        struct iphdr *iph = (struct iphdr*)datagram;
        struct tcphdr *tcph = (struct tcphdr*) (datagram + sizeof(struct iphdr));

        char *data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
        strcpy(data, "");
        
        char source_ip[32];
        strcpy(source_ip, "127.0.0.1");

        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data);
        iph->id = htonl(54321);
        iph->frag_off = 0;
        iph->ttl = 255;
        iph->protocol = 6;
        iph->check = 0;
        iph->saddr = inet_addr(source_ip);
        iph->daddr = inet_addr(source_ip);
        iph->check = checksum((unsigned short*)datagram, iph->tot_len);
        
        tcph->source = htons(1234);
        tcph->dest = htons(dest_port);
        tcph->seq = 0;
        tcph->ack_seq = 0;
        tcph->syn=1;
        tcph->urg=0;
        tcph->rst=0;
        tcph->ack=0;
        tcph->doff=5;
        tcph->window=htons(5840);
        tcph->check=0;
        tcph->urg_ptr=0;
        
        struct tcphdr_p psh;
        psh.src_ip = inet_addr(source_ip);
        psh.dest_ip = inet_addr(source_ip);
        psh.reserved=0;
        psh.protocol=6;
        psh.tcp_len=htons(sizeof(struct tcphdr) + strlen(data));
        
        int psize = sizeof(struct tcphdr_p) + sizeof(struct tcphdr) + strlen(data);
        char* pseudogram;
        pseudogram = malloc(psize);
        memcpy(pseudogram,(char*)&psh,sizeof(struct tcphdr_p));
        memcpy(pseudogram+sizeof(struct tcphdr_p),tcph, sizeof(struct tcphdr)+strlen(data));

        tcph->check=checksum((unsigned short*)pseudogram, psize);
        
        free(pseudogram);
        return datagram;
}

int main(void){

        int sockfd;
        if((sockfd = socket(AF_INET,SOCK_RAW,6)) == -1){
                fprintf(stderr, "socket creation failed.\n");       
        };

        int one = 1;
        const int *val = &one;
        if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, val,sizeof(one))<0){
                fprintf(stderr, "setsockopt failed");
                exit(0);
        }

        struct timeval timeout;
        timeout.tv_sec=5;
        timeout.tv_usec=0;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,&timeout,sizeof(timeout));

        int recv_buf_size = 1024*1024;
        setsockopt(sockfd,SOL_SOCKET,SO_RCVBUF,&recv_buf_size,sizeof(recv_buf_size));

        struct sockaddr_in target;
        memset(&target,0,sizeof(target));
        target.sin_family = AF_INET;
        target.sin_addr.s_addr = inet_addr("127.0.0.1");

        for(int i = 1000;i < 10000;i++){
                char* datagram = construct_packet(i);
                if((sendto(sockfd, datagram, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr*)&target, sizeof(target)))<0){
                                fprintf(stderr,"sendto failed");
                };
                free(datagram);
                usleep(1000);
        }
        
        char buffer[4096];
        struct sockaddr_in source;
        socklen_t sourcelen = sizeof(source);

        while (1) {
            int bytes = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&source, &sourcelen);
            if (bytes > 0) {
                struct iphdr* iph = (struct iphdr*)buffer;
                struct tcphdr* tcph = (struct tcphdr*)(buffer + iph->ihl * 4);

                printf("Received: src=%s src_port=%d dest_port=%d flags=SYN:%d ACK:%d RST:%d\n",
                       inet_ntoa(source.sin_addr), ntohs(tcph->source), ntohs(tcph->dest),
                       tcph->syn, tcph->ack, tcph->rst);
            } else {
                perror("recvfrom failed");
            }
        }

        close(sockfd);
        return 0;
}
