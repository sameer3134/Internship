#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define BUF_SIZE 30
void error_handling(char *message);

int main(int argc, char *argv[])
{
	int sock;
	char msg1[]="hi";
    char msg2[]="i am another user";
    char msg3[]="nice to meet you";
    
	
	socklen_t adr_sz;
	
	struct sockaddr_in serv_adr;
	if(argc!=3){
		printf("Usage : %s <IP> <port>\n", argv[0]);
		exit(1);
	}
	
	sock=socket(PF_INET, SOCK_DGRAM, 0);   
	if(sock==-1)
		error_handling("socket() error");
	
	memset(&serv_adr, 0, sizeof(serv_adr));
	serv_adr.sin_family=AF_INET;
	serv_adr.sin_addr.s_addr=inet_addr(argv[1]);
	serv_adr.sin_port=htons(atoi(argv[2]));

    sendto(sock, msg1, strlen(msg1), 0, 
					(struct sockaddr*)&serv_adr, sizeof(serv_adr));
    sendto(sock, msg2, strlen(msg2), 0, 
					(struct sockaddr*)&serv_adr, sizeof(serv_adr));
    sendto(sock, msg3, strlen(msg3), 0, 
					(struct sockaddr*)&serv_adr, sizeof(serv_adr));
	close(sock);
	return 0;
}

void error_handling(char *message)
{
	fputs(message, stderr);
	fputc('\n', stderr);
	exit(1);
}