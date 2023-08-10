#include<stdio.h>
#include<stdlib.h>

#include<sys/socket.h>
#include<sys/types.h>
#include<netinet/in.h>

int main(){
    char server_message[256]="socket programming";
    int server_socket=socket(AF_INET,SOCK_STREAM,0);    // create socket
    struct sockaddr_in server_address;
    server_address.sin_family=AF_INET;
    server_address.sin_port=htons(8000);
    server_address.sin_addr.s_addr= INADDR_ANY;

    bind(server_socket,(struct sockadd *) & server_address, sizeof(server_address));    //bind

    listen(server_socket,5);       //listen

    int cliemt_sock;
    cliemt_sock= accept(server_socket,NULL,NULL);   //accept

    send(cliemt_sock,server_message, sizeof(server_message),0);    //send
    close(server_socket);    //close
    return 0;
}