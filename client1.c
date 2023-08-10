#include<stdio.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<netinet/in.h>

int main(){
    int network_socket;         
    network_socket = socket(AF_INET,SOCK_STREAM,0);      //socket
    struct sockaddr_in server_address;~
    server_address.sin_family=AF_INET;
    server_address.sin_port=htons(8000);
    server_address.sin_addr.s_addr= INADDR_ANY;

    int connection_status;      //connect
    connection_status=connect(network_socket,(struct sockadd *) & server_address, sizeof(server_address));
    if(connection_status==-1){
        printf("error");
    }
    char msg[256];
    recv(network_socket,&msg , sizeof(msg),0);    //recv
    printf("the server send the ddata --> %s \n",msg);
    close(network_socket);    //close
    return 0;
}