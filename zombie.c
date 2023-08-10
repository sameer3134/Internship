#include<stdio.h>
#include<unistd.h>
int gval=10;

int main(int argc, char *argv[]){
    pid_t pid=fork();
    int lval=20;
    gval++, lval+=5;
    if(pid==0){   // child process
        puts("children");               // if we put printf it shows after 300 second
        sleep(300);
    }else{         // parent process
        printf("parent");
        sleep(5);
    }
    if(pid==0){
        printf("child process %d %d",gval,lval);
    }else{
        printf("parent process %d %d",gval,lval);
    }
}