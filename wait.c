#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/wait.h>

int main(int argc, char *argv[]){
    int status;
    pid_t pid=fork();
    if(pid==0){   // child process
        exit(3);
    }else{         // parent process
        printf("child pid %d\n",pid);
        pid=fork();
        if(pid==0){
            exit(7);
        }else{
            printf("child pid %d \n",pid);
            wait(&status);
        if(WIFEXITED(status))
            printf("CHILD SEND ONE %d\n",WEXITSTATUS(status));
        wait(&status);
        if(WIFEXITED(status))
            printf("CHILD SEND ONE  %d \n",WEXITSTATUS(status));
        }
    }
}