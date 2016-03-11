/*
 *    Rootkit Programming
 *    Assignment 0 -- TCP Port Scanner
 *
 *    @author : Zonghao Huang
 *    @date : Wed Jul 15 16:17:57 HKT 2015
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>       // gettimeofday()
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>         // take in params
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <signal.h>         // user interrupt handler

using namespace std;

/* some global variables */
int portIdx = 1;
int openPortCounter = 0;

/* print out the usage & help manual */
void help_manual(void){
    printf( "This simple program checks the open ports of the given host.\n"
            "Usage: <command>\n"
            "Command:\n"
            "\t-s Set the starting port, default = 1\n"
            "\t-e Set the ending port, default = 65535\n"
            "\t-p Input the IP address of the host. And note whenever -p is "
                "set, any -h , -l settings will be ignored\n"
            "\t-w Input the hostname directly\n"
            "\t-l Check the open ports on the local host\n"
            "\t-v Verbose, prints all the ports status including both the open "
                "ports and the closed ports\n"
            "\t-h Print this list\n");
    return;
}

/* convert the hostname to IP address */
void hostname2ip(char const* hostname, char * ip){
    hostent *record = NULL;
    record = gethostbyname(hostname);
    if (record == NULL){
        printf("%s is unavailable.\n", hostname );
        exit(1);
    }
    in_addr * address;
    address  = (in_addr * )record->h_addr;
    string ip_tmp;
    ip_tmp = inet_ntoa(* address);
    strcpy(ip, ip_tmp.c_str());
    return;
}

/* interrupt handler for <C-C> */
void userInterruptHandler (int s){
    if (s == 2){
        printf ("\nProcess has been terminated\n");
        printf ("Total number of ports checked : \e[38;5;46m%d \e[m\n", portIdx);
        printf ("Total number of ports open : \e[38;5;46m%d \e[m\n", \
                openPortCounter);
    }
    exit(1);

}


int main(int argc,char **argv){
    /* set up the user interrupt handler */
    struct sigaction sigIntHandler;
    sigIntHandler.sa_handler = userInterruptHandler;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;
    sigaction(SIGINT, &sigIntHandler, NULL);

    /* variables for port scan */
    char command;
    char ip[30];
    char hostname[50];

    int startingPort = 1;
    int endingPort = 65535;
    int sock = -1;
    int doCheckHostName = 1;

    int verbose = 0;

    sockaddr_in addr;
    timeval  tv1, tv2;

    gettimeofday(&tv1, NULL);

    /* read in the commands */
    if (argc < 2){
        printf("Insufficient input, checkout the usage:\n");
        help_manual();
        exit(1);
    }

    while ((command = getopt(argc, argv, "?s:e:p:w:lvh")) > 0){
        switch (command){
            case 's':
                startingPort = atoi(optarg);
                break;
            case 'e':
                endingPort = atoi(optarg);
                break;
            case 'p':
                memcpy(ip,optarg,sizeof(ip));
                doCheckHostName = 0;
                break;
            case 'w':
                if(doCheckHostName){
                    memcpy(hostname,optarg,sizeof(hostname));
                    hostname2ip(hostname, ip);
                    printf("hostname: %s \t ip: %s \n", hostname, ip);
                }
                break;
            case 'l':
                if (doCheckHostName)
                    hostname2ip("localhost", ip);
                break;
            case 'v':
                verbose = 1;
                break;
            case 'h':
            default:
                help_manual();
                return 0;
        }
    }

    /* validate the port range */
    if(startingPort < 1 || endingPort > 65535){
        printf("\e[38;5;1mError: port number out of range!\e[m\n");
        return -1;
    }

    /* fill in the parameters */
    addr.sin_family=AF_INET;
    addr.sin_addr.s_addr=inet_addr(ip);

    printf("Scanning ports \e[38;5;46m%d\e[m-\e[38;5;46m%d\e[m on \e[38;5;14m%s\e[m\n"\
            ,startingPort,endingPort,ip);
    printf("\tAddress:Port \t\t Status\n");

    /* scanning all the ports within the given range */
    openPortCounter = 0;

    for( portIdx = startingPort; portIdx < endingPort + 1; portIdx++ ){
        sock = socket(AF_INET,SOCK_STREAM,0);
        addr.sin_port=htons(portIdx);
        if(connect(sock,(const struct sockaddr *)&addr, \
                    sizeof(struct sockaddr_in)) == 0){
            printf("\t%s:\e[38;5;172m%-5d \t \e[m \e[38;5;12mopen\e[m\n", \
                    ip, portIdx);
            openPortCounter ++;
        }
        else if (verbose){
            printf("\t%s:\e[38;5;172m%-5d \t \e[m closed\n", ip, portIdx);
        }
        close(sock);
    }

    gettimeofday(&tv2, NULL);

    printf("\nScan finished: \e[38;5;14m%s\e[m scanned in \e[38;5;46m%f\e[m seconds\n"\
            ,ip,(double) (tv2.tv_usec - tv1.tv_usec) / 1000000 + \
            (double) (tv2.tv_sec - tv1.tv_sec));
    printf("Total open ports count: \e[38;5;46m%d\e[m\n", openPortCounter);

    return 0;
}
