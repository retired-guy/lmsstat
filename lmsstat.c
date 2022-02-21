/*
 *   SlimProtoLib is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with SlimProtoLib; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h> /* struct hostent, gethostbyname */

#include <assert.h>
#include <sys/types.h>
#include <signal.h>
#include <ctype.h>

#include "cJSON.h"
    
#ifdef __WIN32__
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include "poll.h"
  #define CLOSESOCKET(s) closesocket(s)
  #define MSG_DONTWAIT (0)
#else
  #include <sys/poll.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <sys/types.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h> 
  #include <netdb.h>
  #include <net/if.h>
  #include <sys/socket.h>
  #include <sys/ioctl.h>
  #include <sys/time.h>
  #include <errno.h>
  #define CLOSESOCKET(s) close(s)
#endif

#define BUF_LENGTH 4096

/* fprintf(stderr, __VA_ARGS__) */
#define DEBUGF(...)
#define VDEBUGF(...)

#define packN4(ptr, off, v) { ptr[off] = (char)(v >> 24) & 0xFF; ptr[off+1] = (v >> 16) & 0xFF; ptr[off+2] = (v >> 8) & 0xFF; ptr[off+3] = v & 0xFF; }
#define packN2(ptr, off, v) { ptr[off] = (char)(v >> 8) & 0xFF; ptr[off+1] = v & 0xFF; }
#define packC(ptr, off, v) { ptr[off] = v & 0xFF; }
#define packA4(ptr, off, v) { strncpy((char*)(&ptr[off]), v, 4); }

#define unpackN4(ptr, off) ((ptr[off] << 24) | (ptr[off+1] << 16) | (ptr[off+2] << 8) | ptr[off+3])
#define unpackN2(ptr, off) ((ptr[off] << 8) | ptr[off+1])
#define unpackC(ptr, off) (ptr[off])

#define	bool	int
#define	true	1
#define	false	0

#define DISCOVERY_PKTSIZE	1516
#define SLIMPROTO_DISCOVERY	"eNAME\0JSON\0"

int slimproto_discover(char *server_addr, int server_addr_len, int port, unsigned int *jsonport, bool scan)
{
	int sockfd;
	int try;
	char *packet;
	int pktlen;
	int pktidx;
	char *t;
	unsigned int l;
	char *v;
	char *server_name;
	char *server_json;
	struct pollfd pollfd;
	struct sockaddr_in sendaddr;
	struct sockaddr_in recvaddr;
#ifdef __WIN32__
        WSADATA info;
#endif

	socklen_t sockaddr_len = sizeof(sendaddr);

	int broadcast=1;
	int serveraddr_len = -1;

#ifdef __WIN32__
        /* Need to initialize winsock if scanning on windows as slimproto_init has not been called */
        if ( scan )
        {
                if (WSAStartup(MAKEWORD(1,1), &info) != 0)
                {
                        fprintf(stderr, "Cannot initialize WinSock");
                        return -1;
                }
        }
#endif

        if((sockfd = socket(PF_INET, SOCK_DGRAM, 0)) == -1)
	{
                perror("sockfd");
                return -1;
        }

	pollfd.fd = sockfd;
	pollfd.events = POLLIN;

       if((setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, (const  void*) &broadcast, sizeof broadcast)) == -1)
	{
		perror("setsockopt - SO_BROADCAST");
                return -1;
        }

        sendaddr.sin_family = AF_INET;
        sendaddr.sin_port = htons(0);
        sendaddr.sin_addr.s_addr = INADDR_ANY;
        memset(sendaddr.sin_zero,'\0',sizeof sendaddr.sin_zero);

        if(bind(sockfd, (struct sockaddr*) &sendaddr, sizeof sendaddr) == -1)
	{
		perror("bind");
		return -1;
        }

	recvaddr.sin_family = AF_INET;
	recvaddr.sin_port = htons(port);
	recvaddr.sin_addr.s_addr = INADDR_BROADCAST;

	memset(recvaddr.sin_zero,'\0',sizeof recvaddr.sin_zero);

	packet = malloc ( sizeof ( char ) * DISCOVERY_PKTSIZE );
	v = malloc ( sizeof ( char ) * 256 );
	t = malloc ( sizeof ( char ) * 256 );
	server_name = malloc ( sizeof ( char ) * 256 );
	server_json = malloc ( sizeof ( char ) * 256 );
	if ( (packet == NULL) ||
		(v == NULL) ||
		(t == NULL) ||
		(server_name == NULL) ||
		(server_json == NULL) )
	{
		perror("malloc");
		return -1;
	}

	for (try = 0; try < 5; try ++)
	{
		if (sendto(sockfd, SLIMPROTO_DISCOVERY, sizeof(SLIMPROTO_DISCOVERY), 0,
			(struct sockaddr *)&recvaddr, sizeof(recvaddr)) == -1)
		{
			CLOSESOCKET(sockfd);
			perror("sendto");
			return -1;
		}

		DEBUGF("slimproto_discover: discovery packet sent\n");

		/* Wait up to 1 second for response */
		while (poll(&pollfd, 1, 1000))
		{
			memset(packet,0,sizeof(packet));

			pktlen = recvfrom(sockfd, packet, DISCOVERY_PKTSIZE, MSG_DONTWAIT,
				(struct sockaddr *)&sendaddr, &sockaddr_len);

			if ( pktlen == -1 ) continue;

			/* Invalid response packet, try again */
			if ( packet[0] != 'E') continue;

			memset(server_name,0,sizeof(server_name));
			memset(server_json,0,sizeof(server_json));

			VDEBUGF("slimproto_discover: pktlen:%d\n",pktlen);

			/* Skip the E */
			pktidx = 1;

			while ( pktidx < (pktlen - 5) )
			{
				strncpy ( t, &packet[pktidx], pktidx + 3 );
				t[4] = '\0';
				l = (unsigned int) ( packet[pktidx + 4] );
				strncpy ( v, &packet[pktidx + 5], pktidx + 4 + l);
				v[l] = '\0';
				pktidx = pktidx + 5 + l;

				if ( memcmp ( t, "NAME", 4 ) == 0 )
				{
					strncpy ( server_name, v, l );
					server_name[l] = '\0';
				}
				else if ( memcmp ( t, "JSON", 4 ) == 0 )
				{
					strncpy ( server_json, v, l );
					server_json[l] = '\0';
				}

				VDEBUGF("slimproto_discover: key: %s len: %d value: %s pktidx: %d\n",
					t, l, v, pktidx);
			}

			inet_ntop(AF_INET, &sendaddr.sin_addr.s_addr, server_addr, server_addr_len);

			*jsonport = (unsigned int) strtoul(server_json, NULL, 10);

			DEBUGF("slimproto_discover: discovered %s:%u (%s)\n",
				server_name, *jsonport, server_addr);

			serveraddr_len = strlen(server_addr);

			/* Server(s) responded, so don't try again */
			try = 5;

			if ( scan )
				printf("%s:%u (%s)\n", server_name, *jsonport, server_addr);
			else
				break ; /* Return first server that replied */
		}
	}

	CLOSESOCKET(sockfd);

	if ( scan )
	{
		strcpy ( server_addr, "0.0.0.0" );
		*jsonport = 0;
		serveraddr_len = -1;
#ifdef __WIN32__
                WSACleanup();
#endif
	}

	if ( server_json != NULL )
		free (server_json);

	if ( server_name != NULL )
		free (server_name);

	if ( t != NULL )
		free (t);

	if ( v != NULL )
		free (v);

	if ( packet != NULL )
		free (packet);

	DEBUGF("slimproto_discover: end\n");
	
	return serveraddr_len ;
}

static void license(void) {
	printf( "\n"
		"This program is free software: you can redistribute it and/or modify\n"
		"it under the terms of the GNU General Public License as published by\n"
		"the Free Software Foundation, either version 3 of the License, or\n"
		"(at your option) any later version.\n\n"
		"This program is distributed in the hope that it will be useful,\n"
		"but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
		"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
		"GNU General Public License for more details.\n\n"
		"You should have received a copy of the GNU General Public License\n"
		"along with this program.  If not, see <http://www.gnu.org/licenses/>.\n\n"
		"The source is available from https://github.com/ralph-irving/squeezelite\n"
		);
}

static size_t get_hash(const char* cp)
{
    size_t hash = 0;
    while (*cp)
        hash = hash + (unsigned char) *cp++;
    return hash;
}


int get_mac(char *mac) {

        int fd;
        struct ifreq ifr;

        fd = socket(AF_INET, SOCK_DGRAM, 0);
        ifr.ifr_addr.sa_family = AF_INET;
        strncpy(ifr.ifr_name, "wlan0", IFNAMSIZ-1);

        ioctl(fd, SIOCGIFHWADDR, &ifr);
        close(fd);

        sprintf(mac,"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
        (unsigned char)ifr.ifr_hwaddr.sa_data[0],
        (unsigned char)ifr.ifr_hwaddr.sa_data[1],
        (unsigned char)ifr.ifr_hwaddr.sa_data[2],
        (unsigned char)ifr.ifr_hwaddr.sa_data[3],
        (unsigned char)ifr.ifr_hwaddr.sa_data[4],
        (unsigned char)ifr.ifr_hwaddr.sa_data[5]);
        
        return(0);
}

void error(const char *msg) { perror(msg); exit(0); }

int post(char *host, int portno, char *q, char *buf, int buflen)
{
    int i;

    struct hostent *server;
    struct sockaddr_in serv_addr;
    int sockfd, bytes, sent, received, total, message_size;
    char *message;
    char *response = buf;

    /* How big is the message? */
    message_size=0;
    message_size+=strlen("%s %s HTTP/1.0\r\nPOST /jsonrpc.js");
    message_size+=strlen(q)+strlen("\r\n");
    message_size+=strlen("Content-Length: %d\r\n")+10; /* content length */
    message_size+=strlen("\r\n");                          /* blank line     */

    /* allocate space for the message */
    message=malloc(message_size);

    /* fill in the parameters */
    sprintf(message,"POST /jsonrpc.js HTTP/1.0\r\n");
    sprintf(message+strlen(message),"Content-Length: %d\r\n",strlen(q));
    strcat(message,"\r\n");                                /* blank line     */
    strcat(message,q);
    strcat(message,"\r\n");

    /* create the socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) error("ERROR opening socket");

    /* lookup the ip address */
    server = gethostbyname(host);
    if (server == NULL) error("ERROR, no such host");

    /* fill in the structure */
    memset(&serv_addr,0,sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(portno);
    memcpy(&serv_addr.sin_addr.s_addr,server->h_addr,server->h_length);

    /* connect the socket */
    if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0)
        error("ERROR connecting");

    /* send the request */
    total = strlen(message);
    sent = 0;
    do {
        bytes = write(sockfd,message+sent,total-sent);
        if (bytes < 0)
            error("ERROR writing message to socket");
        if (bytes == 0)
            break;
        sent+=bytes;
    } while (sent < total);

    /* receive the response */
    memset(response,0,buflen);
    total = buflen-1;

    received = 0;
    do {
        bytes = read(sockfd,response+received,total-received);
        if (bytes < 0)
            error("ERROR reading response from socket");
        if (bytes == 0)
            break;
        received+=bytes;
    } while (received < total);


    /*
     * if the number of received bytes is the total size of the
     * array then we have run out of space to store the response
     * and it hasn't all arrived yet - so that's a bad thing
     */
    if (received == total)
        error("ERROR storing complete response from socket");

    /* close the socket */
    close(sockfd);

    free(message);
    return 0;
}

int main(int argc, char **argv) {

    char decoded[2048];
    char query[2048];
    char filename[1024];
    char *d = decoded;
    char *q = query;
    char *r;
    char tags[32] = "aCdefgGIjkKlLmNopPrsTuvwxEXyY";
    size_t hash=0;
    size_t old_hash=0;
    char *string = NULL;
    FILE *fp;
    cJSON *results = NULL;
    cJSON *result = NULL;
    cJSON *items = NULL;
    cJSON *item = NULL;
    cJSON *json = NULL;

    char slimserver_address[256] = "127.0.0.1";
    int port = 3483;
    unsigned int json_port;
    int len ;
    char mac[256];
    if (argc > 1)
    {
	license();
        exit (1);
    }

    /* Scan */
    len = slimproto_discover(slimserver_address, sizeof (slimserver_address), port, &json_port, false);
    port = json_port;

    get_mac(mac);
    sprintf(filename,"/tmp/%s.json",mac);
    char *host = slimserver_address;
    

    sprintf(q,"{\"id\":1,\"method\":\"slim.request\",\"params\":[\"%s\", [\"status\", \"-\", \"1\", \"tags:%s\"]]}",mac,tags);

    post(host,port,q,decoded,2048);

    r = strstr(decoded,"{");
    strcpy(decoded,r);

    json = cJSON_Parse(decoded);

    if (json == NULL)
    {
      const char *error_ptr = cJSON_GetErrorPtr();
      if (error_ptr != NULL)
      {
          fprintf(stderr, "Error before %s\n", error_ptr);
          exit(1);
      }
    }

    results = cJSON_GetObjectItem(json, "result");

    string = cJSON_Print(results);
    printf("%s\n",string);

    cJSON_Delete(json);
    free(string);

}

