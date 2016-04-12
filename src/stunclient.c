/*
** STUNTrace
*/

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
/* #include <netinet/ip6.h> */
/* #include <netinet/icmp6.h> */
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <pthread.h>
#include <getopt.h>

/* #include <netinet/ip.h> */
/* #include <netinet/ip_icmp.h> */

#include <string.h>
#include <ctype.h>

#include <stunlib.h>
#include <stunclient.h>
/* #include <stuntrace.h> */
#include <stun_intern.h>


#include <uuid/uuid.h>

#include "utils.h"
#include "iphelper.h"
#include "sockethelper.h"
#include "ip_query.h"
#include "version.h"

int                        sockfd;
static struct listenConfig listenConfig;
struct timeval             start;
struct timeval             stop;

pthread_mutex_t mutex;

char username[] = "evtj:h6vY\0";
char password[] = "VOkJxbRl1RmTxUk/WvJxBt\0";
char uuid_str[37];
#define max_iface_len 10

typedef enum {
  txt,
  json,
  csv
} OUTPUT_FORMAT;

OUTPUT_FORMAT out_format = txt;

struct client_config {
  char                    interface[10];
  struct sockaddr_storage localAddr;
  struct sockaddr_storage remoteAddr;
  int                     port;
  bool                    debug;
};

static void
teardown()
{
  close(sockfd);
  exit(0);
}


void
printTimeSpent()
{
  int time;
  gettimeofday(&stop, NULL);

  time =
    (stop.tv_sec * 1000000 +
     stop.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec);

  printf("User: %i.%ims\n", time / 1000, time % 1000);
}

void
handleStunResp( const StunMsgId *msgId,
                const struct sockaddr* serverAddr,
               const struct sockaddr* rflxAddr,
               const int              rtt,
              const int              retrans)
{
  char addr_str[SOCKADDR_MAX_STRLEN];
  printf("----------------------------\n");
  printf("TransID: ");
  for(int i=0;i<STUN_MSG_ID_SIZE;i++){
    printf("%02x", msgId->octet[i]);
  }
  printf("\n");
  printf( "src addr: %s\n",
          sockaddr_toString(serverAddr,
                            addr_str,
                            sizeof(addr_str),
                            true) );
  printf( "rflx addr: %s\n",
          sockaddr_toString(rflxAddr,
                            addr_str,
                            sizeof(addr_str),
                            true) );
  printf("RTT: %i\n", rtt);
    printf("Retrans: %i\n", retrans);
  printf("----------------------------\n");
}

void
StunCallBack(void*               userCtx,
             StunCallBackData_T* data)
{
  (void)userCtx;

  switch (data->stunResult)
  {
  case StunResult_BindOk:
    handleStunResp( &data->msgId,
                    (struct sockaddr*)&data->srcAddr,
                    (struct sockaddr*)&data->rflxAddr,
                    data->rtt,
                    data->retransmits );
    break;
  case StunResult_ICMPResp:
    printf("Got ICMP response (Should check if it is host unreachable?)\n");
    break;
  case StunResult_BindFailNoAnswer:
    printf("No answer from stunserver\n");
    break;
  default:
    printf("Unhandled..\n");

  }
  printTimeSpent();
  teardown();
}



void
stundbg(void*              ctx,
        StunInfoCategory_T category,
        char*              errStr)
{
  (void) category;
  (void) ctx;
  printf("%s\n", errStr);
}

static void*
tickStun(void* ptr)
{
  struct timespec   timer;
  struct timespec   remaining;
  STUN_CLIENT_DATA* clientData = (STUN_CLIENT_DATA*)ptr;

  timer.tv_sec  = 0;
  timer.tv_nsec = 50000000;

  for (;; )
  {
    nanosleep(&timer, &remaining);
    StunClient_HandleTick(clientData, 50);
  }
  return NULL;
}


void
stunHandler(struct socketConfig* config,
            struct sockaddr*     from_addr,
            void*                cb,
            unsigned char*       buf,
            int                  buflen)
{
  StunMessage       stunResponse;
  STUN_CLIENT_DATA* clientData = (STUN_CLIENT_DATA*)cb;
  char              realm[STUN_MSG_MAX_REALM_LENGTH];

  if ( stunlib_DecodeMessage(buf, buflen, &stunResponse, NULL, NULL) )
  {
    if (stunResponse.msgHdr.msgType == STUN_MSG_DataIndicationMsg)
    {
      if (stunResponse.hasData)
      {
        /* Decode and do something with the data? */
        /* config->data_handler(config->socketConfig[i].sockfd, */
        /*                     config->socketConfig[i].tInst, */
        /*                     &buf[stunResponse.data.offset]); */
      }
    }
    if (stunResponse.hasRealm)
    {
      memcpy(&realm, stunResponse.realm.value, STUN_MSG_MAX_REALM_LENGTH);
    }
    if (stunResponse.hasMessageIntegrity)
    {
      if ( stunlib_checkIntegrity( buf,
                                   buflen,
                                   &stunResponse,
                                   (uint8_t*)config->pass,
                                   strlen(config->pass) ) )
      {
        /* printf("     - Integrity check OK\n"); */
      }
      else
      {
        /* printf("     - Integrity check NOT OK\n"); */
      }
    }
    StunClient_HandleIncResp(clientData,
                             &stunResponse,
                             from_addr);
  }
}





void
printUsage()
{
  printf("Usage: nptrace [options] host\n");
  printf("Options: \n");
  printf("  -i, --interface           Interface\n");
  printf("  -p <port>, --port <port>  Destination port\n");
  printf(
    "  -r [N], --recuring [N]    Number of recuring traces before stopping\n");
  printf("  -l, --as                  Enable AS number lookup\n");
  printf("  --post <ip>               Send results to server\n");
  printf("  -v, --version             Print version number\n");
  printf("  -h, --help                Print help text\n");
  exit(0);
}


void
configure(struct client_config* config,
          int                   argc,
          char*                 argv[])
{
  int c;
  /* int                 digit_optind = 0; */
  /* set config to default values */
  strncpy(config->interface, "default", 7);
  config->port  = 3478;
  config->debug = false;

  static struct option long_options[] = {
    {"interface", 1, 0, 'i'},
    {"port", 1, 0, 'p'},
    {"debug", 0, 0, 'd'},
    {"help", 0, 0, 'h'},
    {"version", 0, 0, 'v'},
    {NULL, 0, NULL, 0}
  };
  if (argc < 2)
  {
    printUsage();
    exit(0);
  }
  int option_index = 0;
  while ( ( c = getopt_long(argc, argv, "hvdli:p:m:M:w:r:",
                            long_options, &option_index) ) != -1 )
  {
    /* int this_option_optind = optind ? optind : 1; */
    switch (c)
    {
    case 'i':
      strncpy(config->interface, optarg, max_iface_len);
      break;
    case 'p':
      config->port = atoi(optarg);
      break;
    case 'd':
      config->debug = true;
      break;
    case 'h':
      printUsage();
      break;
    case 'v':
      printf("Version %s\n", VERSION_SHORT);
      exit(0);
      break;
    default:
      printf("?? getopt returned character code 0%o ??\n", c);
    }
  }
  if (optind < argc)
  {
    if ( !getRemoteIpAddr( (struct sockaddr*)&config->remoteAddr,
                           argv[optind++],
                           config->port ) )
    {
      printf("Error getting remote IPaddr");
      exit(1);
    }
  }


  if ( !getLocalInterFaceAddrs( (struct sockaddr*)&config->localAddr,
                                config->interface,
                                config->remoteAddr.ss_family,
                                IPv6_ADDR_NORMAL,
                                false ) )
  {
    printf("Error getting IPaddr on %s\n", config->interface);
    exit(1);
  }

}


int
setupSocket(struct client_config* config,
            STUN_CLIENT_DATA*     clientData)
{
  int sockfd = createLocalSocket(config->remoteAddr.ss_family,
                                 (struct sockaddr*)&config->localAddr,
                                 SOCK_DGRAM,
                                 0);
  listenConfig.tInst                  = clientData;
  listenConfig.socketConfig[0].sockfd = sockfd;
  listenConfig.socketConfig[0].user   = username;
  listenConfig.socketConfig[0].pass   = password;
  listenConfig.stun_handler           = stunHandler;
  listenConfig.numSockets             = 1;

  return sockfd;
}



int
main(int   argc,
     char* argv[])
{
  pthread_t stunTickThread;
  pthread_t socketListenThread;

  STUN_CLIENT_DATA* clientData;
  char              addrStr[SOCKADDR_MAX_STRLEN];

  struct client_config config;
  StunMsgId            stunMsgId;
  time_t t;
  /* Initialise the random seed. */
  srand( time(&t) );

  /* Set up PAlib */
  gettimeofday(&start, NULL);
  uuid_t uuid;
  uuid_generate(uuid);
  uuid_unparse_lower(uuid, uuid_str);

  /* Read cmd line argumens and set it up */
  configure(&config,argc,argv);

  /* Initialize STUNclient data structures */
  StunClient_Alloc(&clientData);

  /* Setting up UDP socket and and aICMP sockhandle */
  sockfd = setupSocket(&config, clientData);

  /* at least close the socket if we get a signal.. */
  signal(SIGINT, teardown);

  /* Turn on debugging */
  if (config.debug)
  {
    printf("Registering logger\n");
    StunClient_RegisterLogger(clientData,
                              stundbg,
                              clientData);
  }
  pthread_create(&stunTickThread, NULL, tickStun, (void*)clientData);
  pthread_create(&socketListenThread,
                 NULL,
                 socketListenDemux,
                 (void*)&listenConfig);

  printf( "Sending binding Req from: '%s'",
          sockaddr_toString( (struct sockaddr*)&config.localAddr,
                             addrStr,
                             sizeof(addrStr),
                             true ) );

  printf( "to: '%s'\n",
          sockaddr_toString( (struct sockaddr*)&config.remoteAddr,
                             addrStr,
                             sizeof(addrStr),
                             true ) );
  printf("UUID: %s\n", uuid_str);

  stunlib_createId(&stunMsgId,
                   rand(), rand());

  StunClient_startBindTransaction(clientData,
                                  &config,
                                  (const struct sockaddr*)&config.remoteAddr,
                                  (const struct sockaddr*)&config.localAddr,
                                  17,
                                  false,
                                  username,
                                  password,
                                  0,
                                  false,
                                  false,
                                  0,
                                  stunMsgId,
                                  sockfd,
                                  sendPacket,
                                  StunCallBack,
                                  NULL);
  pause();
}
