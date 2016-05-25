/*
** STUNClient
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


#include "utils.h"
#include "iphelper.h"
#include "sockethelper.h"
/* #include "ip_query.h" */
#include "version.h"

/* int                        sockfd; */
static struct listenConfig listenConfig;
struct timeval             start;
struct timeval             stop;
int                        numresp;
pthread_mutex_t            mutex;

char username[] = "evtj:h6vY\0";
char password[] = "VOkJxbRl1RmTxUk/WvJxBt\0";

#define max_iface_len 10


struct client_config {
  char                    interface[10];
  struct sockaddr_storage localAddr;
  struct sockaddr_storage remoteAddr;
  int                     port;
  int                     jobs;
  bool                    debug;
  bool                    csv_output;
};
static struct client_config config;

struct stunTransSummary {
  int32_t  numTransactions;
  int32_t  numFailedTransactions;
  int32_t  maxRTT;
  int32_t  minRTT;
  int32_t  sumRTT;
  int32_t  numRetrans;
  int32_t  numClientSent;
  int32_t  numServSent;
  uint16_t startPort;
  uint16_t stopPort;
};

static struct stunTransSummary stunTransSummary;

static void
initSummary()
{
  stunTransSummary.numTransactions       = 0;
  stunTransSummary.numFailedTransactions = 0;
  stunTransSummary.maxRTT                = 0;
  stunTransSummary.minRTT                = 0;
  stunTransSummary.sumRTT                = 0;
  stunTransSummary.numRetrans            = 0;
  stunTransSummary.numClientSent         = 0;
  stunTransSummary.numServSent           = 0;
}

static void
printCSV(/* arguments */)
{
  time_t     nowtime;
  struct tm* nowtm;
  char       tmbuf[64], buf[64];

  /* gettimeofday(&tv, NULL); */
  nowtime = start.tv_sec;
  nowtm   = localtime(&nowtime);
  strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
  #ifdef __APPLE__
  snprintf(buf, sizeof buf, "%s.%06d",  tmbuf, start.tv_usec);
  #else
  snprintf(buf, sizeof buf, "%s.%06ld", tmbuf, start.tv_usec);
  #endif

  printf("%s, ", buf);

  nowtime = stop.tv_sec;
  nowtm   = localtime(&nowtime);
  strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
  #ifdef __APPLE__
  snprintf(buf, sizeof buf, "%s.%06d",  tmbuf, stop.tv_usec);
  #else
  snprintf(buf, sizeof buf, "%s.%06ld", tmbuf, stop.tv_usec);
  #endif
  printf("%s, ", buf);

  printf("%i, %i, %i, %i, %i, %i, %i, %i, %i, %i\n",
         stunTransSummary.numTransactions,
         stunTransSummary.numFailedTransactions,
         stunTransSummary.maxRTT,
         stunTransSummary.minRTT,
         stunTransSummary.sumRTT / stunTransSummary.numTransactions,
         stunTransSummary.numRetrans,
         stunTransSummary.numClientSent,
         stunTransSummary.numServSent,
         stunTransSummary.startPort,
         stunTransSummary.stopPort
         );

}

static void
printSummary(/* arguments */)
{
  printf(
    "  Num Trans  Failed      Max RTT  Min RTT  Avg RTT  Retrans    Client  Server  Port Range\n");
  printf(
    "     %i        %i    %i    %i    %i      %i         %i      %i  %i-%i\n",
    stunTransSummary.numTransactions,
    stunTransSummary.numFailedTransactions,
    stunTransSummary.maxRTT,
    stunTransSummary.minRTT,
    stunTransSummary.sumRTT / stunTransSummary.numTransactions,
    stunTransSummary.numRetrans,
    stunTransSummary.numClientSent,
    stunTransSummary.numServSent,
    stunTransSummary.startPort,
    stunTransSummary.stopPort
    );

}

static void
teardown()
{
  for (int i = 0; i < listenConfig.numSockets; i++)
  {
    close(listenConfig.socketConfig[i].sockfd);
  }

  exit(0);
}


void
printTimeSpent()
{
  int time;


  time =
    (stop.tv_sec * 1000000 +
     stop.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec);

  printf("User: %i.%ims\n", time / 1000, time % 1000);
}

void
handleStunResp(const StunMsgId*       msgId,
               const struct sockaddr* serverAddr,
               const struct sockaddr* rflxAddr,
               const int              rtt,
               const int              retrans,
               const int              req,
               const int              resp)
{
  char addr_str[SOCKADDR_MAX_STRLEN];
  if (!config.csv_output)
  {
    printf("----------- Start: %i -----------------\n", numresp);
    printf("TransID: ");
    for (int i = 0; i < STUN_MSG_ID_SIZE; i++)
    {
      printf("%02x", msgId->octet[i]);
    }
    printf( "\n");
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
    printf("RTT: %i\n",                                 rtt);
    printf("Retrans: %i\n",                             retrans);
    printf("Sent requests: %i\n",                       req);
    printf("Responses sent by server: %i\n",            resp);
    printf("------------ End: %i ------------------\n", numresp);
  }
  stunTransSummary.numTransactions++;
  if (stunTransSummary.maxRTT < rtt)
  {
    stunTransSummary.maxRTT = rtt;
  }
  if ( (stunTransSummary.minRTT > rtt) || (stunTransSummary.minRTT == 0) )
  {
    stunTransSummary.minRTT = rtt;
  }
  stunTransSummary.sumRTT        += rtt;
  stunTransSummary.numRetrans    += retrans;
  stunTransSummary.numClientSent += req;
  stunTransSummary.numServSent   += resp;
  uint16_t port = sockaddr_ipPort(rflxAddr);
  if ( (stunTransSummary.startPort > port) ||
       (stunTransSummary.startPort == 0) )
  {
    stunTransSummary.startPort = port;
  }
  if (stunTransSummary.stopPort < port)
  {
    stunTransSummary.stopPort = port;
  }

}

void
StunCallBack(void*               userCtx,
             StunCallBackData_T* data)
{
  (void)userCtx;
  (void)data;

  switch (data->stunResult)
  {
  case StunResult_BindOk:
    handleStunResp(&data->msgId,
                   (struct sockaddr*)&data->srcAddr,
                   (struct sockaddr*)&data->rflxAddr,
                   data->rtt,
                   data->retransmits,
                   data->reqTransCnt,
                   data->respTransCnt);
    break;
  case StunResult_ICMPResp:
    printf("Got ICMP response (Should check if it is host unreachable?)\n");
    break;
  case StunResult_BindFailNoAnswer:
    stunTransSummary.numTransactions++;
    stunTransSummary.numFailedTransactions++;
    if (!config.csv_output)
    {
      printf("No answer from stunserver\n");
    }
    break;
  default:
    printf("Unhandled..\n");

  }
  numresp++;

  if (numresp >= listenConfig.numSockets)
  {
    gettimeofday(&stop, NULL);
    /* Todo: Check what transactions and so on we are missing.. */
    if (config.csv_output)
    {
      printCSV();
    }
    else
    {
      printSummary();
      printTimeSpent();
    }
    teardown();
  }
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
  else
  {
    printf("STUN Decode failed\n");
  }

}


void
printUsage()
{
  printf("Usage: stunclient [options] server\n");
  printf("Options: \n");
  printf("  -i, --interface           Interface\n");
  printf("  -p <port>, --port <port>  Destination port\n");
  printf(
    "  -j <num>, --jobs <num>    Run <num> transactions in paralell(almost)\n");
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
  config->jobs  = 1;
  config->debug = false;


  static struct option long_options[] = {
    {"interface", 1, 0, 'i'},
    {"port", 1, 0, 'p'},
    {"jobs", 1, 0, 'j'},
    {"debug", 0, 0, 'd'},
    {"csv", 0, 0, '2'},
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
  while ( ( c = getopt_long(argc, argv, "hvdi:p:j:o:",
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
    case 'j':
      config->jobs = atoi(optarg);
      break;
    case '2':
      config->csv_output = true;
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
  for (int i = 0; i < config->jobs; i++)
  {
    int sockfd = createLocalSocket(config->remoteAddr.ss_family,
                                   (struct sockaddr*)&config->localAddr,
                                   SOCK_DGRAM,
                                   0);
    listenConfig.tInst                  = clientData;
    listenConfig.socketConfig[i].sockfd = sockfd;
    listenConfig.socketConfig[i].user   = username;
    listenConfig.socketConfig[i].pass   = password;
    listenConfig.stun_handler           = stunHandler;
    listenConfig.numSockets++;
  }
  return listenConfig.numSockets;
}



int
main(int   argc,
     char* argv[])
{
  pthread_t stunTickThread;
  pthread_t socketListenThread;

  STUN_CLIENT_DATA* clientData;
  char              addrStr[SOCKADDR_MAX_STRLEN];

  /* time_t t; */
  /* Initialise the random seed. */
  /* srand( time(&t) ); */


  initSummary();

  gettimeofday(&start, NULL);

  /* Read cmd line argumens and set it up */
  configure(&config,argc,argv);

  /* Initialize STUNclient data structures */
  StunClient_Alloc(&clientData);

  /* Setting up UDP socket and and aICMP sockhandle */
  setupSocket(&config, clientData);

  /* at least close the socket if we get a signal.. */
  signal(SIGINT, teardown);

  /* Turn on debugging */
  if (config.debug)
  {
    StunClient_RegisterLogger(clientData,
                              stundbg,
                              clientData);
  }
  pthread_create(&stunTickThread, NULL, tickStun, (void*)clientData);
  pthread_create(&socketListenThread,
                 NULL,
                 socketListenDemux,
                 (void*)&listenConfig);
  if (!config.csv_output)
  {
    printf( "Sending binding  %i Req(s) from: '%s'",
            config.jobs,
            sockaddr_toString( (struct sockaddr*)&config.localAddr,
                               addrStr,
                               sizeof(addrStr),
                               true ) );

    printf( "to: '%s'\n",
            sockaddr_toString( (struct sockaddr*)&config.remoteAddr,
                               addrStr,
                               sizeof(addrStr),
                               true ) );
  }
  for (int i = 0; i < listenConfig.numSockets; i++)
  {
    TransactionAttributes transAttr;
    stunlib_createId(&transAttr.transactionId);
    transAttr.sockhandle = listenConfig.socketConfig[i].sockfd;
    strncpy( transAttr.username, username, strlen(username) );
    strncpy( transAttr.password, password, strlen(password) );
    transAttr.peerPriority                    = 34567;
    transAttr.useCandidate                    = false;
    transAttr.iceControlling                  = false;
    transAttr.tieBreaker                      = 4567;
    transAttr.addEnf                          = true;
    transAttr.enfFlowDescription.type         = 0x04;
    transAttr.enfFlowDescription.bandwidthMax = 4096;

    StunClient_startBindTransaction(clientData,
                                    &config,
                                    (const struct sockaddr*)&config.remoteAddr,
                                    (const struct sockaddr*)&config.localAddr,
                                    17,
                                    false,
                                    &transAttr,
                                    sendPacket,
                                    StunCallBack);
  }
  pause();
}
