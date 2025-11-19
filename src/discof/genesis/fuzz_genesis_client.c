#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_genesis_client.h"

/* Include the implementation to access private struct and static functions */
#include "fd_genesis_client.c"

/* Persistent client allocation to avoid stack overflow */
static void *                 client_mem = NULL;
static fd_genesis_client_t * client     = NULL;

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set(3); /* crash on warning log */

  /* Allocate client on heap (too large for stack) */
  ulong footprint = fd_genesis_client_footprint();
  client_mem = malloc( footprint );
  if( FD_UNLIKELY( !client_mem ) ) {
    FD_LOG_ERR(( "malloc failed for client_mem" ));
    return -1;
  }

  client = (fd_genesis_client_t *)fd_genesis_client_new( client_mem );
  if( FD_UNLIKELY( !client ) ) {
    FD_LOG_ERR(( "fd_genesis_client_new failed" ));
    return -1;
  }

  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( FD_UNLIKELY( size < 1UL ) ) return -1;
  if( FD_UNLIKELY( !client ) ) return -1;

  /* Create a socketpair to inject fuzz data */
  int fds[2];
  if( FD_UNLIKELY( -1==socketpair( AF_UNIX, SOCK_STREAM, 0, fds ) ) ) return -1;

  int client_fd = fds[0];
  int server_fd = fds[1];

  /* Set client socket to non-blocking */
  int flags = fcntl( client_fd, F_GETFL, 0 );
  if( FD_UNLIKELY( -1==flags ) ) {
    close( client_fd );
    close( server_fd );
    return -1;
  }
  if( FD_UNLIKELY( -1==fcntl( client_fd, F_SETFL, flags | O_NONBLOCK ) ) ) {
    close( client_fd );
    close( server_fd );
    return -1;
  }

  /* Reinitialize client state for this iteration */
  client->peer_cnt           = 1UL;
  client->remaining_peer_cnt = 1UL;
  client->start_time_nanos   = fd_log_wallclock();

  /* Configure the pollfd for reading only (not writing) */
  client->pollfds[0].fd      = client_fd;
  client->pollfds[0].events  = POLLIN;
  client->pollfds[0].revents = 0;

  /* Mark remaining pollfds as unused */
  for( ulong i=1UL; i<FD_TOPO_GOSSIP_ENTRYPOINTS_MAX; i++ ) {
    client->pollfds[i].fd = -1;
  }

  /* Set up peer state - not writing, ready to read response */
  client->peers[0].addr.addr          = 0U;
  client->peers[0].addr.port          = 0U;
  client->peers[0].writing            = 0;
  client->peers[0].request_bytes_sent = 0UL;
  client->peers[0].response_bytes_read = 0UL;

  /* Write fuzz input to the server end of the socketpair */
  long written = write( server_fd, data, size );
  (void)written; /* Ignore partial writes for fuzzing purposes */

  /* Close the server end so the client sees EOF after reading */
  close( server_fd );

  /* Call read_conn directly to exercise the HTTP parsing logic */
  uchar * buffer    = NULL;
  ulong   buffer_sz = 0UL;
  int result = read_conn( client, 0UL, &buffer, &buffer_sz );
  (void)result; /* Result doesn't matter for fuzzing - we're testing for crashes */

  /* Clean up */
  close( client_fd );

  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
