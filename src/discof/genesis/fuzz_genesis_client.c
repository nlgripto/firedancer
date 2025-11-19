#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "../../waltz/http/picohttpparser.h"
#include "../../ballet/sha256/fd_sha256.h"

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set(3); /* crash on warning log */
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( FD_UNLIKELY( size < 1UL ) ) return -1;

  /* Test HTTP response parsing which is the main external input
     processing in fd_genesis_client */
  
  int           minor_version;
  int           status;
  const char *  message;
  ulong         message_len;
  struct phr_header headers[ 32 ];
  ulong         num_headers = 32UL;
  
  /* Parse HTTP response - this exercises the main parsing logic
     used in read_conn function */
  int len = phr_parse_response( (char const *)data, size,
                                &minor_version, &status, &message, &message_len,
                                headers, &num_headers, 0L );
  
  /* If parsing succeeded, test content-length header extraction */
  if( FD_LIKELY( len>0 ) ) {
    FD_FUZZ_MUST_BE_COVERED;
    
    /* Search for Content-Length header */
    for( ulong i=0UL; i<num_headers; i++ ) {
      if( FD_LIKELY( headers[i].name_len!=14UL ) ) continue;
      if( FD_LIKELY( strncasecmp( headers[i].name, "Content-Length", 14UL ) ) ) continue;
      
      char * end;
      ulong content_length = strtoul( headers[i].value, &end, 10 );
      (void)content_length;
      
      /* If we have a body after headers, hash it like the real code does */
      if( FD_LIKELY( (ulong)len<size ) ) {
        FD_FUZZ_MUST_BE_COVERED;
        uchar hash[ 32UL ] = {0};
        fd_sha256_hash( data + (ulong)len, size - (ulong)len, hash );
      }
      break;
    }
  } else if( FD_UNLIKELY( -2==len ) ) {
    /* Incomplete response */
    FD_FUZZ_MUST_BE_COVERED;
  } else {
    /* Parse error */
    FD_FUZZ_MUST_BE_COVERED;
  }

  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
