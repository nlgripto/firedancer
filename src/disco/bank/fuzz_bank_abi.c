//includes
#include "fd_bank_abi.h"
#include "../../flamenco/runtime/fd_system_ids_pp.h"
//globals
fd_blake3_t blake[1];
//llvmfuzzerinitialize
int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );
  return 0;
}

//llvmfuzzertestoneinput
int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         data_sz ) {
  fd_txn_t tx [1];
  // coinflip tx ver
  if (heads)
  {
    tx->transaction_version = FD_TXN_VLEGACY;
  }
  else if (tails)
  {
    tx->transaction_version = FD_TXN_V0;
  }
  // roll for signature count


  int res = fd_bank_abi_txn_init( fd_bank_abi_txn_t * out_txn,
                      uchar *             out_sidecar,
                      void const *        bank,
                      fd_blake3_t *       blake,
                      uchar *             payload,
                      ulong               payload_sz,
                      fd_txn_t *          tx,
                      int                 is_simple_vote );

}