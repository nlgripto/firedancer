//includes
#include <assert.h>

#include "fd_bank_abi.h"
#include "../metrics/fd_metrics.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../ballet/blake3/blake3.h"
#include "../../flamenco/runtime/fd_system_ids_pp.h"
#include "../../util/sanitize/fd_fuzz.h"
//globals
fd_blake3_t blake[1];
uchar metrics_scratch[ FD_METRICS_FOOTPRINT( 0, 0 ) ] __attribute__((aligned(FD_METRICS_ALIGN)));
int fd_bank_abi_txn_init( fd_bank_abi_txn_t * out_txn,       /* Memory to place the result in, must be at least FD_BANK_ABI_TXN_FOOTPRINT bytes. */
                      uchar *             out_sidecar,   /* Memory to place sidecar data in, must be at least FD_BANK_ABI_TXN_FOOTPRINT_SIDECAR( out_txn ) bytes. */
                      void const *        bank,          /* Pointer to a Solana `Bank` object the transaction is being loaded for.  */
                      fd_blake3_t *       blake3,        /* Blake3 implementation used to create `message_hash` of the transaction. */
                      uchar *             payload,       /* Transaction raw wire payload. */
                      ulong               payload_sz,    /* Transaction raw wire size. */
                      fd_txn_t *          txn,           /* The Firedancer parsed transaction representation. */
                      int                 is_simple_vote /* If the transaction is a "simple vote" or not. */ );
// mock this here
int
fd_ext_bank_sanitized_txn_load_addresess( void const * bank,
                                          void *       address_table_lookups,
                                          ulong        address_table_lookups_cnt,
                                          void *       out_sidecar ) {
  (void)bank;
  (void)address_table_lookups;
  (void)address_table_lookups_cnt;
  (void)out_sidecar;
  return 0;
}
//llvmfuzzerinitialize
int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  fd_metrics_register( (ulong *)fd_metrics_new( metrics_scratch, 0UL, 0UL ) );

  atexit( fd_halt );
  return 0;
}

// LLVMFuzzerTestOneInput
int 
LLVMFuzzerTestOneInput(uchar const* data, ulong data_sz) {
  if (data_sz < sizeof(fd_txn_t)) {
    return 0;  // Input too small
  }

  fd_txn_t* tx = (fd_txn_t*)data;

  // Limit signature_cnt to valid range
  tx->signature_cnt = tx->signature_cnt % (FD_TXN_SIG_MAX + 1);
  if (tx->signature_cnt == 0) {
    tx->signature_cnt = 1;  // Ensure at least one signature
  }

  //TODO coinflip; hardcode version 
  tx->transaction_version = FD_TXN_VLEGACY;

  // Limit readonly_signed_cnt to valid range
  tx->readonly_signed_cnt = tx->readonly_signed_cnt % tx->signature_cnt;

  // Limit acct_addr_cnt to valid range
  tx->acct_addr_cnt = tx->acct_addr_cnt % (FD_TXN_ACCT_ADDR_MAX + 1);
  if (tx->acct_addr_cnt == 0) {
    tx->acct_addr_cnt = 1;  // Ensure at least one account address
  }

  // Limit readonly_unsigned_cnt to valid range
  tx->readonly_unsigned_cnt = tx->readonly_unsigned_cnt % (tx->acct_addr_cnt - tx->signature_cnt + 1);

  // Limit addr_table_lookup_cnt to valid range
  tx->addr_table_lookup_cnt = tx->addr_table_lookup_cnt % (FD_TXN_ADDR_TABLE_LOOKUP_MAX + 1);

  // Limit addr_table_adtl_writable_cnt to valid range
  tx->addr_table_adtl_writable_cnt = tx->addr_table_adtl_writable_cnt % (tx->addr_table_adtl_cnt + 1);

  // Limit addr_table_adtl_cnt to valid range
  tx->addr_table_adtl_cnt = tx->addr_table_adtl_cnt % (255 - tx->acct_addr_cnt + 1);

  // Limit instr_cnt to valid range
  tx->instr_cnt = tx->instr_cnt % (FD_TXN_INSTR_MAX + 1);

 // Allocate and initialize fd_bank_abi_txn_t and sidecar buffer
  uchar out_txn_buf[FD_BANK_ABI_TXN_FOOTPRINT];
  fd_bank_abi_txn_t* out_txn = (fd_bank_abi_txn_t*)out_txn_buf;

  uchar out_sidecar[FD_BANK_ABI_TXN_FOOTPRINT_SIDECAR_MAX];
  // uchar bank_scratch[272UL*1024UL*1024UL];
  //need to not oob on the payload_sz - tx->message_off
  if (tx->message_off > data_sz) {
    tx->message_off = tx->message_off % data_sz;
  }
  //make sure payload is big enough for bank abi to look for upgradeable loader
  uchar bigp [data_sz*tx->acct_addr_cnt];
  // make sure acct_addr_off is within our newly-sized payload
  tx->acct_addr_off = 0;
  int res = fd_bank_abi_txn_init(out_txn,
                                 out_sidecar,
                                 NULL,
                                //  (void *)bank_scratch,  //TODO figure out howto get a valid `bank` obj
                                 blake,
                                 (uchar*)bigp,
                                 data_sz,
                                 tx,
                                 0);  // is_simple_vote
  assert(res != 0);
  return 0;
}
