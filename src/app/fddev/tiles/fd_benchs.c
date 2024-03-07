#include "../../fdctl/run/tiles/tiles.h"

#include <linux/unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

typedef struct {
  int conn_fd;

  fd_wksp_t * mem;
} fd_benchs_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof( fd_benchs_ctx_t );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_benchs_ctx_t ), sizeof( fd_benchs_ctx_t ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof( fd_benchs_ctx_t ) );
}

static inline void
during_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter ) {
  (void)in_idx;
  (void)seq;
  (void)sig;
  (void)opt_filter;

  fd_benchs_ctx_t * ctx = (fd_benchs_ctx_t *)_ctx;

  if( FD_UNLIKELY( -1==send( ctx->conn_fd, fd_chunk_to_laddr( ctx->mem, chunk ), sz, 0 ) ) )
    FD_LOG_ERR(( "send() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile,
                 void *           scratch ) {
  (void)topo;
  (void)tile;
  (void)scratch;

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_benchs_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_benchs_ctx_t ), sizeof( fd_benchs_ctx_t ) );

  int conn_fd = socket( AF_INET, SOCK_DGRAM, 0 );
  if( FD_UNLIKELY( -1==conn_fd ) ) FD_LOG_ERR(( "socket() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  struct sockaddr_in addr = {
    .sin_family = AF_INET,
    .sin_port = fd_ushort_bswap( tile->benchs.send_to_port ),
    .sin_addr.s_addr = tile->benchs.send_to_ip_addr,
  };
  if( FD_UNLIKELY( -1==connect( conn_fd, fd_type_pun( &addr ), sizeof(addr) ) ) ) FD_LOG_ERR(( "connect() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  ctx->conn_fd = conn_fd;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_benchs_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_benchs_ctx_t ), sizeof( fd_benchs_ctx_t ) );

  ctx->mem = topo->workspaces[ topo->objs[ topo->links[ tile->in_link_id[ 0UL ] ].dcache_obj_id ].wksp_id ].wksp;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

fd_topo_run_tile_t fd_tile_benchs = {
  .name                     = "benchs",
  .mux_flags                = FD_MUX_FLAG_MANUAL_PUBLISH | FD_MUX_FLAG_COPY,
  .burst                    = 1UL,
  .mux_ctx                  = mux_ctx,
  .mux_during_frag          = during_frag,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
};