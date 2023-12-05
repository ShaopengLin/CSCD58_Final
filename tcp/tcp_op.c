#include "tcp_op.h"
#include "mt19937ar.h"
#include <stdlib.h>

void
handle_tcp (tcp_hdr_t *hdr)
{
  if (ntohs (hdr->des_port) == 1234)
    {
      tcp_packet_entry_t *e
          = (tcp_packet_entry_t *)calloc (1, sizeof (tcp_packet_entry_t));
      e->hdr = hdr;
      TAILQ_INSERT_HEAD (&pq, e, entry);
      print_tcp_hdr (hdr);
    }
}