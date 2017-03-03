#ifndef ns_dsab_queue_h
#define ns_dsab_queue_h

#include <string.h>
#include "queue.h"
#include "tcp.h"
#include "config.h"

class DSABQueue : public Queue {
public:
  DSABQueue() {
    q_ = new PacketQueue;
    pq_ = q_;
    flow_num_=0;
    bind_bool("drop_front_", &drop_front_);
    bind_bool("summarystats_", &summarystats);
    bind_bool("queue_in_bytes_", &qib_);  // boolean: q in bytes?
    bind("mean_pktsize_", &mean_pktsize_);
    bind("epsilon_", &epsilon_);
    bind("minAliveWnd_", &minAliveWnd_);
    //		_RENAMED("drop-front_", "drop_front_");
    I=epsilon_*qlim_;
    A=0;
  }
  ~DSABQueue() {
    delete q_;
  }
protected:
  void reset();
  int command(int argc, const char*const* argv);
  void enque(Packet*);
  Packet* deque();
  void shrink_queue();	// To shrink queue and drop excessive packets.

  PacketQueue *q_;	/* underlying FIFO queue */
  int drop_front_;	/* drop-from-front (rather than from tail) */
  int summarystats;
  void print_summarystats();
  int qib_;       	/* bool: queue measured in bytes? */
  int mean_pktsize_;	/* configured mean packet size in bytes */
  double epsilon_;   //added by zhj for ltpb
  int flow_num_;  //added by zhj for LTPB
  //ws: added for DSAB
  double I; //Idle buffer size;
  double A; //allocated buffersize;
  double minAliveWnd_; //minimal congestion window to keep alive.
};

#endif