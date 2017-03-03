#ifndef lint
static const char rcsid[] =
    "@(#) $Header: /cvsroot/nsnam/ns-2/queue/dsab-queue.cc,v 0.01 2016/3/14 22:35:37 haldar Exp $ (LBL)";
#endif

#include "dsab-queue.h"

static class DSABQueueClass : public TclClass {
public:
  DSABQueueClass() : TclClass("Queue/DSABQueue") {}
  TclObject* create(int, const char*const*) {
    return (new DSABQueue);
  }
} class_dsab_queue;

void DSABQueue::reset()
{
  Queue::reset();
  flow_num_ = 0;
//	qib_ = 1;
}

int
DSABQueue::command(int argc, const char*const* argv)
{
  if (argc==2) {
    if (strcmp(argv[1], "printstats") == 0) {
      print_summarystats();
      return (TCL_OK);
    }
    if (strcmp(argv[1], "shrink-queue") == 0) {
      shrink_queue();
      return (TCL_OK);
    }
  }
  if (argc == 3) {
    if (!strcmp(argv[1], "packetqueue-attach")) {
      delete q_;
      if (!(q_ = (PacketQueue*) TclObject::lookup(argv[2])))
        return (TCL_ERROR);
      else {
        pq_ = q_;
        return (TCL_OK);
      }
    }
  }
  return Queue::command(argc, argv);
}

/*
 * dsab-queue
 */
void DSABQueue::enque(Packet* p)
{
  if (summarystats) {
    Queue::updateStats(qib_?q_->byteLength():q_->length());
  }
  int qlimBytes = qlim_ * mean_pktsize_;
  if ((!qib_ && (q_->length() + 1) >= qlim_) ||
      (qib_ && (q_->byteLength() + hdr_cmn::access(p)->size()) >= qlimBytes)){

    hdr_tcp *tcph = hdr_tcp::access(p);
    int &DSAB_type= tcph->dsab_type();
    if (hdr_cmn::access(p)->ptype() == PT_LTPB&&tcph->DSAB_SYN_FIN_!=0)
    {
      switch (DSAB_type)
      {
        case DSAB_SAB_PACKET:
          if(tcph->DSAB_SYN_FIN_==1)
            flow_num_++;
          if(tcph->DSAB_SYN_FIN_==-1)
          {
            flow_num_--;
          }
          break;
        default:
          break;
      }
      q_->enque(p);
    } else if (tcph->dsab_type()!=DSAB_NORMAL&&tcph->dsab_type()!=DSAB_SAB_PACKET) {
      q_->enque(p);
    }
    else {
      // if the queue would overflow if we added this packet...
      if (drop_front_) { /* remove from head of queue */
        q_->enque(p);
        Packet *pp = q_->deque();
        drop(pp);
      } else {
        drop(p);
        printf("enque, drop happens. \n");
      }
    }
  } else {
    q_->enque(p);
    //ws: added for DSAB
    hdr_tcp *tcph = hdr_tcp::access(p);
    int &DSAB_type= tcph->dsab_type();
    if (hdr_cmn::access(p)->ptype() == PT_LTPB)
    {
      switch (DSAB_type)
      {
        case DSAB_SAB_PACKET:
          if(tcph->DSAB_SYN_FIN_==1)
            flow_num_++;
          if(tcph->DSAB_SYN_FIN_==-1)
            flow_num_--;
          break;
        default:
//          if(tcph->seqno()==0)
//            flow_num_++;
//          if(tcph->flags()&0x01)
//            flow_num_--;
          break;
      }
    }
  }
}

//AG if queue size changes, we drop excessive packets...
void DSABQueue::shrink_queue()
{
  int qlimBytes = qlim_ * mean_pktsize_;
  if (debug_)
    printf("shrink-queue: time %5.2f qlen %d, qlim %d\n",
           Scheduler::instance().clock(),
           q_->length(), qlim_);
  while ((!qib_ && q_->length() > qlim_) ||
         (qib_ && q_->byteLength() > qlimBytes)) {
    if (drop_front_) { /* remove from head of queue */
      Packet *pp = q_->deque();
      drop(pp);
    } else {
      Packet *pp = q_->tail();
      q_->remove(pp);
      drop(pp);
    }
  }
}

Packet* DSABQueue::deque()
{
  if (summarystats && &Scheduler::instance() != NULL) {
    Queue::updateStats(qib_?q_->byteLength():q_->length());
  }
  //ws: added for DSAB
  Packet *pp = q_->deque();
  double band;
  if(pp!=NULL&&hdr_cmn::access(pp)->ptype() == PT_LTPB)
  {
    hdr_tcp *tcph = hdr_tcp::access(pp);
    int &DSAB_type= tcph->dsab_type();
    double wnd= tcph->DSAB_wnd_;
    double rate = tcph->DSAB_wnd_;
    double diff = tcph->DSAB_wndApply_ - tcph->DSAB_wnd_;
    switch (DSAB_type)
    {
      case DSAB_SAB_PACKET:
        if(flow_num_!=0) {
          band = (epsilon_ * qlim_ - A - q_->length()) / (flow_num_ * 1.0);
        }
        else
          band=epsilon_ * qlim_;
        if(band<0)
          band = minAliveWnd_;
        if(tcph->rwnd_ == 0 || tcph->rwnd_ > band){
          tcph->rwnd_ = band;
        }
        break;
      case DSAB_R_R:
        wnd = epsilon_ * qlim_ * (rate / link_capacity_);
        tcph->DSAB_wnd_ = wnd;
        tcph->DSAB_wndApply_=wnd;
        tcph->DSAB_type_ = DSAB_R_W;
      case DSAB_R_W:
        if (I < tcph->DSAB_wnd_)
        {
          tcph->DSAB_wnd_ = I;
          if (I <= 0)
          {
            tcph->DSAB_wnd_ = minAliveWnd_;
          }
        }
        I-=tcph->DSAB_wndApply_;
        break;
      case DSAB_BC:
        I+=diff;
        A+=wnd;
        break;
      case DSAB_BR:
        I += wnd;
        A -= wnd;
        break;
      case DSAB_BCBR:
        I+=diff;
        A+=wnd;
        I += tcph->DSAB_total_wnd_;
        A -= tcph->DSAB_total_wnd_;
        break;
      default:
        break;
    }
  }

  return pp;
/***************/
}

void DSABQueue::print_summarystats()
{
  //double now = Scheduler::instance().clock();
  printf("True average queue: %5.3f", true_ave_);
  if (qib_)
    printf(" (in bytes)");
  printf(" time: %5.3f\n", total_time_);
}
