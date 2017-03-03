/* -*-	Mode:C++; c-basic-offset:8; tab-width:8; indent-tabs-mode:t -*- */
/*
 * Copyright (c) 1994 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the Computer Systems
 *	Engineering Group at Lawrence Berkeley Laboratory.
 * 4. Neither the name of the University nor of the Laboratory may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef lint
static const char rcsid[] =
    "@(#) $Header: /cvsroot/nsnam/ns-2/queue/ltpb-queue.cc,v 1.17 2004/10/28 23:35:37 haldar Exp $ (LBL)";
#endif

#include "ltpb-queue.h"

static class LTPBQueueClass : public TclClass {
 public:
	LTPBQueueClass() : TclClass("Queue/LTPBQueue") {}
	TclObject* create(int, const char*const*) {
		return (new LTPBQueue);
	}
} class_ltpb_queue;

void LTPBQueue::reset()
{
	Queue::reset();
	flow_num_ = 0;
//	qib_ = 1;
}

int 
LTPBQueue::command(int argc, const char*const* argv) 
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
 * vlpb-queue
 */
void LTPBQueue::enque(Packet* p)
{
	if (summarystats) {
                Queue::updateStats(qib_?q_->byteLength():q_->length());
	}

	int qlimBytes = qlim_ * mean_pktsize_;
	if ((!qib_ && (q_->length() + 1) >= qlim_) ||
  	(qib_ && (q_->byteLength() + hdr_cmn::access(p)->size()) >= qlimBytes)){
		// if the queue would overflow if we added this packet...
		if (drop_front_) { /* remove from head of queue */
			q_->enque(p);
			Packet *pp = q_->deque();
			drop(pp);
		} else {
			drop(p);
			printf("enque, drop happens. \n");
		}
	} else {
		q_->enque(p);
		
		/* added by zhj*/ 
		if(p!=NULL){	
			hdr_tcp *tcph = hdr_tcp::access(p);
			if(hdr_cmn::access(p)->ptype() == PT_LTPB && tcph->seqno() == 0){ //syn pkt
				flow_num_ ++;
			}

      if (hdr_cmn::access(p)->ptype() == PT_LTPB && (tcph->flags() & 0x01))
      {
        flow_num_--;
      }

		}
	}
}

//AG if queue size changes, we drop excessive packets...
void LTPBQueue::shrink_queue() 
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

Packet* LTPBQueue::deque()
{
        if (summarystats && &Scheduler::instance() != NULL) {
                Queue::updateStats(qib_?q_->byteLength():q_->length());
        }
//	return q_->deque();
/* added by zhj*/ 
	Packet *pp = q_->deque();
	double band;
	if(pp!=NULL){	
		hdr_tcp *tcph = hdr_tcp::access(pp);
	//	if(tcph->seqno() == 0){ //syn pkt
		if(hdr_cmn::access(pp)->ptype() == PT_LTPB){
      if(flow_num_!=0)
        band = epsilon_ * qlim_ / (flow_num_ * 1.0);
      else
        band=epsilon_ * qlim_;
			//printf("Deque(), qib_ = %d, flow_num_=%d, epsilon_=%f, band=%f\n, ", qib_, flow_num_, epsilon_, band);
			if(tcph->rwnd_ == 0 || tcph->rwnd_ > band){
				tcph->rwnd_ = band;
			}
		}
	//	printf("Deque, tcph->rwnd_=%f\n", tcph->rwnd_);
	}
	
	return pp;			
/***************/
}

void LTPBQueue::print_summarystats()
{
	//double now = Scheduler::instance().clock();
        printf("True average queue: %5.3f", true_ave_);
        if (qib_)
                printf(" (in bytes)");
        printf(" time: %5.3f\n", total_time_);
}
