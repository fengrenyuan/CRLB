/* -*-	Mode:C++; c-basic-offset:8; tab-width:8; indent-tabs-mode:t -*- */
/*
 * Copyright (c) 1996 Regents of the University of California.
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
 * 	This product includes software developed by the MASH Research
 * 	Group at the University of California Berkeley.
 * 4. Neither the name of the University nor of the Research Group may be
 *    used to endorse or promote products derived from this software without
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
    "@(#) $Header: /cvsroot/nsnam/ns-2/classifier/classifier.cc,v 1.43 2008/11/03 05:34:48 tom_henderson Exp $";
#endif

#include <stdlib.h>
#include <time.h>
#include <cmath>
#include "config.h"
#include "classifier.h"
#include "packet.h"
#include "ip.h"
#include "tcp.h"
#include "queue.h"

static class ClassifierClass : public TclClass {
public:
	ClassifierClass() : TclClass("Classifier") {}
	TclObject* create(int, const char*const*) {
		return (new Classifier());
	}
} class_classifier;


Classifier::Classifier() : 
	slot_(0), nslot_(0), maxslot_(-1), shift_(0), mask_(0xffffffff), nsize_(0),nid_(0),ns_time_(0.0),which_ns(0),rand_(true)
{
	default_target_ = 0;

	bind("offset_", &offset_);
	bind("shift_", &shift_);
	bind("mask_", &mask_);
	bind("tid_", &nid_);
	bind("which_ns", &which_ns);

	//liu: initialize for path table
	for(int i=0;i<8;i++){
		for(int j=0;j<3;j++){
			path_table[i][j] = -1;
			path_util[i][j] = 999999999999;
			path_weight[i][j] = 200000000;
		}
		path_time[i] = 0.0;
	}
}

int Classifier::classify(Packet *p)
{
	return (mshift(*((int*) p->access(offset_))));
}

Classifier::~Classifier()
{
	delete [] slot_;
}

void Classifier::set_table_size(int nn)
{
	nsize_ = nn;
}

void Classifier::alloc(int slot)
{
	NsObject** old = slot_;
	int n = nslot_;
	if (old == 0) 
	    {	
		if (nsize_ != 0) {
			//printf("classifier %x set to %d....%dth visit\n", this, nsize_, i++);
			nslot_ = nsize_;
		}
		else {
			//printf("classifier %x set to 32....%dth visit\n", this, j++);
			nslot_ = 32;
		}
	    }
	while (nslot_ <= slot) 
		nslot_ <<= 1;
	slot_ = new NsObject*[nslot_];
	memset(slot_, 0, nslot_ * sizeof(NsObject*));
	for (int i = 0; i < n; ++i)
		slot_[i] = old[i];
	delete [] old;
}


void Classifier::install(int slot, NsObject* p)
{
	if (slot >= nslot_)
		alloc(slot);
	slot_[slot] = p;
	if (slot >= maxslot_)
		maxslot_ = slot;
}

void Classifier::clear(int slot)
{
	slot_[slot] = 0;
	if (slot == maxslot_) {
		while (--maxslot_ >= 0 && slot_[maxslot_] == 0)
			;
	}
}

int Classifier::allocPort (NsObject *nullagent)
{
	return getnxt (nullagent);
}

int Classifier::getnxt(NsObject *nullagent)
{
	int i;
	for (i=0; i < nslot_; i++)
		if (slot_[i]==0 || slot_[i]==nullagent)
			return i;
	i=nslot_;
	alloc(nslot_);
	return i;
}

/*
 * objects only ever see "packet" events, which come either
 * from an incoming link or a local agent (i.e., packet source).
 */
void Classifier::recv(Packet* p, Handler*h)
{
	hdr_ip* ih = hdr_ip::access(p);
	hdr_cmn* ch = hdr_cmn::access(p);
	int probe = ih->dst_.port_;

	//liu: judge if is time to update util estimation table
	double time_thr = 0.0015;
	double alpha_ = 0.5;
	double time_now = Scheduler::instance().clock();
	if(ns_time_ == 0.0){
		ns_time_ = time_now;
		for(int i=0;i<20;i++){
			pt_[i].last_time_ = time_now;
		}
	}
	else{
		double time_inter  = time_now - ns_time_;
		if(time_inter >= time_thr){
			int freq_ = (int)(time_inter/time_thr);
			for(int i=0;i<20;i++){
				pt_[i].path_util_ *= pow((1-alpha_),freq_);
				//printf("util %f\n", pt_[i].path_util_);
				pt_[i].last_time_ += freq_*time_thr;
			}
			ns_time_ += freq_*time_thr;
		}
	}
	//ToR receives packet
	//normal classify
	if(probe != -1)
	{
		hdr_tcp* th = hdr_tcp::access(p);
		if(which_ns == 1){
			// CRLB
			update_util(p);
			if(!(hdr_cmn::access(p)->ptype_ == PT_ACK)){
				//printf("starting data transmission\n");
				//liu: record link util for every output port
				//ToR receives packet
				if(nid_ >= 20){
					int flowlet_id = th->flow_id_ % 20000;
					int dst_tor = ih->dst_.addr_;
					if(!(ih->dst_.addr_ == nid_)){
						if(!ch->check()){
							ch->check_ = true;
							//liu: judge if in flowlet table, if not, select a new path
							if(flowlet_table[flowlet_id] == 0.0 || time_now-flowlet_table[flowlet_id] > time_thr){
//								printf("test start\n");
								select_path(flowlet_id, dst_tor-20);
//								printf("test end\n");
							}
							if(ih->dst_.addr_ >= 20)
								ch->in_ip_ = ih->dst_.addr_;
							//printf("%d leaf %d %d->%d\n",nid_,ch->in_ip_,ih->src_.addr_,ih->dst_.addr_);
							ih->dst_.addr_ = flowlet_path[flowlet_id];
						}
						flowlet_table[flowlet_id] = time_now;
					}
					else{
						//printf("%d receive %d\n", nid_,ih->dst_);
					}
				}

				//Aggr receives packet
				else if(nid_ >= 10){
					if(ih->dst_.addr_ == nid_){
						ih->dst_.addr_ = ch->in_ip_;
					}
				}

				//Core receives packet
				else{
					if(ih->dst_.addr_ == nid_){
						ih->dst_.addr_ = ch->in_ip_;
					}
				}
			}
		}
		else if(which_ns == 2){
			//ECMP
			if(!(hdr_cmn::access(p)->ptype_ == PT_ACK)){
				if(nid_ >= 20){
					if(!(ih->dst_.addr_ == nid_)){
						if(!ch->check()){
							ch->check_ = true;
							int flow_id_ = th->flow_id_;
							int ip = ((flow_id_ + ih->dst_.addr_ + ih->src_.addr_ + ih->dport())/13)%4;
							ch->in_ip_ = ih->dst_.addr_;
							ih->dst_.addr_ = ip;
						}
					}
				}
				else if(nid_ < 10){
					if(ih->dst_.addr_ == nid_){
						ih->dst_.addr_ = ch->in_ip_;
					}
				}
			}
		}
		NsObject* node = find(p);
		if (node == NULL) {
			/*
			 * XXX this should be "dropped" somehow.  Right now,
			 * these events aren't traced.
			 */
			Packet::free(p);
			return;
		}
		node->recv(p,h);
	}
	//probe classify
	else{
		//if(which_ns == 1)
		process_probe(p,h);
	}
}

/*
 * perform the mapping from packet to object
 * perform upcall if no mapping
 */

NsObject* Classifier::find(Packet* p)
{
	NsObject* node = NULL;
	int cl = classify(p);
	if (cl < 0 || cl >= nslot_ || (node = slot_[cl]) == 0) { 
		if (default_target_) 
			return default_target_;
		/*
		 * Sigh.  Can't pass the pkt out to tcl because it's
		 * not an object.
		 */
		Tcl::instance().evalf("%s no-slot %ld", name(), cl);
		if (cl == TWICE) {
			/*
			 * Try again.  Maybe callback patched up the table.
			 */
			cl = classify(p);
			if (cl < 0 || cl >= nslot_ || (node = slot_[cl]) == 0)
				return (NULL);
		}
	}
	return (node);
}

int Classifier::install_next(NsObject *node) {
	int slot = maxslot_ + 1;
	install(slot, node);
	return (slot);
}

int Classifier::command(int argc, const char*const* argv)
{
	Tcl& tcl = Tcl::instance();
	if(argc == 2) {
                if (strcmp(argv[1], "defaulttarget") == 0) {
                        if (default_target_ != 0)
                                tcl.result(default_target_->name());
                        return (TCL_OK);
                }
        } else if (argc == 3) {
		/*
		 * $classifier alloc-port nullagent
		 */
		if (strcmp(argv[1],"alloc-port") == 0) {
			int slot;
			NsObject* nullagent =
				(NsObject*)TclObject::lookup(argv[2]);
			slot = getnxt(nullagent);
			tcl.resultf("%u",slot);
			return(TCL_OK);
		}
		/*
		 * $classifier clear $slot
		 */
		if (strcmp(argv[1], "clear") == 0) {
			int slot = atoi(argv[2]);
			clear(slot);
			return (TCL_OK);
		}
		/*
		 * $classifier installNext $node
		 */
		if (strcmp(argv[1], "installNext") == 0) {
			//int slot = maxslot_ + 1;
			NsObject* node = (NsObject*)TclObject::lookup(argv[2]);
			if (node == NULL) {
				tcl.resultf("Classifier::installNext attempt "
		    "to install non-object %s into classifier", argv[2]);
				return TCL_ERROR;
			};
			int slot = install_next(node);
			tcl.resultf("%u", slot);
			return TCL_OK;
		}
		/*
		 * $classifier slot snum
		 * returns the name of the object in slot # snum
		 */
		if (strcmp(argv[1], "slot") == 0) {
			int slot = atoi(argv[2]);
			if (slot >= 0 && slot < nslot_ && slot_[slot] != NULL) {
				tcl.resultf("%s", slot_[slot]->name());
				return TCL_OK;
			}
			tcl.resultf("Classifier: no object at slot %d", slot);
			return (TCL_ERROR);
		}
		/*
		 * $classifier findslot $node
		 * finds the slot containing $node
		 */
		if (strcmp(argv[1], "findslot") == 0) {
			int slot = 0;
			NsObject* node = (NsObject*)TclObject::lookup(argv[2]);
			if (node == NULL) {
				return (TCL_ERROR);
			}
			while (slot < nslot_) {
				// check if the slot is empty (xuanc, 1/14/02) 
				// fix contributed by Frank A. Zdarsky 
				// <frank.zdarsky@kom.tu-darmstadt.de>
				if (slot_[slot] && 
				    strcmp(slot_[slot]->name(), argv[2]) == 0){
					tcl.resultf("%u", slot);
					return (TCL_OK);
				}
				slot++;
			}
			tcl.result("-1");
			return (TCL_OK);
		}
		if (strcmp(argv[1], "defaulttarget") == 0) {
			default_target_=(NsObject*)TclObject::lookup(argv[2]);
			if (default_target_ == 0)
				return TCL_ERROR;
			return TCL_OK;
		}
	} else if (argc == 4) {
		/*
		 * $classifier install $slot $node
		 */
		if (strcmp(argv[1], "install") == 0) {
			int slot = atoi(argv[2]);
			NsObject* node = (NsObject*)TclObject::lookup(argv[3]);
			install(slot, node);
			return (TCL_OK);
		}
	}
	return (NsObject::command(argc, argv));
}

void Classifier::process_probe(Packet* p, Handler*h)
{
	NsObject* node = NULL;
	Tcl& tcl = Tcl::instance();
	hdr_cmn* ch = hdr_cmn::access(p);
	int in_node_ = ch->in_node_;
	int output_ = -1;

	//judge if update util
	judge_util(p,nid_,in_node_);

	//spine switch
	if(nid_ < 10) {
		ch->in_node_ = nid_;
		ch->probe_ip_ = nid_;
		if(in_node_ < 14) {
			for(int i=10;i<14;i++){
				if(i != in_node_){
					output_ = i;
					//update_util_probe(p,output_);
					tcl.evalf("[Simulator instance] get-link-head %d %d", 1, 20);
					printf("here %s",tcl.result());
					tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
					node = (NsObject*)TclObject::lookup(tcl.result());
					node->recv(p->copy(),h);
				}
			}
			Packet::free(p);
		}
		else {
			for(int i=14;i<18;i++){
				if(i != in_node_){
					output_ = i;
					//update_util_probe(p,output_);
					tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
					node = (NsObject*)TclObject::lookup(tcl.result());
					node->recv(p->copy(),h);
				}
			}
			Packet::free(p);
		}
	}

	//aggr switch
	else if(nid_ >= 10 && nid_ < 20) {
		//spine -> aggr
		if(in_node_ < 10){
			ch->in_node_ = nid_;
			output_ = ((nid_-10)%4)*2+20;
			//update_util_probe(p,output_);
			tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
			node = (NsObject*)TclObject::lookup(tcl.result());
			node->recv(p->copy(),h);
			output_ = ((nid_-10)%4)*2+21;
			//update_util_probe(p,output_);
			tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
			node = (NsObject*)TclObject::lookup(tcl.result());
			node->recv(p->copy(),h);
			Packet::free(p);
		}

		//leaf -> aggr
		else {
			ch->in_node_ = nid_;
			ch->probe_ip_ = nid_;
			if(nid_ < 14){
				output_ = 0;
				//update_util_probe(p,output_);
				tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
				node = (NsObject*)TclObject::lookup(tcl.result());
				node->recv(p->copy(),h);
				output_ = 1;
				//update_util_probe(p,output_);
				tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
				node = (NsObject*)TclObject::lookup(tcl.result());
				node->recv(p->copy(),h);
			}
			else{
				output_ = 2;
				//update_util_probe(p,output_);
				tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
				node = (NsObject*)TclObject::lookup(tcl.result());
				node->recv(p->copy(),h);
				output_ = 3;
				//update_util_probe(p,output_);
				tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
				node = (NsObject*)TclObject::lookup(tcl.result());
				node->recv(p->copy(),h);
			}
			if(in_node_%2 == 0){
				output_ = in_node_+1;
				//update_util_probe(p,output_);
				tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
				node = (NsObject*)TclObject::lookup(tcl.result());
				node->recv(p->copy(),h);
			}
			else{
				output_ = in_node_-1;
				//update_util_probe(p,output_);
				tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
				node = (NsObject*)TclObject::lookup(tcl.result());
				node->recv(p->copy(),h);
			}
			Packet::free(p);
		}
	}

	//ToR switch
	else {
		//server -> ToR
		if(in_node_ == -1) {
			if(nid_%2 == 0) {
				ch->in_node_ = nid_;
				ch->tor_id_ = nid_;
				output_ = (nid_-20)/2+10;
				//update_util_probe(p,output_);
				tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
				node = (NsObject*)TclObject::lookup(tcl.result());
				node->recv(p->copy(),h);
				output_ = (nid_-20)/2+14;
				//update_util_probe(p,output_);
				tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
				node = (NsObject*)TclObject::lookup(tcl.result());
				node->recv(p->copy(),h);
			}
			else {
				ch->in_node_ = nid_;
				ch->tor_id_ = nid_;
				output_ = (nid_-21)/2+10;
				//update_util_probe(p,output_);
				tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
				node = (NsObject*)TclObject::lookup(tcl.result());
				node->recv(p->copy(),h);
				output_ = (nid_-21)/2+14;
				//update_util_probe(p,output_);
				tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
				node = (NsObject*)TclObject::lookup(tcl.result());
				node->recv(p->copy(),h);
			}
			Packet::free(p);
		}

		//ToR -> server
		else {
			//printf("%d ToR receives and processes probe\n", nid_);
			int tor_id = ch->tor_id() - 20;
			double util_ = ch->path_util();
			int b_switch = ch->probe_ip();
			bool check_in_table = false;

			for(int i=0;i<3;i++){
				if(path_table[tor_id][i] == b_switch){
					check_in_table = true;
					path_util[tor_id][i] = util_;
					break;
				}
			}
			//init weight of path
			double weight_;
			if(path_weight[tor_id][0] <= path_weight[tor_id][1] && path_weight[tor_id][0] <= path_weight[tor_id][2])
				weight_ = path_weight[tor_id][0];
			else if(path_weight[tor_id][1] <= path_weight[tor_id][0] && path_weight[tor_id][1] <= path_weight[tor_id][2])
				weight_ = path_weight[tor_id][1];
			else
				weight_ = path_weight[tor_id][2];
			if(!check_in_table){
				for(int i=0;i<3;i++){
					if(path_table[tor_id][i] == -1){
						path_table[tor_id][i] = b_switch;
						path_util[tor_id][i] = util_;
						path_weight[tor_id][i] = 1;
						break;
					}
					else{
						if(util_ < path_util[tor_id][i]){
							int temp_ip = path_table[tor_id][i];
							double temp_util = path_util[tor_id][i];
							double temp_weight = path_weight[tor_id][i];
							path_table[tor_id][i] = b_switch;
							path_util[tor_id][i] = util_;
							path_weight[tor_id][i] = weight_;
							b_switch = temp_ip;
							util_ = temp_util;
							weight_ = temp_weight;
						}
					}
				}
			}
			//printf("path_table %d %d %d\n", path_table[tor_id][0], path_table[tor_id][1], path_table[tor_id][2]);
			Packet::free(p);
		}
	}
}

void Classifier::process_probe_new(Packet* p, Handler*h)
{
	NsObject* node = NULL;
	Tcl& tcl = Tcl::instance();
	hdr_cmn* ch = hdr_cmn::access(p);
	int in_node_ = ch->in_node_;
	int output_ = -1;

	//judge if update util
	judge_util(p,nid_,in_node_);

	//spine switch
	if(nid_ < 10) {
		ch->in_node_ = nid_;
		ch->probe_ip_ = nid_;
		if(in_node_ < 14) {
			for(int i=10;i<14;i++){
				if(i != in_node_){
					output_ = i;
					//update_util_probe(p,output_);
					tcl.evalf("[Simulator instance] get-link-head %d %d", 1, 20);
					printf("here %s",tcl.result());
					tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
					node = (NsObject*)TclObject::lookup(tcl.result());
					node->recv(p->copy(),h);
				}
			}
			Packet::free(p);
		}
		else {
			for(int i=14;i<18;i++){
				if(i != in_node_){
					output_ = i;
					//update_util_probe(p,output_);
					tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
					node = (NsObject*)TclObject::lookup(tcl.result());
					node->recv(p->copy(),h);
				}
			}
			Packet::free(p);
		}
	}

	//aggr switch
	else if(nid_ >= 10 && nid_ < 20) {
		//spine -> aggr
		if(in_node_ < 10){
			ch->in_node_ = nid_;
			output_ = ((nid_-10)%4)*2+20;
			//update_util_probe(p,output_);
			tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
			node = (NsObject*)TclObject::lookup(tcl.result());
			node->recv(p->copy(),h);
			output_ = ((nid_-10)%4)*2+21;
			//update_util_probe(p,output_);
			tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
			node = (NsObject*)TclObject::lookup(tcl.result());
			node->recv(p->copy(),h);
			Packet::free(p);
		}

		//leaf -> aggr
		else {
			ch->in_node_ = nid_;
			ch->probe_ip_ = nid_;
			if(nid_ < 14){
				output_ = 0;
				//update_util_probe(p,output_);
				tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
				node = (NsObject*)TclObject::lookup(tcl.result());
				node->recv(p->copy(),h);
				output_ = 1;
				//update_util_probe(p,output_);
				tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
				node = (NsObject*)TclObject::lookup(tcl.result());
				node->recv(p->copy(),h);
			}
			else{
				output_ = 2;
				//update_util_probe(p,output_);
				tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
				node = (NsObject*)TclObject::lookup(tcl.result());
				node->recv(p->copy(),h);
				output_ = 3;
				//update_util_probe(p,output_);
				tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
				node = (NsObject*)TclObject::lookup(tcl.result());
				node->recv(p->copy(),h);
			}
			if(in_node_%2 == 0){
				output_ = in_node_+1;
				//update_util_probe(p,output_);
				tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
				node = (NsObject*)TclObject::lookup(tcl.result());
				node->recv(p->copy(),h);
			}
			else{
				output_ = in_node_-1;
				//update_util_probe(p,output_);
				tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
				node = (NsObject*)TclObject::lookup(tcl.result());
				node->recv(p->copy(),h);
			}
			Packet::free(p);
		}
	}

	//ToR switch
	else {
		//server -> ToR
		if(in_node_ == -1) {
			if(nid_%2 == 0) {
				ch->in_node_ = nid_;
				ch->tor_id_ = nid_;
				output_ = (nid_-20)/2+10;
				//update_util_probe(p,output_);
				tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
				node = (NsObject*)TclObject::lookup(tcl.result());
				node->recv(p->copy(),h);
				output_ = (nid_-20)/2+14;
				//update_util_probe(p,output_);
				tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
				node = (NsObject*)TclObject::lookup(tcl.result());
				node->recv(p->copy(),h);
			}
			else {
				ch->in_node_ = nid_;
				ch->tor_id_ = nid_;
				output_ = (nid_-21)/2+10;
				//update_util_probe(p,output_);
				tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
				node = (NsObject*)TclObject::lookup(tcl.result());
				node->recv(p->copy(),h);
				output_ = (nid_-21)/2+14;
				//update_util_probe(p,output_);
				tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
				node = (NsObject*)TclObject::lookup(tcl.result());
				node->recv(p->copy(),h);
			}
			Packet::free(p);
		}

		//ToR -> server
		else {
			//printf("%d ToR receives and processes probe\n", nid_);
			int tor_id = ch->tor_id() - 20;
			double util_ = ch->path_util();
			int b_switch = ch->probe_ip();
			bool check_in_table = false;

			for(int i=0;i<3;i++){
				if(path_table[tor_id][i] == b_switch){
					check_in_table = true;
					path_util[tor_id][i] = util_;
					break;
				}
			}
			//init weight of path
			double weight_;
			if(path_weight[tor_id][0] <= path_weight[tor_id][1] && path_weight[tor_id][0] <= path_weight[tor_id][2])
				weight_ = path_weight[tor_id][0];
			else if(path_weight[tor_id][1] <= path_weight[tor_id][0] && path_weight[tor_id][1] <= path_weight[tor_id][2])
				weight_ = path_weight[tor_id][1];
			else
				weight_ = path_weight[tor_id][2];
			if(!check_in_table){
				for(int i=0;i<3;i++){
					if(path_table[tor_id][i] == -1){
						path_table[tor_id][i] = b_switch;
						path_util[tor_id][i] = util_;
						path_weight[tor_id][i] = 1;
						break;
					}
					else{
						if(util_ < path_util[tor_id][i]){
							int temp_ip = path_table[tor_id][i];
							double temp_util = path_util[tor_id][i];
							double temp_weight = path_weight[tor_id][i];
							path_table[tor_id][i] = b_switch;
							path_util[tor_id][i] = util_;
							path_weight[tor_id][i] = weight_;
							b_switch = temp_ip;
							util_ = temp_util;
							weight_ = temp_weight;
						}
					}
				}
			}
			//printf("path_table %d %d %d\n", path_table[tor_id][0], path_table[tor_id][1], path_table[tor_id][2]);
			Packet::free(p);
		}
	}
}

void Classifier::update_util(Packet* p)
{
	hdr_ip* ih = hdr_ip::access(p);
	hdr_cmn* ch = hdr_cmn::access(p);

	int dst_ = ih->dst().addr_;
	int pt;

	//ToR switch receives packets
	if(nid_ >= 20){
		if(dst_ != nid_){
			if(dst_<10)
				pt = dst_;
			else if(dst_>=20)
				pt = dst_-8;
			else
				pt = dst_-6;

			pt_[pt].path_util_ += ch->size_;
		}
	}

	//Spine switch receives packets
	//Aggr switch receives packets
	else{
		if(dst_ == nid_){
			dst_ = ch->in_ip_;
		}
		if(dst_<10)
			pt = dst_;
		else if(dst_>=20)
			pt = dst_-8;
		else
			pt = dst_-6;

		pt_[pt].path_util_ += ch->size_;
	}
}

void Classifier::update_util_probe(Packet* p, int dst)
{
	hdr_cmn* ch = hdr_cmn::access(p);
	int pt;
	if(dst < 10)
		pt = dst;
	else if(dst >= 20)
		pt = dst-8;
	else
		pt = dst-6;
	pt_[pt].path_util_ += ch->size_;
}

void Classifier::judge_util(Packet* p, int nid, int in_node)
{
	double util = 0;
	hdr_cmn* ch = hdr_cmn::access(p);
	//spine receives probe
	if(nid < 10){
		if(nid < 2){
			util += pt_[in_node-6].path_util_+pt_[in_node*2-8].path_util_+pt_[in_node*2+1-8].path_util_;
		}
		else{
			util += pt_[in_node-6].path_util_+pt_[(in_node-4)*2-8].path_util_+pt_[(in_node-4)*2+1-8].path_util_;
		}
	}

	//leaf receives probe
	else if(nid >= 20){
		if(in_node != -1){
			if(in_node >= 10 && in_node < 14){
				util += pt_[in_node-6].path_util_+pt_[0].path_util_+pt_[1].path_util_;
			}
			else{
				util += pt_[in_node-6].path_util_+pt_[2].path_util_+pt_[3].path_util_;
			}
		}
	}

	//aggr receives probe
	else{
		if(nid >= 20){
			util += pt_[nid-8].path_util_;
		}
		else{
			util += pt_[nid].path_util_;
		}
	}
	if(util > ch->path_util_){
		ch->path_util_ = util;
	}
}

void Classifier::select_path(int flowlet_id, int dst_tor)
{
	//reduce weight according to time
	double time_thr = 0.1;
	double time_now = Scheduler::instance().clock();
	if(path_time[dst_tor] == 0.000000){
		path_time[dst_tor] = time_now;
	}
	else{
		double time_inter = time_now - path_time[dst_tor];
		printf("here %f\n", time_now);
		if(time_inter >= time_thr){
			int freq_ = (int)(time_inter/time_thr);
			printf("freq %d\n", freq_);
			for(int j=0;j<3;j++){
				path_weight[dst_tor][j] *= pow(0.5,freq_);
				if(path_weight[dst_tor][j] < 1)
					path_weight[dst_tor][j] = 1;
			}
			path_time[dst_tor] += time_thr * freq_;
		}
	}

//	if(path_util[dst_tor][0] <= 1)
//		path_util[dst_tor][0] = 1;
//	int weight_1 = 2000000000/path_util[dst_tor][0];
//	if(weight_1 <= 1)
//		weight_1 = 1;
//	if(path_util[dst_tor][1] <= 1)
//		path_util[dst_tor][1] = 1;
//	int weight_2 = 2000000000/path_util[dst_tor][1];
//	if(weight_2 <= 1)
//			weight_2 = 1;
//	if(path_util[dst_tor][2] <= 1)
//		path_util[dst_tor][2] = 1;
//	int weight_3 = 2000000000/path_util[dst_tor][2];
//	if(weight_3 <= 1)
//			weight_3 = 1;

	//select path according to weight
	double weight_1 = 200000000/path_weight[dst_tor][0];
	if(weight_1 <= 1)
		weight_1 = 1;
	double weight_2 = 200000000/path_weight[dst_tor][1];
	if(weight_2 <= 1)
			weight_2 = 1;
	double weight_3 = 200000000/path_weight[dst_tor][2];
	if(weight_3 <= 1)
			weight_3 = 1;
	printf("weight %f %f %f\n", weight_1, weight_2, weight_3);
	printf("path_table %d %d %d\n", path_table[dst_tor][0], path_table[dst_tor][1], path_table[dst_tor][2]);
	printf("path_util %f %f %f\n", path_util[dst_tor][0], path_util[dst_tor][1], path_util[dst_tor][2]);
	double total = weight_1 + weight_2 + weight_3;
	srand(int(time_now*1000000));
	double ran_num = (double)(rand() % int(total));

	//path 1
	if(ran_num < weight_1){
		if(path_table[dst_tor][0] == -1){
			if(rand_){
				flowlet_path[flowlet_id] = path_table[dst_tor][1];
				path_weight[dst_tor][1] *= 1.5;
			}
			else{
				flowlet_path[flowlet_id] = path_table[dst_tor][2];
				path_weight[dst_tor][2] *= 1.5;
			}
			rand_ = not rand_;
		}
		else{
			printf("%f %f %f\n", path_weight[dst_tor][0], path_weight[dst_tor][1], path_weight[dst_tor][2]);
			if((path_util[dst_tor][0]+1)/(path_util[dst_tor][1]+1) > 100){
				flowlet_path[flowlet_id] = path_table[dst_tor][1];
				path_weight[dst_tor][1] *= 1.5;
			}
			else if((path_util[dst_tor][0]+1)/(path_util[dst_tor][2]+1) > 100){
				flowlet_path[flowlet_id] = path_table[dst_tor][2];
				path_weight[dst_tor][2] *= 1.5;
			}
			else{
				flowlet_path[flowlet_id] = path_table[dst_tor][0];
				path_weight[dst_tor][0] *= 1.5;
			}
		}
	}

	//path 2
	else if(ran_num >= weight_1 && ran_num < weight_1+weight_2){
		printf("path2\n");
		if(path_table[dst_tor][1] == -1){
			if(rand_){
				flowlet_path[flowlet_id] = path_table[dst_tor][0];
				path_weight[dst_tor][0] *= 1.5;
			}
			else{
				flowlet_path[flowlet_id] = path_table[dst_tor][2];
				path_weight[dst_tor][2] *= 1.5;
			}
			rand_ = not rand_;
		}
		else{
			printf("%f %f %f\n", path_weight[dst_tor][0], path_weight[dst_tor][1], path_weight[dst_tor][2]);
			if((path_util[dst_tor][1]+1)/(path_util[dst_tor][0]+1) > 100){
				flowlet_path[flowlet_id] = path_table[dst_tor][0];
				path_weight[dst_tor][0] *= 1.5;
			}
			else if((path_util[dst_tor][1]+1)/(path_util[dst_tor][2]+1) > 100){
				flowlet_path[flowlet_id] = path_table[dst_tor][2];
				path_weight[dst_tor][2] *= 1.5;
			}
			else{
				flowlet_path[flowlet_id] = path_table[dst_tor][1];
				path_weight[dst_tor][1] *= 1.5;
			}
		}
	}

	//path 3
	else{
		if(path_table[dst_tor][2] == -1){
			if(rand_){
				flowlet_path[flowlet_id] = path_table[dst_tor][0];
				path_weight[dst_tor][0] *= 1.5;
			}
			else{
				flowlet_path[flowlet_id] = path_table[dst_tor][1];
				path_weight[dst_tor][1] *= 1.5;
			}
			rand_ = not rand_;
		}
		else{
			printf("%f %f %f\n", path_weight[dst_tor][0], path_weight[dst_tor][1], path_weight[dst_tor][2]);
			if((path_util[dst_tor][2]+1)/(path_util[dst_tor][1]+1) > 100){
				flowlet_path[flowlet_id] = path_table[dst_tor][1];
				path_weight[dst_tor][1] *= 1.5;
			}
			else if((path_util[dst_tor][2]+1)/(path_util[dst_tor][0]+1) > 100){
				flowlet_path[flowlet_id] = path_table[dst_tor][0];
				path_weight[dst_tor][0] *= 1.5;
			}
			else{
				flowlet_path[flowlet_id] = path_table[dst_tor][2];
				path_weight[dst_tor][2] *= 1.5;
			}
		}
	}
}
