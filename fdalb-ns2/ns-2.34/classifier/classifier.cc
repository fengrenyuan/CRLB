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
#include "config.h"
#include "classifier.h"
#include "packet.h"
#include "ip.h"
#include "queue.h"

static class ClassifierClass : public TclClass {
public:
	ClassifierClass() : TclClass("Classifier") {}
	TclObject* create(int, const char*const*) {
		return (new Classifier());
	}
} class_classifier;


Classifier::Classifier() : 
	slot_(0), nslot_(0), maxslot_(-1), shift_(0), mask_(0xffffffff), nsize_(0),nid_(0)
{
	default_target_ = 0;

	bind("offset_", &offset_);
	bind("shift_", &shift_);
	bind("mask_", &mask_);
	bind("tid_", &nid_);
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

	//normal classify
	if(probe != -1)
	{
		//record link util for every output port
		update_util(p);

		NsObject* node = find(p);
		if (node == NULL) {
			/*
			 * XXX this should be "dropped" somehow.  Right now,
			 * these events aren't traced.
			 */
			Packet::free(p);
			return;
		}
		printf("%d\n",ch->size_);
		node->recv(p,h);
	}
	else{
		process_probe(p,h);
		for(int i=0;i<20;i++){
			printf("%d %d %f %f\n",nid_,i,pt_[i].path_util_,pt_[i].last_time_);
		}
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

	//spine switch
	if(nid_ < 10) {
		ch->in_node_ = nid_;
		ch->probe_ip_ = nid_;
		if(in_node_ < 14) {
			for(int i=10;i<14;i++){
				if(i != in_node_){
					output_ = i;
					update_util_probe(p,output_);
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
					update_util_probe(p,output_);
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
			update_util_probe(p,output_);
			tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
			node = (NsObject*)TclObject::lookup(tcl.result());
			node->recv(p->copy(),h);
			output_ = ((nid_-10)%4)*2+21;
			update_util_probe(p,output_);
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
				update_util_probe(p,output_);
				tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
				node = (NsObject*)TclObject::lookup(tcl.result());
				node->recv(p->copy(),h);
				output_ = 1;
				update_util_probe(p,output_);
				tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
				node = (NsObject*)TclObject::lookup(tcl.result());
				node->recv(p->copy(),h);
			}
			else{
				output_ = 2;
				update_util_probe(p,output_);
				tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
				node = (NsObject*)TclObject::lookup(tcl.result());
				node->recv(p->copy(),h);
				output_ = 3;
				update_util_probe(p,output_);
				tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
				node = (NsObject*)TclObject::lookup(tcl.result());
				node->recv(p->copy(),h);
			}
			if(in_node_%2 == 0){
				output_ = in_node_+1;
				update_util_probe(p,output_);
				tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
				node = (NsObject*)TclObject::lookup(tcl.result());
				node->recv(p->copy(),h);
			}
			else{
				output_ = in_node_-1;
				update_util_probe(p,output_);
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
				update_util_probe(p,output_);
				tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
				node = (NsObject*)TclObject::lookup(tcl.result());
				node->recv(p->copy(),h);
				output_ = (nid_-20)/2+14;
				update_util_probe(p,output_);
				tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
				node = (NsObject*)TclObject::lookup(tcl.result());
				node->recv(p->copy(),h);
			}
			else {
				ch->in_node_ = nid_;
				ch->tor_id_ = nid_;
				output_ = (nid_-21)/2+10;
				update_util_probe(p,output_);
				tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
				node = (NsObject*)TclObject::lookup(tcl.result());
				node->recv(p->copy(),h);
				output_ = (nid_-21)/2+14;
				update_util_probe(p,output_);
				tcl.evalf("[Simulator instance] get-link-head %d %d", nid_,output_);
				node = (NsObject*)TclObject::lookup(tcl.result());
				node->recv(p->copy(),h);
			}
			Packet::free(p);
		}

		//ToR -> server
		else {
			//TODO:receive packet and update util-table
			output_ = ch->in_node_;
			//printf("%d reveive probe signed with %d to %d\n",nid_,ch->probe_ip_,ch->tor_id_);
			Packet::free(p);
		}
	}
}

void Classifier::update_util(Packet* p)
{
	hdr_ip* ih = hdr_ip::access(p);
	hdr_cmn* ch = hdr_cmn::access(p);

	double time_now = Scheduler::instance().clock();
	int dst_ = ih->dst().addr_;
	double time_thr = 1.0;
	double alpha = 0.5;
	int pt;
	printf("hello %f %d %f\n",time_now,dst_,pt_[dst_].path_util_);

	//ToR switch receives packets
	if(nid_ >= 20){
		if(dst_ != nid_){
			if(dst_<10)
				pt = dst_;
			else if(dst_>=20)
				pt = dst_-8;
			else
				pt = dst_-6;

			if(pt_[pt].last_time_ == 0){
				pt_[pt].path_util_ += ch->size_;
				pt_[pt].last_time_ = time_now;
			}
			else{
				int times = (int)(time_now-pt_[pt].last_time_)/time_thr;
				if(times > 0){
					for(int i=0;i<times;i++)
						pt_[pt].path_util_ *= (1-alpha);
				}
				pt_[pt].path_util_ += ch->size_;
				pt_[pt].last_time_ = time_now;
			}
		}
	}

	//Spine switch receives packets
	else if(nid_ < 10){
		if(dst_ == nid_){
			dst_ = ch->in_ip_;
		}
		if(dst_<10)
			pt = dst_;
		else if(dst_>=20)
			pt = dst_-8;
		else
			pt = dst_-6;

		if(pt_[pt].last_time_ == 0){
			pt_[pt].path_util_ += ch->size_;
			pt_[pt].last_time_ = time_now;
		}
		else{
			int times = (int)(time_now-pt_[pt].last_time_)/time_thr;
			if(times > 0){
				for(int i=0;i<times;i++)
					pt_[pt].path_util_ *= (1-alpha);
			}
			pt_[pt].path_util_ += ch->size_;
			pt_[pt].last_time_ = time_now;
		}
	}

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

		if(pt_[pt].last_time_ == 0){
			pt_[pt].path_util_ += ch->size_;
			pt_[pt].last_time_ = time_now;
		}
		else{
			int times = (int)(time_now-pt_[pt].last_time_)/time_thr;
			if(times > 0){
				for(int i=0;i<times;i++)
					pt_[pt].path_util_ *= (1-alpha);
			}
			pt_[pt].path_util_ += ch->size_;
			pt_[pt].last_time_ = time_now;
		}
	}
}

void Classifier::update_util_probe(Packet* p, int dst)
{
	hdr_cmn* ch = hdr_cmn::access(p);
	double time_now = Scheduler::instance().clock();
	double time_thr = 1.0;
	double alpha = 0.5;
	int pt;
	if(dst < 10)
		pt = dst;
	else if(dst >= 20)
		pt = dst-8;
	else
		pt = dst-6;
	if(pt_[pt].last_time_ == 0){
		pt_[pt].path_util_ += ch->size_;
		pt_[pt].last_time_ = time_now;
	}
	else{
		int times = (int)(time_now-pt_[pt].last_time_)/time_thr;
		if(times > 0){
			for(int i=0;i<times;i++)
				pt_[pt].path_util_ *= (1-alpha);
		}
		pt_[pt].path_util_ += ch->size_;
		pt_[pt].last_time_ = time_now;
	}
}
