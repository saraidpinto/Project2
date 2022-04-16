// threadtest.cc 
//	Simple test case for the threads assignment.
//
//	Create two threads, and have them context switch
//	back and forth between themselves by calling Thread::Yield, 
//	to illustratethe inner workings of the thread system.
//
// Copyright (c) 1992-1993 The Regents of the University of California.
// All rights reserved.  See copyright.h for copyright notice and limitation 
// of liability and disclaimer of warranty provisions.

#include "copyright.h"
#include "system.h"
#include "synch.h"

// testnum is set in main.cc
int testnum = 1;
int activeThreads;
int SharedVariable;

//----------------------------------------------------------------------
// SimpleThread
// 	Loop 5 times, yielding the CPU to another ready thread 
//	each iteration.
//
//	"which" is simply a number identifying the thread, for debugging
//	purposes.
//----------------------------------------------------------------------

#if defined(CHANGED) && defined(HW1_SEMAPHORES)

// initialize Semaphore
Semaphore *s;

void SimpleThread(int which) {
    int num, val;
    for(num = 0; num < 5; num++) {

        // entry section
        if(s==NULL){
            DEBUG('t', "applying semaphores\n");
            s = new Semaphore("starting shared sem", 1);
        }
            // invoke p operation
            s->P();

        /* start of critical section */
        val = SharedVariable;
        printf("*** thread %d sees value %d\n", which, val);
        currentThread->Yield();
        SharedVariable = val+1;
        /* end of critical section */

        // exit section 
            //invoke v operation
            s->V();
        currentThread->Yield();
    }
     
    // decrement activeThreads  
     activeThreads--;
    // // check if activeThreads is 0 with while loop. 
    // Yield self while not. (To wait just Yield to another thread) 
    while(activeThreads>0){
        currentThread->Yield();
    }
   
    val = SharedVariable;
    printf("Thread %d sees final value %d\n", which, val);
}

#elif defined(CHANGED) && defined(HW1_LOCKS)

// initialize Lock
Lock *l;

void SimpleThread(int which) {
    int num, val;
    if(l==NULL){
        DEBUG('t', "applying locks\n");
        l = new Lock("testing"); 
    }

    for(num = 0; num < 5; num++) {

        // entry section
        
        // invoke acquire operation
        l->Acquire();

        /* start of critical section */
        val = SharedVariable;
        printf("*** thread %d sees value %d\n", which, val);
        currentThread->Yield();
        SharedVariable = val+1;
        /* end of critical section */

        // exit section 

        //invoke release operation
        l->Release();

        currentThread->Yield();
    }
     
    // decrement activeThreads  
     activeThreads--;
    // // check if activeThreads is 0 with while loop. 
    // Yield self while not. (To wait just Yield to another thread) 
    while(activeThreads>0){
        currentThread->Yield();
    }
    val = SharedVariable;
    printf("Thread %d sees final value %d\n", which, val);
}

#else
void
SimpleThread(int which)
{
    int num;
    
    for (num = 0; num < 5; num++) {
	printf("*** thread %d looped %d times\n", which, num);
        currentThread->Yield();
    }
}


//----------------------------------------------------------------------
// ThreadTest1
// 	Set up a ping-pong between two threads, by forking a thread 
//	to call SimpleThread, and then calling SimpleThread ourselves.
//----------------------------------------------------------------------

void
ThreadTest1()
{
    DEBUG('t', "Entering ThreadTest1");

    Thread *t = new Thread("forked thread");

    t->Fork(SimpleThread, 1);
    SimpleThread(0);
}
#endif


//----------------------------------------------------------------------
// ThreadTest
// 	Invoke a test routine.
//----------------------------------------------------------------------


#if defined(CHANGED) && defined(THREADS)
void
ThreadTest(int n)
{
    DEBUG('t', "Entering SimpleTest");
    Thread *t;
    activeThreads = n+1;
    
    for (int i =0; i<n; i++){
        t = new Thread("forked thread");
        t->Fork(SimpleThread, i+1);
    }
    SimpleThread(0);
    
}
#else
void
ThreadTest()
{
    switch (testnum) {
    case 1:
	ThreadTest1();
	break;
    default:
	printf("No test specified.\n");
	break;
    }
}
#endif
