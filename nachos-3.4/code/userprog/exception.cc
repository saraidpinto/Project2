// exception.cc
//	Entry point into the Nachos kernel from user programs.
//	There are two kinds of things that can cause control to
//	transfer back to here from user code:
//
//	syscall -- The user code explicitly requests to call a procedure
//	in the Nachos kernel.  Right now, the only function we support is
//	"Halt".
//
//	exceptions -- The user code does something that the CPU can't handle.
//	For instance, accessing memory that doesn't exist, arithmetic errors,
//	etc.
//
//	Interrupts (which can also cause control to transfer from user
//	code into the Nachos kernel) are handled elsewhere.
//
// For now, this only handles the Halt() system call.
// Everything else core dumps.
//
// Copyright (c) 1992-1993 The Regents of the University of California.
// All rights reserved.  See copyright.h for copyright notice and limitation
// of liability and disclaimer of warranty provisions.

#include "copyright.h"
#include "system.h"
#include "syscall.h"

//----------------------------------------------------------------------
// ExceptionHandler
// 	Entry point into the Nachos kernel.  Called when a user program
//	is executing, and either does a syscall, or generates an addressing
//	or arithmetic exception.
//
// 	For system calls, the following is the calling convention:
//
// 	system call code -- r2
//		arg1 -- r4
//		arg2 -- r5
//		arg3 -- r6
//		arg4 -- r7
//
//	The result of the system call, if any, must be put back into r2.
//
// And don't forget to increment the pc before returning. (Or else you'll
// loop making the same system call forever!
//
//	"which" is the kind of exception.  The list of possible exceptions
//	are in machine.h.
//----------------------------------------------------------------------


void doExit(int status) {

    int pid = 99;

    printf("System Call: [%d] invoked [Exit]\n", pid);
    printf ("Process [%d] exits with [%d]\n", pid, status);

    delete currentThread->space;
    currentThread->Finish();
    currentThread->space->pcb->exitStatus = status;

    // Manage PCB memory As a parent process
    PCB* pcb = currentThread->space->pcb;

    // Delete exited children and set parent null for non-exited ones
    pcb->DeleteExitedChildrenSetParentNull();

    // Manage PCB memory As a child process
    if(pcb->parent == NULL) pcbManager->DeallocatePCB(pcb);

}

void incrementPC() {
    int oldPCReg = machine->ReadRegister(PCReg);

    machine->WriteRegister(PrevPCReg, oldPCReg);
    machine->WriteRegister(PCReg, oldPCReg + 4);
    machine->WriteRegister(NextPCReg, oldPCReg + 8);
}


void childFunction(int pid){


    //1. Restore the state of registers
    currentThread->RestoreUserState();

    //2. Restore the page table for child
    currentThread->space->RestoreState();

    PCReg == machine->ReadRegister(PCReg);
    
    //print message for child creation
    printf("System Call: [%d] invoked [Fork]\n", pid);
    printf("Process [%d] Fork: start at address [%d] with [%d] pages memory\n", pid, PCReg, currentThread->space->GetNumPages());

    machine->Run();
    ASSERT(FALSE);

}



int doFork(int functionAddr){
    //1. Check if sufficient memory exist ti create a new process
    //currentThread->space->GetNumPages() <= mm->GetFreePageCount()
    //if check fails, return -1

    if(currentThread->space->GetNumPages() <= mm->GetFreePageCount()){

         //2.SaveUserState for the parent thread
        currentThread->SaveUserState();

        //3.Create a new adress space for child by copying the parent adress space
        //Parent: currentThread->space;
        AddrSpace * space = currentThread->space;
        //childAddrSpace: new AddrSpace(currentThread->space);

        //4. Create a new thread for the child and set its adress space
        Thread * childThread = new Thread("childThread");
        childThread->space = space;

        //5.Create a PCB for the child and connect it all up
        PCB* pcb = currentThread->space->pcb;
       // pcb: pcbManager->AllocatePCB();
        pcb: pcbManager->AllocatePCB();
        pcb->thread = childThread;
        //set parent for child pcb
        //add child for parent pcb
        childThread(AddChild( pcb));
       

       //6. Set up machine registers for child and save it to child thread
        //PCReg: functionAddr;
        machine->WriteRegister(PCReg, functionAddr);
        //PrevPCReg: functionAddr - 4;
        machine->WriteRegister(PrevPCReg, functionAddr-4);
        //NextPCReg: functionAddr + 4;
        machine->WriteRegister(NextPCReg, functionAddr+4);
        childThread->SaveUserState();

        //7. Call thread->fork on Child
        childThread->Fork(childFunction, pcb->pid);

        //8. Restore register state of parent user-level process
        currentThread->RestoreUserState();
        
        //9
        return pcb->pid;
    
    } else {

        return -1;

    }


}

int doExec(char* filename) {

    // Use progtest.cc:StartProcess() as a guide

    // 1. Open the file and check validity
    // OpenFile *executable = fileSystem->Open(filename);
    // AddrSpace *space;

    // if (executable == NULL) {
    //     printf("Unable to open file %s\n", filename);
    //     return -1;
    // }

    // 2. Create new address space
    // space = new AddrSpace(executable);

    // 3. Check if Addrspace creation was successful
    // if(space->valid != true) {
    // printf("Could not create AddrSpace\n");
    //     return -1;
    // }

    // Steps 4 and 5 may not be necessary!!

    // 4. Create a new PCB for the new addrspace
    // ?. Can you reuse existing pcb?
    // PCB* pcb = pcbManager->AllocatePCB();
    // Initialize parent
    // pcb->parent = currentThread->space->pcb->parent;
    // space->pcb = pcb;

    // 5. Set the thread for the new pcb
    // pcb->thread = currentThread;

    // 6. Delete current address space
    // delete currentThread->space;

    // 7. SEt the addrspace for currentThread
    // currentThread->space = space;

    // 8.     delete executable;			// close file

    // 9. Initialize registers for new addrspace
    //  space->InitRegisters();		// set the initial register values

    // 10. Initialize the page table
    // space->RestoreState();		// load page table register

    // 11. Run the machine now that all is set up
    // machine->Run();			// jump to the user progam
    // ASSERT(FALSE); // Execution nevere reaches here

    return 0;
}


int doJoin(int pid) {

    // 1. Check if this is a valid pid and return -1 if not
    // PCB* joinPCB = pcbManager->GetPCB(pid);
    // if (pcb == NULL) return -1;

    // 2. Check if pid is a child of current process
    // PCB* pcb = currentThread->space->pcb;
    // if (pcb != joinPCB->parent) return -1;

    // 3. Yield until joinPCB has not exited
    // while(!joinPCB->hasExited) currentThread->Yield();

    // 4. Store status and delete joinPCB
    // int status = joinPCB->exitStatus;
    // delete joinPCB;

    // 5. return status;

}


int doKill (int pid) {

    // 1. Check if the pid is valid and if not, return -1
    // PCB* joinPCB = pcbManager->GetPCB(pid);
    // if (pcb == NULL) return -1;

    // 2. IF pid is self, then just exit the process
    // if (pcb == currentThread->space->pcb) {
    //         doExit(0);
    //         return 0;
    // }

    // 3. Valid kill, pid exists and not self, do cleanup similar to Exit
    // However, change references from currentThread to the target thread
    // pcb->thread is the target thread

    // 4. return 0 for success!

}



void doYield() {
    currentThread->Yield();
}

char* translate(int virtAddr) {

    unsigned int pageNumber = virtAddr / 128;
    unsigned int pageOffset = virtAddr % 128;
    unsigned int frameNumber = machine->pageTable[pageNumber].physicalPage;
    unsigned int physicalAddr = frameNumber*128 + pageOffset;
    char* filename = &(machine->mainMemory[physicalAddr]);

    return filename;
}

void
ExceptionHandler(ExceptionType which)
{
    int type = machine->ReadRegister(2);

    if ((which == SyscallException) && (type == SC_Halt)) {
	DEBUG('a', "Shutdown, initiated by user program.\n");
   	interrupt->Halt();
    } else  if ((which == SyscallException) && (type == SC_Exit)) {
        // Implement Exit system call
        doExit(machine->ReadRegister(4));
    } else if ((which == SyscallException) && (type == SC_Fork)) {
        int ret = doFork(machine->ReadRegister(4));
        machine->WriteRegister(2, ret);
        incrementPC();
    } else if ((which == SyscallException) && (type == SC_Exec)) {
        int virtAddr = machine->ReadRegister(4);
        char* fileName = translate(virtAddr);
        int ret = doExec(fileName);
        machine->WriteRegister(2, ret);
        incrementPC();
    } else if ((which == SyscallException) && (type == SC_Join)) {
        int ret = doJoin(machine->ReadRegister(4));
        machine->WriteRegister(2, ret);
        incrementPC();
    } else if ((which == SyscallException) && (type == SC_Kill)) {
        int ret = doKill(machine->ReadRegister(4));
        machine->WriteRegister(2, ret);
        incrementPC();
    } else if ((which == SyscallException) && (type == SC_Yield)) {
        doYield();
        incrementPC();
    } else {
	printf("Unexpected user mode exception %d %d\n", which, type);
	ASSERT(FALSE);
    }
}
