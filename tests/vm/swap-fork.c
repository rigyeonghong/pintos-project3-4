/* */

#include <string.h>
#include <syscall.h>
#include <stdio.h>
#include "tests/lib.h"
#include "tests/main.h"
#include "tests/vm/large.inc"

#define CHILD_CNT 10

void
test_main (void) 
{
  pid_t child[CHILD_CNT];
  size_t i;
  
	/* Spawn children */
    for(i =0; i < CHILD_CNT; i++) {
	  child[i] = fork("child-swap");
	  if (child[i] == 0) {
	  	if(exec ("child-swap") == -1)
            fail("exec \"child-swap\"");
	  }
    }
	/* Wait for children */
    for(i =0; i < CHILD_CNT; i++) {
      int a = wait (child[i]);
  	  if(a!=0){
        printf("[wait]: %d\n",a);
        fail("More than one child process' stack is corrupted");
      }
    }
}
