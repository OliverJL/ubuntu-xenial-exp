/*
 * entropy_analysis.h
 *
 *  Created on: Oct 12, 2017
 *      Author: lvr
 */
//#include <linux/types.h>
#include <linux/sched.h>


#ifndef INCLUDE_EXP_ENTROPY_ANALYSIS_H_
#define INCLUDE_EXP_ENTROPY_ANALYSIS_H_



#endif /* INCLUDE_EXP_ENTROPY_ANALYSIS_H_ */



struct randomval
{
   unsigned long stack_canary;
   char comm[TASK_COMM_LEN];
   pid_t pid;

};
