/*
 * entropy_analysis.h
 *
 *  Created on: Oct 12, 2017
 *      Author: lvr
 */
#include <linux/sched.h>
#include <linux/spinlock.h>


#ifndef INCLUDE_EXP_ENTROPY_ANALYSIS_H_
#define INCLUDE_EXP_ENTROPY_ANALYSIS_H_

extern spinlock_t entropy_analysis_lock;

#define KERNEL_ENTROPY_RECORD_MAX 15000

//extern recorded_kernel_entropy

typedef struct
{
   unsigned long stack_canary;
   char comm[TASK_COMM_LEN];
   pid_t pid;

} process_kernel_entropy;

extern bool is_kernel_entropy_recording;
extern unsigned long kernel_entropy_record_size;
extern process_kernel_entropy recorded_kernel_entropy[KERNEL_ENTROPY_RECORD_MAX];

asmlinkage long sys_kernel_entropy_get_size(void);
asmlinkage bool sys_kernel_entropy_get_recorded(process_kernel_entropy * target_buffer);
asmlinkage bool sys_kernel_entropy_start_recording(void);
asmlinkage bool sys_kernel_entropy_stop_recording(void);
asmlinkage bool sys_kernel_entropy_is_recording(void);

#endif /* INCLUDE_EXP_ENTROPY_ANALYSIS_H_ */
