/*
 * entropy_analysis.c
 *
 *  Created on: Oct 14, 2017
 *      Author: lvr
 */



#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/sched.h>
#include<linux/syscalls.h>
#include <exp/entropy_analysis.h>

unsigned long ret_kernel_entropy_record_size;

asmlinkage long sys_kernel_entropy_get_size(void)
{
	spin_lock(&entropy_analysis_lock);
	ret_kernel_entropy_record_size = kernel_entropy_record_size;
	spin_unlock(&entropy_analysis_lock);
	return ret_kernel_entropy_record_size;
}

unsigned long recorded_kernel_entropy_size = 0;

asmlinkage bool sys_kernel_entropy_get_recorded(process_kernel_entropy * target_buffer)
{
	if(target_buffer == NULL)
		return 1;
	spin_lock(&entropy_analysis_lock);
	recorded_kernel_entropy_size = ((kernel_entropy_record_size + 1) * sizeof(process_kernel_entropy));
	copy_to_user (target_buffer, &recorded_kernel_entropy, recorded_kernel_entropy_size);
    spin_unlock(&entropy_analysis_lock);
	return 0;
}

asmlinkage bool sys_kernel_entropy_start_recording(void)
{
	spin_lock(&entropy_analysis_lock);
	is_kernel_entropy_recording = 1;
	spin_unlock(&entropy_analysis_lock);
	return 0;
}

asmlinkage bool sys_kernel_entropy_stop_recording(void)
{
	spin_lock(&entropy_analysis_lock);
	is_kernel_entropy_recording = 0;
	spin_unlock(&entropy_analysis_lock);
	return 0;
}

asmlinkage bool sys_kernel_entropy_is_recording(void)
{
	spin_lock(&entropy_analysis_lock);
	return is_kernel_entropy_recording;
	spin_unlock(&entropy_analysis_lock);
}
