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
int ret_kernel_entropy_copy_to_user = 0;

asmlinkage long sys_kernel_entropy_get_recorded(process_kernel_entropy * target_buffer)
{
	if(target_buffer == NULL)
		return -1;
	spin_lock(&entropy_analysis_lock);
	printk(KERN_EMERG ">>>>>> sizeof(process_kernel_entropy): %zu \n", sizeof(process_kernel_entropy));
	recorded_kernel_entropy_size = ((kernel_entropy_record_size + 1) * sizeof(process_kernel_entropy));
	printk(KERN_EMERG ">>>>>> recorded_kernel_entropy_size: %zu \n", recorded_kernel_entropy_size);
	ret_kernel_entropy_copy_to_user = copy_to_user (target_buffer, &recorded_kernel_entropy, recorded_kernel_entropy_size);
	printk(KERN_EMERG ">>>>>> ret_kernel_entropy_copy_to_user: %zu \n", ret_kernel_entropy_copy_to_user);
    spin_unlock(&entropy_analysis_lock);
	return 0;
}

asmlinkage long sys_kernel_entropy_start_recording(void)
{
	spin_lock(&entropy_analysis_lock);
	is_kernel_entropy_recording = 1;
	spin_unlock(&entropy_analysis_lock);
	return 0;
}

asmlinkage long sys_kernel_entropy_stop_recording(void)
{
	spin_lock(&entropy_analysis_lock);
	is_kernel_entropy_recording = 0;
	spin_unlock(&entropy_analysis_lock);
	return 0;
}

asmlinkage long sys_kernel_entropy_is_recording(void)
{
	spin_lock(&entropy_analysis_lock);
	return is_kernel_entropy_recording;
	spin_unlock(&entropy_analysis_lock);
}
