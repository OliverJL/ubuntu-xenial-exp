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
#include <linux/random.h>
#include <asm/uaccess.h>

//unsigned long ret_kernel_entropy_record_size;
//unsigned long kernel_entropy_record_size = 0;

DEFINE_SPINLOCK(kernel_entropy_malloc_event_lock);

kernel_entropy_event recorded_kernel_entropy[KERNEL_ENTROPY_RECORD_MAX];
kee_add_interrupt_rnd rec_ke_add_interrupt_rnd[KE_RECORD_MAX__ADD_INT_RND];
kee_stack_canary_set rec_ke_stack_canary[KE_RECORD_MAX__STACK_CANARY_SET];
kee_get_rnd_int rec_ke_get_rnd_int[KE_RECORD_MAX__GET_RANDOM_INT];
kee_get_rnd_long rec_ke_get_rnd_long[KE_RECORD_MAX__GET_RANDOM_LONG];
kee_aslr_set rec_ke_aslr_set[KE_RECORD_MAX__ASLR_RND_SET];
kee_arch_mmap_rnd rec_ke_arch_mmap_rnd[KE_RECORD_MAX__ARCH_MMAP_RND];
kee_randomize_range rec_ke_randomize_range[KE_RECORD_MAX__RANDOMIZE_RANGE];
kee_randomize_stack_top rec_ke_randomize_stack_top[KE_RECORD_MAX__STACK_TOP];

/*
326 common	kernel_entropy_get_size	sys_kernel_entropy_get_size
327 common	kernel_entropy_get_recorded	sys_kernel_entropy_get_recorded
328 common	kernel_entropy_start_recording	sys_kernel_entropy_start_recording
329 common	kernel_entropy_stop_recording	sys_kernel_entropy_stop_recording
330 common	kernel_entropy_is_recording	sys_kernel_entropy_is_recording
331 common	kernel_entropy_set_user_tb_kee_aslr_set	sys_kernel_entropy_set_user_tb_kee_aslr_set
*/

kee_rnd_int_secret_set rec_ke_rnd_int_secret;

kernel_entropy_rec_info ke_rec_info;


asmlinkage long sys_kernel_entropy_rec_info(kernel_entropy_rec_info * target_buffer)
{
	//printk(KERN_EMERG ">>>>>> sys_kernel_entropy_rec_info kee_rec_id:%zu - kee_add_interrupt_rnd_id:%zu - kee_stack_canary_set_id:%zu!!!", ke_rec_info.kee_rec_id, ke_rec_info.kee_add_interrupt_rnd_id, ke_rec_info.kee_stack_canary_set_id);
	return copy_to_user(target_buffer, &ke_rec_info, sizeof(kernel_entropy_rec_info));
	//printk(KERN_EMERG ">>>>>> sys_kernel_entropy_rec_info - return 0");
}

unsigned long recorded_kernel_entropy_size = 0;
int ret_kernel_entropy_copy_to_user = 0;

kernel_entropy_event * kernel_entropy_malloc_event(short event_type)
{
	kernel_entropy_event * rec = NULL;

	if(ke_rec_info.kee_rec_id >= KERNEL_ENTROPY_RECORD_MAX)
	{
		is_kernel_entropy_recording = 0;
		printk(KERN_EMERG ">>>>>> KERNEL_ENTROPY_RECORD_MAX reached!!!");
	}
	else
	{
		switch(event_type)
		{
		case KEETYPE__ADD_INT_RND__FAST_POOL_COMPLETE:
		case KEETYPE__ADD_INT_RND__FAST_POOL_LT_64:
		case KEETYPE__ADD_INT_RND__SPIN_TRYLOCK:
			rec =  &recorded_kernel_entropy[ke_rec_info.kee_rec_id];
			rec->id = ke_rec_info.kee_rec_id ++;
			rec->event_type = event_type;
			rec->event_details = kernel_entropy_malloc_interrupt();
			break;
//		case KEETYPE__RND_INT_SECRET_INIT:
//			break;
		case KEETYPE__STACK_CANARY_SET:
			rec =  &recorded_kernel_entropy[ke_rec_info.kee_rec_id];
			rec->id = ke_rec_info.kee_rec_id ++;
			rec->event_type = event_type;
			rec->event_details = kernel_entropy_malloc_stack_canary();
			break;
		case KEETYPE__ASLR_RND_SET:
			rec =  &recorded_kernel_entropy[ke_rec_info.kee_rec_id];
			rec->id = ke_rec_info.kee_rec_id ++;
			rec->event_type = event_type;
			rec->event_details = kernel_entropy_malloc_aslr_set();
			break;
		case KEETYPE__RANDOM_INT_SECRET_SET:
			rec =  &recorded_kernel_entropy[ke_rec_info.kee_rec_id];
			rec->id = ke_rec_info.kee_rec_id ++;
			rec->event_type = event_type;
			rec->event_details = &rec_ke_rnd_int_secret;
			break;
		case KEETYPE__GET_RANDOM_INT:
			rec =  &recorded_kernel_entropy[ke_rec_info.kee_rec_id];
			rec->id = ke_rec_info.kee_rec_id ++;
			rec->event_type = event_type;
			rec->event_details = kernel_entropy_malloc_get_rnd_int();
			break;
		case KEETYPE__GET_RANDOM_LONG:
			rec =  &recorded_kernel_entropy[ke_rec_info.kee_rec_id];
			rec->id = ke_rec_info.kee_rec_id ++;
			rec->event_type = event_type;
			rec->event_details = kernel_entropy_malloc_get_rnd_long();
			break;
		case KEETYPE__ARCH_MMAP_RND:
			rec =  &recorded_kernel_entropy[ke_rec_info.kee_rec_id];
			rec->id = ke_rec_info.kee_rec_id ++;
			rec->event_type = event_type;
			rec->event_details = kernel_entropy_malloc_arch_mmap_rnd();
			break;
		case KEETYPE__RANDOMIZE_RANGE:
			rec =  &recorded_kernel_entropy[ke_rec_info.kee_rec_id];
			rec->id = ke_rec_info.kee_rec_id ++;
			rec->event_type = event_type;
			rec->event_details = kernel_entropy_malloc_randomize_range();
			break;
		case KEETYPE__RANDOMIZE_STACK_TOP:
			rec =  &recorded_kernel_entropy[ke_rec_info.kee_rec_id];
			rec->id = ke_rec_info.kee_rec_id ++;
			rec->event_type = event_type;
			rec->event_details = kernel_entropy_malloc_randomize_stack_top();
		break;
		}
	}
	return rec;
}

int print_rec_interrupt_max = 30;
int print_rec_interrupt_cntr = 0;
int print_rec_stack_canary_max = 100;
int print_rec_stack_canary_cntr = 0;
int print_rec_rec_get_rnd_int_cntr = 0;
int print_rec_rec_get_rnd_int_max = 300;
int print_rec_rec_get_rnd_long_cntr = 0;
int print_rec_rec_get_rnd_long_max = 300;
int print_get_recorded_max = 30;
int print_get_recorded_cntr = 0;

void kernel_entropy_rec_random_int_secret_set(u32 * random_int_secret)
{
	kernel_entropy_event * ke_event;
	kee_rnd_int_secret_set * rnd_int_secret_set;

	ke_event = kernel_entropy_malloc_event(KEETYPE__RANDOM_INT_SECRET_SET);
	if(ke_event != NULL)
	{
		rnd_int_secret_set = (kee_rnd_int_secret_set *)ke_event->event_details;
		memcpy(rnd_int_secret_set, random_int_secret, 16);
		ke_rec_info.random_int_secret_set_id = 1;
	}else{
		printk(KERN_EMERG ">>>>>> kernel_entropy_rec_random_int_secret_set - ke_event == NULL!!!");
	}
}

extern int rec_aslr_set_filename_max;
extern int rec_aslr_set_elf_interpreter_max;

void kernel_entropy_rec_aslr_set(char * filename, char * elf_interpreter, int pid, int elf_prot, int elf_flags, unsigned long load_addr, unsigned long load_bias, unsigned long entry_point, unsigned long mmap_rnd, unsigned long vaddr, unsigned long start_code, unsigned long end_code, unsigned long start_data, unsigned long end_data, unsigned long error )
//void kernel_entropy_rec_aslr_set(int pid, int elf_prot, int elf_flags, unsigned long load_addr, unsigned long load_bias, unsigned long entry_point, unsigned long mmap_rnd, unsigned long vaddr, unsigned long start_code, unsigned long end_code, unsigned long start_data, unsigned long end_data, unsigned long error )
{
	kernel_entropy_event * ke_event;
	kee_aslr_set * aslr_set;
	int len;
	ke_event = kernel_entropy_malloc_event(KEETYPE__ASLR_RND_SET);
	aslr_set = (kee_aslr_set *)ke_event->event_details;

	if(ke_event != NULL)
	{

		if(filename == NULL)
		{

			//printk(KERN_EMERG ">>>>>>>>>>>>>>> kernel_entropy_rec_aslr_set - filename: %s", filename );
			len = strlen(filename);
			//printk(KERN_EMERG ">>>>>>>>>>>>>>> kernel_entropy_rec_aslr_set - filename - len: %d", len );
			if(len > rec_aslr_set_filename_max)
			{
				rec_aslr_set_filename_max = len;
			}

			len = strlen("filename=NULL");
			strncpy(aslr_set->filename, "filename=NULL", len);
		}else
		{
			len = strlen(filename);
			strncpy(aslr_set->filename, filename, len);
		}

		if(elf_interpreter == NULL)
		{
			len = strlen(elf_interpreter);
			if(len > rec_aslr_set_elf_interpreter_max)
			{
				rec_aslr_set_elf_interpreter_max = len;
			}

			len = strlen("elf_interpreter=NULL");
			strncpy(aslr_set->elf_interpreter, "elf_interpreter=NULL", len);
		}else
		{
			len = strlen(elf_interpreter);
			strncpy(aslr_set->elf_interpreter, elf_interpreter, len);
		}

		aslr_set->pid = pid;
		aslr_set->elf_prot = elf_prot;
		aslr_set->elf_flags = elf_flags;
		aslr_set->load_addr = load_addr;
		aslr_set->load_bias = load_bias;
		aslr_set->entry_point = entry_point;
		aslr_set->mmap_rnd = mmap_rnd;
		aslr_set->vaddr = vaddr;
		aslr_set->start_code = start_code;
		aslr_set->end_code = end_code;
		aslr_set->start_data = start_data;
		aslr_set->end_data = end_data;
		aslr_set->error = error;

		//snprintf(aslr_set->info, "pid:%d - elf_prot:0x%08X - elf_flags:0x%08X - load_addr:0x%016lX - load_bias:0x%016lX - entry_point:0x%016lX - mmap_rnd:0x%016lX - vaddr:0x%016lX\n - start_code:0x%016lX - end_code:0x%016lX - start_data:0x%016lX - end_data:0x%016lX - error:%lu", pid, elf_prot, elf_flags, load_addr, load_bias, entry_point, mmap_rnd, vaddr, start_code, end_code, start_data, end_data, error);
		//printk(KERN_EMERG ">>>>>> KEETYPE__ASLR_RND_SET - kernel_entropy_rec_aslr_set - info:%s",  aslr_set->info);

	}else
	{
		printk(KERN_EMERG ">>>>>> kernel_entropy_rec_aslr_set - ke_event == NULL!!!");
	}
}

void kernel_entropy_rec_get_rnd_int(int pid, unsigned long jiffies, unsigned int rnd_raw, unsigned int rnd_final)
{
	kernel_entropy_event * ke_event;
	kee_get_rnd_int * get_rnd_int;
	ke_event = kernel_entropy_malloc_event(KEETYPE__GET_RANDOM_INT);

	if(ke_event != NULL)
	{
		get_rnd_int = (kee_get_rnd_int *)ke_event->event_details;
		get_rnd_int->pid = pid;
		get_rnd_int->jiffies = jiffies;
		get_rnd_int->rnd_raw = rnd_raw;
		get_rnd_int->rnd_final = rnd_final;
		/*
		if(print_rec_rec_get_rnd_int_cntr < print_rec_rec_get_rnd_int_max)
		{
			printk(KERN_EMERG ">>>>>>!! kernel_entropy_rec_get_rnd_int pid:%05d - jiffies:0x%016X - rnd_raw:0x%08X - rnd_final:0x%08X\n", pid, jiffies, rnd_raw, rnd_final);
			printk(KERN_EMERG ">>>>>>?? kernel_entropy_rec_get_rnd_int pid:%05d - jiffies:0x%016X - rnd_raw:0x%08X - rnd_final:0x%08X\n", get_rnd_int->pid, get_rnd_int->jiffies, get_rnd_int->rnd_raw, get_rnd_int->rnd_final);
			print_rec_rec_get_rnd_int_cntr ++;
		}
		*/
	}else
	{
		printk(KERN_EMERG ">>>>>> kernel_entropy_rec_get_rnd_int - ke_event == NULL!!!");
	}
}

void kernel_entropy_rec_arch_mmap_rnd(bool mmap_is_ia32, unsigned long get_random_int_value, unsigned long get_random_int_value_after_828_shift, unsigned long get_random_int_value_after_page_align)
{
	kernel_entropy_event * ke_event;
	kee_arch_mmap_rnd * arch_mmap_rnd;

	ke_event = kernel_entropy_malloc_event(KEETYPE__ARCH_MMAP_RND);

	if(ke_event != NULL)
	{
		arch_mmap_rnd = (kee_arch_mmap_rnd *)ke_event->event_details;
		arch_mmap_rnd->mmap_is_ia32 = mmap_is_ia32;
		arch_mmap_rnd->get_random_int_value = get_random_int_value;
		arch_mmap_rnd->get_random_int_value_after_828_shift = get_random_int_value_after_828_shift;
		arch_mmap_rnd->get_random_int_value_after_page_align = get_random_int_value_after_page_align;
		/*
		if(print_rec_rec_get_rnd_int_cntr < print_rec_rec_get_rnd_int_max)
		{
			printk(KERN_EMERG ">>>>>>!! kernel_entropy_rec_get_rnd_int pid:%05d - jiffies:0x%016X - rnd_raw:0x%08X - rnd_final:0x%08X\n", pid, jiffies, rnd_raw, rnd_final);
			printk(KERN_EMERG ">>>>>>?? kernel_entropy_rec_get_rnd_int pid:%05d - jiffies:0x%016X - rnd_raw:0x%08X - rnd_final:0x%08X\n", get_rnd_int->pid, get_rnd_int->jiffies, get_rnd_int->rnd_raw, get_rnd_int->rnd_final);
			print_rec_rec_get_rnd_int_cntr ++;
		}
		*/
	}else
	{
		printk(KERN_EMERG ">>>>>> kernel_entropy_rec_arch_mmap_rnd - ke_event == NULL!!!");
	}
}

void kernel_entropy_rec_randomize_range(unsigned int random_int_raw, unsigned long start, unsigned long end, unsigned long len, unsigned long add_range_start, unsigned long mod_rnd_add_range_start, unsigned long range_aligned)
{
	kernel_entropy_event * ke_event;
	kee_randomize_range * randomize_range;

	ke_event = kernel_entropy_malloc_event(KEETYPE__RANDOMIZE_RANGE);

	if(ke_event != NULL)
	{
		randomize_range = (kee_randomize_range *)ke_event->event_details;
		randomize_range->random_int_raw = random_int_raw;
		randomize_range->start = start;
		randomize_range->end = end;
		randomize_range->len = len;
		randomize_range->add_range_start = add_range_start;
		randomize_range->mod_rnd_add_range_start = mod_rnd_add_range_start;
		randomize_range->range_aligned = range_aligned;
	}else
	{
		printk(KERN_EMERG ">>>>>> kernel_entropy_rec_randomize_range - ke_event == NULL!!!");
	}
}

void kernel_entropy_rec_get_rnd_long(int pid, unsigned long jiffies, unsigned long rnd_raw, unsigned long rnd_final)
{
	kernel_entropy_event * ke_event;
	kee_get_rnd_long * get_rnd_long;

	ke_event = kernel_entropy_malloc_event(KEETYPE__GET_RANDOM_LONG);

	if(ke_event != NULL)
	{
		get_rnd_long = (kee_get_rnd_long *)ke_event->event_details;
		get_rnd_long->pid = pid;
		get_rnd_long->jiffies = jiffies;
		get_rnd_long->rnd_raw = rnd_raw;
		get_rnd_long->rnd_final = rnd_final;
		/*
		if(print_rec_rec_get_rnd_long_cntr < print_rec_rec_get_rnd_long_max)
		{
			printk(KERN_EMERG ">>>>>>!! kernel_entropy_rec_get_rnd_long pid:%05d - jiffies:0x%016X - rnd_raw:0x%016X - rnd_final:0x%016X\n", pid, jiffies, rnd_raw, rnd_final);
			printk(KERN_EMERG ">>>>>>?? kernel_entropy_rec_get_rnd_long pid:%05d - jiffies:0x%016X - rnd_raw:0x%016X - rnd_final:0x%016X\n", get_rnd_long->pid, get_rnd_long->jiffies, get_rnd_long->rnd_raw, get_rnd_long->rnd_final);
			print_rec_rec_get_rnd_long_cntr ++;
		}
		*/
	}else
	{
		printk(KERN_EMERG ">>>>>> kernel_entropy_rec_get_rnd_long - ke_event == NULL!!!");
	}
}


void kernel_entropy_rec_interrupt(short event, int irq, int irq_flags, cycles_t cycles, unsigned long now_jiffies, __u64 ip, short time_after_exceeded, unsigned char fast_pool_count, unsigned int c_high, unsigned  int j_high, bool print_dmesg)
{
	kernel_entropy_event * ke_event;
	kee_add_interrupt_rnd * int_rnd_event;

	ke_event = kernel_entropy_malloc_event(event);

	if(ke_event != NULL)
	{
		int_rnd_event = (kee_add_interrupt_rnd *)ke_event->event_details;
		int_rnd_event->irq = irq;
		int_rnd_event->irq_flags = irq_flags;
		int_rnd_event->cycles = cycles;
		int_rnd_event->now_jiffies = now_jiffies;
		int_rnd_event->ip = ip;
		int_rnd_event->fast_pool_count = fast_pool_count;
		int_rnd_event->time_after_exceeded = time_after_exceeded;
		int_rnd_event->c_high = c_high;
		int_rnd_event->j_high = j_high;
		/*
		if(print_rec_interrupt_cntr < print_rec_interrupt_max)
		{
			printk(KERN_EMERG ">>>>>> kernel_entropy_rec_interrupt [%d] irq: 0x%08X - irq_flags: 0x%08X - cycles: 0x%08X - now: 0x%08X - ip: 0x%016X \n", print_rec_interrupt_cntr, irq, irq_flags, cycles, now_jiffies, ip);
			printk(KERN_EMERG ">>>>>> kernel_entropy_rec_interrupt [%d] irq: 0x%08X - irq_flags: 0x%08X - cycles: 0x%08X - now: 0x%08X - ip: 0x%016X \n", print_rec_interrupt_cntr, int_rnd_event->irq, int_rnd_event->irq_flags, int_rnd_event->cycles, int_rnd_event->now_jiffies, int_rnd_event->ip);
			print_rec_interrupt_cntr ++;
		}
		*/
	}else
	{
		printk(KERN_EMERG ">>>>>> kernel_entropy_rec_interrupt - ke_event == NULL!!!");
	}
}

void kernel_entropy_rec_stack_canary(unsigned long stack_canary, char * comm, pid_t pid, bool print_dmesg)
{
	//kernel_entropy_malloc_stack_canary

	kernel_entropy_event * ke_event;
	kee_stack_canary_set * stc_set_event;
	int task_exe_name_len;

	ke_event = kernel_entropy_malloc_event(KEETYPE__STACK_CANARY_SET);

	if(ke_event != NULL)
	{
		stc_set_event = (kee_stack_canary_set *)ke_event->event_details;
		stc_set_event->stack_canary = stack_canary;
		task_exe_name_len = strlen(comm);
		strncpy(stc_set_event->comm, comm, task_exe_name_len);
		stc_set_event->pid = pid;
		//printk(KERN_EMERG ">>>>>> kernel_entropy_rec_stack_canary - %s", stc_set_event->comm);
	}else
	{
		printk(KERN_EMERG ">>>>>> kernel_entropy_rec_stack_canary - ke_event == NULL!!!");
	}
}

void kernel_entropy_rec_randomize_stack_top(unsigned int random_int_raw, unsigned long stack_top, unsigned long stack_rnd_mask, unsigned int page_shift, unsigned int  random_int_and_stack_mask, unsigned int random_int_and_stack_mask_shifted, unsigned long stack_top_aligned, unsigned long final_ret)
{
	kernel_entropy_event * ke_event;
	kee_randomize_stack_top * rnd_stack_top;
	ke_event = kernel_entropy_malloc_event(KEETYPE__RANDOMIZE_STACK_TOP);

	if(ke_event != NULL)
	{
		rnd_stack_top = (kee_randomize_stack_top *)ke_event->event_details;
		rnd_stack_top->random_int_raw = random_int_raw;
		rnd_stack_top->stack_top = stack_top;
		rnd_stack_top->stack_rnd_mask = stack_rnd_mask;
		rnd_stack_top->page_shift = page_shift;
		rnd_stack_top->random_int_and_stack_mask = random_int_and_stack_mask;
		rnd_stack_top->random_int_and_stack_mask_shifted = random_int_and_stack_mask_shifted;
		rnd_stack_top->stack_top_aligned = stack_top_aligned;
		rnd_stack_top->final_ret = final_ret;
	}else
	{
		printk(KERN_EMERG ">>>>>> kernel_entropy_rec_randomize_stack_top - ke_event == NULL!!!");
	}
}

kee_get_rnd_int * kernel_entropy_malloc_get_rnd_int(void)
{
	kee_get_rnd_int * rec = NULL;
	if(ke_rec_info.kee_get_random_int_id >= KE_RECORD_MAX__GET_RANDOM_INT)
	{
		is_kernel_entropy_recording = 0;
		printk(KERN_EMERG ">>>>>> KE_RECORD_MAX__GET_RANDOM_INT reached!!!");
	}
	else
	{
		rec = &rec_ke_get_rnd_int[ke_rec_info.kee_get_random_int_id++];
	}
	return rec;
}

kee_get_rnd_long * kernel_entropy_malloc_get_rnd_long(void)
{
	kee_get_rnd_long * rec = NULL;
	if(ke_rec_info.kee_get_random_long_id >= KE_RECORD_MAX__GET_RANDOM_LONG)
	{
		is_kernel_entropy_recording = 0;
		printk(KERN_EMERG ">>>>>> KE_RECORD_MAX__GET_RANDOM_LONG reached!!!");
	}
	else
	{
		rec = &rec_ke_get_rnd_long[ke_rec_info.kee_get_random_long_id++];
	}
	return rec;
}

kee_aslr_set * kernel_entropy_malloc_aslr_set(void)
{
	kee_aslr_set * rec = NULL;
	if(ke_rec_info.kee_aslr_set_id >= KE_RECORD_MAX__ASLR_RND_SET)
	{
		is_kernel_entropy_recording = 0;
		printk(KERN_EMERG ">>>>>> KE_RECORD_MAX__ASLR_SET reached!!!");
	}
	else
	{
		rec = &rec_ke_aslr_set[ke_rec_info.kee_aslr_set_id++];
	}
	return rec;
}

kee_add_interrupt_rnd * kernel_entropy_malloc_interrupt(void)
{
	kee_add_interrupt_rnd * rec = NULL;
	if(ke_rec_info.kee_add_interrupt_rnd_id >= KE_RECORD_MAX__ADD_INT_RND)
	{
		is_kernel_entropy_recording = 0;
		printk(KERN_EMERG ">>>>>> KE_RECORD_MAX__ADD_INT_RND reached!!!");
	}
	else
	{
		rec = &rec_ke_add_interrupt_rnd[ke_rec_info.kee_add_interrupt_rnd_id++];
	}
	return rec;
}


kee_stack_canary_set * kernel_entropy_malloc_stack_canary(void)
{
	kee_stack_canary_set * rec = NULL;
	if(ke_rec_info.kee_stack_canary_set_id >= KE_RECORD_MAX__STACK_CANARY_SET)
	{
		is_kernel_entropy_recording = 0;
		printk(KERN_EMERG ">>>>>> KE_RECORD_MAX__STACK_CANARY_SET reached!!!");
	}
	else
	{
		rec = &rec_ke_stack_canary[ke_rec_info.kee_stack_canary_set_id++];
	}
	return rec;
}

kee_arch_mmap_rnd * kernel_entropy_malloc_arch_mmap_rnd(void)
{
	kee_arch_mmap_rnd * rec = NULL;
	if(ke_rec_info.kee_arch_mmap_rnd_id >= KE_RECORD_MAX__ARCH_MMAP_RND)
	{
		is_kernel_entropy_recording = 0;
		printk(KERN_EMERG ">>>>>> KE_RECORD_MAX__ARCH_MMAP_RND reached!!!");
	}
	else
	{
		rec = &rec_ke_arch_mmap_rnd[ke_rec_info.kee_arch_mmap_rnd_id++];
	}
	return rec;
}

kee_randomize_range * kernel_entropy_malloc_randomize_range(void)
{
	kee_randomize_range * rec = NULL;
	if(ke_rec_info.kee_randomize_range_id >= KE_RECORD_MAX__RANDOMIZE_RANGE)
	{
		is_kernel_entropy_recording = 0;
		printk(KERN_EMERG ">>>>>> KE_RECORD_MAX__RANDOMIZE_RANGE reached!!!");
	}
	else
	{
		rec = &rec_ke_randomize_range[ke_rec_info.kee_randomize_range_id++];
	}
	return rec;
}

kee_randomize_stack_top * kernel_entropy_malloc_randomize_stack_top(void)
{
	kee_randomize_stack_top * rec = NULL;
	if(ke_rec_info.kee_randomize_stack_top_id >= KE_RECORD_MAX__STACK_TOP)
	{
		is_kernel_entropy_recording = 0;
		printk(KERN_EMERG ">>>>>> KE_RECORD_MAX__STACK_TOP reached!!!");
	}
	else
	{
		rec = &rec_ke_randomize_stack_top[ke_rec_info.kee_randomize_stack_top_id++];
	}
	return rec;
}

kee_aslr_set * tb_user_kee_aslr_set;
kee_arch_mmap_rnd * tb_user_kee_arch_mmap_rnd;
kee_randomize_range * tb_user_kee_randomize_range;
kee_randomize_stack_top * tb_user_kee_randomize_stack_top;

asmlinkage long sys_kernel_entropy_set_user_tb_kee_randomize_stack_top(kee_randomize_stack_top * tb_kee_randomize_stack_top)
{
  tb_user_kee_randomize_stack_top = tb_kee_randomize_stack_top;
}

asmlinkage long sys_kernel_entropy_set_user_tb_kee_aslr_set(kee_aslr_set * tb_kee_aslr_set)
{
	tb_user_kee_aslr_set = tb_kee_aslr_set;
	return 0;
}

asmlinkage long sys_kernel_entropy_set_user_tb_kee_arch_mmap_rnd(kee_arch_mmap_rnd * tb_kee_arch_mmap_rnd)
{
	tb_user_kee_arch_mmap_rnd = tb_kee_arch_mmap_rnd;
	return 0;
}

asmlinkage long sys_kernel_entropy_set_user_tb_kee_randomize_range(kee_randomize_range * tb_kee_randomize_range)
{
	tb_user_kee_randomize_range = tb_kee_randomize_range;
	return 0;
}

asmlinkage long sys_kernel_entropy_get_recorded(kernel_entropy_event * tb_ke_event, kee_add_interrupt_rnd * tb_kee_add_int_rnd, kee_stack_canary_set * tb_kee_stc_set, kee_rnd_int_secret_set * tb_kee_rnd_int_secret_set, kee_get_rnd_int * tb_kee_get_rnd_int, kee_get_rnd_long * tb_kee_get_rnd_long, kee_aslr_set * tb_kee_aslr_set)
{
	int kee_rec_cntr = 0;
	int kee_add_int_rnd_cntr = 0;
	int tb_kee_stc_set_cntr = 0;
	int tb_kee_get_rnd_int_cntr = 0;
	int tb_kee_get_rnd_long_cntr = 0;
	int tb_kee_arch_mmap_rnd_cntr = 0;
	int tb_kee_aslr_set_cntr = 0;
	int tb_kee_randomize_range_cntr = 0;
	int tb_kee_randomize_stack_top_cntr = 0;
	int cpy_ret = 0;
	int access_ok = 0;

	kernel_entropy_event * ke_event;
	kernel_entropy_event * tb_kee;
	//kee_add_interrupt_rnd * trg_add_int_rnd_event;
	//kee_add_interrupt_rnd * kee_add_int_rnd;

	while(kee_rec_cntr < ke_rec_info.kee_rec_id )
	{
		ke_event = &recorded_kernel_entropy[kee_rec_cntr];
		tb_kee = &tb_ke_event[kee_rec_cntr];
		//printk(KERN_EMERG ">>>>>> sys_kernel_entropy_get_recorded ke_event->id:%d - ke_event->event_type:%d - ke_event->detail_index:%d - tb_kee:0x%08X\n", ke_event->id, ke_event->event_type, ke_event->detail_index, tb_kee);
		//copy_to_user(&tb_ke_event[kee_rec_cntr], &ke_event, sizeof(kernel_entropy_event));
		//copy_to_user(tb_kee, ke_event, sizeof(kernel_entropy_event));
		//
		switch(ke_event->event_type)
		{
			case KEETYPE__ADD_INT_RND__FAST_POOL_COMPLETE:
			case KEETYPE__ADD_INT_RND__FAST_POOL_LT_64:
			case KEETYPE__ADD_INT_RND__SPIN_TRYLOCK:
				ke_event->detail_index = kee_add_int_rnd_cntr;
				copy_to_user(tb_kee, ke_event, sizeof(kernel_entropy_event));
				copy_to_user(&tb_kee_add_int_rnd[kee_add_int_rnd_cntr], &rec_ke_add_interrupt_rnd[kee_add_int_rnd_cntr], sizeof(kee_add_interrupt_rnd));
				kee_add_int_rnd_cntr ++;
				break;
			case KEETYPE__STACK_CANARY_SET:
				ke_event->detail_index = tb_kee_stc_set_cntr;
				copy_to_user(tb_kee, ke_event, sizeof(kernel_entropy_event));
				cpy_ret = copy_to_user(&tb_kee_stc_set[tb_kee_stc_set_cntr], &rec_ke_stack_canary[tb_kee_stc_set_cntr], sizeof(kee_stack_canary_set));
				//printk(KERN_EMERG ">>>>>> KEETYPE__STACK_CANARY_SET pid:%05d - stack_canary:0x%016lX - comm:%s - cpy_ret:%d\n", rec_ke_stack_canary[tb_kee_stc_set_cntr].pid, rec_ke_stack_canary[tb_kee_stc_set_cntr].stack_canary, rec_ke_stack_canary[tb_kee_stc_set_cntr].comm, cpy_ret);
				//access_ok = access_ok(VERIFY_WRITE, &tb_kee_aslr_set[tb_kee_aslr_set_cntr], sizeof(kee_stack_canary_set));
				//printk(KERN_EMERG ">>>>>> KEETYPE__STACK_CANARY_SET access_ok:%d", access_ok);
				tb_kee_stc_set_cntr ++;
				break;
			case KEETYPE__ASLR_RND_SET:
				ke_event->detail_index = tb_kee_aslr_set_cntr;
				copy_to_user(tb_kee, ke_event, sizeof(kernel_entropy_event));
				//copy_to_user(&tb_kee_aslr_set[tb_kee_aslr_set_cntr], &rec_ke_aslr_set[tb_kee_aslr_set_cntr], sizeof(kee_aslr_set));
				cpy_ret = copy_to_user(&tb_user_kee_aslr_set[tb_kee_aslr_set_cntr], &rec_ke_aslr_set[tb_kee_aslr_set_cntr], sizeof(kee_aslr_set));
				//printk(KERN_EMERG ">>>>>> KEETYPE__ASLR_RND_SET pid:%d - elf_prot:0x%08X - elf_flags:0x%08X - load_addr:0x%016lX - load_bias:0x%016lX - entry_point:0x%016lX - mmap_rnd:0x%016lX - vaddr:0x%016lX\n - start_code:0x%016lX - end_code:0x%016lX - start_data:0x%016lX - end_data:0x%016lX - error:%lu - cpy_ret:%d", rec_ke_aslr_set[tb_kee_aslr_set_cntr].pid, rec_ke_aslr_set[tb_kee_aslr_set_cntr].elf_prot, rec_ke_aslr_set[tb_kee_aslr_set_cntr].elf_flags, rec_ke_aslr_set[tb_kee_aslr_set_cntr].load_addr, rec_ke_aslr_set[tb_kee_aslr_set_cntr].load_bias, rec_ke_aslr_set[tb_kee_aslr_set_cntr].entry_point, rec_ke_aslr_set[tb_kee_aslr_set_cntr].mmap_rnd, rec_ke_aslr_set[tb_kee_aslr_set_cntr].vaddr, rec_ke_aslr_set[tb_kee_aslr_set_cntr].start_code, rec_ke_aslr_set[tb_kee_aslr_set_cntr].end_code, rec_ke_aslr_set[tb_kee_aslr_set_cntr].start_data, rec_ke_aslr_set[tb_kee_aslr_set_cntr].end_data, rec_ke_aslr_set[tb_kee_aslr_set_cntr].error, cpy_ret);
				//printk(KERN_EMERG ">>>>>> KEETYPE__ASLR_RND_SET - cpy_ret:%d", cpy_ret);
				//access_ok = access_ok(VERIFY_WRITE, &tb_user_kee_aslr_set[tb_kee_aslr_set_cntr], sizeof(kee_aslr_set));
				//printk(KERN_EMERG ">>>>>> KEETYPE__ASLR_RND_SET addr:0x%08X - pid:%d - cpy_ret:%d - access_ok:%d", &tb_kee_aslr_set[tb_kee_aslr_set_cntr], rec_ke_aslr_set[tb_kee_aslr_set_cntr].pid, cpy_ret, access_ok);
				tb_kee_aslr_set_cntr ++;
				break;
			case KEETYPE__RANDOM_INT_SECRET_SET:
				copy_to_user(tb_kee, ke_event, sizeof(kernel_entropy_event));
				copy_to_user(tb_kee_rnd_int_secret_set, &rec_ke_rnd_int_secret, sizeof(kee_rnd_int_secret_set));
				break;
			case KEETYPE__GET_RANDOM_INT:
				ke_event->detail_index = tb_kee_get_rnd_int_cntr;
				copy_to_user(tb_kee, ke_event, sizeof(kernel_entropy_event));
				copy_to_user(&tb_kee_get_rnd_int[tb_kee_get_rnd_int_cntr], &rec_ke_get_rnd_int[tb_kee_get_rnd_int_cntr], sizeof(kee_get_rnd_int));
				tb_kee_get_rnd_int_cntr ++;
				break;
			case KEETYPE__GET_RANDOM_LONG:
				ke_event->detail_index = tb_kee_get_rnd_long_cntr;
				copy_to_user(tb_kee, ke_event, sizeof(kernel_entropy_event));
				copy_to_user(&tb_kee_get_rnd_long[tb_kee_get_rnd_long_cntr], &rec_ke_get_rnd_long[tb_kee_get_rnd_long_cntr], sizeof(kee_get_rnd_long));
				tb_kee_get_rnd_long_cntr ++;
				break;
			case KEETYPE__ARCH_MMAP_RND:
				ke_event->detail_index = tb_kee_arch_mmap_rnd_cntr;
				copy_to_user(tb_kee, ke_event, sizeof(kernel_entropy_event));
				copy_to_user(&tb_user_kee_arch_mmap_rnd[tb_kee_arch_mmap_rnd_cntr], &rec_ke_arch_mmap_rnd[tb_kee_arch_mmap_rnd_cntr], sizeof(kee_arch_mmap_rnd));
				tb_kee_arch_mmap_rnd_cntr ++;
				break;
			case KEETYPE__RANDOMIZE_RANGE:
				ke_event->detail_index = tb_kee_arch_mmap_rnd_cntr;
				copy_to_user(tb_kee, ke_event, sizeof(kernel_entropy_event));
				copy_to_user(&tb_user_kee_randomize_range[tb_kee_randomize_range_cntr], &rec_ke_randomize_range[tb_kee_randomize_range_cntr], sizeof(kee_randomize_range));
				tb_kee_randomize_range_cntr ++;
				break;
			case KEETYPE__RANDOMIZE_STACK_TOP:
				ke_event->detail_index = tb_kee_randomize_stack_top_cntr;
				copy_to_user(tb_kee, ke_event, sizeof(kernel_entropy_event));
				copy_to_user(&tb_user_kee_randomize_stack_top[tb_kee_randomize_stack_top_cntr], &rec_ke_randomize_stack_top[tb_kee_randomize_stack_top_cntr], sizeof(kee_randomize_stack_top));
				tb_kee_randomize_stack_top_cntr ++;
				break;
		}
		//printk(KERN_EMERG ">>>>>> KEETYPE__ADD_INT_RND__ kee_rec_cntr++");
		//printk(KERN_EMERG ">>>>>> sys_kernel_entropy_get_recorded ke_event->id:%d - ke_event->event_type:%d - ke_event->detail_index:%d - tb_kee:0x%08X - rc:%d\n", ke_event->id, ke_event->event_type, ke_event->detail_index, tb_kee, rc);
		kee_rec_cntr ++;
	}
	printk(KERN_EMERG ">>>>>> sys_kernel_entropy_get_recorded - done!");
	return 0;
}


asmlinkage long sys_kernel_entropy_start_recording(void)
{
	//spin_lock(&entropy_analysis_lock);
	is_kernel_entropy_recording = 1;
	//spin_unlock(&entropy_analysis_lock);
	return 0;
}

asmlinkage long sys_kernel_entropy_stop_recording(void)
{
	//spin_lock(&entropy_analysis_lock);
	is_kernel_entropy_recording = 0;
	//spin_unlock(&entropy_analysis_lock);
	return 0;
}

asmlinkage long sys_kernel_entropy_is_recording(void)
{
	//spin_lock(&entropy_analysis_lock);
	return is_kernel_entropy_recording;
	//spin_unlock(&entropy_analysis_lock);
}
