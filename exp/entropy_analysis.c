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

//unsigned long ret_kernel_entropy_record_size;
//unsigned long kernel_entropy_record_size = 0;

DEFINE_SPINLOCK(kernel_entropy_malloc_event_lock);

kernel_entropy_event recorded_kernel_entropy[KERNEL_ENTROPY_RECORD_MAX];
kee_add_interrupt_rnd rec_ke_add_interrupt_rnd[KE_RECORD_MAX__ADD_INT_RND];
kee_stack_canary_set rec_ke_stack_canary[KE_RECORD_MAX__STACK_CANARY_SET];
kee_get_rnd_int rec_ke_get_rnd_int[KE_RECORD_MAX__GET_RANDOM_INT];
kee_get_rnd_long rec_ke_get_rnd_long[KE_RECORD_MAX__GET_RANDOM_LONG];


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
		//kernel_entropy_event * rec;
		/*
		rec =  &recorded_kernel_entropy[ke_rec_info.kee_rec_id];
		rec->id = ke_rec_info.kee_rec_id ++;
		rec->event_type = event_type;
		*/

		//printk(KERN_EMERG ">>>>>> kernel_entropy_malloc_event rec->id:%zu - rec->event_type:%zu", rec->id, rec->event_type);

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
		}
	}
	return rec;
}

int print_rec_interrupt_max = 30;
int print_rec_interrupt_cntr = 0;
int print_rec_stack_canary_max = 100;
int print_rec_stack_canary_cntr = 0;

void kernel_entropy_rec_random_int_secret_set(u32 * random_int_secret)
{
	kernel_entropy_event * ke_event;
	kee_rnd_int_secret_set * rnd_int_secret_set;

	ke_event = kernel_entropy_malloc_event(KEETYPE__RANDOM_INT_SECRET_SET);
	if(ke_event != NULL)
	{
		rnd_int_secret_set = (kee_rnd_int_secret_set *)ke_event->event_details;
		memcpy(rnd_int_secret_set, random_int_secret, 16);
		ke_rec_info.random_int_secret_set = 1;
	}else{
		printk(KERN_EMERG ">>>>>> kernel_entropy_rec_random_int_secret_set - ke_event == NULL!!!");
	}
}


void kernel_entropy_rec_get_rnd_int(int pid, unsigned long jiffies, unsigned int rnd_raw, unsigned int rnd_final)
{
	kernel_entropy_event * ke_event;
	kee_get_rnd_int * get_rnd_int;
	ke_event = kernel_entropy_malloc_event(KEETYPE__GET_RANDOM_INT);

	if(ke_event != NULL)
	{
		//spin_lock(&kernel_entropy_malloc_event_lock);
		get_rnd_int = (kee_get_rnd_int *)ke_event->event_details;
		get_rnd_int->pid = pid;
		get_rnd_int->jiffies = jiffies;
		get_rnd_int->rnd_raw = rnd_raw;
		get_rnd_int->rnd_final = rnd_final;
		//spin_unlock(&kernel_entropy_malloc_event_lock);
		printk(KERN_EMERG ">>>>>>!! kernel_entropy_rec_get_rnd_long pid:%05d - jiffies:0x%016X - rnd_raw:0x%016X - rnd_final:0x%016X\n", pid, jiffies, rnd_raw, rnd_final);
		printk(KERN_EMERG ">>>>>>?? kernel_entropy_rec_get_rnd_long pid:%05d - jiffies:0x%016X - rnd_raw:0x%08X - rnd_final:0x%08X\n", get_rnd_int->pid, get_rnd_int->jiffies, get_rnd_int->rnd_raw, get_rnd_int->rnd_final);
	}else
	{
		printk(KERN_EMERG ">>>>>> kernel_entropy_rec_get_rnd_int - ke_event == NULL!!!");
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

		printk(KERN_EMERG ">>>>>>!! kernel_entropy_rec_get_rnd_long pid:%05d - jiffies:0x%016X - rnd_raw:0x%016X - rnd_final:0x%016X\n", pid, jiffies, rnd_raw, rnd_final);
		printk(KERN_EMERG ">>>>>>?? kernel_entropy_rec_get_rnd_long pid:%05d - jiffies:0x%016X - rnd_raw:0x%016X - rnd_final:0x%016X\n", get_rnd_long->pid, get_rnd_long->jiffies, get_rnd_long->rnd_raw, get_rnd_long->rnd_final);
	}else
	{
		printk(KERN_EMERG ">>>>>> kernel_entropy_rec_get_rnd_long - ke_event == NULL!!!");
	}
}


void kernel_entropy_rec_interrupt(short event, int irq, int irq_flags, cycles_t cycles, unsigned long now_jiffies, __u64 ip, bool print_dmesg)
{

	kernel_entropy_event * ke_event;
	kee_add_interrupt_rnd * int_rnd_event;

	ke_event = kernel_entropy_malloc_event(event);

	if(ke_event != NULL)
	{
		//printk(KERN_EMERG ">>>>>> kernel_entropy_rec_interrupt - ke_event->event_details: 0x%08X", ke_event->event_details);
		int_rnd_event = (kee_add_interrupt_rnd *)ke_event->event_details;
		int_rnd_event->irq = irq;
		int_rnd_event->irq_flags = irq_flags;
		int_rnd_event->cycles = cycles;
		int_rnd_event->now_jiffies = now_jiffies;
		int_rnd_event->ip = ip;

		if(print_rec_interrupt_cntr < print_rec_interrupt_max)
		{
			printk(KERN_EMERG ">>>>>> kernel_entropy_rec_interrupt [%d] irq: 0x%08X - irq_flags: 0x%08X - cycles: 0x%08X - now: 0x%08X - ip: 0x%016X \n", print_rec_interrupt_cntr, irq, irq_flags, cycles, now_jiffies, ip);
			printk(KERN_EMERG ">>>>>> kernel_entropy_rec_interrupt [%d] irq: 0x%08X - irq_flags: 0x%08X - cycles: 0x%08X - now: 0x%08X - ip: 0x%016X \n", print_rec_interrupt_cntr, int_rnd_event->irq, int_rnd_event->irq_flags, int_rnd_event->cycles, int_rnd_event->now_jiffies, int_rnd_event->ip);
			print_rec_interrupt_cntr ++;
		}

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

kee_get_rnd_int * kernel_entropy_malloc_get_rnd_int(void)
{
	kee_get_rnd_int * rec = NULL;
	if(ke_rec_info.kee_get_random_int >= KE_RECORD_MAX__GET_RANDOM_INT)
	{
		is_kernel_entropy_recording = 0;
		printk(KERN_EMERG ">>>>>> KE_RECORD_MAX__GET_RANDOM_INT reached!!!");
	}
	else
	{
		rec = &rec_ke_get_rnd_int[ke_rec_info.kee_get_random_int++];
	}
	return rec;
}

kee_get_rnd_long * kernel_entropy_malloc_get_rnd_long(void)
{
	kee_get_rnd_long * rec = NULL;
	if(ke_rec_info.kee_get_random_long >= KE_RECORD_MAX__GET_RANDOM_LONG)
	{
		is_kernel_entropy_recording = 0;
		printk(KERN_EMERG ">>>>>> KEETYPE__GET_RANDOM_LONG reached!!!");
	}
	else
	{
		rec = &rec_ke_get_rnd_long[ke_rec_info.kee_get_random_long++];
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

/*
void kernel_entropy_rec_stack_canary(unsigned long stack_canary, char comm[16], pid_t pid, bool print_dmesg)
{
// if(is_kernel_entropy_recording)

 // STACK_CANARY_SET
	/*
		task_exe_name_len = strlen(tsk->comm);
		strncpy(current_ke_record->comm, tsk->comm, task_exe_name_len);
	 * /
	// printk(KERN_EMERG ">>>>>> dup_task_struct - kernel_entropy_record_size: %zu - %d - %lx - %s\n", kernel_entropy_record_size, current_ke_record->pid, current_ke_record->stack_canary, current_ke_record->comm);
}
 */


int print_get_recorded_max = 30;
int print_get_recorded_cntr = 0;

//asmlinkage long sys_kernel_entropy_get_recorded(kernel_entropy_event * tb_ke_event, kee_add_interrupt_rnd * tb_kee_add_int_rnd, kee_stack_canary_set * tb_kee_stc_set)
asmlinkage long sys_kernel_entropy_get_recorded(kernel_entropy_event * tb_ke_event, kee_add_interrupt_rnd * tb_kee_add_int_rnd, kee_stack_canary_set * tb_kee_stc_set, kee_rnd_int_secret_set * tb_kee_rnd_int_secret_set, kee_get_rnd_int * tb_kee_get_rnd_int, kee_get_rnd_long * tb_kee_get_rnd_long)
//asmlinkage long sys_kernel_entropy_get_recorded(kernel_entropy_event * tb_ke_event)
{
	int kee_rec_cntr = 0;
	int kee_add_int_rnd_cntr = 0;
	int tb_kee_stc_set_cntr = 0;
	int tb_kee_get_rnd_int_cntr = 0;
	int tb_kee_get_rnd_long_cntr = 0;

	kernel_entropy_event * ke_event;
	kernel_entropy_event * tb_kee;
	kee_add_interrupt_rnd * trg_add_int_rnd_event;
	kee_add_interrupt_rnd * kee_add_int_rnd;

	while(kee_rec_cntr < ke_rec_info.kee_rec_id )
	{
		ke_event = &recorded_kernel_entropy[kee_rec_cntr];
		tb_kee = &tb_ke_event[kee_rec_cntr];
		//printk(KERN_EMERG ">>>>>> sys_kernel_entropy_get_recorded ke_event->id:%zu - ke_event->event_type:%zu", ke_event->id, ke_event->event_type);
		//copy_to_user(&tb_ke_event[kee_rec_cntr], &ke_event, sizeof(kernel_entropy_event));
		//copy_to_user(tb_kee, ke_event, sizeof(kernel_entropy_event));

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
				copy_to_user(&tb_kee_stc_set[tb_kee_stc_set_cntr], &rec_ke_stack_canary[tb_kee_stc_set_cntr], sizeof(kee_stack_canary_set));
				tb_kee_stc_set_cntr ++;
				break;
			case KEETYPE__ASLR_RND_SET:
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
		}
		//printk(KERN_EMERG ">>>>>> KEETYPE__ADD_INT_RND__ kee_rec_cntr++");
		kee_rec_cntr ++;
	}
	return 0;
}

/***********
asmlinkage long sys_kernel_entropy_get_recorded(kernel_entropy_event * tb_ke_event, kee_add_interrupt_rnd * tb_kee_add_int_rnd, kee_stack_canary_set * tb_kee_stc_set)
//asmlinkage long sys_kernel_entropy_get_recorded(kernel_entropy_event * tb_ke_event)
{
	int kee_rec_cntr = 0;
	int kee_add_int_rnd_cntr = 0;
	//int tb_kee_stc_set_cntr = 0;
	kernel_entropy_event * ke_event;
	kernel_entropy_event * tb_kee;
	kee_add_interrupt_rnd * trg_add_int_rnd_event;

	if(tb_ke_event == NULL)
		return -1;
	if(tb_kee_add_int_rnd == NULL)
		return -2;
	if(tb_kee_stc_set == NULL)
		return -3;

	while(kee_rec_cntr < ke_rec_info.kee_rec_id )
	{
		ke_event = &recorded_kernel_entropy[kee_rec_cntr];
		tb_kee = &tb_ke_event[kee_rec_cntr];
		//printk(KERN_EMERG ">>>>>> sys_kernel_entropy_get_recorded ke_event->id:%zu - ke_event->event_type:%zu", ke_event->id, ke_event->event_type);
		//copy_to_user(&tb_ke_event[kee_rec_cntr], &ke_event, sizeof(kernel_entropy_event));

		switch(ke_event->event_type)
		{
			case KEETYPE__ADD_INT_RND__FAST_POOL_COMPLETE:
			case KEETYPE__ADD_INT_RND__FAST_POOL_LT_64:
			case KEETYPE__ADD_INT_RND__SPIN_TRYLOCK:
				//printk(KERN_EMERG ">>>>>> KEETYPE__ADD_INT_RND__ kee_add_int_rnd_cntr:%d", kee_add_int_rnd_cntr);
				printk(KERN_EMERG ">>>>>> KEETYPE__ADD_INT_RND ke_event->detail_index = kee_add_int_rnd_cntr;");
				ke_event->detail_index = kee_add_int_rnd_cntr;
				printk(KERN_EMERG ">>>>>> KEETYPE__ADD_INT_RND copy_to_user");
				//copy_to_user(&tb_ke_event[kee_rec_cntr], ke_event, sizeof(kernel_entropy_event));
				copy_to_user(tb_kee, ke_event, sizeof(kernel_entropy_event));
				printk(KERN_EMERG ">>>>>> KEETYPE__ADD_INT_RND tb_ke_event[kee_rec_cntr]->id:%d, ke_event->id:%d", tb_ke_event[kee_rec_cntr].id, ke_event->id);
				printk(KERN_EMERG ">>>>>> KEETYPE__ADD_INT_RND tb_ke_event[kee_rec_cntr]->event_type:%d, ke_event->event_type:%d", tb_ke_event[kee_rec_cntr].event_type, ke_event->event_type);
				printk(KERN_EMERG ">>>>>> KEETYPE__ADD_INT_RND__ ????????");
				copy_to_user(&tb_kee_add_int_rnd[kee_add_int_rnd_cntr], &ke_event->event_details, sizeof(kee_add_interrupt_rnd));
				//copy_to_user(&tb_kee->event_details, &ke_event->event_details, sizeof(kee_add_interrupt_rnd));
				//printk(KERN_EMERG ">>>>>> KEETYPE__ADD_INT_RND__ !!!!!!!!");
				//printk(KERN_EMERG ">>>>>> KEETYPE__ADD_INT_RND__ &tb_kee_add_int_rnd[kee_add_int_rnd_cntr]: 0x%08X", &tb_kee_add_int_rnd[kee_add_int_rnd_cntr]);
				//printk(KERN_EMERG ">>>>>> KEETYPE__ADD_INT_RND__ tb_kee: 0x%08X", tb_kee);
				//printk(KERN_EMERG ">>>>>> KEETYPE__ADD_INT_RND__ &tb_kee: 0x%08X", &tb_kee);
/*
			[614644.261435] >>>>>> KEETYPE__ADD_INT_RND__ ????????
			[614644.261987] >>>>>> KEETYPE__ADD_INT_RND__ !!!!!!!!
			[614644.261996] >>>>>> KEETYPE__ADD_INT_RND__ &tb_kee_add_int_rnd[kee_add_int_rnd_cntr]: 0x00602100
			[614644.262562] >>>>>> KEETYPE__ADD_INT_RND__ tb_kee: 0x006020E0
			[614644.263180] >>>>>> KEETYPE__ADD_INT_RND__ &tb_kee: 0x9601BF10
			[614644.263758] >>>>>> KEETYPE__ADD_INT_RND__ trg_add_int_rnd_event:  0x00602100
			[614644.264380] >>>>>> KEETYPE__ADD_INT_RND__ &tb_kee->event_details: 0x006020E6
			[614644.264959] BUG: unable to handle kernel paging request at 00000000006020e6
			[614644.266094] IP: [<ffffffff813fb428>] sys_kernel_entropy_get_recorded+0x1a8/0x1d0
			[614644.266675] PGD 95abf067 PUD 376a0067 PMD 97a88067 PTE 8000000093ab0867

				//trg_add_int_rnd_event = &tb_kee_add_int_rnd[kee_add_int_rnd_cntr];
				//printk(KERN_EMERG ">>>>>> KEETYPE__ADD_INT_RND__ trg_add_int_rnd_event: 0x%08X", trg_add_int_rnd_event);
				//tb_kee->event_details = &tb_kee_add_int_rnd[kee_add_int_rnd_cntr];
				//printk(KERN_EMERG ">>>>>> KEETYPE__ADD_INT_RND__ &tb_kee->event_details: 0x%08X", &tb_kee->event_details);
				//printk(KERN_EMERG ">>>>>> KEETYPE__ADD_INT_RND__ tb_kee->event_details = trg_add_int_rnd_event");
				//tb_kee->detail_index = kee_add_int_rnd_cntr;
				//tb_kee->event_details = trg_add_int_rnd_event;
				//printk(KERN_EMERG ">>>>>> KEETYPE__ADD_INT_RND__ tb_kee->event_details: 0x%08X", tb_kee->event_details);
				//printk(KERN_EMERG ">>>>>> KEETYPE__ADD_INT_RND__ $$$$$$$$");
				//tb_kee->detail_index = kee_add_int_rnd_cntr;
				printk(KERN_EMERG ">>>>>> kee_add_int_rnd_cntr ++");
				kee_add_int_rnd_cntr ++;
				break;
			case KEETYPE__RND_INT_SECRET_INIT:
				break;
			case KEETYPE__STACK_CANARY_SET:

				break;
			case KEETYPE__ASLR_RND_SET:
				break;
		}
		//printk(KERN_EMERG ">>>>>> KEETYPE__ADD_INT_RND__ kee_rec_cntr++");
		kee_rec_cntr ++;
	}
	return 0;
}
***/

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
