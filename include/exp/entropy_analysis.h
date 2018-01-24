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

// KERNEL ENTROPY EVENT TYPE
#define KEETYPE__ADD_INT_RND__FAST_POOL_COMPLETE 		0
#define KEETYPE__ADD_INT_RND__FAST_POOL_LT_64 			1
#define KEETYPE__ADD_INT_RND__SPIN_TRYLOCK 				2
#define KEETYPE__RND_INT_SECRET_INIT	 				3
#define KEETYPE__STACK_CANARY_SET		 				4
#define KEETYPE__ASLR_RND_SET			 				5

extern spinlock_t entropy_analysis_lock;

extern int print_keent_msg;

extern unsigned int kernel_entropy_rec_id;

//extern bool is_kernel_entropy_recording;

#pragma pack(1)
typedef struct
{
	   unsigned int kee_rec_id;
	   unsigned int kee_add_interrupt_rnd_id;
	   unsigned int kee_stack_canary_set_id;

}kernel_entropy_rec_info;
#pragma pack()

#pragma pack(1)
typedef struct
{
	   short event_type;
	   unsigned int id;
	   void * event_details;

}kernel_entropy_event;
#pragma pack()

#pragma pack(1)
typedef struct
{
   int irq;
   int irq_flags;
   cycles_t cycles;
   unsigned long now_jiffies;
   __u64 ip;

} kee_add_interrupt_rnd;
#pragma pack()

#pragma pack(1)
typedef struct
{
   unsigned long stack_canary;
   char comm[16]; //<----------- ACHTUNG
   pid_t pid;
} kee_stack_canary_set;
#pragma pack()



extern bool is_kernel_entropy_recording;
extern unsigned long kernel_entropy_record_size;

#define KERNEL_ENTROPY_RECORD_MAX 1000000
extern kernel_entropy_event recorded_kernel_entropy[KERNEL_ENTROPY_RECORD_MAX];

#define KE_RECORD_MAX__ADD_INT_RND 1000000
#define KE_RECORD_MAX__STACK_CANARY_SET 1000000

extern kee_add_interrupt_rnd rec_ke_add_interrupt_rnd[KE_RECORD_MAX__ADD_INT_RND];
extern kee_stack_canary_set rec_ke_stack_canary[KE_RECORD_MAX__STACK_CANARY_SET];


extern kernel_entropy_rec_info ke_rec_info;

//asmlinkage kernel_entropy_rec_info sys_kernel_entropy_rec_info(kernel_entropy_rec_info * target_buffer);
asmlinkage long sys_kernel_entropy_rec_info(kernel_entropy_rec_info * target_buffer);
asmlinkage long sys_kernel_entropy_get_recorded(kernel_entropy_event * tb_ke_event, kee_add_interrupt_rnd * tb_kee_add_int_rnd, kee_stack_canary_set * tb_kee_stc_set);
asmlinkage long sys_kernel_entropy_start_recording(void);
asmlinkage long sys_kernel_entropy_stop_recording(void);
asmlinkage long sys_kernel_entropy_is_recording(void);

kernel_entropy_event * kernel_entropy_malloc_event(short event_type);
kee_add_interrupt_rnd * kernel_entropy_malloc_interrupt(void);
kee_stack_canary_set * kernel_entropy_malloc_stack_canary(void);
void kernel_entropy_rec_interrupt(short event, int irq, int irq_flags, cycles_t cycles, unsigned long now_jiffies, __u64 ip, bool print_dmesg);
void kernel_entropy_rec_stack_canary(unsigned long stack_canary, char * comm, pid_t pid, bool print_dmesg);

//asmlinkage long sys_kernel_entropy_rec_aslr(process_kernel_entropy rec);

/*
asmlinkage long sys_kernel_entropy_get_size(void)
asmlinkage bool sys_kernel_entropy_get_recorded(process_kernel_entropy * target_buffer)
asmlinkage bool sys_kernel_entropy_start_recording(void)
asmlinkage bool sys_kernel_entropy_stop_recording(void)
asmlinkage bool sys_kernel_entropy_is_recording(void)
*/

#endif /* INCLUDE_EXP_ENTROPY_ANALYSIS_H_ */
