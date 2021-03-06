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
#define KEETYPE__RANDOM_INT_SECRET_SET					6
#define KEETYPE__GET_RANDOM_INT							7
#define KEETYPE__GET_RANDOM_LONG						8
#define KEETYPE__ARCH_MMAP_RND							9
#define KEETYPE__RANDOMIZE_RANGE						10
#define KEETYPE__RANDOMIZE_STACK_TOP					11

extern spinlock_t entropy_analysis_lock;
extern spinlock_t kernel_entropy_malloc_event_lock;

extern int print_keent_msg;

extern unsigned int kernel_entropy_rec_id;

//extern bool is_kernel_entropy_recording;
// -------------------------->
#pragma pack(1)
typedef struct
{
	   unsigned int kee_rec_id;
	   unsigned int kee_add_interrupt_rnd_id;
	   unsigned int kee_stack_canary_set_id;
	   bool random_int_secret_set_id;
	   unsigned int kee_get_random_int_id;
	   unsigned int kee_get_random_long_id;
	   unsigned int kee_aslr_set_id;
	   unsigned int kee_arch_mmap_rnd_id;
	   unsigned int kee_randomize_range_id;
	   unsigned int kee_randomize_stack_top_id;
}kernel_entropy_rec_info;
#pragma pack()

#pragma pack(1)
typedef struct
{
	   short event_type;
	   unsigned int id;
	   int detail_index;
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
   short time_after_exceeded;
   unsigned char fast_pool_count;
   unsigned int c_high;
   unsigned  int j_high;

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


#pragma pack(1)
typedef struct
{
   int pid;
   char filename[100];
   char elf_interpreter[100];
   int elf_prot;
   int elf_flags;
   unsigned long load_addr;
   unsigned long load_bias;
   unsigned long entry_point;
   unsigned long mmap_rnd;
   unsigned long vaddr;
   unsigned long start_code;
   unsigned long end_code;
   unsigned long start_data;
   unsigned long end_data;
   unsigned long error;
} kee_aslr_set;
#pragma pack()

#pragma pack(1)
typedef struct
{
	unsigned int random_int_secret[16];
} kee_rnd_int_secret_set;
#pragma pack()

#pragma pack(1)
typedef struct
{
  unsigned long jiffies;
  int pid;
  unsigned int rnd_raw;
  unsigned int rnd_final;
} kee_get_rnd_int;
#pragma pack()

#pragma pack(1)
typedef struct
{
  unsigned long jiffies;
  int pid;
  unsigned long rnd_raw;
  unsigned long rnd_final;
} kee_get_rnd_long;
#pragma pack()

#pragma pack(1)
typedef struct
{
  bool mmap_is_ia32;
  unsigned long get_random_int_value;
  unsigned long get_random_int_value_after_828_shift;
  unsigned long get_random_int_value_after_page_align;
} kee_arch_mmap_rnd;
#pragma pack()

#pragma pack(1)
typedef struct
{
  unsigned int  random_int_raw;
  unsigned long start;
  unsigned long end;
  unsigned long len;
  unsigned long add_range_start;
  unsigned long mod_rnd_add_range_start;
  unsigned long range_aligned;
} kee_randomize_range;
#pragma pack()

#pragma pack(1)
typedef struct
{
  unsigned int  random_int_raw;
  unsigned long stack_top;
  unsigned long stack_rnd_mask;
  unsigned int  page_shift;
  unsigned int  random_int_and_stack_mask;
  unsigned int  random_int_and_stack_mask_shifted;
  unsigned long stack_top_aligned;
  unsigned long final_ret;
} kee_randomize_stack_top;
#pragma pack()

#pragma pack(1)
typedef struct
{
	 kee_add_interrupt_rnd * tb_kee_add_int_rnd;
	 kee_stack_canary_set * tb_kee_stc_set;
	 kee_rnd_int_secret_set * tb_kee_rnd_int_secret_set;
	 kee_get_rnd_int * tb_kee_get_rnd_int;
	 kee_get_rnd_long * tb_kee_get_rnd_long;
	 kee_aslr_set * tb_kee_aslr_set;
}kernel_entropy_event_details;
#pragma pack()
// --------------------------<

extern bool is_kernel_entropy_recording;
extern unsigned long kernel_entropy_record_size;

#define KERNEL_ENTROPY_RECORD_MAX 100000
#define KE_RECORD_MAX__ADD_INT_RND 40000
#define KE_RECORD_MAX__STACK_CANARY_SET 60000
#define KE_RECORD_MAX__GET_RANDOM_INT 60000
#define KE_RECORD_MAX__GET_RANDOM_LONG 60000
#define KE_RECORD_MAX__ASLR_RND_SET 60000
#define KE_RECORD_MAX__ARCH_MMAP_RND 60000
#define KE_RECORD_MAX__RANDOMIZE_RANGE 60000
#define KE_RECORD_MAX__STACK_TOP 60000

/*
#define KERNEL_ENTROPY_RECORD_MAX 20000
#define KE_RECORD_MAX__ADD_INT_RND 10000
#define KE_RECORD_MAX__STACK_CANARY_SET 3000
#define KE_RECORD_MAX__GET_RANDOM_INT 10000
#define KE_RECORD_MAX__GET_RANDOM_LONG 3000
#define KE_RECORD_MAX__ASLR_SET 3000
*/
extern kernel_entropy_event recorded_kernel_entropy[KERNEL_ENTROPY_RECORD_MAX];

extern kee_add_interrupt_rnd rec_ke_add_interrupt_rnd[KE_RECORD_MAX__ADD_INT_RND];
extern kee_stack_canary_set rec_ke_stack_canary[KE_RECORD_MAX__STACK_CANARY_SET];
extern kee_get_rnd_int rec_ke_get_rnd_int[KE_RECORD_MAX__GET_RANDOM_INT];
extern kee_get_rnd_long rec_ke_get_rnd_long[KE_RECORD_MAX__GET_RANDOM_LONG];
extern kee_aslr_set rec_ke_aslr_set[KE_RECORD_MAX__ASLR_RND_SET];
extern kee_arch_mmap_rnd rec_ke_arch_mmap_rnd[KE_RECORD_MAX__ARCH_MMAP_RND];
extern kee_randomize_range rec_ke_randomize_range[KE_RECORD_MAX__RANDOMIZE_RANGE];

extern kernel_entropy_rec_info ke_rec_info;

asmlinkage long sys_kernel_entropy_rec_info(kernel_entropy_rec_info * target_buffer);
asmlinkage long sys_kernel_entropy_get_recorded(kernel_entropy_event * tb_ke_event, kee_add_interrupt_rnd * tb_kee_add_int_rnd, kee_stack_canary_set * tb_kee_stc_set, kee_rnd_int_secret_set * tb_kee_rnd_int_secret_set, kee_get_rnd_int * tb_kee_get_rnd_int, kee_get_rnd_long * tb_kee_get_rnd_long, kee_aslr_set * tb_kee_aslr_set);

asmlinkage long sys_kernel_entropy_set_user_tb_kee_aslr_set(kee_aslr_set * tb_kee_aslr_set);
asmlinkage long sys_kernel_entropy_set_user_tb_kee_arch_mmap_rnd(kee_arch_mmap_rnd * tb_kee_arch_mmap_rnd);
asmlinkage long sys_kernel_entropy_set_user_tb_kee_randomize_range(kee_randomize_range * tb_kee_randomize_range);
asmlinkage long sys_kernel_entropy_set_user_tb_kee_randomize_stack_top(kee_randomize_stack_top * tb_kee_randomize_stack_top);

asmlinkage long sys_kernel_entropy_start_recording(void);
asmlinkage long sys_kernel_entropy_stop_recording(void);
asmlinkage long sys_kernel_entropy_is_recording(void);


kernel_entropy_event * kernel_entropy_malloc_event(short event_type);
kee_add_interrupt_rnd * kernel_entropy_malloc_interrupt(void);
kee_stack_canary_set * kernel_entropy_malloc_stack_canary(void);
kee_get_rnd_int * kernel_entropy_malloc_get_rnd_int(void);
kee_arch_mmap_rnd * kernel_entropy_malloc_arch_mmap_rnd(void);
kee_randomize_range * kernel_entropy_malloc_randomize_range(void);
kee_randomize_stack_top * kernel_entropy_malloc_randomize_stack_top(void);

kee_get_rnd_long * kernel_entropy_malloc_get_rnd_long(void);
kee_aslr_set * kernel_entropy_malloc_aslr_set(void);
//void kernel_entropy_rec_interrupt(short event, int irq, int irq_flags, cycles_t cycles, unsigned long now_jiffies, __u64 ip, bool print_dmesg);
void kernel_entropy_rec_interrupt(short event, int irq, int irq_flags, cycles_t cycles, unsigned long now_jiffies, __u64 ip, short time_after_exceeded, unsigned char fast_pool_count, unsigned int c_high, unsigned  int j_high, bool print_dmesg);
void kernel_entropy_rec_stack_canary(unsigned long stack_canary, char * comm, pid_t pid, bool print_dmesg);
void kernel_entropy_rec_random_int_secret_set(u32 * random_int_secret);
void kernel_entropy_rec_get_rnd_int(int pid, unsigned long jiffies, unsigned int rnd_raw, unsigned int rnd_final);
void kernel_entropy_rec_get_rnd_long(int pid, unsigned long jiffies, unsigned long rnd_raw, unsigned long rnd_final);
void kernel_entropy_rec_arch_mmap_rnd(bool mmap_is_ia32, unsigned long get_random_int_value, unsigned long get_random_int_value_after_828_shift, unsigned long get_random_int_value_after_page_align);
void kernel_entropy_rec_randomize_range(unsigned int random_int_raw, unsigned long start, unsigned long end, unsigned long len, unsigned long add_range_start, unsigned long mod_rnd_add_range_start, unsigned long range_aligned);
void kernel_entropy_rec_randomize_stack_top(unsigned int random_int_raw, unsigned long stack_top, unsigned long stack_rnd_mask, unsigned int page_shift, unsigned int  random_int_and_stack_mask, unsigned int random_int_and_stack_mask_shifted, unsigned long stack_top_aligned, unsigned long final_ret);
//void kernel_entropy_rec_aslr_set(const char * filename, char * elf_interpreter, int elf_prot, int elf_flags, unsigned long load_addr, unsigned long load_bias, unsigned long entry_point, unsigned long mmap_rnd, unsigned long vaddr );
//void kernel_entropy_rec_aslr_set(const char * filename, char * elf_interpreter, int elf_prot, int elf_flags, unsigned long load_addr, unsigned long load_bias, unsigned long entry_point, unsigned long mmap_rnd, unsigned long vaddr, unsigned long start_code, unsigned long end_code, unsigned long start_data, unsigned long end_data );

//void kernel_entropy_rec_aslr_set(int pid, int elf_prot, int elf_flags, unsigned long load_addr, unsigned long load_bias, unsigned long entry_point, unsigned long mmap_rnd, unsigned long vaddr, unsigned long start_code, unsigned long end_code, unsigned long start_data, unsigned long end_data, unsigned long error );
void kernel_entropy_rec_aslr_set(char * filename, char * elf_interpreter, int pid, int elf_prot, int elf_flags, unsigned long load_addr, unsigned long load_bias, unsigned long entry_point, unsigned long mmap_rnd, unsigned long vaddr, unsigned long start_code, unsigned long end_code, unsigned long start_data, unsigned long end_data, unsigned long error );

//void kernel_entropy_rec_aslr_set(char * filename, char * elf_interpreter, int elf_prot, int elf_flags, unsigned long load_addr, unsigned long load_bias, unsigned long entry_point, unsigned long mmap_rnd, unsigned long vaddr, unsigned long start_code, unsigned long end_code, unsigned long start_data, unsigned long end_data, unsigned long error );
//ke_rec_info
//asmlinkage long sys_kernel_entropy_rec_aslr(process_kernel_entropy rec);
//
/*
asmlinkage long sys_kernel_entropy_get_size(void)
asmlinkage bool sys_kernel_entropy_get_recorded(process_kernel_entropy * target_buffer)
asmlinkage bool sys_kernel_entropy_start_recording(void)
asmlinkage bool sys_kernel_entropy_stop_recording(void)
asmlinkage bool sys_kernel_entropy_is_recording(void)
*/

#endif /* INCLUDE_EXP_ENTROPY_ANALYSIS_H_ */
