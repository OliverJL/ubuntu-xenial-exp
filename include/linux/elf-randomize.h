#ifndef _ELF_RANDOMIZE_H
#define _ELF_RANDOMIZE_H

struct mm_struct;

#ifndef CONFIG_ARCH_HAS_ELF_RANDOMIZE
// org: static inline unsigned long arch_mmap_rnd(void) { return 0; }
// new:
static inline unsigned long arch_mmap_rnd(int log) { return 0; }
# if defined(arch_randomize_brk) && defined(CONFIG_COMPAT_BRK)
#  define compat_brk_randomized
# endif
# ifndef arch_randomize_brk
#  define arch_randomize_brk(mm)	(mm->brk)
# endif
#else
// org: extern unsigned long arch_mmap_rnd(void);
//new:
extern unsigned long arch_mmap_rnd(int log);
extern unsigned long arch_randomize_brk(struct mm_struct *mm);
# ifdef CONFIG_COMPAT_BRK
#  define compat_brk_randomized
# endif
#endif

#endif
