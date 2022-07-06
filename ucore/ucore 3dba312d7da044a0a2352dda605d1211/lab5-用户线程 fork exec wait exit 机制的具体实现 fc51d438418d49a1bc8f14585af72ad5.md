# lab5-用户线程|fork/exec/wait/exit
机制的具体实现

在 `idt_init` 中对系统调用SYSCALL初始化在IDT里；设置中断请求中CLOCK中断次数，如果时间片用完需要重新调度进程；

![Untitled](lab5-%E7%94%A8%E6%88%B7%E7%BA%BF%E7%A8%8B%20fork%20exec%20wait%20exit%20%E6%9C%BA%E5%88%B6%E7%9A%84%E5%85%B7%E4%BD%93%E5%AE%9E%E7%8E%B0%20fc51d438418d49a1bc8f14585af72ad5/Untitled.png)

- 结构体
    
    ![Untitled](lab5-%E7%94%A8%E6%88%B7%E7%BA%BF%E7%A8%8B%20fork%20exec%20wait%20exit%20%E6%9C%BA%E5%88%B6%E7%9A%84%E5%85%B7%E4%BD%93%E5%AE%9E%E7%8E%B0%20fc51d438418d49a1bc8f14585af72ad5/Untitled%201.png)
    
    ；
    
    ![Untitled](lab5-%E7%94%A8%E6%88%B7%E7%BA%BF%E7%A8%8B%20fork%20exec%20wait%20exit%20%E6%9C%BA%E5%88%B6%E7%9A%84%E5%85%B7%E4%BD%93%E5%AE%9E%E7%8E%B0%20fc51d438418d49a1bc8f14585af72ad5/Untitled%202.png)
    
    ；vmm都是虚拟空间的操作,pmm是物理页
    
    ![Untitled](lab5-%E7%94%A8%E6%88%B7%E7%BA%BF%E7%A8%8B%20fork%20exec%20wait%20exit%20%E6%9C%BA%E5%88%B6%E7%9A%84%E5%85%B7%E4%BD%93%E5%AE%9E%E7%8E%B0%20fc51d438418d49a1bc8f14585af72ad5/Untitled%203.png)
    
    ELF头部描述整个elf文件信息
    
    ![Untitled](lab5-%E7%94%A8%E6%88%B7%E7%BA%BF%E7%A8%8B%20fork%20exec%20wait%20exit%20%E6%9C%BA%E5%88%B6%E7%9A%84%E5%85%B7%E4%BD%93%E5%AE%9E%E7%8E%B0%20fc51d438418d49a1bc8f14585af72ad5/Untitled%204.png)
    
    程序头表是结构体数组，每个数组元素是段表头/ph/描述一个段
    
- **练习1-加载内存程序进入进程空间** do_execve
    
    创建一片虚拟内存（kmalloc vma），创建PDT新建一块物理页表设置页表项对应la插入PDT获取该页表项虚拟地址，获取程序头计算段地址，用memcpy将TEXT/DATA段起始地址填入页表，建立BSS段，构建栈内存，设置当前进程的mm/cr3/sr3，为用户环境设置trapframe。
    
- ****练习2-父进程复制自己的内存空间给子进程（进程A复制到进程B）****
    
    找到进程A和进程B的PDT的va，创建一个物理页给进程B，memcpy拷贝A的上下文给B并建立段映射到线性地址，然后插入到对应的PDT中
    
- ****练习3-fork/exec/wait/exit/syscall 的实现****
    - do_fork：创建当前内核线程的一个副本
        - 它们的执行上下文、代码、数据都一样，但是存储位置不同，在这个过程中，需要给新内核线程分配资源，并且复制原进程的状态（已经实现）
    - do_execve：可执行程序的加载和运行
        - 检查当前进程所分配的内存区域是否存在异常
        - 回收当前进程的所有资源，包括已分配的内存空间/页目录表等等
        - 读取可执行文件，并根据 `ELFheader` 分配特定位置的虚拟内存，并加载代码与数据至特定的内存地址，最后分配堆栈并设置 `trapframe` 属性
        - 设置新进程名称
        - 真正核心且复杂的 load_icode
    - do_wait：程序会使某个进程一直等待，直到（特定）子进程退出后，该进程才会回收该子进程的资源并函数返回，该函数的具体操作如下：
        - 检查当前进程所分配的内存区域是否存在异常
        - 查找特定/所有子进程中是否存在某个等待父进程回收的子进程（PROC_ZOMBIE）
            - 如果有，则回收该进程并函数返回
            - 如果没有，则设置当前进程状态为 `PROC_SLEEPING` 并执行 `schedule` 调度其他进程
            - 当该进程的某个子进程结束运行后，当前进程会被唤醒，并在 `do_wait` 函数中回收子进程的**PCB内存**资源
    - do_exit：退出操作
        - 回收所有内存（除了PCB，该结构只能由父进程回收）
        - 设置当前的进程状态为 `PROC_ZOMBIE`
        - 设置当前进程的退出值 `current->exit_code`
        - 如果有父进程，则唤醒父进程，使其准备回收该进程的PCB
            - 正常情况下，除了 `initproc` 和 `idleproc` 以外，其他进程一定存在父进程
        - 如果当前进程存在子进程，则设置所有子进程的父进程为 `initproc`
            - 这样倘若这些子进程进入结束状态，则 `initproc` 可以代为回收资源
        - 执行进程调度，一旦调度到当前进程的父进程，则可以马上回收该终止进程的 `PCB`
        - code:do_exit
            
            ```c
            int
            do_exit(int error_code) {
                if (current == idleproc) {
                    panic("idleproc exit.\n");
                }
                if (current == initproc) {
                    panic("initproc exit.\n");
                }
                
                struct mm_struct *mm = current->mm;
                
                //如果是用户进程则释放占用用户空间
                if (mm != NULL) {
                    //设置页目录表为内核线程的页目录表 防止cr3为空
                    lcr3(boot_cr3);
                    if (mm_count_dec(mm) == 0) {
                        exit_mmap(mm);
                        put_pgdir(mm);
                        mm_destroy(mm);
                    }
                    current->mm = NULL;
                }
             
                //设置为僵尸进程
                current->state = PROC_ZOMBIE;
                current->exit_code = error_code;
                
                bool intr_flag;
                struct proc_struct *proc;
             
                //原语不可中断 关中断
                local_intr_save(intr_flag);
                {
                    proc = current->parent;
                    
                    //如果父进程等待子进程终结则唤醒父进程
                    if (proc->wait_state == WT_CHILD) {
                        wakeup_proc(proc);
                    }
             
                    //遍历当前进程的子进程 通过optr链接的兄弟进程链表
                    while (current->cptr != NULL) {
                        proc = current->cptr;
                        //cptr指向下一个子进程
                        current->cptr = proc->optr;
                
                        proc->yptr = NULL;
                        //将当前子进程的父进程设置为init
                        if ((proc->optr = initproc->cptr) != NULL) {
                            initproc->cptr->yptr = proc;
                        }
                        proc->parent = initproc;
                        initproc->cptr = proc;
                        
                        //检查当前子进程是否能唤醒init
                        if (proc->state == PROC_ZOMBIE) {
                            if (initproc->wait_state == WT_CHILD) {
                                wakeup_proc(initproc);
                            }
                        }
                    }
                }
                local_intr_restore(intr_flag);
                
                //转进程调度 等待僵尸进程current的父进程回收资源
                schedule();
                panic("do_exit will not return!! %d.\n", current->pid);
            }
            ```
            
        
        ![Untitled](lab5-%E7%94%A8%E6%88%B7%E7%BA%BF%E7%A8%8B%20fork%20exec%20wait%20exit%20%E6%9C%BA%E5%88%B6%E7%9A%84%E5%85%B7%E4%BD%93%E5%AE%9E%E7%8E%B0%20fc51d438418d49a1bc8f14585af72ad5/Untitled%205.png)
        
        - syscall：系统调用
            - syscall 是内核程序为用户程序提供内核服务的一种方式
            - 在用户程序中，若需用到内核服务，则需要执行 `sys_xxxx` 函数（例如`sys_kill`）
            - `sys_xxxx` 函数会设置 `%eax, %edx, %ecx, %ebx, %edi, %esi` 五个寄存器的值
            - 分别为 syscall调用号、参数1、参数2、参数3、参数4、参数5
            - 然后执行int中断进入中断处理例程
            - 在中断处理例程中：程序会根据中断号执行 syscall 函数
            

```c
#include <proc.h>
#include <kmalloc.h>
#include <string.h>
#include <sync.h>
#include <pmm.h>
#include <error.h>
#include <sched.h>
#include <elf.h>
#include <vmm.h>
#include <trap.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>

// the process set's list
list_entry_t proc_list;

#define HASH_SHIFT          10
#define HASH_LIST_SIZE      (1 << HASH_SHIFT)
#define pid_hashfn(x)       (hash32(x, HASH_SHIFT))

// has list for process set based on pid
static list_entry_t hash_list[HASH_LIST_SIZE];

// idle proc
struct proc_struct *idleproc = NULL;
// init proc
struct proc_struct *initproc = NULL;
// current proc
struct proc_struct *current = NULL;

static int nr_process = 0;

void kernel_thread_entry(void);
void forkrets(struct trapframe *tf);
void switch_to(struct context *from, struct context *to);

// alloc_proc - alloc a proc_struct and init all fields of proc_struct
static struct proc_struct *
alloc_proc(void) {
    struct proc_struct *proc = kmalloc(sizeof(struct proc_struct));
    if (proc != NULL) {
    //LAB4:EXERCISE1 YOUR CODE
    /*
     * below fields in proc_struct need to be initialized
     *       enum proc_state state;                      // Process state
     *       int pid;                                    // Process ID
     *       int runs;                                   // the running times of Proces
     *       uintptr_t kstack;                           // Process kernel stack
     *       volatile bool need_resched;                 // bool value: need to be rescheduled to release CPU?
     *       struct proc_struct *parent;                 // the parent process
     *       struct mm_struct *mm;                       // Process's memory management field
     *       struct context context;                     // Switch here to run process
     *       struct trapframe *tf;                       // Trap frame for current interrupt
     *       uintptr_t cr3;                              // CR3 register: the base addr of Page Directroy Table(PDT)
     *       uint32_t flags;                             // Process flag
     *       char name[PROC_NAME_LEN + 1];               // Process name
     */
     //LAB5 YOUR CODE : (update LAB4 steps)
    /*
     * below fields(add in LAB5) in proc_struct need to be initialized	
     *       uint32_t wait_state;                        // waiting state
     *       struct proc_struct *cptr, *yptr, *optr;     // relations between processes
	 */

        proc->state = PROC_UNINIT;
        proc->pid = -1;
        proc->runs = 0;
        proc->kstack = 0;
        proc->need_resched = 0;
        proc->parent = NULL;
        proc->mm = NULL;
        memset(&(proc->context), 0, sizeof(struct context));
        proc->tf = NULL;
        proc->cr3 = boot_cr3;
        proc->flags = 0;
        memset(proc->name, 0, PROC_NAME_LEN);
        proc->wait_state = 0; /* lab5新增:设置进程为等待态 */
        proc->cptr = proc->optr = proc->yptr = NULL; /* lab5新增:进程的兄弟父母节点为空 */
    }
    return proc;
}

// set_links - set the relation links of process, set_links就是在list_add的基础上,对部分proc_struct条目进行了初始化
static void
set_links(struct proc_struct *proc) {
    list_add(&proc_list, &(proc->list_link));
    proc->yptr = NULL;/* 后续对进程结构体proc_struct进行设置 */
    if ((proc->optr = proc->parent->cptr) != NULL) {
        proc->optr->yptr = proc;    //链入子进程链表???
    }
    proc->parent->cptr = proc;
    nr_process ++;
}

// kernel_thread - create a kernel thread using "fn" function
// NOTE: the contents of temp trapframe tf will be copied to 
//       proc->tf in do_fork-->copy_thread function
int
kernel_thread(int (*fn)(void *), void *arg, uint32_t clone_flags) {
    struct trapframe tf;
    memset(&tf, 0, sizeof(struct trapframe));
    tf.tf_cs = KERNEL_CS;
    tf.tf_ds = tf.tf_es = tf.tf_ss = KERNEL_DS;
    tf.tf_regs.reg_ebx = (uint32_t)fn;
    tf.tf_regs.reg_edx = (uint32_t)arg;
    tf.tf_eip = (uint32_t)kernel_thread_entry;
    return do_fork(clone_flags | CLONE_VM, 0, &tf);
}

// setup_kstack - alloc pages with size KSTACKPAGE as process kernel stack
static int
setup_kstack(struct proc_struct *proc) {
    struct Page *page = alloc_pages(KSTACKPAGE);
    if (page != NULL) {
        proc->kstack = (uintptr_t)page2kva(page);
        return 0;
    }
    return -E_NO_MEM;
}

// put_kstack - free the memory space of process kernel stack
static void
put_kstack(struct proc_struct *proc) {
    free_pages(kva2page((void *)(proc->kstack)), KSTACKPAGE);
}

// setup_pgdir - alloc one page as PDT
static int
setup_pgdir(struct mm_struct *mm) {
    struct Page *page;
    if ((page = alloc_page()) == NULL) {  /* 分配物理页,作为页目录表 */
        return -E_NO_MEM;
    }
    pde_t *pgdir = page2kva(page); /* 获取页目录表的虚拟地址 */
    memcpy(pgdir, boot_pgdir, PGSIZE); /* 把boot_pgdir拷贝到pgdir(这里两边都是虚拟地址,C语言的'&'符号用于获取虚拟地址) */
    pgdir[PDX(VPT)] = PADDR(pgdir) | PTE_P | PTE_W;/* PADDR转为物理地址后装入对应的页目录表项 */
    mm->pgdir = pgdir;/* 更新mm_struct结构体中的pgdir条目 */
    return 0;
}

// put_pgdir - free the memory space of PDT
static void
put_pgdir(struct mm_struct *mm) {
    free_page(kva2page(mm->pgdir));
}

// copy_mm - process "proc" duplicate OR share process "current"'s mm according clone_flags
//         - if clone_flags & CLONE_VM, then "share" ; else "duplicate"
static int
copy_mm(uint32_t clone_flags, struct proc_struct *proc) {
    struct mm_struct *mm, *oldmm = current->mm;

    /* current is a kernel thread */
    if (oldmm == NULL) {
        return 0;
    }
    if (clone_flags & CLONE_VM) {
        mm = oldmm;
        goto good_mm;
    }

    int ret = -E_NO_MEM;
    if ((mm = mm_create()) == NULL) {
        goto bad_mm;
    }
    if (setup_pgdir(mm) != 0) {
        goto bad_pgdir_cleanup_mm;
    }

    lock_mm(oldmm);
    {
        ret = dup_mmap(mm, oldmm);
    }
    unlock_mm(oldmm);

    if (ret != 0) {
        goto bad_dup_cleanup_mmap;
    }

good_mm:
    mm_count_inc(mm);
    proc->mm = mm;
    proc->cr3 = PADDR(mm->pgdir);
    return 0;
bad_dup_cleanup_mmap:
    exit_mmap(mm);
    put_pgdir(mm);
bad_pgdir_cleanup_mm:
    mm_destroy(mm);
bad_mm:
    return ret;
}

// copy_thread - setup the trapframe on the  process's kernel stack top and
//             - setup the kernel entry point and stack of process
static void
copy_thread(struct proc_struct *proc, uintptr_t esp, struct trapframe *tf) {
    proc->tf = (struct trapframe *)(proc->kstack + KSTACKSIZE) - 1;
    *(proc->tf) = *tf;
    proc->tf->tf_regs.reg_eax = 0;
    proc->tf->tf_esp = esp;
    proc->tf->tf_eflags |= FL_IF;

    proc->context.eip = (uintptr_t)forkret;
    proc->context.esp = (uintptr_t)(proc->tf);
}

/* do_fork -     parent process for a new child process
 * @clone_flags: used to guide how to clone the child process
 * @stack:       the parent's user stack pointer. if stack==0, It means to fork a kernel thread.
 * @tf:          the trapframe info, which will be copied to child process's proc->tf
 */
int
do_fork(uint32_t clone_flags, uintptr_t stack, struct trapframe *tf) {
    int ret = -E_NO_FREE_PROC;
    struct proc_struct *proc;
    if (nr_process >= MAX_PROCESS) {
        goto fork_out;
    }
    ret = -E_NO_MEM;
    //LAB4:EXERCISE2 YOUR CODE
    /*
     * Some Useful MACROs, Functions and DEFINEs, you can use them in below implementation.
     * MACROs or Functions:
     *   alloc_proc:   create a proc struct and init fields (lab4:exercise1)
     *   setup_kstack: alloc pages with size KSTACKPAGE as process kernel stack
     *   copy_mm:      process "proc" duplicate OR share process "current"'s mm according clone_flags
     *                 if clone_flags & CLONE_VM, then "share" ; else "duplicate"
     *   copy_thread:  setup the trapframe on the  process's kernel stack top and
     *                 setup the kernel entry point and stack of process
     *   hash_proc:    add proc into proc hash_list
     *   get_pid:      alloc a unique pid for process
     *   wakup_proc:   set proc->state = PROC_RUNNABLE
     * VARIABLES:
     *   proc_list:    the process set's list
     *   nr_process:   the number of process set
     */

    //    1. call alloc_proc to allocate a proc_struct
    //    2. call setup_kstack to allocate a kernel stack for child process
    //    3. call copy_mm to dup OR share mm according clone_flag
    //    4. call copy_thread to setup tf & context in proc_struct
    //    5. insert proc_struct into hash_list && proc_list
    //    6. call wakup_proc to make the new child process RUNNABLE
    //    7. set ret vaule using child proc's pid

	//LAB5 YOUR CODE : (update LAB4 steps)
   /* Some Functions
    *    set_links:  set the relation links of process.  ALSO SEE: remove_links:  lean the relation links of process 
    *    -------------------
	*    update step 1: set child proc's parent to current process, make sure current process's wait_state is 0
	*    update step 5: insert proc_struct into hash_list && proc_list, set the relation links of process
    */
	
fork_out:
    return ret;

bad_fork_cleanup_kstack:
    put_kstack(proc);
bad_fork_cleanup_proc:
    kfree(proc);
    goto fork_out;
}

// do_exit - called by sys_exit
//   1. call exit_mmap & put_pgdir & mm_destroy to free the almost all memory space of process
//   2. set process' state as PROC_ZOMBIE, then call wakeup_proc(parent) to ask parent reclaim itself.
//   3. call scheduler to switch to other process
int
do_exit(int error_code) {
    if (current == idleproc) {
        panic("idleproc exit.\n");
    }
    if (current == initproc) {
        panic("initproc exit.\n");
    }
    
    struct mm_struct *mm = current->mm;
    if (mm != NULL) {
        lcr3(boot_cr3);
        if (mm_count_dec(mm) == 0) {
            exit_mmap(mm);
            put_pgdir(mm);
            mm_destroy(mm);
        }
        current->mm = NULL;
    }
    current->state = PROC_ZOMBIE;
    current->exit_code = error_code;
    
    bool intr_flag;
    struct proc_struct *proc;
    local_intr_save(intr_flag);
    {
        proc = current->parent;
        if (proc->wait_state == WT_CHILD) {
            wakeup_proc(proc);
        }
        while (current->cptr != NULL) {
            proc = current->cptr;
            current->cptr = proc->optr;
    
            proc->yptr = NULL;
            if ((proc->optr = initproc->cptr) != NULL) {
                initproc->cptr->yptr = proc;
            }
            proc->parent = initproc;
            initproc->cptr = proc;
            if (proc->state == PROC_ZOMBIE) {
                if (initproc->wait_state == WT_CHILD) {
                    wakeup_proc(initproc);
                }
            }
        }
    }
    local_intr_restore(intr_flag);
    
    schedule();
    panic("do_exit will not return!! %d.\n", current->pid);
}

/* load_icode - load the content of binary program(ELF format) as the new content of current process加载并解析一个处于内存中的ELF执行文件格式的应用程序
    用来将执行程序加载到进程空间（执行程序本身已从磁盘读取到内存中），这涉及到修改页表、分配用户栈等工作
 * @binary:  the memory addr of the content of binary program
 * @size:  the size of the content of binary program
 */
static int
load_icode(unsigned char *binary, size_t size) {
    if (current->mm != NULL) {//检查当前进程内存管理片区是否为NULL
        panic("load_icode: current->mm must be empty.\n");
    }

    int ret = -E_NO_MEM;
    struct mm_struct *mm;   // mm_struct结构体用于描述虚拟内存区域(vma)的各种信息
    //(1) create a new mm for current process
    if ((mm = mm_create()) == NULL) { // 创建一片虚拟内存
        goto bad_mm;
    }
    //(2) create a new PDT, and mm->pgdir= kernel virtual addr of PDT
    if (setup_pgdir(mm) != 0) { // 新建一个页目录项表PDT,每个进程都需要一个PDT
        goto bad_pgdir_cleanup_mm;
    }
    //(3) copy TEXT/DATA section, build BSS parts in binary to memory space of process
    struct Page *page;
    //(3.1) get the file header of the bianry program (ELF format)
    struct elfhdr *elf = (struct elfhdr *)binary; // 获取文件ELF头部
    //(3.2) get the entry of the program section headers of the bianry program (ELF format)
    struct proghdr *ph = (struct proghdr *)(binary + elf->e_phoff); // 获取文件程序头部表
    //(3.3) This program is valid?
    if (elf->e_magic != ELF_MAGIC) { // 检查该程序的魔数是否正确
        ret = -E_INVAL_ELF;
        goto bad_elf_cleanup_pgdir;
    }
    /* <---- 遍历程序头表,并构建vma ----> */
    uint32_t vm_flags, perm;
    struct proghdr *ph_end = ph + elf->e_phnum; // ph_end:计算出程序头表的结尾地址（头部基址+程序头表中的条目数）
    for (; ph < ph_end; ph ++) {    // 遍历整个程序头表(ph就是各个段头表)
    //(3.4) find every program section headers
        if (ph->p_type != ELF_PT_LOAD) {    //遍历寻找到ELF_PT_LOAD为止,在ucore中,该段是TEXT/DATA
            continue ;
        }
        if (ph->p_filesz > ph->p_memsz) { //？？？
              /* 文件中段的大小 > 内存中段的大小 */
            /* 内存中p_memsz大于p_filesz的原因是,可加载段可能包含一个.bss部分,没有此部分则是等于状态,绝对不可能是小于状态 */
 
            ret = -E_INVAL_ELF;
            goto bad_cleanup_mmap; /* 调用exit_mmap */
        }
        if (ph->p_filesz == 0) {
            continue ;
        }
    //(3.5) call mm_map fun to setup the new vma ( ph->p_va, ph->p_memsz)
            /* <---- 根据标志位进行初始化,准备构建vma ----> */
        vm_flags = 0, perm = PTE_U;
        if (ph->p_flags & ELF_PF_X) vm_flags |= VM_EXEC;
        if (ph->p_flags & ELF_PF_W) vm_flags |= VM_WRITE;
        if (ph->p_flags & ELF_PF_R) vm_flags |= VM_READ;
        if (vm_flags & VM_WRITE) perm |= PTE_W;
        if ((ret = mm_map(mm, ph->p_va, ph->p_memsz, vm_flags, NULL)) != 0) {   // 调用mm_map,为目标段构建新的vma(用kmalloc申请了一片区域)
            goto bad_cleanup_mmap;
        }
          /* <---- 建立并分配页目录表PDT,复制TEXT/DATA段到进程的内存(建立映射) ----> */
        unsigned char *from = binary + ph->p_offset;    // 获取TEXT/DATA的段地址？？？
        size_t off, size;
        uintptr_t start = ph->p_va, end, la = ROUNDDOWN(start, PGSIZE);
        /* start:初始化为段起始地址(映射段的虚拟地址) */
        /* la(可变参数):start进行内存页对齐后(只舍不进)的地址 */
        ret = -E_NO_MEM;

     //(3.6) alloc memory, and  copy the contents of every program section (from, from+end) to process's memory (la, la+end)
     /* end:初始化为段结束地址(映射段的虚拟地址+文件中段的大小) */
        end = ph->p_va + ph->p_filesz;
     //(3.6.1) copy TEXT/DATA section of bianry program
        while (start < end) {   //持续为pgdir（页目录表）分配页表,直到整个段都完成映射
            if ((page = pgdir_alloc_page(mm->pgdir, la, perm)) == NULL) {
                /* 分配一块物理页(作为页表),设置页表项(对应la),插入页表目录(pgdir) */
                goto bad_cleanup_mmap;
            }
            off = start - la;// 更新偏移
            size = PGSIZE - off;  /* 更新已分配的段大小(每次增加PGSIZE) */
            la += PGSIZE; /* 更新当前的物理地址(每次增加PGSIZE) */   
            /* 第一次: off='start为了页对齐而舍弃的数值'(正) */
            /* 后续: off='0' */
            if (end < la) {
                size -= la - end;/* 获取准确的段大小 */
            }
            /* 获取该页表的页目录表PDT的虚拟地址,加off计算出对应页目录表项,用memcpy在其中填入from(TEXT/DATA段的起始地址) */ 
            memcpy(page2kva(page) + off, from, size);
            start += size, from += size;
            /* 第一次: start增加的值比la小一些 */
            /* 后续: start和la都增加相同的值(PGSIZE),并且地址也相同 */
        }

        /* <---- 分配内存,建立并分配页目录表PDT,建立BSS段(建立映射) ---->？？多出来的区域就是BSS了嘛*/
      //(3.6.2) build BSS section of binary program
        end = ph->p_va + ph->p_memsz; /* end:初始化为段结束地址(映射段的虚拟地址+内存中段的大小) */
        if (start < la) { 
            /* start最后会小于等于la,以下代码就是为了当"start<la"时,实现"start=la",并且置空原start距新start多出的部分 */
            /* ph->p_memsz == ph->p_filesz */
            if (start == end) {
                continue ;
            }
            off = start + PGSIZE - la, size = PGSIZE - off;
            if (end < la) {
                size -= la - end;
            }
            /* 获取页目录表的虚拟地址,通过off计算出对应页目录表项,并使用memset置空 */
            memset(page2kva(page) + off, 0, size);
            start += size;
            assert((end < la && start == end) || (end >= la && start == la));
        }
        while (start < end) {
            if ((page = pgdir_alloc_page(mm->pgdir, la, perm)) == NULL) {/* 持续为pgdir分配页表,直到整个段都完成映射 */
                goto bad_cleanup_mmap;
            }
            off = start - la, size = PGSIZE - off, la += PGSIZE;
            if (end < la) {
                size -= la - end;
            }
             /* 获取页目录表的虚拟地址,通过off计算出对应页目录表项,并使用memset置空 */
            memset(page2kva(page) + off, 0, size);
            start += size;
        }
    }

    /* <---- 构建用户堆栈内存 ----> */
    //(4) build user stack memory
    vm_flags = VM_READ | VM_WRITE | VM_STACK;
    if ((ret = mm_map(mm, USTACKTOP - USTACKSIZE, USTACKSIZE, vm_flags, NULL)) != 0) {
        goto bad_cleanup_mmap; /* 调用exit_mmap */
    }
    assert(pgdir_alloc_page(mm->pgdir, USTACKTOP-PGSIZE , PTE_USER) != NULL); //分配栈大小的物理页面
    assert(pgdir_alloc_page(mm->pgdir, USTACKTOP-2*PGSIZE , PTE_USER) != NULL);
    assert(pgdir_alloc_page(mm->pgdir, USTACKTOP-3*PGSIZE , PTE_USER) != NULL);
    assert(pgdir_alloc_page(mm->pgdir, USTACKTOP-4*PGSIZE , PTE_USER) != NULL);
    
    
    /* <---- 设置当前进程的mm,sr3,设置CR3寄存器 ----> */
    //(5) set current process's mm, sr3, and set CR3 reg = physical addr of Page Directory
    mm_count_inc(mm); // 设置并返回"共享该虚拟内存空间mva的进程数" 
    current->mm = mm;   // 设置当前进程的"proc_struct->mm"为该虚拟内存空间mva
    current->cr3 = PADDR(mm->pgdir); // 设置当前进程的"proc_struct->cr3"为该页目录表PDT的地址
    lcr3(PADDR(mm->pgdir)); // 设置CR3寄存器为当前页目录表PDT的物理地址

    /* <---- 为用户环境设置trapframe ----> */
    //(6) setup trapframe for user environment
    struct trapframe *tf = current->tf;
    memset(tf, 0, sizeof(struct trapframe)); /* 把trapframe清零 */
    /* LAB5:EXERCISE1 YOUR CODE
     * should set tf_cs,tf_ds,tf_es,tf_ss,tf_esp,tf_eip,tf_eflags
     * NOTICE: If we set trapframe correctly, then the user level process can return to USER MODE from kernel. So
     *          tf_cs should be USER_CS segment (see memlayout.h)
     *          tf_ds=tf_es=tf_ss should be USER_DS segment
     *          tf_esp should be the top addr of user stack (USTACKTOP)
     *          tf_eip should be the entry point of this binary program (elf->e_entry)
     *          tf_eflags should be set to enable computer to produce Interrupt
     */
    tf->tf_cs = USER_CS; // 执行TEXT段用户权限？
    tf->tf_ds = tf->tf_es = tf->tf_ss = USER_DS;
    tf->tf_esp = USTACKTOP;
    tf->tf_eip = elf->e_entry;
    tf->tf_eflags = FL_IF;
    ret = 0;
out:
    return ret;
bad_cleanup_mmap:
    exit_mmap(mm);
bad_elf_cleanup_pgdir:
    put_pgdir(mm);
bad_pgdir_cleanup_mm:
    mm_destroy(mm);
bad_mm:
    goto out;
}

// do_execve - call exit_mmap(mm)&pug_pgdir(mm) to reclaim memory space of current process
//           - call load_icode to setup new memory space accroding binary prog.
int
do_execve(const char *name, size_t len, unsigned char *binary, size_t size) {
    struct mm_struct *mm = current->mm;
    if (!user_mem_check(mm, (uintptr_t)name, len, 0)) {   /* 检查当前进程所分配的内存区域是否存在异常 */
        return -E_INVAL;
    }
    if (len > PROC_NAME_LEN) {
        len = PROC_NAME_LEN;
    }

    char local_name[PROC_NAME_LEN + 1];
    memset(local_name, 0, sizeof(local_name));	/* 回收当前进程的所有资源，包括已分配的内存空间/页目录表等等 */
    memcpy(local_name, name, len);

    if (mm != NULL) {
        lcr3(boot_cr3);
        if (mm_count_dec(mm) == 0) {
            exit_mmap(mm);
            put_pgdir(mm);
            mm_destroy(mm);
        }
        current->mm = NULL;
    }
    int ret;
    /* 读取可执行文件 */
    if ((ret = load_icode(binary, size)) != 0) {
        goto execve_exit;
    }
    /* 设置新进程名称 */
    set_proc_name(current, local_name);
    return 0;

execve_exit:
    do_exit(ret);
    panic("already exit: %e.\n", ret);
}
```