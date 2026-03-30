#include <linux/export.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/workqueue.h>
#include <linux/moduleparam.h>
#include <linux/susfs.h>

#include "policy/allowlist.h"
#include "policy/app_profile.h"
#include "policy/feature.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_observer.h"
#include "manager/throne_tracker.h"
#include "hook/syscall_hook_manager.h"
#include "runtime/ksud.h"
#include "runtime/ksud_boot.h"
#include "feature/sulog.h"
#include "supercall/supercall.h"
#include "ksu.h"
#include "infra/file_wrapper.h"
#include "selinux/selinux.h"
#include "hook/syscall_hook.h"

/* * 强制定义区：将变量放在所有头文件之后，逻辑逻辑之前。
 * 这样即使 Patch 失败，这里的定义也不会被破坏。
 */
struct cred *ksu_cred = NULL;
bool ksu_late_loaded = false;
extern bool ksu_boot_completed;

#if defined(__x86_64__)
#include <asm/cpufeature.h>
#include <linux/version.h>
#ifndef X86_FEATURE_INDIRECT_SAFE
#error "FATAL: Your kernel is missing the indirect syscall bypass patches!"
#endif
#endif

#if defined(CONFIG_STACKPROTECTOR) &&                                                                                  \
      (defined(CONFIG_ARM64) && defined(MODULE) && !defined(CONFIG_STACKPROTECTOR_PER_TASK))
#include <linux/stackprotector.h>
#include <linux/random.h>
unsigned long __stack_chk_guard __ro_after_init __attribute__((visibility("hidden")));

__attribute__((no_stack_protector)) void ksu_setup_stack_chk_guard(void)
{
      unsigned long canary;
      get_random_bytes(&canary, sizeof(canary));
      canary ^= LINUX_VERSION_CODE;
      canary &= CANARY_MASK;
      __stack_chk_guard = canary;
}

__attribute__((naked)) int __init kernelsu_init_early(void)
{
      asm("mov x19, x30;\n"
            "bl ksu_setup_stack_chk_guard;\n"
            "mov x30, x19;\n"
            "b kernelsu_init;\n");
}
#define NEED_OWN_STACKPROTECTOR 1
#else
#define NEED_OWN_STACKPROTECTOR 0
#endif

#ifdef CONFIG_KSU_DEBUG
bool allow_shell = true;
#else
bool allow_shell = false;
#endif
module_param(allow_shell, bool, 0);

int __init kernelsu_init(void)
{
#if defined(__x86_64__)
      if (!boot_cpu_has(X86_FEATURE_INDIRECT_SAFE)) {
            return -ENOSYS;
      }
#endif

#ifdef MODULE
      ksu_late_loaded = (current->pid != 1);
#else
      ksu_late_loaded = false;
#endif

      ksu_cred = prepare_creds();
      if (!ksu_cred) {
            pr_err("KernelSU: prepare_creds failed\n");
      }

      ksu_syscall_hook_init();
      ksu_feature_init();
      ksu_sulog_init();
      ksu_supercalls_init();

      if (ksu_late_loaded) {
            apply_kernelsu_rules();
            cache_sid();
            setup_ksu_cred();
            escape_to_root_for_init();
            ksu_allowlist_init();
            ksu_load_allow_list();
            ksu_syscall_hook_manager_init();
            ksu_throne_tracker_init();
            ksu_observer_init();
            ksu_file_wrapper_init();
            ksu_boot_completed = true;
            track_throne(false);
            if (!getenforce()) {
                  setenforce(true);
            }
      } else {
            ksu_syscall_hook_manager_init();
            ksu_allowlist_init();
            ksu_throne_tracker_init();
            ksu_ksud_init();
            ksu_file_wrapper_init();
      }

#ifdef MODULE
#ifndef CONFIG_KSU_DEBUG
      kobject_del(&THIS_MODULE->mkobj.kobj);
#endif
#endif

      /* 核心：确保 SUSFS 初始化被执行 */
      susfs_init();

      return 0;
}

void kernelsu_exit(void)
{
      ksu_syscall_hook_manager_exit();
      ksu_supercalls_exit();

      if (!ksu_late_loaded)
            ksu_ksud_exit();

      synchronize_rcu();
      ksu_observer_exit();
      ksu_throne_tracker_exit();
      ksu_allowlist_exit();
      ksu_sulog_exit();
      ksu_feature_exit();

      if (ksu_cred) {
            put_cred(ksu_cred);
      }
}

#if NEED_OWN_STACKPROTECTOR
module_init(kernelsu_init_early);
#else
module_init(kernelsu_init);
#endif
module_exit(kernelsu_exit);

MODULE_LICENSE("GPL");
