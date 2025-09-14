#include <linux/module.h>
#include <linux/init.h>
#include <linux/seq_file.h>
#include <linux/debugfs.h>
#include <linux/jiffies.h>
#include <linux/atomic.h>
#include <linux/uaccess.h>

#define NFMINI_DIR "nfmini"

static struct dentry *nfmini_dir;
static struct dentry *stats_ent;
static struct dentry *reset_ent;

/* Global counters (later replaced with per-CPU counters) */
static atomic64_t g_pkts = ATOMIC_LONG_INIT(0);
static atomic64_t g_bytes = ATOMIC_LONG_INIT(0);

/* This function will be called by Netfilter hook in nf-mini-qos.c */
void nfmini_stats_add(u64 bytes)
{
  atomic64_inc(&g_pkts);
  atomic64_add(bytes, &g_bytes);
}
EXPORT_SYMBOL_GPL(nfmini_stats_add);

/* Show function for seq_file: prints stats to debugfs */
static int nfmini_stats_show(struct seq_file *m, void *v)
{
  u64 pkts  = atomic64_read(&g_pkts);
  u64 bytes = atomic64_read(&g_bytes);
  unsigned long uptime_j = get_jiffies_64();
  u64 uptime_ms = jiffies_to_msecs(uptime_j);

  seq_printf(m, "nfmini stats\n");
  seq_printf(m, "-----------\n");
  seq_printf(m, "uptime_ms: %llu\n", uptime_ms);
  seq_printf(m, "packets  : %llu\n,", pkts);
  seq_printf(m, "bytes    : %llu\n", bytes);
  return 0;
}

/* Wrapper for seq_file open */
static int nfmini_stats_open(struct inode *inode, struct file *file)
{
  return single_open(file, nfmini_stats_show, NULL);
}

/* File operations for /sys/kernel/debug/nfmini/stats */
static const struct file_operations nfmini_stats_fops = {
  .owner   = THIS_MODULE,
  .open    = nfmini_stats_open,
  .read    = seq_read,
  .llseek  = seq_lseek,
  .release = single_release,
};

/* Write handler for /sys/kernel/debug/nfmini/reset
 * Any write will reset counters to zero.
 */
static ssize_t nfmini_reset_write(struct file *f, const char __user *buf, size_t len, loff_t *off)
{
  /* Input buffer is ignored, only used to trigger reset */
  atomic64_set(&g_pkts, 0);
  atomic64_set(&g_bytes, 0);
  pr_info("nfmini: stats reset\n");
  return len;
}

/* File operations for reset file */
static const struct file_operations nfmini_reset_fops = {
  .owner = THIS_MODULE,
  .write = nfmini_reset_write,
};

static int __init nfmini_init(void)
{
  /* Create base directory under debugfs */
  nfmini_dir = debugfs_create_dir(NFMINI_DIR, NULL);
  if (!nfmini_dir) {
    pr_err("nfmini: failed to create debugfs dir\n");
    return -ENOMEM;
  }

  /* Create read-only stats file */
  stats_ent = debugfs_create_file("stats", 0444, nfmini_dir, NULL, &nfmini_stats_fops);
  if (!stats_ent) {
    pr_err("nfmini: failed to create stats file\n");
    debugfs_remove_recursive(nfmini_dir);
    return -ENOMEM;
  }

  /* Create write-only reset file */
  reset_ent = debugfs_create_file("reset", 0200, nfmini_dir, NULL, &nfmini_reset_fops);
  if (!reset_ent) {
    pr_err("nfmini: failed to create reset file\n");
    debugfs_remove_recursive(nfmini_dir);
    return -ENOMEM;
  }

  pr_info("nfmini: stats module loaded\n");
  return 0;
}

static void __exit nfmini_exit(void)
{
  debugfs_remove_recursive(nfmini_dir);
  pr_info("nfmini: stats module unloaded\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("hide227");
MODULE_DESCRIPTION("nfmini stats via debugfs (seq_file)");

module_init(nfmini_init);
module_exit(nfmini_exit);
