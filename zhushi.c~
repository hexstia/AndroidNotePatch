 关于 模拟器运行系统镜像的方式，配置信息在：
hexstia@unbuntu0:~/adt-bundle-linux-x86_64-20140702/sdk/.android/avd/xzc.avd$ ls
cache.img  config.ini  emulator-user.ini  hardware-qemu.ini  sdcard.img  userdata.img  userdata-qemu.img
 init:
 路径为 system /core/init 
首先是内核启动过程加载 函数startkernel（）-》init_post()->run_init_process()内部执行execute ——command 中哦能否的进程文件路径
执行execve（）调用查找的是系统路径下的脚本文件所 init.rc init.goldfish.rc
init
int fd_count = 0;
    struct pollfd ufds[4];
    char *tmpdev;
    char* debuggable;
    char tmp[32];
    int property_set_fd_init = 0;
    int signal_fd_init = 0;
    int keychord_fd_init = 0;
    bool is_charger = false;

    if (!strcmp(basename(argv[0]), "ueventd"))
        return ueventd_main(argc, argv);

    if (!strcmp(basename(argv[0]), "watchdogd"))
        return watchdogd_main(argc, argv);
=============================================================
 /* clear the umask */
    umask(0);

        /* Get the basic filesystem setup we need put
         * together in the initramdisk on / and then we'll
         * let the rc file figure out the rest.
         */
    mkdir("/dev", 0755);//设备驱动程序 文件系统
    mkdir("/proc", 0755);//虚拟文件系统
    mkdir("/sys", 0755);

    mount("tmpfs", "/dev", "tmpfs", MS_NOSUID, "mode=0755");
    mkdir("/dev/pts", 0755);
    mkdir("/dev/socket", 0755);
    mount("devpts", "/dev/pts", "devpts", 0, NULL);
    mount("proc", "/proc", "proc", 0, NULL);
    mount("sysfs", "/sys", "sysfs", 0, NULL);
//以上创建基本的文件系统目录以及挂在文件
  close(open("/dev/.booting", O_WRONLY | O_CREAT, 0000));

        /* 
	我们必须有一些/创建以外的地方
	*设备节点kmsg和零,否则我们不会
	*能够重新安装/只读。
	*现在tmpfs是安装在/ dev,我们可以
	*跟外面的世界。

         */
    open_devnull_stdio();//打开3个文件：输入，输出，错误  将会在 /dev下生成 __null__设备文件节点所有输入输出全部重定向__null__
	    klog_init();//初始化log
property_init();//属性初始化 
init_parse_config_file("/init.rc");//使用函数init_parse_config_file读取并分析init.rc文件
当前涉及到init .rc文件的脚本 
文件脚本的路径在 system/core/rootdir/init.rc
如果想自己挂在文件的话。
#############
snprintf(tmp,sizeof(tmp),"/init.%s/rc",hardware);
init_parse_config_file(tmp);
#############
=========================================================
 action_for_each_trigger("early-init", action_add_queue_tail);
    /* execute all the boot actions to get us started */
    action_for_each_trigger("init", action_add_queue_tail);//执行与动作列表的init区块相关的命令
不要挂载文件系统或启动核心系统服务
如果在充电模式
  if (is_charger) {
        action_for_each_trigger("charger", action_add_queue_tail);
    } else {
        action_for_each_trigger("late-init", action_add_queue_tail);
    }
/// *运行所有属性触发器基于当前状态属性* /
  queue_builtin_action(queue_property_triggers_action, "queue_property_triggers");
=======================================================================================
========================================================================================
下面讲解initrc脚本语法
链接其他的脚本文件
import /init.environ.rc
import /init.usb.rc
import /init.${ro.hardware}.rc
import /init.${ro.zygote}.rc
import /init.trace.rc

on early-init
    # Set init and its forked children's oom_adj.
    #设置初始化及其派生的子类 oom_adj。
    write /proc/1/oom_score_adj -1000

    # Apply strict SELinux checking of PROT_EXEC on mmap/mprotect calls.4
   #应用严格的PROT_EXEC mmap / SELinux检查mprotect调用
    write /sys/fs/selinux/checkreqprot 0

    # Set the security context for the init process.
    # This should occur before anything else (e.g. ueventd) is started.这应该发生什么(例如ueventd)之前开始
    setcon u:r:init:s0

    # Set the security context of /adb_keys if present.设置/ adb_keys如果存在的安全上下文。
    restorecon /adb_keys

    start ueventd

    # create mountpoints创建挂在点
    mkdir /mnt 0775 root system

on init
    sysclktz 0

    loglevel 3

    # Backward compatibility向后兼容性  symlink建立新的链接 路径文件节点 symlink(oldpath,newpath)
    symlink /system/etc /etc  
    symlink /sys/kernel/debug /d

    # Right now vendor lives on the same filesystem as system,
    # but someday that may change.
    symlink /system/vendor /vendor

    # Create cgroup mount point for cpu accounting
    mkdir /acct
    mount cgroup none /acct cpuacct
    mkdir /acct/uid

    # Create cgroup mount point for memory
    mount tmpfs none /sys/fs/cgroup mode=0750,uid=0,gid=1000
    mkdir /sys/fs/cgroup/memory 0750 root system
    mount cgroup none /sys/fs/cgroup/memory memory
    write /sys/fs/cgroup/memory/memory.move_charge_at_immigrate 1
    chown root system /sys/fs/cgroup/memory/tasks
    chmod 0660 /sys/fs/cgroup/memory/tasks
    mkdir /sys/fs/cgroup/memory/sw 0750 root system
    write /sys/fs/cgroup/memory/sw/memory.swappiness 100
    write /sys/fs/cgroup/memory/sw/memory.move_charge_at_immigrate 1
    chown root system /sys/fs/cgroup/memory/sw/tasks
    chmod 0660 /sys/fs/cgroup/memory/sw/tasks

    mkdir /system
    mkdir /data 0771 system system
    mkdir /cache 0770 system cache
    mkdir /config 0500 root root

    # See storage config details at http://source.android.com/tech/storage/ 这里是存储的挂在点 注意这个位置
    mkdir /mnt/shell 0700 shell shell
    mkdir /mnt/media_rw 0770 media_rw media_rw
    mkdir /storage 0751 root sdcard_r

    # Directory for putting things only root should see.目录将只有根应该看到的东西
    mkdir /mnt/secure 0700 root root

    # Directory for staging bindmounts 目录暂存绑定安装
    mkdir /mnt/secure/staging 0700 root root

    # Directory-target for where the secure container 安全内容
    # imagefile directory will be bind-mounted
    mkdir /mnt/secure/asec  0700 root root

    # Secure container public mount points.安全容器公开挂载点。
    mkdir /mnt/asec  0700 root system
    mount tmpfs tmpfs /mnt/asec mode=0755,gid=1000

    # Filesystem image public mount points.文件系统映像公共挂载点。
    mkdir /mnt/obb 0700 root system
    mount tmpfs tmpfs /mnt/obb mode=0755,gid=1000

    # memory control cgroup 内存控制组
    mkdir /dev/memcg 0700 root system
    mount cgroup none /dev/memcg memory

    write /proc/sys/kernel/panic_on_oops 1
    write /proc/sys/kernel/hung_task_timeout_secs 0
    write /proc/cpu/alignment 4
    write /proc/sys/kernel/sched_latency_ns 10000000
    write /proc/sys/kernel/sched_wakeup_granularity_ns 2000000
    write /proc/sys/kernel/sched_compat_yield 1
    write /proc/sys/kernel/sched_child_runs_first 0
    write /proc/sys/kernel/randomize_va_space 2
    write /proc/sys/kernel/kptr_restrict 2
    write /proc/sys/vm/mmap_min_addr 32768
    write /proc/sys/net/ipv4/ping_group_range "0 2147483647"
    write /proc/sys/net/unix/max_dgram_qlen 300
    write /proc/sys/kernel/sched_rt_runtime_us 950000
    write /proc/sys/kernel/sched_rt_period_us 1000000

    # reflect fwmark from incoming packets onto generated replies反映fwmark从传入的数据包到生成的回复
    write /proc/sys/net/ipv4/fwmark_reflect 1
    write /proc/sys/net/ipv6/fwmark_reflect 1

    # set fwmark on accepted sockets 设置fwmark接受套接字
    write /proc/sys/net/ipv4/tcp_fwmark_accept 1

    # Create cgroup mount points for process groups 为过程组创建cgroup挂载点
    mkdir /dev/cpuctl
    mount cgroup none /dev/cpuctl cpu
    chown system system /dev/cpuctl
    chown system system /dev/cpuctl/tasks
    chmod 0660 /dev/cpuctl/tasks
    write /dev/cpuctl/cpu.shares 1024
    write /dev/cpuctl/cpu.rt_runtime_us 950000
    write /dev/cpuctl/cpu.rt_period_us 1000000

    mkdir /dev/cpuctl/apps
    chown system system /dev/cpuctl/apps/tasks
    chmod 0666 /dev/cpuctl/apps/tasks
    write /dev/cpuctl/apps/cpu.shares 1024
    write /dev/cpuctl/apps/cpu.rt_runtime_us 800000
    write /dev/cpuctl/apps/cpu.rt_period_us 1000000

    mkdir /dev/cpuctl/apps/bg_non_interactive
    chown system system /dev/cpuctl/apps/bg_non_interactive/tasks
    chmod 0666 /dev/cpuctl/apps/bg_non_interactive/tasks
    # 5.0 %
    write /dev/cpuctl/apps/bg_non_interactive/cpu.shares 52
    write /dev/cpuctl/apps/bg_non_interactive/cpu.rt_runtime_us 700000
    write /dev/cpuctl/apps/bg_non_interactive/cpu.rt_period_us 1000000

    # qtaguid will limit access to specific data based on group memberships.
    #   net_bw_acct grants impersonation of socket owners.
    #   net_bw_stats grants access to other apps' detailed tagged-socket stats.
    chown root net_bw_acct /proc/net/xt_qtaguid/ctrl
    chown root net_bw_stats /proc/net/xt_qtaguid/stats

    # Allow everybody to read the xt_qtaguid resource tracking misc dev.
    # This is needed by any process that uses socket tagging.
    chmod 0644 /dev/xt_qtaguid

    # Create location for fs_mgr to store abbreviated output from filesystem
    # checker programs.
    mkdir /dev/fscklogs 0770 root system

    # pstore/ramoops previous console log
    mount pstore pstore /sys/fs/pstore
    chown system log /sys/fs/pstore/console-ramoops
    chmod 0440 /sys/fs/pstore/console-ramoops

# Healthd can trigger a full boot from charger mode by signaling this
# property when the power button is held.
on property:sys.boot_from_charger_mode=1
    class_stop charger
    trigger late-init

# Load properties from /system/ + /factory after fs mount.
on load_all_props_action
    load_all_props

# Indicate to fw loaders that the relevant mounts are up.
on firmware_mounts_complete
    rm /dev/.booting

# Mount filesystems and start core system services.挂载文件系统和启动核心系统服务。
on late-init
    trigger early-fs
    trigger fs
    trigger post-fs
    trigger post-fs-data

    # Load properties from /system/ + /factory after fs mount. Place
    # this in another action so that the load will be scheduled after the prior
    # issued fs triggers have completed.
    trigger load_all_props_action

    # Remove a file to wake up anything waiting for firmware.
    trigger firmware_mounts_complete

    trigger early-boot
    trigger boot


on post-fs
    # once everything is setup, no need to modify /
    mount rootfs rootfs / ro remount
    # mount shared so changes propagate into child namespaces
    mount rootfs rootfs / shared rec

    # We chown/chmod /cache again so because mount is run as root + defaults
    chown system cache /cache
    chmod 0770 /cache
    # We restorecon /cache in case the cache partition has been reset.
    restorecon_recursive /cache

    # This may have been created by the recovery system with odd permissions
    chown system cache /cache/recovery
    chmod 0770 /cache/recovery

    #change permissions on vmallocinfo so we can grab it from bugreports
    chown root log /proc/vmallocinfo
    chmod 0440 /proc/vmallocinfo

    chown root log /proc/slabinfo
    chmod 0440 /proc/slabinfo

    #change permissions on kmsg & sysrq-trigger so bugreports can grab kthread stacks
    chown root system /proc/kmsg
    chmod 0440 /proc/kmsg
    chown root system /proc/sysrq-trigger
    chmod 0220 /proc/sysrq-trigger
    chown system log /proc/last_kmsg
    chmod 0440 /proc/last_kmsg

    # make the selinux kernel policy world-readable
    chmod 0444 /sys/fs/selinux/policy

    # create the lost+found directories, so as to enforce our permissions
    mkdir /cache/lost+found 0770 root root

on post-fs-data
    # We chown/chmod /data again so because mount is run as root + defaults
    chown system system /data
    chmod 0771 /data
    # We restorecon /data in case the userdata partition has been reset.
    restorecon /data

    # Avoid predictable entropy pool. Carry over entropy from previous boot.
    copy /data/system/entropy.dat /dev/urandom

    # Create dump dir and collect dumps.
    # Do this before we mount cache so eventually we can use cache for
    # storing dumps on platforms which do not have a dedicated dump partition.
    mkdir /data/dontpanic 0750 root log

    # Collect apanic data, free resources and re-arm trigger
    copy /proc/apanic_console /data/dontpanic/apanic_console
    chown root log /data/dontpanic/apanic_console
    chmod 0640 /data/dontpanic/apanic_console

    copy /proc/apanic_threads /data/dontpanic/apanic_threads
    chown root log /data/dontpanic/apanic_threads
    chmod 0640 /data/dontpanic/apanic_threads

    write /proc/apanic_console 1

    # create basic filesystem structure
    mkdir /data/misc 01771 system misc
    mkdir /data/misc/adb 02750 system shell
    mkdir /data/misc/bluedroid 0770 bluetooth net_bt_stack
    mkdir /data/misc/bluetooth 0770 system system
    mkdir /data/misc/keystore 0700 keystore keystore
    mkdir /data/misc/keychain 0771 system system
    mkdir /data/misc/net 0750 root shell
    mkdir /data/misc/radio 0770 system radio
    mkdir /data/misc/sms 0770 system radio
    mkdir /data/misc/zoneinfo 0775 system system
    mkdir /data/misc/vpn 0770 system vpn
    mkdir /data/misc/shared_relro 0771 shared_relro shared_relro
    mkdir /data/misc/systemkeys 0700 system system
    mkdir /data/misc/wifi 0770 wifi wifi
    mkdir /data/misc/wifi/sockets 0770 wifi wifi
    mkdir /data/misc/wifi/wpa_supplicant 0770 wifi wifi
    mkdir /data/misc/ethernet 0770 system system
    mkdir /data/misc/dhcp 0770 dhcp dhcp
    mkdir /data/misc/user 0771 root root
    # give system access to wpa_supplicant.conf for backup and restore
    chmod 0660 /data/misc/wifi/wpa_supplicant.conf
    mkdir /data/local 0751 root root
    mkdir /data/misc/media 0700 media media

    # For security reasons, /data/local/tmp should always be empty.
    # Do not place files or directories in /data/local/tmp
    mkdir /data/local/tmp 0771 shell shell
    mkdir /data/data 0771 system system
    mkdir /data/app-private 0771 system system
    mkdir /data/app-asec 0700 root root
    mkdir /data/app-lib 0771 system system
    mkdir /data/app 0771 system system
    mkdir /data/property 0700 root root

    # create dalvik-cache, so as to enforce our permissions
    mkdir /data/dalvik-cache 0771 root root
    mkdir /data/dalvik-cache/profiles 0711 system system

    # create resource-cache and double-check the perms
    mkdir /data/resource-cache 0771 system system
    chown system system /data/resource-cache
    chmod 0771 /data/resource-cache

    # create the lost+found directories, so as to enforce our permissions
    mkdir /data/lost+found 0770 root root

    # create directory for DRM plug-ins - give drm the read/write access to
    # the following directory.
    mkdir /data/drm 0770 drm drm

    # create directory for MediaDrm plug-ins - give drm the read/write access to
    # the following directory.
    mkdir /data/mediadrm 0770 mediadrm mediadrm

    # symlink to bugreport storage location
    symlink /data/data/com.android.shell/files/bugreports /data/bugreports

    # Separate location for storing security policy files on data
    mkdir /data/security 0711 system system

    # Reload policy from /data/security if present.
    setprop selinux.reload_policy 1

    # Set SELinux security contexts on upgrade or policy update.
    restorecon_recursive /data

    # If there is no fs-post-data action in the init.<device>.rc file, you
    # must uncomment this line, otherwise encrypted filesystems
    # won't work.
    # Set indication (checked by vold) that we have finished this action
    #setprop vold.post_fs_data_done 1

on boot
    # basic network init
    ifup lo
    hostname localhost
    domainname localdomain

    # set RLIMIT_NICE to allow priorities from 19 to -20
    setrlimit 13 40 40

    # Memory management.  Basic kernel parameters, and allow the high
    # level system server to be able to adjust the kernel OOM driver
    # parameters to match how it is managing things.
    write /proc/sys/vm/overcommit_memory 1
    write /proc/sys/vm/min_free_order_shift 4
    chown root system /sys/module/lowmemorykiller/parameters/adj
    chmod 0220 /sys/module/lowmemorykiller/parameters/adj
    chown root system /sys/module/lowmemorykiller/parameters/minfree
    chmod 0220 /sys/module/lowmemorykiller/parameters/minfree

    # Tweak background writeout
    write /proc/sys/vm/dirty_expire_centisecs 200
    write /proc/sys/vm/dirty_background_ratio  5

    # Permissions for System Server and daemons.
    chown radio system /sys/android_power/state
    chown radio system /sys/android_power/request_state
    chown radio system /sys/android_power/acquire_full_wake_lock
    chown radio system /sys/android_power/acquire_partial_wake_lock
    chown radio system /sys/android_power/release_wake_lock
    chown system system /sys/power/autosleep
    chown system system /sys/power/state
    chown system system /sys/power/wakeup_count
    chown radio system /sys/power/wake_lock
    chown radio system /sys/power/wake_unlock
    chmod 0660 /sys/power/state
    chmod 0660 /sys/power/wake_lock
    chmod 0660 /sys/power/wake_unlock

    chown system system /sys/devices/system/cpu/cpufreq/interactive/timer_rate
    chmod 0660 /sys/devices/system/cpu/cpufreq/interactive/timer_rate
    chown system system /sys/devices/system/cpu/cpufreq/interactive/timer_slack
    chmod 0660 /sys/devices/system/cpu/cpufreq/interactive/timer_slack
    chown system system /sys/devices/system/cpu/cpufreq/interactive/min_sample_time
    chmod 0660 /sys/devices/system/cpu/cpufreq/interactive/min_sample_time
    chown system system /sys/devices/system/cpu/cpufreq/interactive/hispeed_freq
    chmod 0660 /sys/devices/system/cpu/cpufreq/interactive/hispeed_freq
    chown system system /sys/devices/system/cpu/cpufreq/interactive/target_loads
    chmod 0660 /sys/devices/system/cpu/cpufreq/interactive/target_loads
    chown system system /sys/devices/system/cpu/cpufreq/interactive/go_hispeed_load
    chmod 0660 /sys/devices/system/cpu/cpufreq/interactive/go_hispeed_load
    chown system system /sys/devices/system/cpu/cpufreq/interactive/above_hispeed_delay
    chmod 0660 /sys/devices/system/cpu/cpufreq/interactive/above_hispeed_delay
    chown system system /sys/devices/system/cpu/cpufreq/interactive/boost
    chmod 0660 /sys/devices/system/cpu/cpufreq/interactive/boost
    chown system system /sys/devices/system/cpu/cpufreq/interactive/boostpulse
    chown system system /sys/devices/system/cpu/cpufreq/interactive/input_boost
    chmod 0660 /sys/devices/system/cpu/cpufreq/interactive/input_boost
    chown system system /sys/devices/system/cpu/cpufreq/interactive/boostpulse_duration
    chmod 0660 /sys/devices/system/cpu/cpufreq/interactive/boostpulse_duration
    chown system system /sys/devices/system/cpu/cpufreq/interactive/io_is_busy
    chmod 0660 /sys/devices/system/cpu/cpufreq/interactive/io_is_busy

    # Assume SMP uses shared cpufreq policy for all CPUs
    chown system system /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq
    chmod 0660 /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq

    chown system system /sys/class/timed_output/vibrator/enable
    chown system system /sys/class/leds/keyboard-backlight/brightness
    chown system system /sys/class/leds/lcd-backlight/brightness
    chown system system /sys/class/leds/button-backlight/brightness
    chown system system /sys/class/leds/jogball-backlight/brightness
    chown system system /sys/class/leds/red/brightness
    chown system system /sys/class/leds/green/brightness
    chown system system /sys/class/leds/blue/brightness
    chown system system /sys/class/leds/red/device/grpfreq
    chown system system /sys/class/leds/red/device/grppwm
    chown system system /sys/class/leds/red/device/blink
    chown system system /sys/class/timed_output/vibrator/enable
    chown system system /sys/module/sco/parameters/disable_esco
    chown system system /sys/kernel/ipv4/tcp_wmem_min
    chown system system /sys/kernel/ipv4/tcp_wmem_def
    chown system system /sys/kernel/ipv4/tcp_wmem_max
    chown system system /sys/kernel/ipv4/tcp_rmem_min
    chown system system /sys/kernel/ipv4/tcp_rmem_def
    chown system system /sys/kernel/ipv4/tcp_rmem_max
    chown root radio /proc/cmdline

    # Define default initial receive window size in segments.
    setprop net.tcp.default_init_rwnd 60

    class_start core

on nonencrypted
    class_start main
    class_start late_start

on property:vold.decrypt=trigger_default_encryption
    start defaultcrypto

on property:vold.decrypt=trigger_encryption
    start surfaceflinger
    start encrypt

on property:sys.init_log_level=*
    loglevel ${sys.init_log_level}

on charger
    class_start charger

on property:vold.decrypt=trigger_reset_main
    class_reset main

on property:vold.decrypt=trigger_load_persist_props
    load_persist_props

on property:vold.decrypt=trigger_post_fs_data
    trigger post-fs-data

on property:vold.decrypt=trigger_restart_min_framework
    class_start main

on property:vold.decrypt=trigger_restart_framework
    class_start main
    class_start late_start

on property:vold.decrypt=trigger_shutdown_framework
    class_reset late_start
    class_reset main

on property:sys.powerctl=*
    powerctl ${sys.powerctl}

# system server cannot write to /proc/sys files,
# and chown/chmod does not work for /proc/sys/ entries.
# So proxy writes through init.
on property:sys.sysctl.extra_free_kbytes=*
    write /proc/sys/vm/extra_free_kbytes ${sys.sysctl.extra_free_kbytes}

# "tcp_default_init_rwnd" Is too long!
on property:sys.sysctl.tcp_def_init_rwnd=*
    write /proc/sys/net/ipv4/tcp_default_init_rwnd ${sys.sysctl.tcp_def_init_rwnd}


## Daemon processes to be run by init.
##
service ueventd /sbin/ueventd
    class core
    critical
    seclabel u:r:ueventd:s0

service logd /system/bin/logd
    class core
    socket logd stream 0666 logd logd
    socket logdr seqpacket 0666 logd logd
    socket logdw dgram 0222 logd logd
    seclabel u:r:logd:s0

service healthd /sbin/healthd
    class core
    critical
    seclabel u:r:healthd:s0

service console /system/bin/sh
    class core
    console
    disabled
    user shell
    group shell log
    seclabel u:r:shell:s0

on property:ro.debuggable=1
    start console

# adbd is controlled via property triggers in init.<platform>.usb.rc
service adbd /sbin/adbd --root_seclabel=u:r:su:s0
    class core
    socket adbd stream 660 system system
    disabled
    seclabel u:r:adbd:s0

# adbd on at boot in emulator
on property:ro.kernel.qemu=1
    start adbd

service lmkd /system/bin/lmkd
    class core
    critical
    socket lmkd seqpacket 0660 system system

service servicemanager /system/bin/servicemanager
    class core
    user system
    group system
    critical
    onrestart restart healthd
    onrestart restart zygote
    onrestart restart media
    onrestart restart surfaceflinger
    onrestart restart drm

service vold /system/bin/vold
    class core
    socket vold stream 0660 root mount
    ioprio be 2

service netd /system/bin/netd
    class main
    socket netd stream 0660 root system
    socket dnsproxyd stream 0660 root inet
    socket mdns stream 0660 root system
    socket fwmarkd stream 0660 root inet

service debuggerd /system/bin/debuggerd
    class main

service debuggerd64 /system/bin/debuggerd64
    class main

service ril-daemon /system/bin/rild
    class main
    socket rild stream 660 root radio
    socket rild-debug stream 660 radio system
    user root
    group radio cache inet misc audio log

service surfaceflinger /system/bin/surfaceflinger
    class core
    user system
    group graphics drmrpc
    onrestart restart zygote

service drm /system/bin/drmserver
    class main
    user drm
    group drm system inet drmrpc

service media /system/bin/mediaserver
    class main
    user media
    group audio camera inet net_bt net_bt_admin net_bw_acct drmrpc mediadrm
    ioprio rt 4

# One shot invocation to deal with encrypted volume.
service defaultcrypto /system/bin/vdc --wait cryptfs mountdefaultencrypted
    disabled
    oneshot
    # vold will set vold.decrypt to trigger_restart_framework (default
    # encryption) or trigger_restart_min_framework (other encryption)

# One shot invocation to encrypt unencrypted volumes
service encrypt /system/bin/vdc --wait cryptfs enablecrypto inplace default
    disabled
    oneshot
    # vold will set vold.decrypt to trigger_restart_framework (default
    # encryption)

# 动画安装的服务
service bootanim /system/bin/bootanimation
    class core
    user graphics
    group graphics audio media
    disabled
    oneshot

service installd /system/bin/installd
    class main
    socket installd stream 600 system system

service flash_recovery /system/bin/install-recovery.sh
    class main
    seclabel u:r:install_recovery:s0
    oneshot

service racoon /system/bin/racoon
    class main
    socket racoon stream 600 system system
    # IKE uses UDP port 500. Racoon will setuid to vpn after binding the port.
    group vpn net_admin inet
    disabled
    oneshot

service mtpd /system/bin/mtpd
    class main
    socket mtpd stream 600 system system
    user vpn
    group vpn net_admin inet net_raw
    disabled
    oneshot

service keystore /system/bin/keystore /data/misc/keystore
    class main
    user keystore
    group keystore drmrpc

service dumpstate /system/bin/dumpstate -s
    class main
    socket dumpstate stream 0660 shell log
    disabled
    oneshot

service mdnsd /system/bin/mdnsd
    class main
    user mdnsr
    group inet net_raw
    socket mdnsd stream 0660 mdnsr inet
    disabled
    oneshot

service pre-recovery /system/bin/uncrypt
    class main
    disabled
    oneshot
========================================================
对于关键字的定义在sysytem/core/keywordc文件中
KEYWORD(mkdir,       COMMAND, 1, do_mkdir)
第一个参数 脚本中使用的名字
第二个参数 flags 为关键字的类型
第三个参数 关键字参数的个数
第三个参数 关键字所对应的函数  （函数的实现在builtins.c文件中实现的）
关于init的内建动作和初始化
=======================================================
我们在返回init.c文件
queue_builtin_action(wait_for_coldboot_done_action, "wait_for_coldboot_done");等待启动结束
属于内建动作
内建动作和init脚本一样，形成命令的序列，在init可执行程序的for循环中真正的执行
终端初始化
static int console_init_action(int nargs, char **args)
{
    int fd;

    if (console[0]) {
        snprintf(console_name, sizeof(console_name), "/dev/%s", console);
    }

    fd = open(console_name, O_RDWR);
    if (fd >= 0)
        have_console = 1;
    close(fd);

    fd = open("/dev/tty0", O_WRONLY);//获取系统的默认的首个终端
    if (fd >= 0) {
        const char *msg;
            msg = "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"  // console is 40 cols x 30 lines
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "             A N D R O I D ";//显示在终端的字符串上
        write(fd, msg, strlen(msg));//写设备以显示字符串
        close(fd);
    }

    return 0;
}
===========================================keychord初始化（keychords.c）=========================
keychord组合键的一种 由/dev/keychord设备用于一些调试类的功能 
void keychord_init()
{
    int fd, ret;

    service_for_each(add_service_keycodes);//对每个服务增加keycode

    /* nothing to do if no services require keychords */
    if (!keychords)
        return;

    fd = open("/dev/keychord", O_RDWR);//打开
    if (fd < 0) {
        ERROR("could not open /dev/keychord\n");
        return;
    }
    fcntl(fd, F_SETFD, FD_CLOEXEC);

    ret = write(fd, keychords, keychords_length);//写
    if (ret != keychords_length) {
        ERROR("could not configure /dev/keychord %d (%d)\n", ret, errno);
        close(fd);
        fd = -1;
    }

    free(keychords);
    keychords = 0;//保存标志和文件描述符

    keychord_fd = fd;
}
==========================property_service.c===========================
void property_init(void)
{
    init_property_area();
}
实际上包括属性存储区域，初始化和默认属性文件的处理
void property_load_boot_defaults(void)
{
    load_properties_from_file(PROP_PATH_RAMDISK_DEFAULT, NULL);
}

int properties_inited(void)
{
    return property_area_inited;
}
=========================bootchart.c=================




===================for(;;)===========================

  for(;;) {
        int nr, i, timeout = -1;

        execute_one_command();//执行一个单行的命令
        restart_processes();// 重新启动进程 

        if (!property_set_fd_init && get_property_set_fd() > 0) {
            ufds[fd_count].fd = get_property_set_fd();
            ufds[fd_count].events = POLLIN;
            ufds[fd_count].revents = 0;
            fd_count++;
            property_set_fd_init = 1;//设置属性的初始化标志
        }
        if (!signal_fd_init && get_signal_fd() > 0) {
            ufds[fd_count].fd = get_signal_fd();
            ufds[fd_count].events = POLLIN;
            ufds[fd_count].revents = 0;
            fd_count+ +;
            signal_fd_init = 1;//设置signal的初始化标志
        }
        if (!keychord_fd_init && get_keychord_fd() > 0) {
            ufds[fd_count].fd = get_keychord_fd();
            ufds[fd_count].events = POLLIN;
            ufds[fd_count].revents = 0;
            fd_count++;
            keychord_fd_init = 1;//设置keychord的初始化标志
        }

        if (process_needs_restart) {
            timeout = (process_needs_restart - gettime()) * 1000;
            if (timeout < 0)
                timeout = 0;
        }

        if (!action_queue_empty() || cur_action)
            timeout = 0;

#if BOOTCHART
        if (bootchart_count > 0) {
            if (timeout < 0 || timeout > BOOTCHART_POLLING_MS)
                timeout = BOOTCHART_POLLING_MS;
            if (bootchart_step() < 0 || --bootchart_count == 0) {
                bootchart_finish();
                bootchart_count = 0;
            }
        }
#endif

        nr = poll(ufds, fd_count, timeout);//获取用于时间的文件描述符
        if (nr <= 0)
            continue;

        for (i = 0; i < fd_count; i++) {
            if (ufds[i].revents & POLLIN) {
                if (ufds[i].fd == get_property_set_fd())//
                    handle_property_set_fd();//设置属性方面的处理
                else if (ufds[i].fd == get_keychord_fd())
                    handle_keychord();//keychord方面的处理
                else if (ufds[i].fd == get_signal_fd())
                    handle_signal();//signal方面的处理
            }
        }
    }

    return 0;
}
======================================execute_one_command()====================
void execute_one_command(void)
{
    int ret, i;
    char cmd_str[256] = "";

    if (!cur_action || !cur_command || is_last_command(cur_action, cur_command)) {
        cur_action = action_remove_queue_head();
        cur_command = NULL;
        if (!cur_action)//无动作将退出
            return;
        INFO("processing action %p (%s)\n", cur_action, cur_action->name);
        cur_command = get_first_command(cur_action);//获取第一个命令
    } else {
        cur_command = get_next_command(cur_action, cur_command);//获取下一个命令
    }

    if (!cur_command)
        return;
	//执行命令
    ret = cur_command->func(cur_command->nargs, cur_command->args);
    if (klog_get_level() >= KLOG_INFO_LEVEL) {
        for (i = 0; i < cur_command->nargs; i++) {
            strlcat(cmd_str, cur_command->args[i], sizeof(cmd_str));
            if (i < cur_command->nargs - 1) {
                strlcat(cmd_str, " ", sizeof(cmd_str));
            }
        }
        INFO("command '%s' action=%s status=%d (%s:%d)\n",
             cmd_str, cur_action ? cur_action->name : "", ret, cur_command->filename,
             cur_command->line);
    }
}
====================================
