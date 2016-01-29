main.mk文件
Android Build 系统的主控文件。该文件主要作用是包含进其他mk文件，以及定义几个最重要的编译目标，如droid,sdk,ndk等。同时检查编译工具的版本，如make,gcc,javac等
config.mk文件
Android Build系统的配置文件，主要定义了许多的常量来负责不同类型模块编译，定义编译器参数并引入产品的BoardConfig.mk文件来配置产品参数，同时也定义了一些编译工具的路径，如aapt，mkbooting，javajar等。
1/编译脚本的定义
2/生成文件的命令也就是脚本include的写法
3/pathmap.mk给一些头文件定义别名，将framwork下的一些源码目录按类别组合在意其并定义了别名，方便使用。
4/定义C/C++代码编译时的参数以及系统常用包的后缀名：
5/envsetup.mk包含进product_config.mk产品的编译参数。
6/sekect.mk指定4次，指定的是交叉编译工具以及目标平台
7javac的编译javac.mk文件
8/bison和flex工具 /yasm工具 doxygen
9/定义host平台和target平台各自编译，链接C/C++使用的参数
10/clang/config.mk C/C++编译器
12/定义sdk版本
13/包含dumpvar.mk文件，打印出本次编译产品的配置信息


