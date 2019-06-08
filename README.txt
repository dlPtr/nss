一，依赖环境：
	libpcap。
二，libpcap安装方法：
	1、将lib文件夹中的动态库已经静态库文件移至系统路径下，例如"/usr/local/lib"；移动后可能需要执行"ldconfig"指令，更新动态库路径缓存。
	2、将include文件夹中的头文件移至系统路径下，例如"/usr/local/include"。
三，使用make，编译工程。
四，使用"./nss -h"指令，即可查看指令帮助信息。