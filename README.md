# tcpdump

## 1、介绍
这是一个在基于 RT-Thread 的捕获IP报文的小工具，PCAP格式文件可以保存文件系统，导出到PC上可用Wireshark软件解析。

## 2、使用

### 2.1 插入SD卡

### 2.1 开启抓包

在msh/>命令行，输入如下命令，抓16个数据包

```
msh />tcpdump_c 16
[TCPDUMP]numbers of pkt: 16
msh />
```

### 2.2 ping

在msh/>命令行，输入 ping 192.168.1.29
或在cmd命令行输入 ping 192.168.1.30（板子是静态IP地址）

### 2.3 查看结果

在msh/>命令行，输入ls命令查看保存结果

```
msh />ls
Directory /:
System Volume Information<DIR>                    
sample.pcap         1372                     
msh />
```
使用rdb工具，或用读卡器把sd卡里的文件，用wireshark软件打开

### 2.4 用新的名字保存文件

可以通过电脑 ping 板子或者板子 ping 电脑（需要开启netutils组件包中的 ping 功能）来测试驱动是否移植成功。

```
msh />tcpdump_f 33.pcap 16
[TCPDUMP]set file name: 33.pcap
[TCPDUMP]numbers of pkt: 16
msh />
```

### 2.5 ping

在msh/>命令行，输入 ping 192.168.1.29
或在cmd命令行输入 ping 192.168.1.30（板子是静态IP地址）

### 2.6 查看结果

```
msh />ls
Directory /:
System Volume Information<DIR>                    
sample.pcap         1372                     
33.pcap             1418                     
msh />
```
使用rdb工具，或用读卡器把sd卡里的文件，用wireshark软件打开

## 4、注意事项

如果不用新名字保存文件，则沿用"sample.pcap"保存，并且覆盖旧文件。

## 5、联系方式 & 感谢

* 维护：[never](https://github.com/neverxie)
* 主页：https://github.com/neverxie/tcpdump
