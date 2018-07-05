# tcpdump

## 1、介绍
这是一个在基于 RT-Thread 的捕获IP报文的小工具，PCAP格式文件可以保存文件系统，导出到PC上可用Wireshark软件解析。

## 2、使用

使用msh/>操作

### 2.1 插入SD卡

### 2.1 输入文件名

```
msh />tcpdump_name test.pcap
set file name: test.pcap
msh />
```

在msh/>输入ls命令查看

```
msh />ls
Directory /:
System Volume Information<DIR>
test.pcap           0
msh />
```
### 2.2 开始抓包

```
```

### 2.3 保存文件

```
```


## 4、注意事项

如果不需要抓包了请close tcpdump 功能

## 5、联系方式 & 感谢

* 维护：[never](https://github.com/neverxie)
* 主页：https://github.com/neverxie/tcpdump
