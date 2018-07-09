# tcpdump

## 1、介绍
这是一个在基于 RT-Thread 的捕获IP报文的小工具，PCAP格式文件可以保存文件系统，导出到PC上可用Wireshark软件解析。

## 2、使用

## 2.1 tcpdump命令说明

-i: 指定监听的网络接口

-w: 将抓到的数据包写入文件中

-p: 停止抓包

### 2.2 插入SD卡

### 2.3 开启抓包

msh/>里，输入"tcpdump -i e0 -w sample.pcap"，详情如下：

```
msh />tcpdump -i e0 -w sample.pcap
[TCPDUMP]tcpdump start!
msh />
```

如果不指定网卡，则选用默认网卡。
可以输入"tcpdump -w sample.pcap"，详情如下：

```
msh />tcpdump -w sample.pcap
[TCPDUMP]tcpdump start!
msh />
```


另外，msh/> 带自动补全功能，输入tc，按tab键，详情如下：

```
msh />tc
tcpdump
msh />tcpdump
```

### 2.4 ping

msh/>里输入ifconfig得到IP，电脑ping这个IP

### 2.5 查看结果

msh/>里，输入ls命令查看保存结果，详情如下：

```
msh />ls
Directory /:
System Volume Information<DIR>                    
sample.pcap         1372                     
msh />
```
使用rdb工具，或用读卡器把sd卡里的文件，用wireshark软件打开

### 2.6 停止抓包

msh/>里，输入"tcpdump -p"，详情如下：

```
msh />tcpdump -p
tcp dump thread exit
msh />
```

## 3、注意事项

暂无

## 4、联系方式 & 感谢

* 维护：[never](https://github.com/neverxie)
* 主页：https://github.com/neverxie/tcpdump
