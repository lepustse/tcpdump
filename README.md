# tcpdump

## 1、介绍
这是一个在基于 RT-Thread 的捕获IP报文的小工具，PCAP格式文件可以保存文件系统，导出到PC上可用Wireshark软件解析。

## 2、使用

### 2.1 启用tcpdump

调用相关API
```
rt_tcp_dump_init();
rt_tcpdump_write_enable();

```

### 2.2 关闭tcpdump

调用相关API
```
rt_tcp_dump_deinit();
```

### 2.3 msh/>输出文件名

```
msh />tcpdump_name test.pcap
set file name: test.pcap
msh />
```

## 4、注意事项

暂无

## 5、联系方式 & 感谢

* 维护：[never](https://github.com/neverxie)
* 主页：https://github.com/neverxie/tcpdump
