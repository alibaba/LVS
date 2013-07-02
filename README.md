LVS
===

A distribution of Linux Virtual Server with some advanced features.

FullNAT: A new packet forwarding method for IPVS, other than DR/NAT/TUNNEL
The main principle is as follows: the module introduces local ip address (IDC internal ip address, lip), IPVS translates cip-vip to/from lip-rip, in which lip and rip both are IDC internal ip address, so that LVS load balancer and real servers can be in different vlans, and real servers only need to access internal network. See Virtual Server via Full NAT for more information. 

SYNPROXY: Defence module against synflooding attack
The main principle: based on tcp syncookies, please refer to http://en.wikipedia.org/wiki/SYN_cookies; 

This FullNAT and SYNPROXY code for IPVS in Linux kernel 2.6.32 was written by Jiaming Wu,Jiajun Chen,Ziang Chen,Shunmin Zhu at taobao.com, Jian Chen at 360.cn, with some advising from Wensong Zhang at taobao.com. The code was affected by ideas of the source NAT and SYNPROXY version that was hard coded to IPVS in Linux kernel 2.6.9 by Wen Li, Yan Tian, Jian Chen, Yang Yi, Yaoguang Sun, Fang Han, Ying liu and Jiaming Wu at baidu.com in 2009.

The FullNAT and SYNPROXY support were added to keepalived/ipvsadm by Jiajun Chen and Ziang Chen at taobao.com.
