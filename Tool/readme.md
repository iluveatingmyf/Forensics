**FilterProtocol**
- 过滤协议
- 筛选IP地址
- frequent 函数暂时没用

**HATrafficAnalyzer**
- 进行netwwork flow的重组
- 有一些具体的网络事件，不能单纯的通过port ip 来划分，他可能会更换port，两个或多个本来的networkflow组成一个网络事件。例如，两个连续的udp flow代表的是gateway的开启事件
- [138,106],[122,106]
