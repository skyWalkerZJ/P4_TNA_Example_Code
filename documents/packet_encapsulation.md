# what we solved
tunnel在网络中被广泛应用，常见的tunnel有GRE tunnel，IP tunnel等。通常我们需要在router或switch上做tunnel的encapsulation与decapsulation。在fault injection的场景中，我们考虑到可能出现的miss encapsulation/decapsulation.<br>
packet_capsulation.p4实现了基本的encapsulation/decapsulation,可以通过在数据面下发特定的表项实现IP/GRE encapsulation以及自定义encapsulation。
# How we solved it
![流程图](https://github.com/skyWalkerZJ/Zion/blob/main/image/capsulation.jpg)
# tips
1. IP encapsulation包括IPv4和IPv6两部分。
2. 自定义encapsulation规则有限，仅提供了三个自定义header,分别为20bytes,28bytes,40bytes.
# something not solved
1. 在对IP报文重新封装的过程中，可能会与MTU不符，该程序忽略了此问题。
2. 隧道的类型对应的索引为自定义的，非标准，具体以控制平面下发的表项为准。
