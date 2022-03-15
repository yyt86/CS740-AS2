# CS740-AS2

This is the an implement of [Hedera](https://www.usenix.org/legacy/event/nsdi10/tech/full_papers/al-fares.pdf) , a dynamic flow scheduling system for data center network. Some files are base on the [Li Cheng's Ryu applications](https://github.com/muzixing/ryu/tree/master/ryu/app).
### Installation
1. install mininet according to the [instruction](http://mininet.org/download/)
	`` git://github.com/mininet/mininet ``
	`` mininet/util/install.sh -a``
	
2. install PRu 
``git clone git://github.com/osrg/ryu.git``
``cd ryu``
``pip install -r tools/optional-requires``
``sudo pip install  .``
3. install Networkx
``pip install networkx``
4. install bwm-ng
``sudo apt install bwm-ng``

5. replace ``ryu/ryu/flag.py`` with the file in the repo
### Run Experiments
First change the IP address in the ``fattree.py`` into your IP address, then run
```
./script.sh arg1 arg2 arg3 arg4
```
arg1 is port number in Fat-Tree topology, arg2 is the CPUs allocated to the hosts, arg3 is num of  Iperf TCP flows for each host, arg4 is the lasting time for the traffic. I use the ``./script.sh 4 1 1 30`` to test the program.
