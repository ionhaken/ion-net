Ion Net
===========================

Ion Net is a networking library, which provides basic transport for applications. 

Ion was originally a RakNet fork, but it has been since rewritten from many parts.
The biggest change is replacing the RakNet ARQ protocol with KCP [1]. KCP provides better latency than Sliding Window 
or UDT by sacrificing some bandwidth [2] (Please see also benchmarks below). KCP is a really good bet, 
if you are implementing fast paced multiplayer games. [3]

[1] https://github.com/skywind3000/kcp
[2] https://www.improbable.io/blog/kcp-a-new-low-latency-secure-network-stack
[3] https://paytonturnage.com/writing/latency-of-reliable-streams/


Library Goals
-------------
- Easy to use.
- Robust. Tested and fuzzed. Library peer instances can run 24/7 without need to restart or do any maintenance.
- Tenacious. Ability to handle poor network conditions or malicious data.
- Efficient. Fast data serialization/deserialization with no extra copying. Feasible for thousands of simultanous connections.


Key features
------------------------------------------
- Message ordering on multiple channels 
- Message coalescence, splitting and reassembly of packets
- Congestion control
- Data encryption
- MTU discovery
- Bandwidth stats
- Time synchronization
- Modifiable via plugin support


Limitations
------------------------------------------
- Tailored for client-server model and hence has no support for NAT Punch or UPnP.


Benchmarks
-----------------------------------------
Benchmark code is under benchmark directory. As a RakNet reference, Jul 1, 2021 snapshot of SLikeNet was used, because original RakNet build does not compile out of the box. 

Benchmarks have been run using Intel i5-9600k CPU with 32 GB memory and Windows 10/VS2022 17.2.6. For packet loss test cases debug build has been used since in RakNet reference network simulator is available only in debug build. This has insignificant impact on results.


1. Testing real conditions. Measured client to server messaging with 20ms RTT latency. Reported results are high mean values including standard deviation.

|Test case                                         |Ion Net|RakNet reference|
|--------------------------------------------------|-------|----------------|
|400B reliable ordered packet - no packet loss     |28ms   |28ms |
|400B reliable ordered packet - 1% packet loss 	   |40ms   |85ms |
|400B reliable ordered packet - 5% packet loss     |55ms   |125ms|

- Better ARQ implementation significantly improves performance on packet loss situations.


2. Testing ideal conditions. Measured client to server messaging with no latencies to detect protocol overhead. Reported results are low mean values. Command line parameter "--benchmark-samples 2000" was used to run tests.

|Test case                                         |Ion Net|RakNet reference|
|--------------------------------------------------|-------|----------------|
|400B unrealiable packet               	           |0.2ms  |0.3ms |
|400B reliable ordered packet            	       |0.3ms  |0.3ms |
|32KB reliable ordered packet        	           |0.6ms  |1.3ms |
|1300B unreliable 20 packets burst 		           |0.5ms  |1.0ms |
|1300B reliable 20 packets burst 		           |0.5ms  |1.0ms |
|1300B reliable packet by 4 clients same PC        |0.3ms  |0.4ms |

- In general,  Ion Net implementation has less than or equal CPU overhead compared to the reference.
- RakNet reference may be limited by its congestion control.
- Note that most of the measured time these tests spend on waiting for update thread to wake up, the actual processing time is ~10% of measured time. It would be possible to busy loop receiver and sender to relay packets in less than 0.1 milliseconds, but that use case is not in the scope of game networking library - current send delays should be more than adequate for any game.



Getting Started
-----------------------------------------
Run cmake from your work directory, e.g. "cmake [Ion Net root directory]"


Example implementations
-----------------------------------------

Please see example_client and example_server under samples/ for examples.
