Ion - Ionhaken Core Library
===========================

Ion is open source library of application core components designed at <a href="https://ionhaken.com">Ionhaken</a> with performance in mind. It's purpose is to replace STL, Boost or other common c++ libraries for any software we build, because common c++ libraries tend to be large, complex and suited for many requirements, and we need something that fits exactly for our use cases without compromises. Additionally, we need our software to behave similar in all platforms, when possible, which prevents use of STL.


Features / Submodules
---------------------

* arena - Tools for managing memory arenas.
* batch - Classes for processing data in batches using SIMD.
* byte - Serializing, deserializing and buffering data in binary format.
* compression - Compression utilities
* concurrency - Primitives for concurrent processing. Mutexes, lock free queues, etc.
* container - Standard container types. Includes also custom dynamic array (vector) implementation, which supports small and tiny vector optimizations.
* core - Tweakables, concurrency, tracing, temporary, jobs and memory submodules require explicit initialization and memory allocation. Core is responsible for doing that in safe manner.  
* database - Database is data system implementation. Data is put into components and components are kept in component stores. The idea here is to allow configuring data layout anytime without needing to change how the data is being accessed. I.e. you can change data layout of a component store from/to structs of arrays or arrays of structs without need to do any changes to user code. You can tune your application when you have the actual use cases and know how your data is going to be accessed.
* debug - Development and error checking tools. This includes race condition checkers, memory leak tracking, profiling and error handling
* filesystem - Types for accessing file system.
* fixedpoint - Fixed-point classes.
* graph - Directed acyclic graph processing
* hw - Hardware specific functionality
* jobs - Job scheduler for processing tasks in parallel. You can also have timed jobs via Job Dispatcher.
* json - JSON wrapper
* memory - Memory resources and allocators. Including general purpose memory allocator taking advantage of TLSF
* string - String wrappers
* temporary - Temporary allocator for short-term allocations. Useful for events or internal messages that are expected to be deallocated on reception.
* time - System time module.
* tracing - Logging implementation. Since most time of logging is spent on writing logs to output, Tracing will try defer all logging in a lock free manner to a separate thread.
* tweakables - Customizable variables that can be set from code, commadline or using a JSON file. They do allow also hardcoded values for final build.
* util - Collection of miscellaneous tools that did not fit in any other module.


# Library Design Pillars

* Performance first in production
- We want to fail as fast as possible during development. When ever our code needs to assume something it has hard checks and program termination if assumptions were not valid. If there is abnormal behaviour code still needs to handle, we'll have error logging for that. However, for final product, we assume code is well tested during development hence for released product all error checks are disabled and there is no defensive coding enabled.

Disclaimer: We use microbenchmarking rigorously and run large scale application tests, but we are obviously fast only for our own use cases. If you want to compare performance you should at least have all optimizations enabled, and define macros _RETAIL and _FINAL.

* Optimize for worst case
- We want to run well when all CPU cores are saturated. Due to this reason spin locks are not allowed, for example.

* No need to match STL or other APIs
- We have custom API that does not match with other libarires - We define functionality and use naming that works best for us. 


Internal coding guidelines
--------------------------

* Subset of c++20
- We use only c++ features that improve readability, but don't hurt performance. We avoid heavy abstractions until it's proven that they are as fast as having no abstractions.
- We do not use c++ features that would reduce our platform support.

* No exceptions
- Exception handling is slow, therefore we do not let the code raise exceptions at all. 
- Exceptions are questionable from readability point of view. Code flow with error codes is pretty clear.

* No RTTI


Current Limitations
---------------------

* Supported platforms
- Android (32-bit&64-bit)
- Linux
- Windows


Getting Started
---------------

You can use CMake or the unofficial way, which is to just take code under ion/ and 3rdpary/, and copy them over to your own project. Check that settings in ion/Config.h are correct. In your main() you need to add an instance of ion::Engine to support full Ion functionality.
