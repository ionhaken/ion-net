#pragma once

#include <ion/memory/Memory.h>

namespace ion
{
template <typename BaseResource, MemTag Tag>
class TSMultiPoolResource;

class VirtualMemoryBuffer;

using NetInterfaceResource = TSMultiPoolResource<VirtualMemoryBuffer, ion::tag::Network>;

template <typename T, typename Source>
class ArenaAllocator;

template <typename T>
class Ptr;

template <typename T, typename Resource>
using ArenaPtr = ion::Ptr<T>;

struct NetCommand;
using NetCommandPtr = ArenaPtr<NetCommand, NetInterfaceResource>;

class BitStream;
struct RequestedConnection;

enum class NetBindResult;
struct NetConnections;
struct NetControl;
struct NetInterface;
struct NetReception;
struct NetExchange;
struct NetStartupParameters;

template <typename T, typename ResourceProxy>
class DomainAllocator;

class NetResourceProxy;

}  // namespace ion
