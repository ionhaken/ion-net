#pragma once

#include <ion/memory/Memory.h>
#include <ion/memory/MemoryScope.h>

#if ION_CONFIG_DEV_TOOLS

#include <memory>

namespace ion
{

	using alloc = std::allocator<uint8_t>;

// Debug allocator that uses native allocation, but skips memory tracking.
template <typename T>
class DebugAllocator
{
public:
	using value_type = T;
	using size_type = size_t;
	using difference_type = ptrdiff_t;

	//using propagate_on_container_copy_assignment = std::false_type;
	using propagate_on_container_move_assignment = std::true_type;
	//using propagate_on_container_swap = std::false_type;

	template <class U>
	struct rebind
	{
		using other = DebugAllocator<U>;
	};
	using is_always_equal = std::true_type;

	DebugAllocator() {}
	DebugAllocator(const DebugAllocator&) throw() {}

	template <class U>
	DebugAllocator(const DebugAllocator<U>&) throw()
	{
	}
	[[nodiscard]] inline T* allocate(size_t num)
	{
		ION_MEMORY_SCOPE(ion::tag::IgnoreLeaks);
		return reinterpret_cast<T*>(ion::detail::NativeMalloc(num * sizeof(T)));
	}

	inline void deallocate(void* p, size_t /*n*/) { ion::detail::NativeFree(p); }
};

}  // namespace ion
#endif
