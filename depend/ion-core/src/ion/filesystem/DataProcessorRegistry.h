#pragma once

#include <ion/container/UnorderedMap.h>

#include <ion/string/String.h>

namespace ion
{

class JobScheduler;

struct FileJobWorkspace;
class DataProcessorRegistry
{
public:
	using ProcessorProcessFunc = size_t (*)(ArrayView<byte, uint32_t>& dst, const ArrayView<byte, uint32_t>& src, FileJobWorkspace& workspace,
										  ion::JobScheduler* js);
	using ProcessorDeinitFunc = void (*)(FileJobWorkspace& workspace);

	struct Processor
	{
		ProcessorProcessFunc mProcessFunc;
	};

	template <typename T>
	void RegisterProcessor(const char* name)
	{
		auto iter = mTypeToProcessor.Insert(name, Processor());
		iter->second.mProcessFunc = &T::ProcessorWork;
	}

	size_t Process(const char* name, ArrayView<byte, uint32_t>& dst, const ArrayView<byte, uint32_t>& src, ion::JobScheduler* js,
				   FileJobWorkspace& workspace) const;


private:
	ion::UnorderedMap<ion::String, Processor> mTypeToProcessor;
};

}  // namespace ion
