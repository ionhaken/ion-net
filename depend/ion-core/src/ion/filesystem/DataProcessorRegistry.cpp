#include <ion/filesystem/DataProcessorRegistry.h>
#include <ion/filesystem/File.h>
namespace ion
{

size_t DataProcessorRegistry::Process(const char* name, ArrayView<byte, uint32_t>& dst, const ArrayView<byte, uint32_t>& src,
									  ion::JobScheduler* js, FileJobWorkspace& workspace) const
{
	auto iter = mTypeToProcessor.Find(name);
	ION_ASSERT(iter != mTypeToProcessor.End(), "Missing processor " << name);
	return iter->second.mProcessFunc(dst, src, workspace, js);
}

}  // namespace ion
