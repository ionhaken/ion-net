#include <ion/string/StringWriter.h>
#include <ion/string/StringView.h>
#include <ion/util/Math.h>
namespace ion
{
UInt StringWriter::Write(const StringView& str)
{
	if (Available() == 0)
	{
		return 0;
	}
	size_t length = ion::Min(Available() - 1, str.Length());
	memcpy(mBuffer, str.Copy(), length);
	Skip(length);
	Write(0);
	return SafeRangeCast<UInt>(length);
}



}  // namespace ion
