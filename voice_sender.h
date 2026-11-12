#pragma once
#include <cstdint>
#include <string>
namespace WeixinSend { bool SendVoiceFile(const std::string& target,const std::string& path,uint32_t durationMs); }
namespace WeChatAgentVoice {
    inline constexpr uintptr_t VoiceFactory=0x619A190;
    inline constexpr uintptr_t VoiceVtable=0x8DD0028;
    inline constexpr uintptr_t VoiceOwnerVtable=0x8DCFF98;
}
