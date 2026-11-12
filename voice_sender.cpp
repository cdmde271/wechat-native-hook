#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <string>
#include "global.h"
#include "voice_sender.h"

namespace WeixinSend {
    struct InnerStruct2;
    InnerStruct2* BuildSendParam1(uint64_t);
    void BuildSendParam2_Image(uint64_t*);

    struct SharedMessage { uintptr_t body, owner; };
    // Layout measured from a real client send: {4, 3, 30000, 0, empty string}.
    struct VoiceExtra { uint64_t a; uint64_t b; uint8_t c; std::string s; };

    bool SendVoiceFile(const std::string& target,const std::string& path,uint32_t durationMs) {
        auto base=reinterpret_cast<uintptr_t>(GetModuleHandleW(L"Weixin.dll"));
        if(!base)return false;
        std::ifstream input(path,std::ios::binary);
        if(!input)return false;
        std::string raw((std::istreambuf_iterator<char>(input)),std::istreambuf_iterator<char>());
        if(raw.size()<10)return false;
        // The client stores the voice payload with a leading 0x02 format byte
        // before the SILK stream header.
        std::string data;
        if(static_cast<unsigned char>(raw[0])==0x02)data=raw;
        else{data.reserve(raw.size()+1);data.push_back(static_cast<char>(0x02));data+=raw;}
        std::string destination=target;
        uint32_t duration=durationMs?durationMs:3000;
        VoiceExtra extra{};
        extra.a=0x0000000300000004ull;
        extra.b=30000;
        extra.c=0;
        SharedMessage message{};
        using Factory=SharedMessage*(*)(SharedMessage*,void*,void*,void*,void*);
        reinterpret_cast<Factory>(base+WeChatAgentVoice::VoiceFactory)(&message,&destination,&data,&duration,&extra);
        if(!message.body||!message.owner)return false;
        if(*reinterpret_cast<uintptr_t*>(message.body)!=base+WeChatAgentVoice::VoiceVtable)return false;
        *reinterpret_cast<uint32_t*>(message.body+0xD8)=34;
        auto first=BuildSendParam1(message.owner);
        auto second=static_cast<uint64_t*>(HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,0xE8));
        if(!first||!second)return false;
        BuildSendParam2_Image(second);
        using Send=__int64(*)(uint64_t,uint64_t);
        reinterpret_cast<Send>(base+offset::send_message)(reinterpret_cast<uint64_t>(first),reinterpret_cast<uint64_t>(second));
        return true;
    }
}
