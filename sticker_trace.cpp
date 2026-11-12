#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <filesystem>
#include <fstream>
#include <array>
#include <chrono>
#include <mutex>
#include <vector>
#include <string>
#include "MinHook.h"
#include "json.hpp"
#include "sticker_sender.h"
namespace WeChatAgentSticker {
namespace {
using DispatchCall=uintptr_t(*)(uintptr_t,uintptr_t,uintptr_t,bool);
DispatchCall original=nullptr;
using VoiceCall=void(*)(uintptr_t,uintptr_t,uintptr_t,uintptr_t,unsigned long long,uintptr_t);
VoiceCall originalVoice=nullptr;
void VoiceTraced(uintptr_t,uintptr_t,uintptr_t,uintptr_t,unsigned long long,uintptr_t);
uintptr_t TracedDispatch(uintptr_t,uintptr_t,uintptr_t,bool);
std::mutex traceMutex;
std::string target;
ULONGLONG expires=0;
std::vector<nlohmann::json> rows;
struct Snapshot {
    uintptr_t vtable=0; unsigned type=0,subtype=0,infoType=0;
    bool emoji=false,hasInfo=false,hasSecondary=false; char md5[33]{};
    std::array<size_t,11> lengths{};
    std::array<unsigned,11> categories{};
    std::array<uint64_t,8> baseFields{};
};
// This bounded, target-specific diagnostic records layout metadata only. It
// never copies text, URLs, AES keys, usernames or resource contents to output.
bool Inspect(uintptr_t body,const char* receiver,size_t receiverSize,uintptr_t base,Snapshot* out) {
    __try {
        auto length=*reinterpret_cast<size_t*>(body+0xC0);
        auto cap=*reinterpret_cast<size_t*>(body+0xC8);
        auto value=cap<16?reinterpret_cast<const char*>(body+0xB0):*reinterpret_cast<const char**>(body+0xB0);
        if(length!=receiverSize || memcmp(value,receiver,length))return false;
        out->vtable=*reinterpret_cast<uintptr_t*>(body)-base;
        out->type=*reinterpret_cast<unsigned*>(body+0xD8);
        out->subtype=*reinterpret_cast<unsigned*>(body+0xDC);
        const uintptr_t offsets[]={0x98,0xA0,0xF0,0x118,0x178,0x188,0x6B8,0x728};
        for(size_t i=0;i<8;i++)out->baseFields[i]=i==7?(*reinterpret_cast<uint64_t*>(body+offsets[i])!=0):*reinterpret_cast<uint64_t*>(body+offsets[i]);
        out->emoji=out->vtable==EmojiVtable;
        if(!out->emoji)return true;
        auto info=*reinterpret_cast<uintptr_t*>(body+0x708);
        out->hasInfo=info!=0;
        out->hasSecondary=*reinterpret_cast<uintptr_t*>(body+0x718)!=0;
        if(!info)return true;
        out->infoType=*reinterpret_cast<unsigned*>(info+8);
        for(size_t i=0;i<11;i++) {
            auto offset=i<10?0x10+i*0x20:0x160;
            auto size=*reinterpret_cast<size_t*>(info+offset+0x10);
            auto capacity=*reinterpret_cast<size_t*>(info+offset+0x18);
            auto bytes=capacity<16?reinterpret_cast<const char*>(info+offset):*reinterpret_cast<const char**>(info+offset);
            out->lengths[i]=size;
            if(!size)continue;
            if(size>32768){out->categories[i]=9;continue;}
            bool hex=true;
            for(size_t j=0;j<size;j++)if(!((bytes[j]>='0'&&bytes[j]<='9')||(bytes[j]>='a'&&bytes[j]<='f'))) {hex=false;break;}
            out->categories[i]=hex?1:(size>=4&&memcmp(bytes,"http",4)==0)?2:(size>2&&bytes[1]==':')?3:4;
            if(i==0&&size==32&&hex)memcpy(out->md5,bytes,32);
        }
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {return false;}
}
uintptr_t SingleBody(uintptr_t vector) {
    __try {auto begin=*reinterpret_cast<uintptr_t*>(vector);auto end=*reinterpret_cast<uintptr_t*>(vector+8);return end-begin==16?*reinterpret_cast<uintptr_t*>(begin):0;}
    __except(EXCEPTION_EXECUTE_HANDLER) {return 0;}
}

// ---- generic dispatch trace (layout metadata only, no message content) ----
struct RawSnapshot {uintptr_t vtable=0;unsigned type=0,subtype=0;std::array<uint64_t,8> fields{};std::array<uint8_t,0x140> bytes{};uintptr_t p0=0,p1=0;};
bool ReadRaw(uintptr_t body,uintptr_t base,RawSnapshot* out) {
    __try {
        out->vtable=*reinterpret_cast<uintptr_t*>(body)-base;
        out->type=*reinterpret_cast<unsigned*>(body+0xD8);
        out->subtype=*reinterpret_cast<unsigned*>(body+0xDC);
        const uintptr_t offsets[]={0x98,0xA0,0xF0,0x118,0x178,0x188,0x6B8,0x728};
        for(size_t i=0;i<8;i++)out->fields[i]=*reinterpret_cast<uint64_t*>(body+offsets[i]);
        if(out->type==34){memcpy(out->bytes.data(),reinterpret_cast<const void*>(body),out->bytes.size());out->p0=*reinterpret_cast<uintptr_t*>(body+0x08);out->p1=*reinterpret_cast<uintptr_t*>(body+0x10);}
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {return false;}
}
std::mutex dispatchMutex;
ULONGLONG dispatchExpires=0;
std::vector<nlohmann::json> dispatchRows;
constexpr size_t kDispatchRows=200;
constexpr ULONGLONG kDispatchWindowMs=10ull*60ull*1000ull;
bool ReadBlock(uintptr_t address,uint8_t* out,size_t length) {
    if(!address)return false;
    __try {memcpy(out,reinterpret_cast<const void*>(address),length);return true;}
    __except(EXCEPTION_EXECUTE_HANDLER) {return false;}
}
std::string HexOf(const uint8_t* data,size_t length) {
    static const char* digits="0123456789abcdef";
    std::string hex;hex.reserve(length*2);
    for(size_t i=0;i<length;i++){hex.push_back(digits[data[i]>>4]);hex.push_back(digits[data[i]&15]);}
    return hex;
}
void ReadStdString(uintptr_t str,char* out,size_t outCap,size_t* length) {
    if(!out||!outCap)return;
    *length=0;out[0]=0;
    __try {
        size_t size=*reinterpret_cast<size_t*>(str+0x10);
        size_t cap=*reinterpret_cast<size_t*>(str+0x18);
        *length=size;
        if(!size)return;
        const char* data=cap<16?reinterpret_cast<const char*>(str):*reinterpret_cast<const char**>(str);
        if(!data)return;
        size_t copy=size<outCap-1?size:outCap-1;
        memcpy(out,data,copy);out[copy]=0;
    } __except(EXCEPTION_EXECUTE_HANDLER) {*length=~(size_t)0;}
}
void VoiceTraced(uintptr_t a,uintptr_t b,uintptr_t c,uintptr_t d,unsigned long long e,uintptr_t f) {
    try {
        char target[160]={0}, data[160]={0};
        size_t targetLen=0,dataLen=0;
        ReadStdString(b,target,sizeof(target)-1,&targetLen);
        ReadStdString(c,data,sizeof(data)-1,&dataLen);
        std::string hex;
        {static const char* digits="0123456789abcdef";size_t n=dataLen<120?dataLen:120;for(size_t i=0;i<n;i++){unsigned char ch=(unsigned char)data[i];hex.push_back(digits[ch>>4]);hex.push_back(digits[ch&15]);}}
        std::string ascii;
        {size_t n=dataLen<120?dataLen:120;for(size_t i=0;i<n;i++){unsigned char ch=(unsigned char)data[i];ascii.push_back(ch>=32&&ch<127?(char)ch:'.');}}
        if(dataLen&&dataLen<4000000&&dataLen!=~(size_t)0){
            try {
                wchar_t module[MAX_PATH]{};
                auto self=GetModuleHandleW(L"version.dll");
                if(self&&GetModuleFileNameW(self,module,MAX_PATH)){
                    auto dir=std::filesystem::path(module).parent_path().parent_path().parent_path().parent_path();
                    auto out=dir/L"state"/L"voices";
                    std::error_code ec;std::filesystem::create_directories(out,ec);
                    auto file=out/(std::wstring(L"capture-")+std::to_wstring(GetTickCount64())+L".silk");
                    std::ofstream write(file,std::ios::binary);write.write(data,static_cast<std::streamsize>(dataLen));
                }
            } catch(...) {}
        }
        std::lock_guard<std::mutex> guard(dispatchMutex);
        if(GetTickCount64()>dispatchExpires||dispatchRows.size()>=kDispatchRows)return;
        unsigned char extra[0x28]={0}; size_t extraHexLen=ReadBlock(f,extra,sizeof(extra))?sizeof(extra):0;
        std::string extraHex;
        {static const char* digits="0123456789abcdef";for(size_t i=0;i<extraHexLen;i++){unsigned char ch=(unsigned char)extra[i];extraHex.push_back(digits[ch>>4]);extraHex.push_back(digits[ch&15]);}}
        nlohmann::json row={{"kind","voice-call"},{"tick",GetTickCount64()},{"target",target},{"targetLen",targetLen},{"dataLen",dataLen},{"dataHex",hex},{"dataAscii",ascii},{"dur",e},{"arg1",a},{"arg2",b},{"arg5",e},{"arg6",f},{"extraHex",extraHex}};
        dispatchRows.push_back(std::move(row));
    } catch(...) {}
    originalVoice(a,b,c,d,e,f);
}
void ObserveAny(uintptr_t vector) {
    {std::lock_guard<std::mutex> guard(dispatchMutex);if(GetTickCount64()>dispatchExpires||dispatchRows.size()>=kDispatchRows)return;}
    auto base=reinterpret_cast<uintptr_t>(GetModuleHandleW(L"Weixin.dll"));
    if(!base)return;
    auto body=SingleBody(vector);
    if(!body)return;
    RawSnapshot snapshot;
    if(!ReadRaw(body,base,&snapshot))return;
    std::lock_guard<std::mutex> guard(dispatchMutex);
    if(GetTickCount64()>dispatchExpires||dispatchRows.size()>=kDispatchRows)return;
    nlohmann::json row={{"tick",GetTickCount64()},{"vtableRva",snapshot.vtable},{"type",snapshot.type},{"subtype",snapshot.subtype}};
    row["baseFields"]=snapshot.fields;
    if(snapshot.type==34){
        row["hex"]=HexOf(snapshot.bytes.data(),snapshot.bytes.size());
        row["p0"]=snapshot.p0;row["p1"]=snapshot.p1;
        std::array<uint8_t,0x100> b0{},b1{};
        if(ReadBlock(snapshot.p0,b0.data(),b0.size()))row["hexP0"]=HexOf(b0.data(),b0.size());
        if(ReadBlock(snapshot.p1,b1.data(),b1.size()))row["hexP1"]=HexOf(b1.data(),b1.size());
    }
    dispatchRows.push_back(std::move(row));
}
bool EnsureHook() {
    if(original)return true;
    auto base=reinterpret_cast<uintptr_t>(GetModuleHandleW(L"Weixin.dll"));
    if(!base)return false;
    auto status=MH_Initialize();if(status!=MH_OK&&status!=MH_ERROR_ALREADY_INITIALIZED)return false;
    auto address=reinterpret_cast<void*>(base+Dispatch);
    if(MH_CreateHook(address,reinterpret_cast<void*>(TracedDispatch),reinterpret_cast<void**>(&original))!=MH_OK)return false;
    if(MH_EnableHook(address)!=MH_OK){MH_RemoveHook(address);original=nullptr;return false;}
    if(!originalVoice){
        auto voiceAddress=reinterpret_cast<void*>(base+0x6199D10);
        if(MH_CreateHook(voiceAddress,reinterpret_cast<void*>(VoiceTraced),reinterpret_cast<void**>(&originalVoice))==MH_OK){
            if(MH_EnableHook(voiceAddress)!=MH_OK){MH_RemoveHook(voiceAddress);originalVoice=nullptr;}
        }
    }
    return true;
}
void Observe(uintptr_t vector) {
    std::string selected;
    {std::lock_guard<std::mutex> lock(traceMutex);if(GetTickCount64()>expires||target.empty())return;selected=target;}
    auto base=reinterpret_cast<uintptr_t>(GetModuleHandleW(L"Weixin.dll"));
    Snapshot snapshot;
    auto body=SingleBody(vector);if(!body)return;
    if(!Inspect(body,selected.data(),selected.size(),base,&snapshot))return;
    nlohmann::json row={{"tick",GetTickCount64()},{"vtableRva",snapshot.vtable},{"type",snapshot.type},{"subtype",snapshot.subtype},{"emojiClass",snapshot.emoji},{"hasInfo",snapshot.hasInfo},{"hasSecondary",snapshot.hasSecondary}};
    row["baseFields"]=snapshot.baseFields;
    if(snapshot.hasInfo){row["infoType"]=snapshot.infoType;row["md5"]=snapshot.md5;row["fieldLengths"]=snapshot.lengths;row["fieldCategories"]=snapshot.categories;}
    std::lock_guard<std::mutex> lock(traceMutex);
    if(target!=selected||GetTickCount64()>expires)return;
    if(rows.size()>=20)rows.erase(rows.begin());rows.push_back(std::move(row));
}
uintptr_t TracedDispatch(uintptr_t context,uintptr_t out,uintptr_t vector,bool flag) {
    try {ObserveAny(vector);}catch(...){}
    try {Observe(vector);}catch(...){}
    return original(context,out,vector,flag);
}
}
bool StartTrace(const std::string& selected) {
    std::lock_guard<std::mutex> lock(traceMutex);
    if(selected.empty()){target.clear();expires=0;return true;}
    if(!EnsureHook())return false;
    target=selected;expires=GetTickCount64()+5*60*1000;rows.clear();return true;
}
std::string TraceJson() {std::lock_guard<std::mutex> lock(traceMutex);return nlohmann::json({{"active",!target.empty()&&GetTickCount64()<=expires},{"rows",rows}}).dump();}
void StartDispatchTrace() {
    {std::lock_guard<std::mutex> lock(dispatchMutex);dispatchRows.clear();dispatchExpires=GetTickCount64()+kDispatchWindowMs;}
    if(!EnsureHook()){std::lock_guard<std::mutex> lock(dispatchMutex);dispatchExpires=0;}
}
void StopDispatchTrace() {std::lock_guard<std::mutex> lock(dispatchMutex);dispatchExpires=0;}
std::string DispatchTraceJson() {
    std::lock_guard<std::mutex> lock(dispatchMutex);
    return nlohmann::json({{"active",GetTickCount64()<=dispatchExpires},{"windowMs",kDispatchWindowMs},{"total",dispatchRows.size()},{"rows",dispatchRows}}).dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}
}
