# wechat-native-hook (voice + mentions)

Native additions for a WeChat 4.1.10.27 hook DLL. These are the parts I wrote;
the upstream proxy DLL and the route scaffold are not included.

## What is here

| File | Purpose |
|---|---|
| `voice_sender.cpp` / `.h` | Builds a WeChat voice message object and dispatches it, so a SILK payload becomes a real voice bubble. Takes the target wxid, the silk file and the duration. |
| `sticker_trace.cpp` | Dispatch tracing plus a receive-side voice hook used while reverse engineering the message layout. Writes captured silk payloads to `state/voices/`. |
| `wechatagent_hook.cpp` | Route layer: `/SendTextMsg` (with `atlist` for @mentions), `/SendImgMsg`, `/SendVoiceMsg`, `/SendFileMsg`, a dispatch trace and a heap scan used to locate voice payloads. |

## Key findings

- A voice message is the SILK stream itself; no CDN upload is involved.
- Layout: target string at `+0xB0`, type 34 at `+0xD8`, silk string at `+0x708`,
  duration at `+0x728`, extra block at `+0x730`.
- Text messages carry a mention list at `+0x728` (`atlist`), which is what makes
  `@name` render as a real mention.

## Build

Drop the files into the `src/` folder of the hook project, add the new
`ClCompile` entries, and build with Visual Studio 2022. Offsets are for
WeChat 4.1.10.27 (Weixin.dll) only.

## Warning

This is research code for a WeChat client you own. Hook injection into a chat
client may violate the service terms and can get accounts limited. Use it on an
account you can afford to lose.

MIT licensed.
