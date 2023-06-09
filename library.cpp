//  Copyright (c) 2023 namazso <admin@namazso.eu>
//  
//  Permission to use, copy, modify, and/or distribute this software for any
//  purpose with or without fee is hereby granted.
//  
//  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
//  REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
//  AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
//  INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
//  LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
//  OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
//  PERFORMANCE OF THIS SOFTWARE.

#include <Windows.h>

#include <strsafe.h>

#include <cstdint>

using fnCreateXmlWriter = HRESULT(WINAPI*)(REFIID, void**, IMalloc*);

EXTERN_C __declspec(dllexport) HRESULT STDAPICALLTYPE CreateXmlWriter(REFIID riid, void** ppvObject, IMalloc* pMalloc) {
  static fnCreateXmlWriter p{};
  if (!p) {
    const auto lib = LoadLibraryExA("XmlLite.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    p = (fnCreateXmlWriter)GetProcAddress(lib, "CreateXmlWriter");
  }
  return p(riid, ppvObject, pMalloc);
}

void* follow_jumps(void* p) {
  auto pb = (uint8_t*)p;
  while (true) {
    if (pb[0] == 0xEB) {
      pb += 2 + (intptr_t) * ((int8_t*)&pb[1]);
      continue;
    }
    if (pb[0] == 0xE9) {
      pb += 5 + (intptr_t) * ((int32_t*)&pb[1]);
      continue;
    }
    if (pb[0] == 0xFF && pb[1] == 0x25) {
      pb = *(uint8_t**)(pb + 6 + (intptr_t) * ((int32_t*)&pb[2]));
      continue;
    }
    if (pb[0] == 0x48 && pb[1] == 0xFF && pb[2] == 0x25) {
      pb = *(uint8_t**)(pb + 7 + (intptr_t) * ((int32_t*)&pb[3]));
      continue;
    }
    break;
  }
  return pb;
}

LONG WINAPI hooked_CertVerifyTimeValidity(LPFILETIME pTimeToVerify, PCERT_INFO pCertInfo) {
  return 0;
}

VOID WINAPI hooked_GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime) {
  *lpSystemTimeAsFileTime = {};
}

static BOOL hook(void* fn, void* hook_fn) {
  const auto patch = follow_jumps(fn);

  struct hkstruct {
    uint8_t arr[8] = {0xff, 0x25, 2, 0, 0, 0, 0x90, 0x90};
    void* p{};
  } s;

  s.p = hook_fn;
  SIZE_T w{};
  return WriteProcessMemory((HANDLE)-1, patch, &s, sizeof(s), &w);
}

static void initialize() {
  hook((void*)&CertVerifyTimeValidity, (void*)hooked_CertVerifyTimeValidity);
  hook((void*)&GetSystemTimeAsFileTime, (void*)hooked_GetSystemTimeAsFileTime);
}

extern "C" BOOL WINAPI DllEntry(HINSTANCE, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH)
    initialize();
  return TRUE;
}
