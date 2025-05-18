#include "pch.h"

#include <memedit.h>
#include <timeapi.h>
#include <WS2tcpip.h>
#include "logger.h"
#include "hooker.h"

constexpr UINT WM_SOCKET_MSG = WM_USER + 1;

typedef VOID(__fastcall *_CSecurityClient__OnPacket_t)(CSecurityClient *pThis, PVOID edx, CInPacket *iPacket);

VOID __fastcall CSecurityClient__OnPacket_Hook(CSecurityClient *pThis, PVOID edx, CInPacket *iPacket) {
    Log("CSecurityClient::OnPacket.");
}

typedef VOID(__fastcall *_CClientSocket__Connect_addr_t)(CClientSocket *pThis, PVOID edx, const sockaddr_in *pAddr);
VOID __fastcall CClientSocket__Connect_Addr_Hook(CClientSocket *pThis, PVOID edx, const sockaddr_in *pAddr);

typedef INT(__fastcall *_CClientSocket__OnConnect_t)(CClientSocket *pThis, PVOID edx, INT bSuccess);

INT __fastcall CClientSocket__OnConnect_Hook(CClientSocket *pThis, PVOID edx, int bSuccess) {
    Log("CClientSocket::OnConnect(bSuccess = %d)", bSuccess);
    if (!pThis->m_ctxConnect.lAddr.GetCount()) {
        return 0;
    }
    if (!bSuccess) {
        if (!pThis->m_ctxConnect.posList) {
            pThis->Close();
            if (pThis->m_ctxConnect.bLogin) {
                Log("CClientSocket::OnConnect login connection failed (570425345)");
                return 0;
            }
            Log("CClientSocket::OnConnect non-login connection failed (553648129)");
            return 0;
        }
        CClientSocket__Connect_Addr_Hook(pThis, edx, pThis->m_ctxConnect.lAddr.GetHeadPosition());
        return 0;
    }

    constexpr int BUFFER_SIZE = 1460;
    ZRef<ZSocketBuffer> pBuff = ZRef<ZSocketBuffer>();
    pBuff.p = ZSocketBuffer::Alloc(BUFFER_SIZE);
    if (!pBuff.p) {
        Log("ZSocketBuffer::Alloc failed");
        CClientSocket__OnConnect_Hook(pThis, edx, 0);
        return 0;
    }
    if (pBuff.p->m_nRef) {
        InterlockedIncrement(&pBuff.p->m_nRef);
    }
    char* buffer = pBuff.p->buf;
    int bytesReceived;
    int total_bytes_in_buffer = 0;
    int retries_left = 40;

    do {
        bytesReceived = recv(pThis->m_sock._m_hSocket, buffer + total_bytes_in_buffer, BUFFER_SIZE - total_bytes_in_buffer, 0);
        if (bytesReceived > 0) {
            total_bytes_in_buffer += bytesReceived;
            break; 
        }
        if (bytesReceived == 0) {
            Log("CClientSocket::OnConnect connection closed by peer during handshake recv.");
            CClientSocket__OnConnect_Hook(pThis, edx, 0);
            return 0;
        }
        // bytesReceived == -1 (error)
        int wsaLastError = WSAGetLastError();
        Log("CClientSocket::OnConnect recv wsaLastError=[%d]", wsaLastError);
        if (wsaLastError == WSAEWOULDBLOCK) {
            if (--retries_left < 0) {
                Log("CClientSocket::OnConnect recv timeout on WSAEWOULDBLOCK.");
                CClientSocket__OnConnect_Hook(pThis, edx, 0);
                return 0;
            }
            Sleep(50);
        } else {
            Log("CClientSocket::OnConnect recv error.");
            CClientSocket__OnConnect_Hook(pThis, edx, 0);
            return 0;
        }
    } while (retries_left >= 0);

    if (total_bytes_in_buffer == 0 && retries_left < 0) {
         CClientSocket__OnConnect_Hook(pThis, edx, 0);
         return 0;
    }


    Log("CClientSocket::OnConnect Recv Decoding (%d bytes)", total_bytes_in_buffer);
    unsigned short majorVersion;
    char *current_ptr = buffer;
    int remaining_len = total_bytes_in_buffer;
    int consumed_len;

    consumed_len = CIOBufferManipulator::Decode2(&majorVersion, current_ptr, remaining_len);
    if (consumed_len == 0) { Log("Failed to decode majorVersion."); CClientSocket__OnConnect_Hook(pThis, edx, 0); return 0; }
    current_ptr += consumed_len; remaining_len -= consumed_len;
    Log("CClientSocket::OnConnect majorVersion=[%hu]", majorVersion);

    ZXString<char> minorVersion = ZXString<char>();
    consumed_len = CIOBufferManipulator::DecodeStr(&minorVersion, current_ptr, remaining_len);
    if (consumed_len == 0 && minorVersion.GetLength() == 0) { Log("Failed to decode minorVersion."); CClientSocket__OnConnect_Hook(pThis, edx, 0); return 0; }
    current_ptr += consumed_len; remaining_len -= consumed_len;
    Log("CClientSocket::OnConnect minorVersion=[%s]", minorVersion.m_pStr ? minorVersion.m_pStr : "NULL");
    
    int version = atoi(minorVersion.m_pStr ? minorVersion.m_pStr : "");
    minorVersion.Empty();
    Log("CClientSocket::OnConnect version=[%d]", version);

    unsigned int uSeqSnd;
    consumed_len = CIOBufferManipulator::Decode4(&uSeqSnd, current_ptr, remaining_len);
    if (consumed_len == 0) { Log("Failed to decode uSeqSnd."); CClientSocket__OnConnect_Hook(pThis, edx, 0); return 0; }
    current_ptr += consumed_len; remaining_len -= consumed_len;

    unsigned int uSeqRcv;
    consumed_len = CIOBufferManipulator::Decode4(&uSeqRcv, current_ptr, remaining_len);
    if (consumed_len == 0) { Log("Failed to decode uSeqRcv."); CClientSocket__OnConnect_Hook(pThis, edx, 0); return 0; }
    current_ptr += consumed_len; remaining_len -= consumed_len;

    unsigned char nVersionHeader;
    consumed_len = CIOBufferManipulator::Decode1(&nVersionHeader, current_ptr, remaining_len);
    if (consumed_len == 0) { Log("Failed to decode nVersionHeader."); CClientSocket__OnConnect_Hook(pThis, edx, 0); return 0; }
    current_ptr += consumed_len; remaining_len -= consumed_len;

    if (remaining_len < 0) {
        Log("Buffer underflow during decoding.");
        CClientSocket__OnConnect_Hook(pThis, edx, 0);
        return 0;
    }


    Log("CClientSocket::OnConnect nVersionHeader=[%hhu]", nVersionHeader);
    Log("CClientSocket::OnConnect m_uSeqSnd=[%u] m_uSeqRcv=[%u]", uSeqSnd, uSeqRcv);
    pThis->m_uSeqSnd = uSeqSnd;
    pThis->m_uSeqRcv = uSeqRcv;

    int nGameStartMode = CWvsApp::GetInstance()->m_nGameStartMode;
    Log("CClientSocket::OnConnect m_nGameStartMode=[%d]", nGameStartMode);
    if (nGameStartMode != 1) {
        if (nGameStartMode == 2) {
            nGameStartMode = 0;
        } else {
            return 0;
        }
    }

    if (nVersionHeader != VERSION_HEADER) throw std::invalid_argument("570425351_VERSION_HEADER");
    if (majorVersion > BUILD_MAJOR_VERSION) throw std::invalid_argument("CPatchException_MAJOR_NEWER");
    if (majorVersion != BUILD_MAJOR_VERSION) throw std::invalid_argument("570425351_MAJOR_MISMATCH");
    if (version > MINOR_VERSION) throw std::invalid_argument("CPatchException_MINOR_NEWER");
    if (!version) throw std::invalid_argument("570425351_MINOR_ZERO");
    
    pThis->ClearSendReceiveCtx();
    pThis->m_ctxConnect.lAddr.RemoveAll();
    pThis->m_ctxConnect.posList = nullptr;
    socklen_t peerAddrLen = sizeof(pThis->m_addr);
    if (getpeername(pThis->m_sock._m_hSocket, reinterpret_cast<struct sockaddr *>(&pThis->m_addr), &peerAddrLen) == -1) {
        Log("CClientSocket::OnConnect getpeername failed, WSALastError=[%d]", WSAGetLastError());
        throw std::invalid_argument("570425351_GETPEERNAME");
    }

    if (pThis->m_ctxConnect.bLogin) {
        Log("CClientSocket::OnConnect login context, sending CLIENT_START_ERROR. Filename: %s", CWvsApp::GetExceptionFileName());
    } else {
        Log("CClientSocket::OnConnect game context, accountId=[%u], worldId=[%d], channelId=[%d], characterId=[%u]",
            CWvsContext::GetInstance()->m_dwAccountId, CWvsContext::GetInstance()->m_nWorldID,
            CWvsContext::GetInstance()->m_nChannelID, CWvsContext::GetInstance()->m_dwCharacterId);
        CSystemInfo systemInfo;
        systemInfo.Init();
        COutPacket cOutPacket(PLAYER_LOGGED_IN);
        cOutPacket.Encode4(CWvsContext::GetInstance()->m_dwCharacterId);
        cOutPacket.EncodeBuffer(systemInfo.GetMachineId(), 16);
#if defined(REGION_GMS)
        cOutPacket.Encode1((CWvsContext::GetInstance()->m_nSubGradeCode.GetData() >= 0) ? 0 : 1);
#elif defined(REGION_JMS)
        cOutPacket.Encode2(CConfig::GetInstance()->dummy1);
#endif
        cOutPacket.Encode1(0);
#if (defined(REGION_GMS) && MAJOR_VERSION > 83) || (defined(REGION_JMS))
        cOutPacket.EncodeBuffer(CWvsContext::GetInstance()->m_aClientKey, 8);
#endif
        CClientSocket::GetInstance()->SendPacket(&cOutPacket);
    }
    return 1;
}

VOID __fastcall CClientSocket__Connect_Addr_Hook(CClientSocket *pThis, PVOID edx, const sockaddr_in *pAddr) {
    Log("CClientSocket::Connect(Addr: %s:%hu)", inet_ntoa(pAddr->sin_addr), ntohs(pAddr->sin_port));
    pThis->ClearSendReceiveCtx();
    pThis->m_sock.CloseSocket();

    pThis->m_sock._m_hSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (pThis->m_sock._m_hSocket == INVALID_SOCKET) {
        Log("CClientSocket::Connect_Addr_Hook socket() failed. WSALastError=[%d]", WSAGetLastError());
        return;
    }

    pThis->m_tTimeout = timeGetTime() + 5000;
    
    const long eventMask = FD_CONNECT | FD_READ | FD_CLOSE;
    int asyncResult = WSAAsyncSelect(pThis->m_sock._m_hSocket, pThis->m_hWnd, WM_SOCKET_MSG, eventMask);
    if (asyncResult == SOCKET_ERROR) {
        Log("CClientSocket::Connect_Addr_Hook WSAAsyncSelect failed. WSALastError=[%d]", WSAGetLastError());
        pThis->m_sock.CloseSocket();
        CClientSocket__OnConnect_Hook(pThis, edx, 0);
        return;
    }

    int connectResult = connect(pThis->m_sock._m_hSocket, reinterpret_cast<const sockaddr *>(pAddr), sizeof(sockaddr_in));
    int lastError = WSAGetLastError();

    Log("CClientSocket::Connect_Addr_Hook asyncResult=[%d], connectResult=[%d], lastError=[%d].", asyncResult, connectResult, lastError);

    if (connectResult == SOCKET_ERROR && lastError != WSAEWOULDBLOCK) {
        Log("CClientSocket::Connect_Addr_Hook connect() failed immediately. WSALastError=[%d]", lastError);
        pThis->m_sock.CloseSocket();
        CClientSocket__OnConnect_Hook(pThis, edx, 0);
    }
    Log("CClientSocket::Connect_Addr_Hook connection attempt pending or succeeded immediately.");
}

typedef VOID(__fastcall *_CClientSocket__Connect_ctx_t)(CClientSocket *pThis, PVOID edx, CClientSocket::CONNECTCONTEXT *ctx);

VOID __fastcall CClientSocket__Connect_Ctx_Hook(CClientSocket *pThis, PVOID edx, CClientSocket::CONNECTCONTEXT *ctx) {
    Log("CClientSocket::Connect(Ctx)");
    pThis->m_ctxConnect.lAddr.RemoveAll();
    pThis->m_ctxConnect.lAddr.AddTail(&ctx->lAddr);
    pThis->m_ctxConnect.posList = ctx->posList;
    pThis->m_ctxConnect.bLogin = ctx->bLogin;
    
    if (!pThis->m_ctxConnect.lAddr.IsEmpty()) {
         pThis->m_ctxConnect.posList = reinterpret_cast<__POSITION *>(pThis->m_ctxConnect.lAddr.GetHeadPosition());
         pThis->m_addr = *pThis->m_ctxConnect.lAddr.GetHeadPosition();
         CClientSocket__Connect_Addr_Hook(pThis, edx, &pThis->m_addr);
    } else {
        Log("CClientSocket::Connect_Ctx_Hook: No addresses in context.");
    }
    Log("CClientSocket::Connect_Ctx_Hook finished.");
}

typedef INT(__fastcall *_CLogin__SendCheckPasswordPacket_t)(CLogin *pThis, PVOID edx, char *sID, char *sPasswd);

INT __fastcall CLogin__SendCheckPasswordPacket_Hook(CLogin *pThis, PVOID edx, char *sID, char *sPasswd) {
    Log("CLogin::SendCheckPasswordPacket. ID [%s]. bRequestSent [%d].", sID, pThis->m_bRequestSent);
    if (pThis->m_bRequestSent) {
        return 0;
    }
    pThis->m_bRequestSent = 1;
    pThis->m_WorldItem.RemoveAll();
    pThis->m_aBalloon.RemoveAll();

    CSystemInfo systemInfo;
    systemInfo.Init();
    COutPacket cOutPacket(1);

    ZXString<char> tempStringID(sID, static_cast<unsigned int>(-1));
    cOutPacket.EncodeStr(tempStringID);

    ZXString<char> tempStringPass(sPasswd, static_cast<unsigned int>(-1));
    cOutPacket.EncodeStr(tempStringPass);

    cOutPacket.EncodeBuffer(systemInfo.GetMachineId(), 16);
    int gameRoomClient = systemInfo.GetGameRoomClient();
    Log("GRC %d", gameRoomClient);
    cOutPacket.Encode4(gameRoomClient);
    cOutPacket.Encode1(CWvsApp::GetInstance()->m_nGameStartMode);
    cOutPacket.Encode1(0);
    cOutPacket.Encode1(0);
#if defined(REGION_GMS)
    cOutPacket.Encode4(CConfig::GetInstance()->GetPartnerCode());
#endif
    CClientSocket::GetInstance()->SendPacket(&cOutPacket);
#if defined(REGION_JMS)
    CWvsContext::GetInstance()->unk1.Assign(sID, static_cast<unsigned int>(-1));
#endif
    CUITitle *cuiTitle = CUITitle::GetInstance();
    if (cuiTitle) {
        cuiTitle->ClearToolTip();
    }
    return 1;
}

CStage *get_stage() {
    return reinterpret_cast<CStage *>(*(void **) GET_STAGE);
}

typedef VOID(__cdecl *_set_stage_t)(CStage *pStage, void *pParam);
_set_stage_t _set_stage = reinterpret_cast<_set_stage_t>(SET_STAGE);

IWzGr2D *get_gr() {
    return reinterpret_cast<IWzGr2D *>(*(uint32_t **) GET_GR);
}

typedef INT(__cdecl *_DR__check_t)();
INT __cdecl DR__check_Hook() {
    return 0;
}

typedef VOID(__fastcall *_CWvsApp__CallUpdate_t)(CWvsApp *pThis, PVOID edx, int tCurTime);

VOID __fastcall CWvsApp__CallUpdate_Hook(CWvsApp *pThis, PVOID edx, int tCurTime) {
    if (pThis->m_bFirstUpdate) {
        pThis->m_tUpdateTime = tCurTime;
#if defined(REGION_GMS)
        pThis->m_tLastServerIPCheck = tCurTime;
        pThis->m_tLastServerIPCheck2 = tCurTime;
        pThis->m_tLastGGHookingAPICheck = tCurTime;
#endif
        pThis->m_tLastSecurityCheck = tCurTime;
        pThis->m_bFirstUpdate = 0;
    }

    while (tCurTime - pThis->m_tUpdateTime > 0) {
        CStage *stage = get_stage();
        if (stage) {
            stage->Update();
        }
        CWndMan::s_Update();
        pThis->m_tUpdateTime += 30;
        if (tCurTime - pThis->m_tUpdateTime > 0) {
            IWzGr2D* gr = get_gr();
            if (gr) {
                 HRESULT hr = gr->UpdateCurrentTime(pThis->m_tUpdateTime);
                 if (FAILED(hr)) { Log("gr->UpdateCurrentTime failed in catch-up loop. HR=0x%08X", hr); return; }
            }
        }
    }
    IWzGr2D* gr = get_gr();
    if (gr) {
        HRESULT hr = gr->UpdateCurrentTime(tCurTime);
        if (FAILED(hr)) { Log("gr->UpdateCurrentTime failed. HR=0x%08X", hr); return; }
    }
    CActionMan::GetInstance()->SweepCache();
}

typedef VOID(__fastcall *_CWvsApp__ConnectLogin_t)(CWvsApp *pThis, PVOID edx);

VOID __fastcall CWvsApp__ConnectLogin_Hook(CWvsApp *pThis, PVOID edx) {
    Log("CWvsApp::ConnectLogin_Hook");
    CClientSocket *pSock = CClientSocket::GetInstance();
    pSock->Close();
    pSock->ConnectLogin();

    MSG msg{};
    while (true) {
        if (PeekMessageA(&msg, nullptr, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_SOCKET_MSG) {
                if (msg.wParam != (UINT_PTR)pSock->m_sock._m_hSocket) {
                    continue; 
                }

                WORD event = LOWORD(msg.lParam);
                WORD error = HIWORD(msg.lParam);

                if (event == FD_CONNECT) {
                    if (error == 0) {
                        Log("CWvsApp::ConnectLogin_Hook: FD_CONNECT success. Calling OnConnect(1).");
                        if (CClientSocket__OnConnect_Hook(pSock, edx, 1)) {
                            break; 
                        }
                    } else {
                        Log("CWvsApp::ConnectLogin_Hook: FD_CONNECT error %hu. Calling OnConnect(0).", error);
                        CClientSocket__OnConnect_Hook(pSock, edx, 0);
                    }
                } else if (event == FD_CLOSE) {
                     Log("CWvsApp::ConnectLogin_Hook: FD_CLOSE received (error %hu). Calling OnConnect(0).", error);
                     CClientSocket__OnConnect_Hook(pSock, edx, 0);
                } else if (error != 0 && error != WSAENOTSOCK) {
                     Log("CWvsApp::ConnectLogin_Hook: WM_SOCKET event %hu with error %hu. Calling OnConnect(0).", event, error);
                     CClientSocket__OnConnect_Hook(pSock, edx, 0);
                }
            } else {
                TranslateMessage(&msg);
                DispatchMessageA(&msg);
            }
        }
        
        if (static_cast<LONG>(timeGetTime() - pSock->m_tTimeout) > 0) {
            Log("CWvsApp::ConnectLogin_Hook: Timeout. timeGetTime [%lu], timeOut [%lu]. Calling OnConnect(0).", timeGetTime(), pSock->m_tTimeout);
            CClientSocket__OnConnect_Hook(pSock, edx, 0);
        }

        if (msg.message == WM_QUIT) {
            break;
        }

        if (pSock->m_sock._m_hSocket == INVALID_SOCKET && !pSock->m_ctxConnect.lAddr.GetCount()) {
             Log("CWvsApp::ConnectLogin_Hook: Socket closed and no more addresses to try.");
             break; 
        }
        Sleep(1);
    }

    if (pSock->m_sock._m_hSocket == 0 || pSock->m_sock._m_hSocket == INVALID_SOCKET) {
        Log("CWvsApp::ConnectLogin_Hook: Failed to connect, socket is invalid.");
    }
}

typedef VOID(__fastcall *_CWvsApp__InitializeInput_t)(CWvsApp *pThis, PVOID edx);

VOID __fastcall CWvsApp__InitializeInput_Hook(CWvsApp *pThis, PVOID edx) {
    Log("CWvsApp::InitializeInput");
    CInputSystem::CreateInstance();
    CInputSystem::GetInstance()->Init(pThis->m_hWnd, pThis->m_ahInput);
}

typedef VOID(__stdcall *_CWvsApp__Run_t)(CWvsApp *pThis, int *pbTerminate);

VOID __fastcall CWvsApp__Run_Hook(CWvsApp *pThis, PVOID edx, int *pbTerminate) {
    Log("CWvsApp::Run");
    MSG msg{};
    ISMSG isMsg{};

    if (CClientSocket::GetInstance()) {
        CClientSocket::GetInstance()->ManipulatePacket();
    }

    do {
        DWORD dwRet = MsgWaitForMultipleObjects(3u, pThis->m_ahInput, FALSE, 0, QS_ALLINPUT);
        if (dwRet >= WAIT_OBJECT_0 && dwRet < WAIT_OBJECT_0 + 3) { // Input event
            CInputSystem::GetInstance()->UpdateDevice(dwRet - WAIT_OBJECT_0);
            do {
                if (!CInputSystem::GetInstance()->GetISMessage(&isMsg)) break;
                pThis->ISMsgProc(isMsg.message, isMsg.wParam, isMsg.lParam);
            } while (!*pbTerminate);
        } else if (dwRet == WAIT_OBJECT_0 + 3) { // Windows message
            while (PeekMessageA(&msg, nullptr, 0, 0, PM_REMOVE)) {
                if (msg.message == WM_QUIT) { *pbTerminate = TRUE; break; }
                TranslateMessage(&msg);
                DispatchMessageA(&msg);

                if (pThis->m_hrComErrorCode != 0) {
                    Log("COM Error Occurred: 0x%08X. Raising.", pThis->m_hrComErrorCode);
                    HRESULT hr = pThis->m_hrComErrorCode;
                    pThis->m_hrComErrorCode = 0;
                    pThis->m_hrZExceptionCode = 0; 
                    
                    return; 
                }
                if (pThis->m_hrZExceptionCode != 0) {
                    Log("ZException Occurred: 0x%08X. Raising.", pThis->m_hrZExceptionCode);
                     HRESULT hr = pThis->m_hrZExceptionCode;
                    pThis->m_hrZExceptionCode = 0;
                    
                    return;
                }
                 if (*pbTerminate) break;
            }
        } else {
            if (CInputSystem::GetInstance()->GenerateAutoKeyDown(&isMsg)) {
                pThis->ISMsgProc(isMsg.message, isMsg.wParam, isMsg.lParam);
            }
            int tCurTime = 0;
            IWzGr2D* gr = get_gr();
            if (gr) {
                HRESULT hr = gr->GetnextRenderTime(&tCurTime);
                if (FAILED(hr)) { Log("gr->GetnextRenderTime failed. HR=0x%08X", hr); return; }
                
                CWvsApp__CallUpdate_Hook(pThis, edx, tCurTime);
                CWndMan::RedrawInvalidatedWindows();
                
                hr = gr->RenderFrame();
                if (FAILED(hr)) { Log("gr->RenderFrame failed. HR=0x%08X", hr); return; }
            }
            Sleep(1u);
        }
    } while (!*pbTerminate);

    if (msg.message == WM_QUIT || *pbTerminate) {
        PostQuitMessage(static_cast<int>(msg.wParam));
    }
}

void GetSEPrivilege() {
    ((VOID * *(_fastcall * )()) GET_SE_PRIVILEGE)();
}

typedef VOID(__stdcall *_CWvsApp__SetUp_t)(CWvsApp *pThis);

VOID __fastcall CWvsApp__SetUp_Hook(CWvsApp *pThis) {
    Log("CWvsApp::SetUp");
#if defined(REGION_GMS)
    pThis->InitializeAuth();
#endif
    srand(timeGetTime());
#if defined(REGION_GMS)
    GetSEPrivilege();
#endif

    CSecurityClient::CreateInstance();

    PVOID cfgAlloc = ZAllocEx<ZAllocAnonSelector>::GetInstance()->Alloc(sizeof(CConfig));
    if (cfgAlloc) new(cfgAlloc) CConfig();
    
    pThis->InitializePCOM();
    pThis->CreateMainWindow();

    CClientSocket::CreateInstance();
    pThis->ConnectLogin();

    CSecurityClient::GetInstance()->m_hMainWnd = pThis->m_hWnd;

    CFuncKeyMappedMan::CreateInstance();
    CQuickslotKeyMappedMan::CreateInstance();
    CMacroSysMan::CreateInstance();

    pThis->InitializeResMan();
    pThis->InitializeGr2D();
    pThis->InitializeInput();

#if defined(REGION_JMS)
    ShowWindow(pThis->m_hWnd, SW_SHOW);
    UpdateWindow(pThis->m_hWnd);
    SetForegroundWindow(pThis->m_hWnd);
    IWzGr2D* gr = get_gr();
    if (gr) {
        HRESULT hr = gr->RenderFrame();
        if (FAILED(hr)) { Log("gr->RenderFrame in SetUp failed. HR=0x%08X", hr); return; }
    }
#endif

    Sleep(300);
    pThis->InitializeSound();
    Sleep(300);
    pThis->InitializeGameData();
    pThis->CreateWndManager();

    CConfig::GetInstance()->ApplySysOpt(nullptr, 0);

    CActionMan::CreateInstance();
    CActionMan::GetInstance()->Init();
    CAnimationDisplayer::CreateInstance();
    CMapleTVMan::CreateInstance();
#if defined(REGION_GMS)
    CMapleTVMan::GetInstance()->Init();
#elif defined(REGION_JMS)
    CMapleTVMan::GetInstance()->Init(pThis->unk1[1], pThis->unk1[0]);
#endif

    CQuestMan::CreateInstance();
    if (!CQuestMan::GetInstance()->LoadDemand()) { Log("CQuestMan::LoadDemand failed."); return; }
    CQuestMan::GetInstance()->LoadPartyQuestInfo();
    CQuestMan::GetInstance()->LoadExclusive();

    CMonsterBookMan::CreateInstance();
    if (!CMonsterBookMan::GetInstance()->LoadBook()) { Log("CMonsterBookMan::LoadBook failed."); return; }
    
    CRadioManager::CreateInstance();

    char sModulePath[MAX_PATH];
    GetModuleFileNameA(nullptr, sModulePath, MAX_PATH);
    CWvsApp::Dir_BackSlashToSlash(sModulePath);
    CWvsApp::Dir_upDir(sModulePath);
    CWvsApp::Dir_SlashToBackSlash(sModulePath);

    ZXString<char> tempString(sModulePath, static_cast<unsigned int>(-1));
    CConfig::GetInstance()->CheckExecPathReg(tempString);

    PVOID logoAlloc = ZAllocEx<ZAllocAnonSelector>::GetInstance()->Alloc(sizeof(CLogo));
    CStage *cLogo = nullptr;
    if (logoAlloc) cLogo = new(logoAlloc) CLogo();
    _set_stage(cLogo, nullptr);
}

typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);
DWORD ResetLSP() {
    return reinterpret_cast<DWORD>(*(void **) RESET_LSP);
}

typedef VOID(__stdcall *_CWvsApp__CWvsApp_t)(CWvsApp *pThis, const char *sCmdLine);

VOID __fastcall CWvsApp__CWvsApp_Hook(CWvsApp *pThis, PVOID edxUnused, const char *sCmdLine) {
    Log("CWvsApp::CWvsApp");
    void **instance = reinterpret_cast<void **>(C_WVS_APP_INSTANCE);
    *instance = pThis;

    pThis->m_hWnd = nullptr;
    pThis->m_bPCOMInitialized = 0;
    pThis->m_hHook = nullptr;
    pThis->m_tUpdateTime = 0;
    pThis->m_bFirstUpdate = 1;
    pThis->m_sCmdLine = ZXString<char>();
    pThis->m_nGameStartMode = 0;
    pThis->m_bAutoConnect = 1;
#if defined(REGION_JMS)
    pThis->unk1[0] = 0;
    pThis->unk1[1] = 0;
    pThis->unk2[0] = ZXString<char>();
    pThis->unk2[1] = ZXString<char>();
#endif
    pThis->m_bShowAdBalloon = 0;
    pThis->m_bExitByTitleEscape = 0;
    pThis->m_hrZExceptionCode = 0;
    pThis->m_hrComErrorCode = 0;
#if (defined(REGION_GMS) && BUILD_MAJOR_VERSION >= 87)
    pThis->m_tNextSecurityCheck = 0;
    pThis->m_pBackupBuffer = ZArray<unsigned char>();
    pThis->m_dwBackupBufferSize = 0;
#endif

#if defined(REGION_JMS)
    pThis->unk2[0] = ZXString<char>("", static_cast<unsigned int>(-1));
    pThis->unk2[1] = ZXString<char>("", static_cast<unsigned int>(-1));
#endif
    pThis->m_sCmdLine = ZXString<char>(sCmdLine, static_cast<unsigned int>(-1));
    pThis->m_sCmdLine = *pThis->m_sCmdLine.TrimRight("\" ")->TrimLeft("\" ");
#if (defined(REGION_GMS) && BUILD_MAJOR_VERSION >= 87)
    pThis->m_pBackupBuffer.Alloc(0x1000);
#endif
    ZXString<char> sToken;
    pThis->GetCmdLine(&sToken, 0);

    pThis->m_nGameStartMode = 2;
    pThis->m_dwMainThreadId = GetCurrentThreadId();

    OSVERSIONINFOA ovi;
    ZeroMemory(&ovi, sizeof(OSVERSIONINFOA));
    ovi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
    GetVersionExA(&ovi);
    pThis->m_bWin9x = (ovi.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS);
    if (ovi.dwMajorVersion >= 6 && !pThis->m_nGameStartMode) {
        pThis->m_nGameStartMode = 2;
    }

#if defined(REGION_GMS)
    int *g_dwTargetOS = reinterpret_cast<int *>(G_DW_TARGET_OS);
    if (ovi.dwMajorVersion < 5) *g_dwTargetOS = 1996; // WinNT 4 or older

    BOOL bIsWow64 = FALSE;
    LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandleA("kernel32"), "IsWow64Process");
    if (fnIsWow64Process) {
        fnIsWow64Process(GetCurrentProcess(), &bIsWow64);
    }
    if (bIsWow64) *g_dwTargetOS = 1996;
    if (ovi.dwMajorVersion >= 6 && !bIsWow64) ResetLSP();
#endif
}

DWORD WINAPI MainProc(LPVOID lpParam) {
    HOOKTYPEDEF_C(CWvsApp__CWvsApp);
    INITMAPLEHOOK(_CWvsApp__CWvsApp, _CWvsApp__CWvsApp_t, CWvsApp__CWvsApp_Hook, C_WVS_APP);

    HOOKTYPEDEF_C(CWvsApp__SetUp);
    INITMAPLEHOOK(_CWvsApp__SetUp, _CWvsApp__SetUp_t, CWvsApp__SetUp_Hook, C_WVS_APP_SET_UP);

    HOOKTYPEDEF_C(CWvsApp__InitializeInput);
    INITMAPLEHOOK(_CWvsApp__InitializeInput, _CWvsApp__InitializeInput_t, CWvsApp__InitializeInput_Hook, C_WVS_APP_INITIALIZE_INPUT);

    HOOKTYPEDEF_C(CWvsApp__Run);
    INITMAPLEHOOK(_CWvsApp__Run, _CWvsApp__Run_t, CWvsApp__Run_Hook, C_WVS_APP_RUN);

#if defined(REGION_JMS)
    static const BYTE patch_B3B96B[] = {0xC3};
    MemEdit::WriteBytes(0x00B3B96B, (LPVOID)patch_B3B96B, sizeof(patch_B3B96B));
#endif
#if (defined(REGION_GMS) && MAJOR_VERSION >= 87) || defined(REGION_JMS)
    HOOKTYPEDEF_C(DR__check);
    INITMAPLEHOOK(_DR__check, _DR__check_t, DR__check_Hook, DR_CHECK);
#endif
#if defined(REGION_JMS)
    static const BYTE patch_B3B610[] = {0x90, 0x90};
    MemEdit::WriteBytes(0x00B3B5F7 + 0x19, (LPVOID)patch_B3B610, sizeof(patch_B3B610));
#endif

    HOOKTYPEDEF_C(CWvsApp__CallUpdate);
    INITMAPLEHOOK(_CWvsApp__CallUpdate, _CWvsApp__CallUpdate_t, CWvsApp__CallUpdate_Hook, C_WVS_APP_CALL_UPDATE);

    HOOKTYPEDEF_C(CWvsApp__ConnectLogin);
    INITMAPLEHOOK(_CWvsApp__ConnectLogin, _CWvsApp__ConnectLogin_t, CWvsApp__ConnectLogin_Hook, C_WVS_APP_CONNECT_LOGIN);

    HOOKTYPEDEF_C(CLogin__SendCheckPasswordPacket);
    INITMAPLEHOOK(_CLogin__SendCheckPasswordPacket, _CLogin__SendCheckPasswordPacket_t, CLogin__SendCheckPasswordPacket_Hook, C_LOGIN_SEND_CHECK_PASSWORD_PACKET);

    HOOKTYPEDEF_C(CSecurityClient__OnPacket);
    INITMAPLEHOOK(_CSecurityClient__OnPacket, _CSecurityClient__OnPacket_t, CSecurityClient__OnPacket_Hook, C_SECURITY_CLIENT_ON_PACKET);

    HOOKTYPEDEF_C(CClientSocket__Connect_ctx);
    INITMAPLEHOOK(_CClientSocket__Connect_ctx, _CClientSocket__Connect_ctx_t, CClientSocket__Connect_Ctx_Hook, C_CLIENT_SOCKET_CONNECT_CTX);

    HOOKTYPEDEF_C(CClientSocket__Connect_addr);
    INITMAPLEHOOK(_CClientSocket__Connect_addr, _CClientSocket__Connect_addr_t, CClientSocket__Connect_Addr_Hook, C_CLIENT_SOCKET_CONNECT_ADR);

    HOOKTYPEDEF_C(CClientSocket__OnConnect);
    INITMAPLEHOOK(_CClientSocket__OnConnect, _CClientSocket__OnConnect_t, CClientSocket__OnConnect_Hook, C_CLIENT_SOCKET_ON_CONNECT);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        HANDLE hThread = CreateThread(nullptr, 0, MainProc, nullptr, 0, nullptr);
        if (hThread) CloseHandle(hThread); 
    }
    return TRUE;
}
