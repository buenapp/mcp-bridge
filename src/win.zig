// Windows API externs not covered by std.os.windows:
// SChannel (secur32), crypt32, dnsapi, console stdio.

const std = @import("std");

pub const BOOL = i32;
pub const WCHAR = u16;
pub const DWORD = u32;
pub const WORD = u16;
pub const BYTE = u8;
pub const HANDLE = *anyopaque;
pub const HMODULE = ?*anyopaque;

pub const SECURITY_STATUS = i32; // HRESULT-style

pub fn SUCCEEDED(status: SECURITY_STATUS) bool {
    return status >= 0;
}

// ---------------------------------------------------------------- stdio ----

pub const STD_INPUT_HANDLE: DWORD = @bitCast(@as(i32, -10));
pub const STD_OUTPUT_HANDLE: DWORD = @bitCast(@as(i32, -11));
pub const STD_ERROR_HANDLE: DWORD = @bitCast(@as(i32, -12));

pub extern "kernel32" fn GetStdHandle(nStdHandle: DWORD) ?HANDLE;
pub extern "kernel32" fn ReadFile(
    hFile: HANDLE,
    lpBuffer: [*]u8,
    nNumberOfBytesToRead: DWORD,
    lpNumberOfBytesRead: ?*DWORD,
    lpOverlapped: ?*anyopaque,
) BOOL;
pub extern "kernel32" fn WriteFile(
    hFile: HANDLE,
    lpBuffer: [*]const u8,
    nNumberOfBytesToWrite: DWORD,
    lpNumberOfBytesWritten: ?*DWORD,
    lpOverlapped: ?*anyopaque,
) BOOL;
pub extern "kernel32" fn GetLastError() DWORD;

// ------------------------------------------------------- IOCP / events --

pub const FILE_TYPE_PIPE: DWORD = 0x0003;
pub const FILE_TYPE_CHAR: DWORD = 0x0002;
pub const FILE_TYPE_DISK: DWORD = 0x0001;
pub const INFINITE: DWORD = 0xFFFFFFFF;

pub extern "kernel32" fn GetFileType(hFile: HANDLE) DWORD;
pub extern "kernel32" fn CreateEventExW(
    lpEventAttributes: ?*anyopaque,
    lpName: ?[*:0]const u16,
    dwFlags: DWORD,
    dwDesiredAccess: DWORD,
) ?HANDLE;
pub extern "kernel32" fn SetEvent(hEvent: HANDLE) BOOL;
pub extern "kernel32" fn CloseHandle(hObject: HANDLE) BOOL;

// --------------------------------------------------------------- winsock --

pub const ws2 = std.os.windows.ws2_32;
pub const kernel32 = std.os.windows.kernel32;
pub const SOCKET = ws2.SOCKET;
pub const INVALID_SOCKET = ws2.INVALID_SOCKET;

pub const SOL_SOCKET: i32 = 0xffff;
pub const SO_RCVTIMEO: i32 = 0x1006;
pub const SO_SNDTIMEO: i32 = 0x1005;
pub const WSAETIMEDOUT: i32 = 10060;
pub const WSAESHUTDOWN: i32 = 10058;

/// Set blocking recv/send timeouts (milliseconds) on a socket.
pub fn setTimeouts(sock: SOCKET, recv_ms: u32, send_ms: u32) void {
    const r: i32 = @intCast(recv_ms);
    const s: i32 = @intCast(send_ms);
    _ = ws2.setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, std.mem.asBytes(&r), @sizeOf(i32));
    _ = ws2.setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, std.mem.asBytes(&s), @sizeOf(i32));
}

// --------------------------------------------------------------- SChannel --

pub const SEC_WCHAR = u16;
pub const SEC_CHAR = u8;

pub const CredHandle = extern struct { dwLower: usize = 0, dwUpper: usize = 0 };
pub const CtxtHandle = extern struct { dwLower: usize = 0, dwUpper: usize = 0 };
pub const TimeStamp = extern struct { dwLowDateTime: DWORD, dwHighDateTime: DWORD };

pub const SecBuffer = extern struct {
    cbBuffer: DWORD,
    BufferType: DWORD,
    pvBuffer: ?*anyopaque,
};

pub const PSecBufferDesc = *SecBufferDesc;
pub const SecBufferDesc = extern struct {
    ulVersion: DWORD,
    cBuffers: DWORD,
    pBuffers: [*]SecBuffer,
};

pub const SECBUFFER_VERSION: DWORD = 0;
pub const SECBUFFER_EMPTY: DWORD = 0;
pub const SECBUFFER_DATA: DWORD = 1;
pub const SECBUFFER_TOKEN: DWORD = 2;
pub const SECBUFFER_EXTRA: DWORD = 5;
pub const SECBUFFER_STREAM_TRAILER: DWORD = 6;
pub const SECBUFFER_STREAM_HEADER: DWORD = 7;
pub const SECBUFFER_ALERT: DWORD = 17;

// InitializeSecurityContext input flags
pub const ISC_REQ_SEQUENCE_DETECT: DWORD = 0x00000008;
pub const ISC_REQ_REPLAY_DETECT: DWORD = 0x00000004;
pub const ISC_REQ_CONFIDENTIALITY: DWORD = 0x00000010;
pub const ISC_RET_EXTENDED_ERROR: DWORD = 0x00004000;
pub const ISC_REQ_ALLOCATE_MEMORY: DWORD = 0x00000100;
pub const ISC_REQ_STREAM: DWORD = 0x00008000;
pub const ISC_REQ_MANUAL_CRED_VALIDATION: DWORD = 0x00080000;
pub const ISC_REQ_USE_SUPPLIED_CREDS: DWORD = 0x00000080;

pub const ISC_FLAGS: DWORD = ISC_REQ_SEQUENCE_DETECT |
    ISC_REQ_REPLAY_DETECT |
    ISC_REQ_CONFIDENTIALITY |
    ISC_RET_EXTENDED_ERROR |
    ISC_REQ_ALLOCATE_MEMORY |
    ISC_REQ_STREAM |
    ISC_REQ_MANUAL_CRED_VALIDATION;

// SECURITY_STATUS codes
pub const SEC_E_OK: SECURITY_STATUS = 0;
pub const SEC_I_CONTINUE_NEEDED: SECURITY_STATUS = 0x00090312;
pub const SEC_I_INCOMPLETE_CREDENTIALS: SECURITY_STATUS = 0x00090320;
pub const SEC_E_INCOMPLETE_MESSAGE: SECURITY_STATUS = @bitCast(@as(u32, 0x80090318));
pub const SEC_I_CONTEXT_EXPIRED: SECURITY_STATUS = 0x00090317;
pub const SEC_E_INVALID_TOKEN: SECURITY_STATUS = @bitCast(@as(u32, 0x80090308));
pub const SEC_E_CERT_UNKNOWN: SECURITY_STATUS = @bitCast(@as(u32, 0x80090327));
pub const SEC_E_UNTRUSTED_ROOT: SECURITY_STATUS = @bitCast(@as(u32, 0x80090325));
pub const SEC_E_WRONG_PRINCIPAL: SECURITY_STATUS = @bitCast(@as(u32, 0x80090322));
pub const SEC_E_BUFFER_TOO_SMALL: SECURITY_STATUS = @bitCast(@as(u32, 0x80090321));
pub const SEC_E_MESSAGE_ALTERED: SECURITY_STATUS = @bitCast(@as(u32, 0x8009030F));
pub const SEC_E_OUT_OF_SEQUENCE: SECURITY_STATUS = @bitCast(@as(u32, 0x80090310));

// SCHANNEL_CRED
pub const SCHANNEL_CRED_VERSION: DWORD = 4;
pub const SCH_CRED_MANUAL_CRED_VALIDATION: DWORD = 0x0008;
pub const SCH_CRED_NO_DEFAULT_CREDS: DWORD = 0x0010;
pub const SCH_CRED_AUTO_CRED_VALIDATION: DWORD = 0x0020;
pub const SCH_CRED_USE_DEFAULT_CREDS: DWORD = 0x0040;

pub const SP_PROT_TLS1_2: DWORD = 0x00000800;
pub const SP_PROT_TLS1_3: DWORD = 0x00002000;

pub const SCHANNEL_CRED = extern struct {
    dwVersion: DWORD = SCHANNEL_CRED_VERSION,
    cCreds: DWORD = 0,
    paCred: ?*anyopaque = null,
    hRootStore: ?*anyopaque = null,
    cMappers: DWORD = 0,
    aphMappers: ?*anyopaque = null,
    cSupportedAlgs: DWORD = 0,
    palgSupportedAlgs: ?*DWORD = null,
    grbitEnabledProtocols: DWORD = 0, // system default
    dwMinimumCipherStrength: DWORD = 0,
    dwMaximumCipherStrength: DWORD = 0,
    dwSessionLifespan: DWORD = 0,
    dwFlags: DWORD,
    dwCredFormat: DWORD = 0,
};

pub const UNISP_NAME_W = [*:0]const u16;
pub const SCHANNEL_NAME_W = std.unicode.utf8ToUtf16LeStringLiteral("Schannel");

pub const SECPKG_ATTR_STREAM_SIZES: DWORD = 4;
pub const SECPKG_ATTR_REMOTE_CERT_CONTEXT: DWORD = 0x53;

pub const SecPkgContext_StreamSizes = extern struct {
    cbHeader: DWORD,
    cbTrailer: DWORD,
    cbMaximumMessage: DWORD,
    cBuffers: DWORD,
    cbBlockSize: DWORD,
};

pub const SECPKG_CRED_OUTBOUND: DWORD = 2;
pub const SECPKG_ATTR_NAMES: DWORD = 1;
pub const SCHANNEL_SHUTDOWN: DWORD = 1;

pub const SECURITY_NATIVE_DREP: DWORD = 0x00000010;

pub extern "secur32" fn AcquireCredentialsHandleW(
    pszPrincipal: ?[*:0]const u16,
    pszPackage: [*:0]const u16,
    fCredentialUse: DWORD,
    pvLogonId: ?*anyopaque,
    pAuthData: ?*anyopaque,
    pGetKeyFn: ?*anyopaque,
    pvGetKeyArgument: ?*anyopaque,
    phCredential: *CredHandle,
    ptsExpiry: ?*TimeStamp,
) SECURITY_STATUS;

pub extern "secur32" fn InitializeSecurityContextW(
    phCredential: *CredHandle,
    phContext: ?*CtxtHandle,
    pszTargetName: ?[*:0]const u16,
    fContextReq: DWORD,
    Reserved1: DWORD,
    TargetDataRep: DWORD,
    pInput: ?*SecBufferDesc,
    Reserved2: DWORD,
    phNewContext: *CtxtHandle,
    pOutput: ?*SecBufferDesc,
    pfContextAttr: *DWORD,
    ptsExpiry: ?*TimeStamp,
) SECURITY_STATUS;

pub extern "secur32" fn QueryContextAttributesW(
    phContext: *CtxtHandle,
    ulAttribute: DWORD,
    pBuffer: *anyopaque,
) SECURITY_STATUS;

pub extern "secur32" fn EncryptMessage(
    phContext: *CtxtHandle,
    fQOP: DWORD,
    pMessage: *SecBufferDesc,
    MessageSeqNo: DWORD,
) SECURITY_STATUS;

pub extern "secur32" fn DecryptMessage(
    phContext: *CtxtHandle,
    pMessage: *SecBufferDesc,
    MessageSeqNo: DWORD,
    pfQOP: ?*DWORD,
) SECURITY_STATUS;

pub extern "secur32" fn ApplyControlToken(
    phContext: *CtxtHandle,
    pInput: *SecBufferDesc,
) SECURITY_STATUS;

pub extern "secur32" fn DeleteSecurityContext(phContext: *CtxtHandle) SECURITY_STATUS;
pub extern "secur32" fn FreeCredentialsHandle(phCredential: *CredHandle) SECURITY_STATUS;
pub extern "secur32" fn FreeContextBuffer(pvContextBuffer: ?*anyopaque) SECURITY_STATUS;

// ---------------------------------------------------------------- crypt32 --

pub const CERT_CONTEXT = extern struct {
    dwCertEncodingType: DWORD,
    pbCertEncoded: [*]u8,
    cbCertEncoded: DWORD,
    pCertInfo: ?*CERT_INFO,
    hCertStore: ?*anyopaque,
};
pub const PCCERT_CONTEXT = ?*CERT_CONTEXT;

pub const CERT_PUBLIC_KEY_INFO = extern struct {
    Algorithm: CRYPT_ALGORITHM_IDENTIFIER,
    PublicKey: CRYPT_BIT_BLOB,
};

pub const CRYPT_ALGORITHM_IDENTIFIER = extern struct {
    pszObjId: ?[*:0]const u8,
    Parameters: CERT_NAME_BLOB,
};

pub const CERT_NAME_BLOB = extern struct {
    cbData: DWORD,
    pbData: ?[*]u8,
};

pub const CRYPT_BIT_BLOB = extern struct {
    cbData: DWORD,
    pbData: ?[*]u8,
    cUnusedBits: DWORD,
};

// CERT_INFO is large; we only need SubjectPublicKeyInfo which sits at a
// fixed offset.  Rather than redeclaring every field, declare the full
// prefix faithfully.
pub const FILETIME = extern struct { dwLowDateTime: DWORD, dwHighDateTime: DWORD };

pub const CERT_INFO = extern struct {
    dwVersion: DWORD,
    SerialNumber: CERT_NAME_BLOB,
    SignatureAlgorithm: CRYPT_ALGORITHM_IDENTIFIER,
    Issuer: CERT_NAME_BLOB,
    NotBefore: FILETIME,
    NotAfter: FILETIME,
    Subject: CERT_NAME_BLOB,
    SubjectPublicKeyInfo: CERT_PUBLIC_KEY_INFO,
    // remaining fields omitted
};

pub const CERT_CHAIN_CONTEXT = extern struct {
    cbSize: DWORD,
    TrustStatus: CERT_TRUST_STATUS,
    cChain: DWORD,
    rgpChain: ?[*]?*CERT_SIMPLE_CHAIN,
    cLowerQualityChainContext: DWORD,
    rgpLowerQualityChainContext: ?*anyopaque,
    fHasRevocationFreshnessTime: BOOL,
    dwRevocationFreshnessTime: DWORD,
    dwCreateFlags: DWORD,
    ChainId: [16]u8, // GUID
};

pub const CERT_TRUST_STATUS = extern struct {
    dwErrorStatus: DWORD,
    dwInfoStatus: DWORD,
};

pub const CERT_SIMPLE_CHAIN = extern struct {
    cbSize: DWORD,
    TrustStatus: CERT_TRUST_STATUS,
    cElement: DWORD,
    rgpElement: ?[*]?*CERT_CHAIN_ELEMENT,
    pTrustListInfo: ?*anyopaque,
    fHasRevocationFreshnessTime: BOOL,
    dwRevocationFreshnessTime: DWORD,
};

pub const CERT_CHAIN_ELEMENT = extern struct {
    cbSize: DWORD,
    pCertContext: ?*CERT_CONTEXT,
    TrustStatus: CERT_TRUST_STATUS,
    pRevocationInfo: ?*anyopaque,
    pIssuanceUsage: ?*anyopaque,
    pApplicationUsage: ?*anyopaque,
    pwszExtendedErrorInfo: ?[*:0]u16,
};

pub const CERT_CHAIN_PARA = extern struct {
    cbSize: DWORD,
    RequestedUsage: CERT_USAGE_MATCH,
    RequstedIssuancePolicy: CERT_USAGE_MATCH,
    dwUrlRetrievalTimeout: DWORD,
    fCheckRevocationFreshnessTime: BOOL,
    dwRevocationFreshnessTime: DWORD,
    pftCacheResync: ?*FILETIME,
    pStrongSignPara: ?*anyopaque,
    dwStrongSignFlags: DWORD,
};

pub const CERT_USAGE_MATCH = extern struct {
    dwType: DWORD,
    Usage: CERT_ENHKEY_USAGE,
};

pub const CERT_ENHKEY_USAGE = extern struct {
    cUsageIdentifier: DWORD,
    rgpszUsageIdentifier: ?[*]?[*:0]u8,
};

pub const USAGE_MATCH_TYPE_AND: DWORD = 1;

pub const CERT_CHAIN_CACHE_END_CERT: DWORD = 0x00000001;
pub const CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY: DWORD = 0x80000000;
pub const CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL: DWORD = 0x00000004;

pub const CERT_CHAIN_POLICY_SSL: [*:0]const u8 = @ptrFromInt(1);
pub const AUTHTYPE_SERVER: DWORD = 2;

pub const SSL_EXTRA_CERT_CHAIN_POLICY_PARA = extern struct {
    cbSize: DWORD,
    dwAuthType: DWORD,
    fdwChecks: DWORD,
    pwszServerName: ?[*:0]const u16,
};

pub const CERT_CHAIN_POLICY_PARA = extern struct {
    cbSize: DWORD,
    dwFlags: DWORD,
    pvExtraPolicyPara: ?*anyopaque,
};

pub const CERT_CHAIN_POLICY_STATUS = extern struct {
    cbSize: DWORD,
    dwError: DWORD,
    lChainIndex: i32,
    lElementIndex: i32,
    pvExtraPolicyStatus: ?*anyopaque,
};

pub const X509_ASN_ENCODING: DWORD = 0x00000001;
pub const X509_PUBLIC_KEY_INFO: [*:0]const u8 = @ptrFromInt(8);

pub extern "crypt32" fn CertGetCertificateChain(
    hChainEngine: ?*anyopaque,
    pCertContext: *CERT_CONTEXT,
    pTime: ?*FILETIME,
    hAdditionalStore: ?*anyopaque,
    pChainPara: ?*CERT_CHAIN_PARA,
    dwFlags: DWORD,
    pvReserved: ?*anyopaque,
    ppChainContext: *?*CERT_CHAIN_CONTEXT,
) BOOL;

pub extern "crypt32" fn CertFreeCertificateChain(pChainContext: *CERT_CHAIN_CONTEXT) void;
pub extern "crypt32" fn CertFreeCertificateContext(pCertContext: PCCERT_CONTEXT) BOOL;

pub extern "crypt32" fn CertVerifyCertificateChainPolicy(
    pszPolicyOID: [*:0]const u8,
    pChainContext: *CERT_CHAIN_CONTEXT,
    pPolicyPara: ?*CERT_CHAIN_POLICY_PARA,
    pPolicyStatus: *CERT_CHAIN_POLICY_STATUS,
) BOOL;

pub extern "crypt32" fn CryptEncodeObjectEx(
    dwCertEncodingType: DWORD,
    lpszStructType: [*:0]const u8,
    pvStructInfo: *const anyopaque,
    dwFlags: DWORD,
    pEncodePara: ?*anyopaque,
    pvEncoded: ?*anyopaque,
    pcbEncoded: *DWORD,
) BOOL;

// ----------------------------------------------------------------- dnsapi --

pub const DNS_TYPE_TLSA: WORD = 52;
pub const DNS_QUERY_STANDARD: DWORD = 0;
pub const DNS_QUERY_BYPASS_CACHE: DWORD = 0x0008;

pub const DNS_R_OK: i32 = 0;
pub const DNS_R_ERROR_NAME_DOES_NOT_EXIST: i32 = 9003; // DNS_INFO_NO_RECORDS
pub const DNS_INFO_NO_RECORDS: i32 = 9501;

pub const DNS_TLSA_DATA = extern struct {
    bCertUsage: BYTE,
    bSelector: BYTE,
    bMatchingType: BYTE,
    bCertificateAssociationDataLength: WORD,
    bPad: [3]BYTE,
    // Inline data follows (bCertificateAssociationDataLength bytes total).
    bCertificateAssociationData: [1]BYTE,
};

pub const DNS_SOA_DATA = extern struct {
    pNamePrimaryServer: ?[*:0]u8,
    pNameAdministrator: ?[*:0]u8,
    dwSerialNo: DWORD,
    dwRefresh: DWORD,
    dwRetry: DWORD,
    dwExpire: DWORD,
    dwDefaultTtl: DWORD,
};

pub const DNS_RECORD_DATA = extern union {
    TLSA: DNS_TLSA_DATA,
    SOA: DNS_SOA_DATA, // largest member, forces correct union size
};

pub const DNS_RECORD = extern struct {
    pNext: ?*DNS_RECORD,
    pName: ?[*:0]u8,
    wType: WORD,
    wDataLength: WORD,
    dwFlags: DWORD,
    dwTtl: DWORD,
    dwReserved: DWORD,
    Data: DNS_RECORD_DATA,
};

pub const DNS_FREE_TYPE = enum(i32) {
    FreeFlat = 0,
    FreeRecordList = 1,
    FreeParsedMessageFields = 2,
};

pub extern "dnsapi" fn DnsQuery_A(
    pszName: [*:0]const u8,
    wType: WORD,
    Options: DWORD,
    pExtra: ?*anyopaque,
    ppQueryResults: ?*?*DNS_RECORD,
    pReserved: ?*anyopaque,
) i32;

pub extern "dnsapi" fn DnsRecordListFree(pRecordList: ?*DNS_RECORD, FreeType: DNS_FREE_TYPE) void;

// --------------------------------------------------------------- misc -----

pub extern "kernel32" fn Sleep(dwMilliseconds: DWORD) void;

pub fn utf16Z(allocator: std.mem.Allocator, s: []const u8) ![:0]u16 {
    return std.unicode.utf8ToUtf16LeAllocZ(allocator, s);
}
