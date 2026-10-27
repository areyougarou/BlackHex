#include "tamper_scan.h"
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace {

struct Sha256 {
    uint32_t h[8]; uint64_t len; uint8_t buf[64]; size_t n;
    void init() {
        h[0]=0x6a09e667;h[1]=0xbb67ae85;h[2]=0x3c6ef372;h[3]=0xa54ff53a;
        h[4]=0x510e527f;h[5]=0x9b05688c;h[6]=0x1f83d9ab;h[7]=0x5be0cd19;
        len=0;n=0;
    }
    static uint32_t ror(uint32_t x,int r){return (x>>r)|(x<<(32-r));}
    void block(const uint8_t* p){
        static const uint32_t K[64]={
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
        uint32_t w[64];
        for(int i=0;i<16;i++) w[i]=(p[i*4]<<24)|(p[i*4+1]<<16)|(p[i*4+2]<<8)|p[i*4+3];
        for(int i=16;i<64;i++){
            uint32_t s0=ror(w[i-15],7)^ror(w[i-15],18)^(w[i-15]>>3);
            uint32_t s1=ror(w[i-2],17)^ror(w[i-2],19)^(w[i-2]>>10);
            w[i]=w[i-16]+s0+w[i-7]+s1;
        }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for(int i=0;i<64;i++){
            uint32_t S1=ror(e,6)^ror(e,11)^ror(e,25);
            uint32_t ch=(e&f)^((~e)&g);
            uint32_t t1=hh+S1+ch+K[i]+w[i];
            uint32_t S0=ror(a,2)^ror(a,13)^ror(a,22);
            uint32_t maj=(a&b)^(a&c)^(b&c);
            uint32_t t2=S0+maj;
            hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
    }
    void update(const uint8_t* p,size_t l){
        len+=l;
        while(l){ size_t k=64-n; if(k>l)k=l; memcpy(buf+n,p,k); n+=k; p+=k; l-=k;
            if(n==64){ block(buf); n=0; } }
    }
    std::string hex(){
        uint64_t bits=len*8; uint8_t pad=0x80; update(&pad,1);
        uint8_t z=0; while(n!=56) update(&z,1);
        uint8_t be[8]; for(int i=0;i<8;i++) be[i]=(uint8_t)(bits>>(56-i*8)); update(be,8);
        static const char* hx="0123456789abcdef"; std::string out; out.reserve(64);
        for(int i=0;i<8;i++) for(int j=3;j>=0;j--){ uint8_t v=(uint8_t)(h[i]>>(j*8)); out+=hx[v>>4]; out+=hx[v&0xf]; }
        return out;
    }
};

std::string sha256_hex(const uint8_t* p,size_t n){ Sha256 s; s.init(); s.update(p,n); return s.hex(); }

}

int raw_open(const char* path){ return (int)syscall(__NR_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC | O_LARGEFILE, 0); }
namespace {

void raw_close(int fd){ syscall(__NR_close, fd); }
int64_t raw_size(int fd){ return (int64_t)syscall(__NR_lseek, fd, 0, SEEK_END); }

bool raw_pread(int fd, void* buf, size_t len, int64_t off){
    uint8_t* p=(uint8_t*)buf; size_t got=0;
    while(got<len){
        int64_t at=off+(int64_t)got;
#if defined(__arm__)  // ARM EABI passes a 64-bit syscall argument in an even register pair: pad one word
        long n=syscall(__NR_pread64, fd, p+got, len-got, 0, (uint32_t)at, (uint32_t)((uint64_t)at>>32));
#else
        long n=syscall(__NR_pread64, fd, p+got, len-got, at);
#endif
        if(n<=0) return false; got+=(size_t)n;
    }
    return true;
}

bool rd_u32(const std::string& b,size_t off,uint32_t& v){
    if(off+4>b.size()) return false;
    const uint8_t* p=(const uint8_t*)b.data()+off;
    v=(uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24); return true;
}
bool rd_u64(const std::string& b,size_t off,uint64_t& v){
    if(off+8>b.size()) return false;
    const uint8_t* p=(const uint8_t*)b.data()+off; v=0;
    for(int i=0;i<8;i++) v|=((uint64_t)p[i])<<(8*i); return true;
}

}

namespace {

bool installer_path(const std::string& p){
    if(p.compare(0,10,"/data/app/")==0) return true;
    size_t u=p.find('/',12);
    return p.compare(0,12,"/mnt/expand/")==0 && u!=std::string::npos && p.compare(u,5,"/app/")==0;
}

bool fits(size_t off, uint64_t len, size_t end){ return off<=end && len<=end-off; }

void entry_certs(const std::string& val, std::vector<std::string>& out){
    uint32_t u;
    if(!rd_u32(val,0,u) || !fits(4,u,val.size())) return;
    size_t q=4, end=4+(size_t)u;
    while(fits(q,4,end)){
        if(!rd_u32(val,q,u) || !fits(q+4,u,end)) return;
        size_t s=q+4, s_end=s+u; q=s_end;
        if(!rd_u32(val,s,u) || !fits(s+4,u,s_end)) return;
        size_t sd=s+4, sd_end=sd+u;
        if(!rd_u32(val,sd,u) || !fits(sd+4,u,sd_end)) return;
        size_t c=sd+4+u; uint32_t c0;
        if(!fits(c,8,sd_end) || !rd_u32(val,c+4,c0) || !fits(c+8,c0,sd_end)) return;
        out.push_back(sha256_hex((const uint8_t*)val.data()+c+8, c0));
    }
}

}

std::string own_apk_path(const std::vector<VmaEntry>& maps, const std::string& pkg){
    const std::string seg="/"+pkg+"-", base="/base.apk";
    if(pkg.empty()) return "";
    for(const auto& v : maps)
        if(v.path.size()>base.size() && v.path.compare(v.path.size()-base.size(),base.size(),base)==0 &&
           installer_path(v.path) && v.path.find(seg)!=std::string::npos) return v.path;
    return "";
}

struct Signer { std::vector<std::string> certs; std::string err; bool v1_only = false; };

static Signer parse_own_signer(){
    Signer s;
    std::string apk=own_apk_path(g_maps, g_own_package);
    if(apk.empty()){ s.err="installed base.apk not found among the app's mapped files"; return s; }

    int fd=raw_open(apk.c_str());
    if(fd<0){ s.err="open(base.apk) failed - cannot judge"; return s; }
    int64_t fsz=raw_size(fd);
    if(fsz<22){ raw_close(fd); s.err="apk too small - cannot judge"; return s; }

    size_t tail = (size_t)(fsz < 65557 ? fsz : 65557);
    std::string buf; buf.resize(tail);
    if(!raw_pread(fd, &buf[0], tail, fsz-(int64_t)tail)){ raw_close(fd); s.err="tail read failed"; return s; }
    long eocd=-1;
    for(long i=(long)tail-22;i>=0;i--)
        if((uint8_t)buf[i]==0x50&&(uint8_t)buf[i+1]==0x4b&&(uint8_t)buf[i+2]==0x05&&(uint8_t)buf[i+3]==0x06 &&
           (size_t)i+22+((uint8_t)buf[i+20]|((size_t)(uint8_t)buf[i+21]<<8))==tail){ eocd=i; break; }
    if(eocd<0){ raw_close(fd); s.err="no ZIP end record - not judging"; return s; }
    uint32_t cd_off, cd_size; rd_u32(buf,(size_t)eocd+16,cd_off); rd_u32(buf,(size_t)eocd+12,cd_size);
    if((uint64_t)cd_off+cd_size!=(uint64_t)(fsz-(int64_t)tail+eocd) || cd_off<32){ raw_close(fd); s.err="unexpected ZIP layout - not judging"; return s; }

    uint8_t foot[24];
    if(!raw_pread(fd, foot, 24, (int64_t)cd_off-24)){ raw_close(fd); s.err="footer read failed"; return s; }
    if(memcmp(foot+8,"APK Sig Block 42",16)!=0){ raw_close(fd); s.v1_only=true; return s; }
    uint64_t blk=0, head=0; for(int i=0;i<8;i++) blk|=((uint64_t)foot[i])<<(8*i);
    if(blk<24 || blk>16*1024*1024 || (uint64_t)cd_off<blk+8){ raw_close(fd); s.err="implausible signing-block size"; return s; }
    if(!raw_pread(fd, &head, 8, (int64_t)cd_off-(int64_t)blk-8) || head!=blk){ raw_close(fd); s.err="signing block sizes do not match"; return s; }

    int64_t pairs_off=(int64_t)cd_off-(int64_t)blk;
    size_t pairs_len=(size_t)(blk-24);
    std::string pairs; pairs.resize(pairs_len);
    if(!raw_pread(fd, &pairs[0], pairs_len, pairs_off)){ raw_close(fd); s.err="pairs read failed"; return s; }
    raw_close(fd);

    size_t pos=0;
    while(pos+12<=pairs.size()){
        uint64_t plen; if(!rd_u64(pairs,pos,plen)) break;
        if(plen<4 || !fits(pos+8,plen,pairs.size())) break;
        uint32_t id; if(!rd_u32(pairs,pos+8,id)){ break; }
        if(id==0x7109871au || id==0xf05368c0u || id==0x1b93ad61u) entry_certs(pairs.substr(pos+12,(size_t)plen-4), s.certs);
        pos+=8+(size_t)plen;
    }
    if(s.certs.empty()) s.err="no parseable v2/v3 signer cert - not judging";
    return s;
}

NativeResult check_tamper_signing_block(){
    static Signer cached;
    if(cached.certs.empty()) cached=parse_own_signer();
    if(cached.v1_only)
        return g_target_sdk>=30
            ? NativeResult{STATUS_DETECTED, "no v2/v3 signing block: the APK is signed with v1 only, which Android refuses for targetSdkVersion "+std::to_string(g_target_sdk)}
            : NativeResult{STATUS_INCONCLUSIVE, "signed with v1 only, which Android accepts below targetSdkVersion 30; this check reads only v2/v3 signers"};
    if(cached.certs.empty()) return {STATUS_INCONCLUSIVE, cached.err};
    NativeResult r;

    std::vector<std::string> expected; std::string cur;
    for(size_t i=0;i<=g_expected_signers.size();i++){
        char c = i<g_expected_signers.size() ? g_expected_signers[i] : ',';
        if(c==','){ if(!cur.empty()) expected.push_back(cur); cur.clear(); }
        else if(c!=':' && c!=' ') cur += (char)tolower((unsigned char)c);
    }
    if(expected.empty()){ r.status=STATUS_INCONCLUSIVE; r.details="no signer from Android to compare"; return r; }
    std::string listed, file;
    for(const auto& c : cached.certs){
        if(std::find(expected.begin(), expected.end(), c)!=expected.end()){
            r.status=STATUS_CLEAN; r.details="a signing entry in the file carries the signer Android reports: "+c.substr(0,16)+"..."; return r;
        }
        file += c.substr(0,16)+"... ";
    }
    for(const auto& p : expected) listed += p.substr(0,16)+"... ";
    r.status=STATUS_DETECTED; r.details="no signing entry in the file carries the signer Android reports: file="+file+"android="+listed;
    return r;
}
