# wheel-cheeze

네트워크 스택의 "바퀴"를 처음부터 다시 만들어 보는 저장소입니다. Go 표준 라이브러리의 암호 프리미티브(AES, SHA-2, ECDH, ML-KEM, X.509 등)만 사용하고, 프로토콜은 RFC를 보고 직접 구현했습니다. 메인 모듈은 **서드파티 의존성이 0개**입니다.

| 프로젝트 | 내용 | 위치 |
| --- | --- | --- |
| **네트워크 진단기** | DNS → TCP → TLS → HTTP 중 **어느 단계에서, 왜** 실패하는지 식별 (선택적으로 QUIC/HTTP3 경로까지) | [`netdiag/`](netdiag), [`cmd/netdiag`](cmd/netdiag), [`internal/dns`](internal/dns) |
| **암호화 전송 계층** | TLS 1.3 (RFC 8446)과 QUIC v1 (RFC 9000/9001/9002) 클라이언트·서버 구현 | [`tls13/`](tls13), [`quic/`](quic), [`cmd/wheelcat`](cmd/wheelcat) |

> ⚠️ 학습·실험용 구현입니다. 보안 감사를 받지 않았으니 실제 서비스에는 `crypto/tls`, quic-go 같은 검증된 구현을 쓰세요.

## 빠른 시작

Go 1.24 이상이 필요합니다.

```sh
go build -o bin/ ./cmd/...        # bin/netdiag, bin/wheelcat
go test ./...                     # 단위·통합 테스트
(cd interop && go test ./...)     # quic-go, x/crypto와의 상호운용 테스트
```

---

## 1. 네트워크 진단기 — `netdiag`

URL 하나를 받아 요청이 지나가는 계층을 순서대로 확인하고, 처음 실패한 단계와 그 원인을 사람이 읽을 수 있는 설명·힌트와 함께 보고합니다.

```
$ netdiag -cacert ca.pem -sni app.example https://127.0.0.1:18444/
netdiag https://127.0.0.1:18444/
target: 127.0.0.1 port 18444 (https), path /

 - DNS              target is an IP address; no lookup needed
 ✔ TCP       149µs  connected to 127.0.0.1:18444 in 137µs
 ✘ TLS         1ms  the certificate expired on 2026-10-19 (expired 3 days ago)
                  certificate: CN=app.example
                  valid for: app.example
                  issuer: CN=Demo Root CA, O=wheel-cheeze
                  expires: 2026-10-19 (expired 3 days ago)
                  chain: 2 certificate(s) sent by the server
                  hint: the server must renew its certificate (or this machine's clock is wrong)
 - HTTP             skipped: TLS failed

 result: FAILED at the TLS stage (tls.cert_expired)
```

모든 단계가 통과한 경우 (`-quic`으로 QUIC/HTTP3 경로도 함께 점검):

```
 - DNS              target is an IP address; no lookup needed
 ✔ TCP       158µs  connected to 127.0.0.1:18443 in 137µs
 ✔ TLS       1.4ms  TLS 1.3, TLS_AES_128_GCM_SHA256, ALPN (none)
                  certificate: CN=app.example
                  ...
 ✔ HTTP      254µs  HTTP/1.1 200 OK in 236µs
 ✔ QUIC      1.5ms  QUIC v1 handshake with 127.0.0.1:18443 in 1.5ms, TLS_AES_128_GCM_SHA256, X25519MLKEM768, ALPN h3

 result: OK: all stages passed in 3.4ms
```

### 단계별로 구분하는 실패 원인

각 실패에는 스크립트에서 쓸 수 있는 고정 코드(`-json` 출력의 `code`)가 붙습니다.

| 단계 | 대표 코드 | 의미 |
| --- | --- | --- |
| **DNS** | `dns.nxdomain` `dns.nodata` `dns.servfail` `dns.refused` `dns.timeout` `dns.network` `dns.malformed` | 도메인 없음 / 이름은 있으나 A·AAAA 없음 / 리졸버 실패(DNSSEC 등) / 질의 거부 / 무응답 / 질의 전송 불가 / 변조된 응답 |
| **TCP** | `tcp.refused` `tcp.timeout` `tcp.reset` `tcp.host_unreachable` `tcp.net_unreachable` `tcp.blocked_locally` `tcp.partial` | RST로 거부(포트 닫힘) / SYN 무응답(방화벽 drop) / 리셋 / 라우팅 실패 / IPv6 경로 없음 등 / 로컬 정책 차단 / 일부 주소만 실패(경고) |
| **TLS** | `tls.cert_expired` `tls.cert_not_yet_valid` `tls.cert_hostname` `tls.cert_untrusted` `tls.alert_<이름>` `tls.not_tls` `tls.closed` `tls.timeout` `tls.cert_expiring` `tls.deprecated_version` | 만료 / 시계 문제 / 이름 불일치(SAN 표시) / 신뢰할 수 없는 CA·자체 서명·중간 인증서 누락·TLS 가로채기 / 서버 alert / 평문 HTTP 포트 / 핸드셰이크 중 끊김(SNI 차단 등) / 무응답 / 곧 만료(경고) / TLS 1.0·1.1(경고) |
| **HTTP** | `http.server_error` `http.client_error` `http.timeout` `http.closed` `http.malformed` | 5xx(502/503/504별 힌트) / 4xx(경고) / 응답 없음 / 응답 없이 종료 / HTTP가 아닌 응답(첫 바이트 표시) |
| **QUIC** | `quic.timeout` `quic.no_h3` `quic.version` `quic.tls_*` | UDP 차단 또는 HTTP/3 미지원 / ALPN h3 거부 / QUIC v1 미지원 / QUIC 위 TLS 실패 |

설계상 특징:

- **DNS는 직접 질의합니다.** OS 리졸버는 실패를 "host not found" 하나로 뭉뚱그리기 때문에, [`internal/dns`](internal/dns)에서 DNS 와이어 프로토콜(RFC 1035)을 직접 구현했습니다. `/etc/resolv.conf`(nameserver, search, ndots, timeout, attempts)와 `/etc/hosts`를 읽고, UDP로 A/AAAA를 동시에 질의하며 EDNS(0)을 쓰고, TC 비트가 오면 TCP로 재시도합니다. 서버별로 어떤 응답(NXDOMAIN/SERVFAIL/무응답 …)이 왔는지 그대로 보여줍니다. `-system-resolver`로 OS 리졸버를 쓸 수도 있습니다.
- **암호화 DNS로 차단·변조를 우회합니다.** 평문 DNS(UDP/53)는 중간 장비가 그대로 읽고 위조·차단할 수 있습니다(진단기가 `dns.malformed`로 탐지). `-dns`에 스킴을 붙이면 같은 조회를 인증된 채널로 보냅니다 — **DoT**(`tls://`, RFC 7858), **DoH**(`https://`, RFC 8484), **DoQ**(`quic://`, RFC 9250). 세 전송 모두 이 저장소의 TLS 1.3·QUIC 위에서 동작하고, 서버 인증서는 `-cacert`/시스템 루트로 검증합니다. 즉 평문 DNS가 가로채이는 환경에서 진단기가 **진짜 응답을 받아올** 수 있습니다. 브라우저·OS에 내장된 것과 같은 표준 프라이버시 기능입니다.
  ```
  netdiag -dns tls://1.1.1.1#cloudflare-dns.com     https://example.com/
  netdiag -dns https://dns.google/dns-query         https://example.com/
  netdiag -dns quic://dns.adguard.com               https://example.com/
  ```
- **인증서가 거부되어도 내용을 보여줍니다.** 검증을 콜백 안에서 직접 수행해, 만료·이름 불일치·신뢰 불가 상황에서도 주체·SAN·발급자·만료일·체인 길이를 출력합니다.
- **TLS 구현을 고를 수 있습니다.** 기본은 `crypto/tls`(TLS 1.0~1.3을 받아들여 오래된 서버도 진단)이고, `-tls wheel`을 주면 이 저장소의 TLS 1.3 구현으로 핸드셰이크합니다.
- **종료 코드**: `0` 정상(경고 포함), `2` DNS, `3` TCP, `4` TLS, `5` HTTP, `1` 사용법 오류.

### 주요 옵션

```
netdiag [flags] URL          # URL: https://host/path, http://host:8080, host:port, host

  -dns SERVER          /etc/resolv.conf 대신 이 DNS 서버에 질의
                       ip[:port] (평문) | tls://ip#name (DoT) | https://host/dns-query (DoH) | quic://host (DoQ)
  -system-resolver     OS 리졸버 사용
  -4 / -6              IPv4 / IPv6 주소만 시도
  -tls stdlib|wheel    TLS 클라이언트 선택 (wheel = 이 저장소의 TLS 1.3)
  -cacert ca.pem       시스템 루트 대신 신뢰할 CA
  -insecure            인증서 문제를 보고만 하고 실패로 처리하지 않음
  -sni name            SNI·인증서 검증에 쓸 이름
  -quic                QUIC(UDP) 경로도 점검 (ALPN h3)
  -timeout 5s          단계별 제한 시간
  -json                JSON 보고서
```

---

## 2. 암호화 전송 계층 — TLS 1.3 & QUIC

### 구조

```
internal/chacha20poly1305  ChaCha20, Poly1305, AEAD (RFC 8439) — 표준 라이브러리에 공개 API가 없어 직접 구현
tls13/                     TLS 1.3 (RFC 8446)
  handshake_client.go        클라이언트 상태 머신 ┐ 전송 계층과 무관한 메시지 단위 상태 머신
  handshake_server.go        서버 상태 머신       ┘ (handshakeIO 인터페이스로 출력·키 설치)
  conn.go                    TLS 레코드 계층 → net.Conn  (TCP 위의 TLS)
  quic.go                    QUIC용 이벤트 API (RFC 9001) → quic 패키지가 사용
  cipher_suites.go           HKDF-Expand-Label, 키 스케줄
quic/                      QUIC v1 (RFC 9000/9001/9002)
  protection.go              패킷 보호·헤더 보호(AES/ChaCha20), Initial 키, Retry 무결성 태그
  packet.go frames.go        롱/숏 헤더, 프레임 인코딩
  conn*.go                   연결 상태 머신, 송수신 경로, ACK·손실 감지
  stream.go                  스트림, 흐름 제어
  server.go client.go        Listener(Retry 토큰, 버전 협상) / Dial
cmd/wheelcat               TLS 1.3/QUIC용 netcat
```

TLS 핸드셰이크 상태 머신을 한 번만 작성하고, 두 가지 전송 방식이 이를 공유합니다. TCP에서는 레코드 계층이 메시지를 레코드로 감싸 암호화하고, QUIC에서는 같은 메시지가 CRYPTO 프레임으로 암호화 수준(Initial/Handshake/1-RTT)별로 오가며 트래픽 시크릿이 QUIC 패킷 보호 키로 내보내집니다.

### TLS 1.3 (`tls13`)

- 클라이언트·서버, `net.Conn` 호환 `Conn` (`Dial`, `Listen`, `Client`, `Server`)
- 암호 스위트: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`
- 키 교환: **X25519MLKEM768**(하이브리드 양자내성), X25519, P-256/384/521 — 키 쉐어가 안 맞으면 **HelloRetryRequest**
- 인증서: ECDSA, RSA-PSS, Ed25519 서명 / `crypto/x509`로 체인 검증 / **상호 인증(mTLS)**
- ALPN, SNI, KeyUpdate, 익스포터(RFC 8446 7.5), 미들박스 호환 모드, NSS 키 로그(`KeyLogWriter` → Wireshark 복호화)
- 실패 원인을 담은 오류 타입: `AlertError`(누가 어떤 alert를 보냈는지), `RecordHeaderError`(TLS가 아닌 응답의 첫 바이트), x509 오류 래핑

```go
conn, err := tls13.Dial("tcp", "example.com:443", &tls13.Config{NextProtos: []string{"http/1.1"}})
```

### QUIC v1 (`quic`)

- 클라이언트(`Dial`)·서버(`Listen`/`Accept`), 양방향·단방향 스트림
- 패킷 보호 + 헤더 보호(AES-ECB, ChaCha20), 패킷 번호 인코딩/복원, 합쳐진(coalesced) 패킷
- 1200바이트 Initial 패딩, 서버 **증폭 공격 방지(3배 제한)**, **Retry**(HMAC 상태 없는 토큰), **버전 협상**
- ACK 생성(지연 ACK, ACK-of-ACK 정리), RFC 9002 **손실 감지(패킷/시간 임계값)와 PTO 프로브**, **NewReno 혼잡 제어**
- 연결·스트림 **흐름 제어**(MAX_DATA/MAX_STREAM_DATA/MAX_STREAMS), RESET_STREAM/STOP_SENDING
- 1-RTT **키 업데이트**(상대 시작·자체 시작 `UpdateKeys`), 연결 ID 교체, idle 타임아웃·keep-alive, stateless reset 감지
- `CONNECTION_CLOSE`의 TLS alert를 `TransportError.TLSError`로 노출 → 진단기가 QUIC 위 인증서 오류도 분류

```go
conn, err := quic.Dial(ctx, "localhost:4433", &tls13.Config{NextProtos: []string{"h3"}}, nil)
stream, _ := conn.OpenStreamSync(ctx)
```

### `wheelcat`: 직접 써 보기

```sh
bin/wheelcat -l -echo -write-cert srv.pem :4433            # TLS 1.3 에코 서버 (자체 서명 인증서 자동 생성)
echo hi | bin/wheelcat -v -cacert srv.pem localhost:4433
connected to 127.0.0.1:4433: TLS 1.3 over TCP, TLS_AES_128_GCM_SHA256, X25519MLKEM768, ALPN "wheelcat" in 1.693ms
  certificate "localhost" issued by "localhost", expires 2026-11-21, signature ecdsa_secp256r1_sha256
hi

bin/wheelcat -l -quic -echo :4433                          # QUIC 에코 서버
bin/wheelcat -quic -insecure -v localhost:4433 < big.bin   # -v: QUIC 이벤트 추적 출력
```

`-keylog keys.txt`를 주면 Wireshark에서 TLS·QUIC 트래픽을 복호화해 볼 수 있습니다.

---

## 어떻게 검증했나

| 대상 | 방법 |
| --- | --- |
| ChaCha20-Poly1305 | RFC 8439 테스트 벡터, `math/big` 기준 구현과 Poly1305 비교, `golang.org/x/crypto`와 3,000건 차등 테스트 |
| TLS 1.3 | `crypto/tls`와 **양방향** 상호운용 (스위트 3종 × 키 5종, HRR, mTLS, KeyUpdate, 익스포터 값 일치, 1 MiB 전송), 실패 시나리오(호스트명·CA·만료·버전·ALPN·비TLS 응답), QUIC 모드를 `crypto/tls`의 `QUICConn`과 연결해 양쪽 시크릿 일치 확인, 메시지 파서 퍼징 |
| QUIC | RFC 9001 부록 A 벡터(Initial 시크릿, ChaCha20 숏 헤더 패킷, Retry 태그), 루프백 테스트(10% 손실·10% 재정렬 링크, 수 MB 동시 스트림, 스트림 한도 갱신, Retry, 키 업데이트, idle/keep-alive, 리셋, 버전 협상), **quic-go와 양방향 상호운용**(스위트 3종, 5 MB 전송 중 quic-go가 시작하는 키 업데이트, Retry, 스트림 250개, 애플리케이션 종료) |
| DNS 클라이언트 | 가짜 DNS 서버로 CNAME 체인, NXDOMAIN/NODATA/SERVFAIL/REFUSED, 타임아웃, 서버 폴백, TC→TCP, 위조 ID 무시, search 목록, hosts 파일 테스트 + 파서 퍼징 |
| 암호화 DNS | `tls13`·`quic`로 세운 루프백 DoT/DoH/DoQ 서버에 조회해 왕복 확인, NXDOMAIN 등 RCode 전달, 신뢰할 수 없는 인증서·DoH의 비dns-message 응답 거부, `parseServer` 스킴 파싱 테스트 |
| netdiag | 결함을 주입하는 로컬 서버(가짜 DNS, 닫힌 포트, 만료/이름 불일치/자체 서명 인증서, 평문 HTTP, 침묵·끊는 서버, TLS 1.2 전용 서버, 5xx, 비HTTP 응답, QUIC, DoT로 해석하는 전체 경로)로 단계·코드 판정 검증 |

`go test -race ./...`가 깨끗하게 통과합니다. 상호운용 테스트는 의존성을 메인 모듈에서 분리하려고 별도 모듈([`interop/`](interop))에 있습니다.

## 구현하지 않은 것

- TLS: 1.2 이하, PSK 세션 재개·0-RTT, OCSP stapling/SCT, 사후 클라이언트 인증
- QUIC: 0-RTT, 경로 MTU 탐색(항상 1200바이트 데이터그램), 연결 마이그레이션·경로 검증 시작, ECN, 페이싱, stateless reset 송신, QUIC v2, HTTP/3(진단기의 QUIC 단계는 ALPN `h3` 핸드셰이크까지만 확인)
