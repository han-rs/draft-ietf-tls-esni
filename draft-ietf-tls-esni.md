---
title: TLS Encrypted Client Hello
abbrev: TLS Encrypted Client Hello
docname: draft-ietf-tls-esni-latest
category: std

ipr: trust200902
submissiontype: IETF
area: SEC
workgroup: tls
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
       ins: E. Rescorla
       name: Eric Rescorla
       organization: Independent
       email: ekr@rtfm.com

 -
       ins: K. Oku
       name: Kazuho Oku
       organization: Fastly
       email: kazuhooku@gmail.com

 -
       ins: N. Sullivan
       name: Nick Sullivan
       organization: Cryptography Consulting LLC
       email: nicholas.sullivan+ietf@gmail.com

 -
       ins: C. A. Wood
       name: Christopher A. Wood
       organization: Cloudflare
       email: caw@heapingbits.net


normative:
  RFC2119:
  RFC7918:

informative:
  WHATWG-IPV4:
   title: "URL Living Standard - IPv4 Parser"
   target: https://url.spec.whatwg.org/#concept-ipv4-parser
   date: May 2021
  ECH-Analysis:
    title: "A Symbolic Analysis of Privacy for TLS 1.3 with Encrypted Client Hello"
    target: https://www.cs.ox.ac.uk/people/vincent.cheval/publis/BCW-ccs22.pdf
    date: November 2022
    authors:
      -
        ins: K. Bhargavan
        org: Inria
      -
        ins: V. Cheval
        org: Inria
      -
        ins: C. Wood
        org: Cloudflare


--- abstract

This document describes a mechanism in Transport Layer Security (TLS) for
encrypting a ClientHello message under a server public key.

本文档描述了传输层安全协议 (TLS) 中使用服务器公钥加密 ClientHello 消息的机制.

--- middle

# Introduction | 导语 {#intro}

Although TLS 1.3 {{!RFC8446}} encrypts most of the handshake, including the
server certificate, there are several ways in which an on-path attacker can
learn private information about the connection. The plaintext Server Name
Indication (SNI) extension in ClientHello messages, which leaks the target
domain for a given connection, is perhaps the most sensitive information
left unencrypted in TLS 1.3.

尽管 TLS 1.3 {{!RFC8446}} 加密了大部分握手过程, 包括服务器证书, 但中间人仍有几种方式可以了解连接的私有信息. ClientHello 消息中的明文的服务器名称指示 (SNI) 扩展会泄露给定连接的目标域名, 这可能是 TLS 1.3 中未加密的信息中最敏感的.

This document specifies a new TLS extension, called Encrypted Client Hello
(ECH), that allows clients to encrypt their ClientHello to the TLS server.
This protects the SNI and other potentially sensitive fields, such as the
Application Layer Protocol Negotiation (ALPN)
list {{?RFC7301}}. Co-located servers with consistent externally visible TLS
configurations and behavior, including supported versions and cipher suites and
how they respond to incoming client connections, form an anonymity set. (Note
that implementation-specific choices, such as extension ordering within TLS
messages or division of data into record-layer boundaries, can result in
different externally visible behavior, even for servers with consistent TLS
configurations.) Usage of this mechanism reveals that a client is connecting
to a particular service provider, but does not reveal which server from the
anonymity set terminates the connection. Deployment implications of this
feature are discussed in {{deployment}}.

本文档规定了一个新的 TLS 扩展, 称 Encrypted Client Hello (ECH) , 允许客户端向 TLS 服务器发送其 ClientHello 的加密版本. 这保护了 SNI 和其他潜在敏感字段, 如应用层协议协商 (ALPN) 列表 {{?RFC7301}}. 具有一致的外部可见的 TLS 配置和行为的同址服务器形成了一个匿名集, 这些配置和行为包括支持的版本和密码套件、以及它们如何响应传入的客户端连接.  (请注意, 特定于实现的选择, 如 TLS 消息中的扩展排序或数据分割到记录层边界, 可能导致不同的外部可见行为, 即使对于具有一致 TLS 配置的服务器也是如此. ) 使用此机制会透露客户端正在连接到特定服务提供商, 但不会透露匿名集中的哪个服务器终止连接. {{deployment}} 中讨论了此功能的部署影响.

ECH is not in itself sufficient to protect the identity of the server.
The target domain may also be visible through other channels, such as
plaintext client DNS queries or visible server IP addresses. However,
encrypted DNS mechanisms such as
DNS over HTTPS {{?RFC8484}}, DNS over TLS/DTLS {{?RFC7858}} {{?RFC8094}}, and
DNS over QUIC {{?RFC9250}}
provide mechanisms for clients to conceal
DNS lookups from network inspection, and many TLS servers host multiple domains
on the same IP address. Private origins may also be deployed behind a common
provider, such as a reverse proxy. In such environments, the SNI remains the
primary explicit signal available to observers to determine the
server's identity.

ECH 本身不足以保护服务器的身份. 目标域名也可能通过其他渠道可见, 如明文客户端 DNS 查询或可见的服务器 IP 地址. 但是, 加密 DNS 机制如 DNS over HTTPS {{?RFC8484}}、DNS over TLS/DTLS {{?RFC7858}} {{?RFC8094}} 和 DNS over QUIC {{?RFC9250}} 为客户端提供了从网络审查中隐藏 DNS 查找的机制, 许多 TLS 服务器在同一 IP 地址上托管了多个域名. 私有源站也可能部署在公共提供商后面, 如反向代理. 在这种环境中, SNI 仍然是观察者确定服务器身份的主要显式信号.

ECH is supported in TLS 1.3 {{!RFC8446}}, DTLS 1.3 {{!RFC9147}}, and
newer versions of the TLS and DTLS protocols.

ECH 在 TLS 1.3 {{!RFC8446}}、DTLS 1.3 {{!RFC9147}} 和更新版本的 TLS 和 DTLS 协议中受支持.

# Conventions and Definitions | 约定和定义 {#conventions-and-definitions}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{RFC2119}} {{!RFC8174}}
when, and only when, they appear in all capitals, as shown here. All TLS
notation comes from {{RFC8446, Section 3}}.

本文档中的关键词 "必须" ("MUST" / "SHALL" / "REQUIRED")、"绝不能" ("MUST NOT" / "SHALL NOT"), "推荐" ("SHOULD" / "RECOMMENDED")、"不推荐" ("SHOULD NOT" / "NOT RECOMMENDED"), "可以/可能/可选" ("MAY" / "OPTIONAL") 按照 BCP 14 {{RFC2119}} {{!RFC8174}} 中的描述进行解释, 当且仅当它们以全大写字母出现时, 如此处所示.
所有 TLS 符号来自 {{RFC8446, Section 3}}.

# Overview | 概述 {#overview}

This protocol is designed to operate in one of two topologies illustrated below,
which we call "Shared Mode" and "Split Mode". These modes are described in the
following section.

该协议设计为在下面所示的两种拓扑结构之一中运行, 我们称之为 "同址模式" ("Shared Mode") 和 "异址模式" ("Split Mode"). 这些模式将在下一节中描述.

(译者注: 这里的 "同址模式" 和 "异址模式" 非相关术语的正式中文翻译, 此处为意译, "址" 即 "地址", 面向客户端的服务器和后端服务器的相对位置.)

## Topologies | 拓扑结构 {#topologies}

~~~~
                +---------------------+
                |                     |
                |   2001:DB8::1111    |
                |                     |
Client <----->  | private.example.org |
                |                     |
                | public.example.com  |
                |                     |
                +---------------------+
                        Server
          (Client-Facing and Backend Combined)
~~~~
{: #shared-mode title="Shared Mode Topology"}

In Shared Mode, the provider is the origin server for all the domains whose DNS
records point to it. In this mode, the TLS connection is terminated by the
provider.

在同址模式下, (网络服务)提供商提供、域名 DNS 记录所指向的服务器, 亦是源服务器. 在此模式下, TLS 连接由(网络服务)提供商终止.

~~~~
           +--------------------+     +---------------------+
           |                    |     |                     |
           |   2001:DB8::1111   |     |   2001:DB8::EEEE    |
Client <----------------------------->|                     |
           | public.example.com |     | private.example.org |
           |                    |     |                     |
           +--------------------+     +---------------------+
            Client-Facing Server            Backend Server
~~~~
{: #split-mode title="Split Mode Topology"}

In Split Mode, the provider is not the origin server for private domains.
Rather, the DNS records for private domains point to the provider, and the
provider's server relays the connection back to the origin server, who
terminates the TLS connection with the client. Importantly, the service provider
does not have access to the plaintext of the connection beyond the unencrypted
portions of the handshake.

在异址模式下, (网络服务)提供商(提供的面向客户端的)服务器不再是私有域(即内层 ClientHello 实际所指示的 SNI 对应的)的源服务器(后端服务器). 相反, 私有域的 DNS 记录指向(网络服务)提供商(提供的面向客户端的服务器), (网络服务)提供商再将连接中继给源服务器, 由源服务器终止与客户端的 TLS 连接. 重要的是, 除了握手过程中未加密的部分, (网络)服务提供商无法访问连接的明文.

In the remainder of this document, we will refer to the ECH-service provider as
the "client-facing server" and to the TLS terminator as the "backend server".
These are the same entity in Shared Mode, but in Split Mode, the client-facing
and backend servers are physically separated.

在本文档的其余部分, 我们将把 ECH 服务提供商称为 "面向客户端的服务器", 把(提供实际服务, 并负责)中止 TLS 连接的服务器称为 "后端服务器". 在同址模式下, 它们是同一个实体, 但在异址模式下, 面向客户端的服务器和后端服务器在物理上是分离的.

See {{security-considerations}} for more discussion about the ECH threat model
and how it relates to the client, client-facing server, and backend server.

有关 ECH 威胁模型以及它与客户端、面向客户端的服务器和后端服务器的关系的更多讨论, 参见 {{security-considerations}}.

## Encrypted ClientHello (ECH)

A client-facing server enables ECH by publishing an ECH configuration, which
is an encryption public key and associated metadata. Domains which wish to
use ECH must publish this configuration, using the key associated
with the client-facing server. This document
defines the ECH configuration's format, but delegates DNS publication details
to {{!RFC9460}}. See
{{!ECH-IN-DNS=I-D.ietf-tls-svcb-ech}} for specifics about how ECH configurations
are advertised in SVCB and HTTPS records. Other delivery mechanisms are
also possible. For example, the client may have the ECH configuration
preconfigured.

面向客户端的服务器通过发布 ECH 配置来启用 ECH, 该配置是加密公钥和相关元数据. 希望使用 ECH 的域名必须发布此配置, 使用与面向客户端的服务器关联的密钥. 本文档定义了 ECH 配置的格式, 但将 DNS 发布细节委托给 {{!RFC9460}}. 有关如何在 SVCB 和 HTTPS 记录中公布 ECH 配置的具体信息, 请参见 {{!ECH-IN-DNS=I-D.ietf-tls-svcb-ech}}. 其他传递机制也是可能的. 例如, 客户端可能预配置了 ECH 配置.

When a client wants to establish a TLS session with some backend server, it
constructs a private ClientHello, referred to as the ClientHelloInner.
The client then constructs a public ClientHello, referred to as the
ClientHelloOuter. The ClientHelloOuter contains innocuous values for
sensitive extensions and an "encrypted_client_hello" extension
({{encrypted-client-hello}}), which carries the encrypted ClientHelloInner.
Finally, the client sends ClientHelloOuter to the server.

当客户端想要与某个后端服务器建立 TLS 会话时, 它构造一个私有 ClientHello, 称为 ClientHelloInner. 然后客户端构造一个公共 ClientHello, 称为 ClientHelloOuter. ClientHelloOuter 包含敏感扩展的无害值和一个 "encrypted_client_hello" 扩展 ({{encrypted-client-hello}}) , 该扩展携带加密的 ClientHelloInner. 最后, 客户端向服务器发送 ClientHelloOuter.

The server takes one of the following actions:

服务器采取以下操作之一：

1. If it does not support ECH or cannot decrypt the extension, it completes
   the handshake with ClientHelloOuter. This is referred to as rejecting ECH.

   如果它不支持 ECH 或无法解密扩展, 它用 ClientHelloOuter 完成握手. 这被称为拒绝 ECH.
1. If it successfully decrypts the extension, it forwards the ClientHelloInner
   to the backend server, which completes the handshake. This is referred to
   as accepting ECH.

   如果它成功解密了扩展, 它将 ClientHelloInner 转发给后端服务器, 由后端服务器完成握手过程. 这被称为接受 ECH.

Upon receiving the server's response, the client determines whether or not ECH
was accepted ({{determining-ech-acceptance}}) and proceeds with the handshake
accordingly. When ECH is rejected, the resulting connection is not usable by
the client for application data. Instead, ECH rejection allows the client to
retry with up-to-date configuration ({{rejected-ech}}).

收到服务器响应后, 客户端确定 ECH 是否被接受 ({{determining-ech-acceptance}}) 并相应地进行握手. 当 ECH 被拒绝时, 生成的连接不能被客户端用于应用数据. 相反, ECH 被拒绝后允许客户端使用最新配置重试 ({{rejected-ech}}) .

The primary goal of ECH is to ensure that connections to servers in the same
anonymity set are indistinguishable from one another. Moreover, it should
achieve this goal without affecting any existing security properties of TLS 1.3.
See {{goals}} for more details about the ECH security and privacy goals.

ECH 的主要目标是确保到同一匿名集中服务器的连接彼此无法区分. 此外, 它应该在不影响 TLS 1.3 的任何现有安全属性的情况下实现这一目标. 有关 ECH 安全和隐私目标的更多详细信息, 请参见 {{goals}}.

# Encrypted ClientHello Configuration | Encrypted ClientHello 配置 {#ech-configuration}

ECH uses HPKE for public key encryption {{!HPKE=RFC9180}}.
The ECH configuration is defined by the following `ECHConfig` structure.

ECH 使用 HPKE 进行公钥加密 {{!HPKE=RFC9180}}. ECH 配置由以下 `ECHConfig` 结构定义.

~~~~
    opaque HpkePublicKey<1..2^16-1>;
    uint16 HpkeKemId;              // Defined in RFC9180
    uint16 HpkeKdfId;              // Defined in RFC9180
    uint16 HpkeAeadId;             // Defined in RFC9180
    uint16 ECHConfigExtensionType; // Defined in Section 11.3

    struct {
        HpkeKdfId kdf_id;
        HpkeAeadId aead_id;
    } HpkeSymmetricCipherSuite;

    struct {
        uint8 config_id;
        HpkeKemId kem_id;
        HpkePublicKey public_key;
        HpkeSymmetricCipherSuite cipher_suites<4..2^16-4>;
    } HpkeKeyConfig;

    struct {
        ECHConfigExtensionType type;
        opaque data<0..2^16-1>;
    } ECHConfigExtension;

    struct {
        HpkeKeyConfig key_config;
        uint8 maximum_name_length;
        opaque public_name<1..255>;
        ECHConfigExtension extensions<0..2^16-1>;
    } ECHConfigContents;

    struct {
        uint16 version;
        uint16 length;
        select (ECHConfig.version) {
          case 0xfe0d: ECHConfigContents contents;
        }
    } ECHConfig;
~~~~

The structure contains the following fields:

该结构包含以下字段：

version
: The version of ECH for which this configuration is used. The version
is the same as the code point for the
"encrypted_client_hello" extension. Clients MUST ignore any `ECHConfig`
structure with a version they do not support.
: 此配置使用的 ECH 版本. 版本与"encrypted_client_hello"扩展的代码点相同.
客户端**必须**忽略任何版本不支持的 `ECHConfig` 结构.

length
: The length, in bytes, of the next field. This length field allows
implementations to skip over the elements in such a list where they cannot
parse the specific version of ECHConfig.
: 下一个字段的长度 (以字节为单位) . 此长度字段允许实现跳过此类列表中无法解析特定版本 ECHConfig 的元素.

contents
: An opaque byte string whose contents depend on the version. For this
specification, the contents are an `ECHConfigContents` structure.
: 不透明的字节串, 其内容取决于版本. 对于此规范, 内容是 `ECHConfigContents` 结构.

The `ECHConfigContents` structure contains the following fields:

`ECHConfigContents` 结构包含以下字段：

key_config
: A `HpkeKeyConfig` structure carrying the configuration information
associated with the HPKE public key (an "ECH key"). Note that this
structure contains the `config_id` field, which applies to the entire
ECHConfigContents.
: 一个 `HpkeKeyConfig` 结构, 携带与 HPKE 公钥 ("ECH 密钥") 关联的配置信息. 请注意, 此结构包含 `config_id` 字段, 该字段适用于整个 ECHConfigContents.

maximum_name_length
: The longest name of a backend server, if known. If not known, this value can
be set to zero. It is used to compute padding ({{padding}}) and does not
constrain server name lengths. Names may exceed this length if, e.g.,
the server uses wildcard names or added new names to the anonymity set.
: 后端服务器的最长名称 (如果已知) . 如果未知, 此值可以设置为零. 它用于计算填充 ({{padding}}) 并且不限制服务器名称长度. 如果服务器使用通配符名称或向匿名集添加新名称, 名称可能超过此长度.

public_name
: The DNS name of the client-facing server, i.e., the entity trusted
to update the ECH configuration. This is used to correct misconfigured clients,
as described in {{rejected-ech}}.
: 面向客户端的服务器的 DNS 名称, 即受信任更新 ECH 配置的实体. 这用于纠正配置错误的客户端, 如 {{rejected-ech}} 中所述.
: See {{auth-public-name}} for how the client interprets and validates the
public_name.
: 有关客户端如何解释和验证 public_name, 请参见 {{auth-public-name}}.

extensions
: A list of ECHConfigExtension values that the client must take into
consideration when generating a ClientHello message. Each ECHConfigExtension
has a 2-octet type and opaque data value, where the data value is encoded
with a 2-octet integer representing the length of the data, in network byte
order. ECHConfigExtension values are described below ({{config-extensions}}).
: 客户端在生成 ClientHello 消息时必须考虑的 ECHConfigExtension 值列表. 每个 ECHConfigExtension 都有一个 2 字节类型和不透明数据值, 其中数据值用表示数据长度的 2 字节整数编码, 按网络字节顺序. ECHConfigExtension 值在下面描述 ({{config-extensions}}) .

The `HpkeKeyConfig` structure contains the following fields:

`HpkeKeyConfig` 结构包含以下字段：

config_id
: A one-byte identifier for the given HPKE key configuration. This is used by
clients to indicate the key used for ClientHello encryption. {{config-ids}}
describes how client-facing servers allocate this value.
: 给定 HPKE 密钥配置的单字节标识符. 客户端使用它来指示用于 ClientHello 加密的密钥. {{config-ids}} 描述了面向客户端的服务器如何分配此值.

kem_id
: The HPKE Key Encapsulation Mechanism (KEM) identifier corresponding
to `public_key`. Clients MUST ignore any `ECHConfig` structure with a
key using a KEM they do not support.
: 对应于 `public_key` 的 HPKE 密钥封装机制 (KEM) 标识符. 客户端必须忽略任何使用不支持的 KEM 的密钥的 `ECHConfig` 结构.

public_key
: The HPKE public key used by the client to encrypt ClientHelloInner.
: 客户端用于加密 ClientHelloInner 的 HPKE 公钥.

cipher_suites
: The list of HPKE KDF and AEAD identifier pairs clients can use for encrypting
ClientHelloInner. See {{real-ech}} for how clients choose from this list.
: 客户端可用于加密 ClientHelloInner 的 HPKE KDF 和 AEAD 标识符对列表. 有关客户端如何从此列表中选择, 请参见 {{real-ech}}.

The client-facing server advertises a sequence of ECH configurations to clients,
serialized as follows.

面向客户端的服务器向客户端公布一系列 ECH 配置, 序列化如下.

~~~~
    ECHConfig ECHConfigList<4..2^16-1>;
~~~~

The `ECHConfigList` structure contains one or more `ECHConfig` structures in
decreasing order of preference. This allows a server to support multiple
versions of ECH and multiple sets of ECH parameters.

`ECHConfigList` 结构包含一个或多个 `ECHConfig` 结构, 按偏好递减顺序排列. 这允许服务器支持多个版本的 ECH 和多组 ECH 参数.

## Configuration Identifiers | 配置标识符 {#config-ids}

A client-facing server has a set of known ECHConfig values, with corresponding
private keys. This set SHOULD contain the currently published values, as well as
previous values that may still be in use, since clients may cache DNS records
up to a TTL or longer.

面向客户端的服务器有一组已知的 ECHConfig 值, 以及相应的私钥. 此集合应包含当前发布的值, 以及可能仍在使用的先前值, 因为客户端可能会缓存 DNS 记录达到 TTL 或更长时间.

{{client-facing-server}} describes a trial decryption process for decrypting the
ClientHello. This can impact performance when the client-facing server maintains
many known ECHConfig values. To avoid this, the client-facing server SHOULD
allocate distinct `config_id` values for each ECHConfig in its known set. The
RECOMMENDED strategy is via rejection sampling, i.e., to randomly select
`config_id` repeatedly until it does not match any known ECHConfig.

{{client-facing-server}} 描述了解密 ClientHello 的试验解密过程. 当面向客户端的服务器维护许多已知的 ECHConfig 值时, 这可能会影响性能. 为了避免这种情况, 面向客户端的服务器应为其已知集合中的每个 ECHConfig 分配不同的 `config_id` 值. 推荐的策略是通过接受-拒绝算法, 即重复随机选择 `config_id`, 直到它不匹配任何已知的 ECHConfig.

It is not necessary for `config_id` values across different client-facing
servers to be distinct. A backend server may be hosted behind two different
client-facing servers with colliding `config_id` values without any performance
impact. Values may also be reused if the previous ECHConfig is no longer in the
known set.

`config_id` 值不必在不同面向客户端的服务器之间全局唯一. 后端服务器可能托管在两个不同的面向客户端的服务器后面, 具有冲突的 `config_id` 值, 但不会对性能产生任何影响. 如果先前的 ECHConfig 不再在已知集合中, 也可以重用值.

## Configuration Extensions | 配置扩展 {#config-extensions}

ECH configuration extensions are used to provide room for additional
functionality as needed. The format is as defined in
{{ech-configuration}} and mirrors {{Section 4.2 of RFC8446}}. However,
ECH configuration extension types are maintained by IANA as described
in {{config-extensions-iana}}.  ECH configuration extensions follow
the same interpretation rules as TLS extensions: extensions MAY appear
in any order, but there MUST NOT be more than one extension of the
same type in the extensions block. Unlike TLS extensions, an extension
can be tagged as mandatory by using an extension type codepoint with
the high order bit set to 1.

ECH 配置扩展用于根据需要为附加功能提供空间. 格式如 {{ech-configuration}} 中定义, 镜像自 {{Section 4.2 of RFC8446}}. 但是, ECH 配置扩展类型由 IANA 维护, 如 {{config-extensions-iana}} 中所述. ECH 配置扩展遵循与 TLS 扩展相同的解释规则：扩展**可以**以任何顺序出现, 但扩展块中**绝不能**有多个相同类型的扩展. 与 TLS 扩展不同, 可以通过使用高位设置为 1 的扩展类型代码点将扩展标记为强制性的.

Clients MUST parse the extension list and check for unsupported mandatory
extensions. If an unsupported mandatory extension is present, clients MUST
ignore the `ECHConfig`.

客户端**必须**解析扩展列表并检查不支持的强制性扩展. 如果强制性扩展不被支持, 客户端**必须**忽略此 `ECHConfig`.

Any future information or hints that influence ClientHelloOuter SHOULD be
specified as ECHConfig extensions. This is primarily because the outer
ClientHello exists only in support of ECH. Namely, it is both an envelope for
the encrypted inner ClientHello and enabler for authenticated key mismatch
signals (see {{server-behavior}}). In contrast, the inner ClientHello is the
true ClientHello used upon ECH negotiation.

任何影响 ClientHelloOuter 的未来可能加入的信息或提示都**推荐**指定为 ECHConfig 扩展. 这主要是因为外部 ClientHello 仅存在于支持 ECH. 也就是说, 它既充当内部保存有加密 ClientHello 的信封, 又作为认证密钥不匹配信号的启用机制 (参见 {{server-behavior}}) . 相比之下, 内部 ClientHello 才是在 ECH 协商时使用的真正 ClientHello.

# The "encrypted_client_hello" Extension | "encrypted_client_hello" 扩展 {#encrypted-client-hello}

To offer ECH, the client sends an "encrypted_client_hello" extension in the
ClientHelloOuter. When it does, it ``MUST`` also send the extension in
ClientHelloInner.

为了提供 ECH, 客户端在 ClientHelloOuter 中发送 "encrypted_client_hello" 扩展. 当它这样做时, 它也**必须**在 ClientHelloInner 中发送扩展.

~~~
    enum {
       encrypted_client_hello(0xfe0d), (65535)
    } ExtensionType;
~~~

The payload of the extension has the following structure:

扩展的有效载荷具有以下结构：

~~~~
    enum { outer(0), inner(1) } ECHClientHelloType;

    struct {
       ECHClientHelloType type;
       select (ECHClientHello.type) {
           case outer:
               HpkeSymmetricCipherSuite cipher_suite;
               uint8 config_id;
               opaque enc<0..2^16-1>;
               opaque payload<1..2^16-1>;
           case inner:
               Empty;
       };
    } ECHClientHello;
~~~~

The outer extension uses the `outer` variant and the inner extension uses the
`inner` variant. The inner extension has an empty payload, which is included
because TLS servers are not allowed to provide extensions in ServerHello
which were not included in ClientHello. The outer extension has the following
fields:

外部扩展使用 `outer` 变体, 内部扩展使用 `inner` 变体. 内部扩展有一个空的有效载荷, 包含它是因为 TLS 服务器不允许在 ServerHello 中提供未包含在 ClientHello 中的扩展. 外部扩展具有以下字段：

config_id
: The ECHConfigContents.key_config.config_id for the chosen ECHConfig.
: 所选 ECHConfig 的 ECHConfigContents.key_config.config_id.

cipher_suite
: The cipher suite used to encrypt ClientHelloInner. This MUST match a value
provided in the corresponding `ECHConfigContents.cipher_suites` list.
: 用于加密 ClientHelloInner 的密码套件. 这**必须**匹配相应 `ECHConfigContents.cipher_suites` 列表中提供的值.

enc
: The HPKE encapsulated key, used by servers to decrypt the corresponding
`payload` field. This field is empty in a ClientHelloOuter sent in response to
HelloRetryRequest.
: HPKE 封装后的密钥, 服务器用于解密相应的 `payload` 字段. 在响应 HelloRetryRequest 发送的 ClientHelloOuter 中, 此字段为空.

payload
: The serialized and encrypted EncodedClientHelloInner structure, encrypted
using HPKE as described in {{real-ech}}.
: 序列化和加密的 EncodedClientHelloInner 结构, 使用 HPKE 加密, 如 {{real-ech}} 中所述.

When a client offers the `outer` version of an "encrypted_client_hello"
extension, the server MAY include an "encrypted_client_hello" extension in its
EncryptedExtensions message, as described in {{client-facing-server}}, with the
following payload:

当客户端提供 "encrypted_client_hello" 扩展的 `outer` 版本时, 服务器**可能**在其 EncryptedExtensions 消息中包含 "encrypted_client_hello" 扩展, 如 {{client-facing-server}} 中所述, 具有以下有效载荷：

~~~
    struct {
       ECHConfigList retry_configs;
    } ECHEncryptedExtensions;
~~~

The response is valid only when the server used the ClientHelloOuter. If the
server sent this extension in response to the `inner` variant, then the client
MUST abort with an "unsupported_extension" alert.

仅在服务器响应 ClientHelloOuter 时有效. 如果服务器响应了 `inner` 变体却发送了此扩展, 则客户端**必须**以 "unsupported_extension" 警报中止.

retry_configs
: An ECHConfigList structure containing one or more ECHConfig structures, in
decreasing order of preference, to be used by the client as described in
{{rejected-ech}}. These are known as the server's "retry configurations".
: 包含一个或多个 ECHConfig 结构的 ECHConfigList 结构, 按偏好递减顺序排列, 供客户端使用, 如 {{rejected-ech}} 中所述. 这些被称为服务器的 "重试配置".

Finally, when the client offers the "encrypted_client_hello", if the payload is
the `inner` variant and the server responds with HelloRetryRequest, it MUST
include an "encrypted_client_hello" extension with the following payload:

最后, 当客户端提供 "encrypted_client_hello" 时, 如果有效载荷是 `inner` 变体且服务器响应 HelloRetryRequest, 它必须包含具有以下有效载荷的 "encrypted_client_hello" 扩展：

~~~
    struct {
       opaque confirmation[8];
    } ECHHelloRetryRequest;
~~~

The value of ECHHelloRetryRequest.confirmation is set to
`hrr_accept_confirmation` as described in {{backend-server-hrr}}.

ECHHelloRetryRequest.confirmation 的值设置为 `hrr_accept_confirmation`, 如 {{backend-server-hrr}} 中所述.

This document also defines the "ech_required" alert, which the client MUST send
when it offered an "encrypted_client_hello" extension that was not accepted by
the server. (See {{alerts}}.)

本文档还定义了 "ech_required" 警报, 当客户端提供的 "encrypted_client_hello" 扩展未被服务器接受时, 客户端**必须**发送该警报.  (参见 {{alerts}}. ) 

## Encoding the ClientHelloInner | 编码 ClientHelloInner {#encoding-inner}

Before encrypting, the client pads and optionally compresses ClientHelloInner
into a EncodedClientHelloInner structure, defined below:

在加密之前, 客户端将 ClientHelloInner 填充并可选地压缩到 EncodedClientHelloInner 结构中, 定义如下：

~~~
    struct {
        ClientHello client_hello;
        uint8 zeros[length_of_padding];
    } EncodedClientHelloInner;
~~~

The `client_hello` field is computed by first making a copy of ClientHelloInner
and setting the `legacy_session_id` field to the empty string. In TLS, this
field uses the ClientHello structure defined in {{Section 4.1.2 of RFC8446}}.
In DTLS, it uses the ClientHello structured defined in
{{Section 5.3 of RFC9147}}. This does not include Handshake structure's
four-byte header in TLS, nor twelve-byte header in DTLS. The `zeros` field MUST
be all zeroes of length `length_of_padding` (see {{padding}}).

`client_hello` 字段通过首先复制 ClientHelloInner 并将 `legacy_session_id` 字段设置为空字符串来计算. 在 TLS 中, 此字段使用 {{Section 4.1.2 of RFC8446}} 中定义的 ClientHello 结构. 在 DTLS 中, 它使用 {{Section 5.3 of RFC9147}} 中定义的 ClientHello 结构. 这不包括 TLS 中握手结构的四字节头部, 也不包括 DTLS 中的十二字节头部. `zeros` 字段**必须**是长度为 `length_of_padding` 的全零填充 (参见 {{padding}}) .

Repeating large extensions, such as "key_share" with post-quantum algorithms,
between ClientHelloInner and ClientHelloOuter can lead to excessive size. To
reduce the size impact, the client MAY substitute extensions which it knows
will be duplicated in ClientHelloOuter. It does so by removing and replacing
extensions from EncodedClientHelloInner with a single "ech_outer_extensions"
extension, defined as follows:

在 ClientHelloInner 和 ClientHelloOuter 之间重复引入大型扩展, 如带有后量子算法的 "key_share", 可能导致过大的 ClientHello. 为了减少大小影响, 客户端**可以**替换它知道将在 ClientHelloOuter 中重复的扩展. 它通过从 EncodedClientHelloInner 中删除和替换扩展为单个 "ech_outer_extensions" 扩展来实现, 定义如下：

~~~
    enum {
       ech_outer_extensions(0xfd00), (65535)
    } ExtensionType;

    ExtensionType OuterExtensions<2..254>;
~~~

OuterExtensions contains the removed ExtensionType values. Each value references
the matching extension in ClientHelloOuter. The values MUST be ordered
contiguously in ClientHelloInner, and the "ech_outer_extensions" extension MUST
be inserted in the corresponding position in EncodedClientHelloInner.
Additionally, the extensions MUST appear in ClientHelloOuter in the same
relative order. However, there is no requirement that they be contiguous. For
example, OuterExtensions may contain extensions A, B, C, while ClientHelloOuter
contains extensions A, D, B, C, E, F.

OuterExtensions 包含已略去的拓展的 ExtensionType. 代表对 ClientHelloOuter 中相应扩展的引用. 这些值**必须**在 ClientHelloInner 中连续, 并且 "ech_outer_extensions" 扩展**必须**插入到 EncodedClientHelloInner 中的相应位置. 此外, 扩展**必须**以相同的相对顺序出现在 ClientHelloOuter 中. 但是, 不要求它们是连续的. 例如, OuterExtensions 可能包含扩展 A、B、C, 而 ClientHelloOuter 包含扩展 A、D、B、C、E、F.

The "ech_outer_extensions" extension can only be included in
EncodedClientHelloInner, and MUST NOT appear in either ClientHelloOuter or
ClientHelloInner.

"ech_outer_extensions" 扩展只能包含在 EncodedClientHelloInner 中, **绝不能**出现在 ClientHelloOuter 或 ClientHelloInner 中.

Finally, the client pads the message by setting the `zeros` field to a byte
string whose contents are all zeros and whose length is the amount of padding
to add. {{padding}} describes a recommended padding scheme.

最后, 客户端通过将 `zeros` 字段设置为内容全为零且长度为要添加的填充量的字节字符串来填充消息. {{padding}} 描述了推荐的填充方案.

The client-facing server computes ClientHelloInner by reversing this process.
First it parses EncodedClientHelloInner, interpreting all bytes after
`client_hello` as padding. If any padding byte is non-zero, the server MUST
abort the connection with an "illegal_parameter" alert.

面向客户端的服务器通过逆转此过程来计算 ClientHelloInner. 首先它解析 EncodedClientHelloInner, 将 `client_hello` 之后的所有字节解释为填充. 如果任何填充字节非零, 服务器**必须**以 "illegal_parameter" 警报中止连接.

Next it makes a copy of the `client_hello` field and copies the
`legacy_session_id` field from ClientHelloOuter. It then looks for an
"ech_outer_extensions" extension. If found, it replaces the extension with the
corresponding sequence of extensions in the ClientHelloOuter. The server MUST
abort the connection with an "illegal_parameter" alert if any of the following
are true:

接下来, 它复制 `client_hello` 字段并从 ClientHelloOuter 复制 `legacy_session_id` 字段. 然后它查找 "ech_outer_extensions" 扩展. 如果找到, 它用 ClientHelloOuter 中相应的扩展序列替换扩展. 如果以下任何情况为真, 服务器必须以 "illegal_parameter" 警报中止连接：

* Any referenced extension is missing in ClientHelloOuter.

  ClientHelloOuter 中缺少任何引用的扩展.

* Any extension is referenced in OuterExtensions more than once.

  OuterExtensions 中多次引用任何扩展.

* "encrypted_client_hello" is referenced in OuterExtensions.

  OuterExtensions 中引用了 "encrypted_client_hello".

* The extensions in ClientHelloOuter corresponding to those in OuterExtensions
  do not occur in the same order.

  ClientHelloOuter 中对应于 OuterExtensions 中那些扩展的扩展没有以相同顺序出现.

These requirements prevent an attacker from performing a packet amplification
attack, by crafting a ClientHelloOuter which decompresses to a much larger
ClientHelloInner. This is discussed further in {{decompression-amp}}.

这些要求是为了防止攻击者通过制作解压缩为更大 ClientHelloInner 的 ClientHelloOuter 执行数据包放大攻击. 这在 {{decompression-amp}} 中进一步讨论.

Implementations SHOULD construct the ClientHelloInner in linear
time. Quadratic time implementations (such as may happen via naive
copying) create a denial of service risk.
{{linear-outer-extensions}} describes a linear-time procedure that may be used
for this purpose.

**推荐**以线性时间构造 ClientHelloInner. 二次型时间实现 (如朴素复制) 会产生拒绝服务风险. {{linear-outer-extensions}} 描述了可用于此目的的线性时间过程.

## Authenticating the ClientHelloOuter | 认证 ClientHelloOuter {#authenticating-outer}

To prevent a network attacker from modifying the `ClientHelloOuter`
while keeping the same encrypted `ClientHelloInner`
(see {{flow-clienthello-malleability}}), ECH authenticates ClientHelloOuter
by passing ClientHelloOuterAAD as the associated data for HPKE sealing
and opening operations. The ClientHelloOuterAAD is a serialized
ClientHello structure, defined in {{Section 4.1.2 of RFC8446}} for TLS and
{{Section 5.3 of RFC9147}} for DTLS, which matches the ClientHelloOuter except
that the `payload` field of the "encrypted_client_hello" is replaced with a byte
string of the same length but whose contents are zeros. This value does not
include Handshake structure's four-byte header in TLS nor twelve-byte header in
DTLS.

为了防止网络攻击者在保持相同加密 `ClientHelloInner` 的同时修改 `ClientHelloOuter` (参见 {{flow-clienthello-malleability}}) , ECH 通过将 ClientHelloOuterAAD 作为 HPKE 密封和打开操作的关联数据来认证 ClientHelloOuter. ClientHelloOuterAAD 是一个序列化的 ClientHello 结构, 在 TLS 的 {{Section 4.1.2 of RFC8446}} 和 DTLS 的 {{Section 5.3 of RFC9147}} 中定义, 它匹配 ClientHelloOuter, 除了 "encrypted_client_hello" 的 `payload` 字段被替换为相同长度但内容为零的字节字符串. 此值不包括 TLS 中握手结构的四字节头部, 也不包括 DTLS 中的十二字节头部.

# Client Behavior | 客户端行为 {#client-behavior}

Clients that implement the ECH extension behave in one of two ways: either they
offer a real ECH extension, as described in {{real-ech}}; or they send a
Generate Random Extensions And Sustain Extensibility (GREASE) {{?RFC8701}}
ECH extension, as described in {{grease-ech}}. Clients of the latter type do not
negotiate ECH. Instead, they generate a dummy ECH extension that is ignored by
the server. (See {{dont-stick-out}} for an explanation.) The client offers ECH
if it is in possession of a compatible ECH configuration and sends GREASE ECH
(see {{grease-ech}}) otherwise.

实现 ECH 扩展的客户端以两种方式之一行为：要么它们提供真正的 ECH 扩展, 如 {{real-ech}} 中所述；要么它们发送生成随机扩展并维持可扩展性 (GREASE) {{?RFC8701}} ECH 扩展, 如 {{grease-ech}} 中所述. 后一种类型的客户端不协商 ECH. 相反, 它们生成被服务器忽略的虚拟 ECH 扩展.  (有关解释, 请参见 {{dont-stick-out}}. ) 如果客户端拥有兼容的 ECH 配置, 则提供 ECH, 否则发送 GREASE ECH (参见 {{grease-ech}}) .

## Offering ECH | 提供 ECH {#real-ech}

To offer ECH, the client first chooses a suitable ECHConfig from the server's
ECHConfigList. To determine if a given `ECHConfig` is suitable, it checks that
it supports the KEM algorithm identified by `ECHConfig.contents.kem_id`, at
least one KDF/AEAD algorithm identified by `ECHConfig.contents.cipher_suites`,
and the version of ECH indicated by `ECHConfig.contents.version`. Once a
suitable configuration is found, the client selects the cipher suite it will
use for encryption. It MUST NOT choose a cipher suite or version not advertised
by the configuration. If no compatible configuration is found, then the client
SHOULD proceed as described in {{grease-ech}}.

为了提供 ECH, 客户端首先从服务器的 ECHConfigList 中选择合适的 ECHConfig. 为了确定给定的 `ECHConfig` 是否合适, 它检查是否支持由 `ECHConfig.contents.kem_id` 标识的 KEM 算法, 至少一个由 `ECHConfig.contents.cipher_suites` 标识的 KDF / AEAD 算法, 以及由 `ECHConfig.contents.version` 指示的 ECH 版本. 一旦找到合适的配置, 客户端选择它将用于加密的密码套件. 它不得选择配置未公布的密码套件或版本. 如果找不到兼容的配置, 则客户端**必须**按照 {{grease-ech}} 中的描述进行.

Next, the client constructs the ClientHelloInner message just as it does a
standard ClientHello, with the exception of the following rules:

接下来, 客户端构造 ClientHelloInner 消息, 就像构造标准 ClientHello 一样, 但有以下规则的例外：

1. It MUST NOT offer to negotiate TLS 1.2 or below. This is necessary to ensure
   the backend server does not negotiate a TLS version that is incompatible with
   ECH.

   它**绝不能**协商 TLS 1.2 或以下版本. 这是必要的, 以确保后端服务器不协商与 ECH 不兼容的 TLS 版本.
1. It MUST NOT offer to resume any session for TLS 1.2 and below.

   它**绝不能**执行 TLS 1.2 及以下任何版本的会话恢复.
1. If it intends to compress any extensions (see {{encoding-inner}}), it MUST
   order those extensions consecutively.

   如果它打算压缩任何扩展 (参见 {{encoding-inner}}) , 它必须连续排序这些扩展.
1. It MUST include the "encrypted_client_hello" extension of type `inner` as
   described in {{encrypted-client-hello}}. (This requirement is not applicable
   when the "encrypted_client_hello" extension is generated as described in
   {{grease-ech}}.)

   它必须包含类型为 `inner` 的 "encrypted_client_hello" 扩展, 如 {{encrypted-client-hello}} 中所述.

The client then constructs EncodedClientHelloInner as described in
{{encoding-inner}}. It also computes an HPKE encryption context and `enc` value
as:

然后客户端按照 {{encoding-inner}} 中的描述构造 EncodedClientHelloInner. 它还计算 HPKE 加密上下文和 `enc` 值：

~~~
    pkR = DeserializePublicKey(ECHConfig.contents.public_key)
    enc, context = SetupBaseS(pkR,
                              "tls ech" || 0x00 || ECHConfig)
~~~

Next, it constructs a partial ClientHelloOuterAAD as it does a standard
ClientHello, with the exception of the following rules:

接下来, 它构造部分 ClientHelloOuterAAD, 就像构造标准 ClientHello 一样, 但有以下规则的例外：

1. It MUST offer to negotiate TLS 1.3 or above.

   它**必须**协商 TLS 1.3 或更高版本.
1. If it compressed any extensions in EncodedClientHelloInner, it MUST copy the
   corresponding extensions from ClientHelloInner. The copied extensions
   additionally MUST be in the same relative order as in ClientHelloInner.

   如果它在 EncodedClientHelloInner 中压缩了任何扩展, 它**必须**从 ClientHelloInner 复制相应的扩展. 复制的扩展还**必须**与 ClientHelloInner 中的相对顺序相同.
1. It MUST copy the legacy\_session\_id field from ClientHelloInner. This
   allows the server to echo the correct session ID for TLS 1.3's compatibility
   mode (see {{Appendix D.4 of RFC8446}}) when ECH is negotiated. Note that
   compatibility mode is not used in DTLS 1.3, but following this rule will
   produce the correct results for both TLS 1.3 and DTLS 1.3.

   它必须从 ClientHelloInner 复制 legacy\_session\_id 字段. 这允许服务器在协商 ECH 时为 TLS 1.3 的兼容模式回显正确的会话 ID (参见 {{Appendix D.4 of RFC8446}}) . 请注意, 兼容模式在 DTLS 1.3 中不使用, 但遵循此规则将为 TLS 1.3 和 DTLS 1.3 产生正确的结果.
1. It MAY copy any other field from the ClientHelloInner except
   ClientHelloInner.random. Instead, It MUST generate a fresh
   ClientHelloOuter.random using a secure random number generator. (See
   {{flow-client-reaction}}.)

   它**可以**从 ClientHelloInner 复制任何其他字段, 除了 ClientHelloInner.random. 相反, 它必须使用安全随机数生成器生成新的 ClientHelloOuter.random.  (参见 {{flow-client-reaction}}. ) 
1. It SHOULD place the value of `ECHConfig.contents.public_name` in the
   "server_name" extension. Clients that do not follow this step, or place a
   different value in the "server_name" extension, risk breaking the retry
   mechanism described in {{rejected-ech}} or failing to interoperate with
   servers that require this step to be done; see {{client-facing-server}}.

   它**必须**将 `ECHConfig.contents.public_name` 的值放在 "server_name" 扩展中. 不遵循此步骤或在 "server_name" 扩展中放置不同值的客户端可能会破坏 {{rejected-ech}} 中描述的重试机制或无法与要求执行此步骤的服务器互操作；参见 {{client-facing-server}}.
1. When the client offers the "pre_shared_key" extension in ClientHelloInner, it
   SHOULD also include a GREASE "pre_shared_key" extension in ClientHelloOuter,
   generated in the manner described in {{grease-psk}}. The client MUST NOT use
   this extension to advertise a PSK to the client-facing server. (See
   {{flow-clienthello-malleability}}.) When the client includes a GREASE
   "pre_shared_key" extension, it MUST also copy the "psk_key_exchange_modes"
   from the ClientHelloInner into the ClientHelloOuter.

   当客户端在 ClientHelloInner 中提供 "pre_shared_key" 扩展时, 它也应该在 ClientHelloOuter 中包含 GREASE "pre_shared_key"扩展, 按照 {{grease-psk}} 中描述的方式生成. 客户端**绝不能**使用此扩展向面向客户端的服务器公布 PSK.  (参见 {{flow-clienthello-malleability}}. ) 当客户端包含 GREASE "pre_shared_key" 扩展时, 它还**必须**将 "psk_key_exchange_modes" 从 ClientHelloInner 复制到 ClientHelloOuter.
1. When the client offers the "early_data" extension in ClientHelloInner, it
   MUST also include the "early_data" extension in ClientHelloOuter. This
   allows servers that reject ECH and use ClientHelloOuter to safely ignore any
   early data sent by the client per {{RFC8446, Section 4.2.10}}.

   当客户端在 ClientHelloInner 中提供"early_data"扩展时, 它也**必须**在 ClientHelloOuter 中包含"early_data"扩展. 这允许拒绝 ECH 并使用 ClientHelloOuter 的服务器根据 {{RFC8446, Section 4.2.10}} 安全地忽略客户端发送的任何早期数据.

The client might duplicate non-sensitive extensions in both messages. However,
implementations need to take care to ensure that sensitive extensions are not
offered in the ClientHelloOuter. See {{outer-clienthello}} for additional
guidance.

客户端可能在两个消息中重复非敏感扩展. 但是, 实现需要注意确保敏感扩展不在 ClientHelloOuter 中提供. 有关其他指导, 请参见 {{outer-clienthello}}.

Finally, the client encrypts the EncodedClientHelloInner with the above values,
as described in {{encrypting-clienthello}}, to construct a ClientHelloOuter. It
sends this to the server, and processes the response as described in
{{determining-ech-acceptance}}.

最后, 客户端使用上述值加密 EncodedClientHelloInner, 如 {{encrypting-clienthello}} 中所述, 以构造 ClientHelloOuter. 它将此发送给服务器, 并按照 {{determining-ech-acceptance}} 中的描述处理响应.

### Encrypting the ClientHello | 加密 ClientHello {#encrypting-clienthello}

Given an EncodedClientHelloInner, an HPKE encryption context and `enc` value,
and a partial ClientHelloOuterAAD, the client constructs a ClientHelloOuter as
follows.

给定 EncodedClientHelloInner、HPKE 加密上下文和 `enc` 值以及部分 ClientHelloOuterAAD, 客户端按如下方式构造 ClientHelloOuter.

First, the client determines the length L of encrypting EncodedClientHelloInner
with the selected HPKE AEAD. This is typically the sum of the plaintext length
and the AEAD tag length. The client then completes the ClientHelloOuterAAD with
an "encrypted_client_hello" extension. This extension value contains the outer
variant of ECHClientHello with the following fields:

首先, 客户端确定使用选定的 HPKE AEAD 加密 EncodedClientHelloInner 的长度 L. 这通常是明文长度和 AEAD 标签长度的总和. 然后客户端用 "encrypted_client_hello" 扩展完成 ClientHelloOuterAAD. 此扩展值包含具有以下字段的 ECHClientHello 的外部变体：

- `config_id`, the identifier corresponding to the chosen ECHConfig structure;

  对应于所选 ECHConfig 结构的标识符；
- `cipher_suite`, the client's chosen cipher suite;

  客户端选择的密码套件；
- `enc`, as given above; and

  如上所述；以及
- `payload`, a placeholder byte string containing L zeros.

  包含 L 个零的占位符字节字符串.

If configuration identifiers (see {{ignored-configs}}) are to be
ignored, `config_id` SHOULD be set to a randomly generated byte in the
first ClientHelloOuter and, in the event of a HelloRetryRequest (HRR),
MUST be left unchanged for the second ClientHelloOuter.

如果要忽略配置标识符 (参见 {{ignored-configs}}) , `config_id` **必须**在第一个 ClientHelloOuter 中设置为随机生成的字节, 且在 HelloRetryRequest (HRR) 中提供的第二个 ClientHelloOuter 中保持不变.

The client serializes this structure to construct the ClientHelloOuterAAD.
It then computes the final payload as:

客户端序列化此结构以构造 ClientHelloOuterAAD. 然后它计算最终有效载荷：

~~~
    final_payload = context.Seal(ClientHelloOuterAAD,
                                 EncodedClientHelloInner)
~~~

Including `ClientHelloOuterAAD` as the HPKE AAD binds the `ClientHelloOuter`
to the `ClientHelloInner`, thus preventing attackers from modifying
`ClientHelloOuter` while keeping the same `ClientHelloInner`, as described in
{{flow-clienthello-malleability}}.

将 `ClientHelloOuterAAD` 作为 HPKE AAD 包含将 `ClientHelloOuter` 绑定到 `ClientHelloInner`, 从而防止攻击者在保持相同 `ClientHelloInner` 的同时修改 `ClientHelloOuter`, 如 {{flow-clienthello-malleability}} 中所述.

Finally, the client replaces `payload` with `final_payload` to obtain
ClientHelloOuter. The two values have the same length, so it is not necessary
to recompute length prefixes in the serialized structure.

最后, 客户端用 `final_payload` 替换 `payload` 以获得 ClientHelloOuter. 这两个值具有相同的长度, 因此不需要重新计算序列化结构中的长度前缀.

Note this construction requires the "encrypted_client_hello" be computed after
all other extensions. This is possible because the ClientHelloOuter's
"pre_shared_key" extension is either omitted, or uses a random binder
({{grease-psk}}).

请注意, 此构造要求在所有其他扩展之后计算 "encrypted_client_hello". 这是可能的, 因为 ClientHelloOuter 的 "pre_shared_key" 扩展要么被省略, 要么使用随机绑定器 ({{grease-psk}}) .

### GREASE PSK {#grease-psk}

When offering ECH, the client is not permitted to advertise PSK identities in
the ClientHelloOuter. However, the client can send a "pre_shared_key" extension
in the ClientHelloInner. In this case, when resuming a session with the client,
the backend server sends a "pre_shared_key" extension in its ServerHello. This
would appear to a network observer as if the server were sending this
extension without solicitation, which would violate the extension rules
described in {{RFC8446}}. When offering a PSK in ClientHelloInner,
clients SHOULD send a GREASE "pre_shared_key" extension in the
ClientHelloOuter to make it appear to the network as if the extension were
negotiated properly.

在提供 ECH 时, 不允许客户端在 ClientHelloOuter 中公布 PSK 身份. 但是, 客户端可以在 ClientHelloInner 中发送 "pre_shared_key" 扩展. 在这种情况下, 当与客户端恢复会话时, 后端服务器在其 ServerHello 中发送 "pre_shared_key" 扩展. 对于网络观察者来说, 这似乎是服务器在没有请求的情况下发送此扩展, 这将违反 {{RFC8446}} 中描述的扩展规则. 当在 ClientHelloInner 中提供 PSK 时, 客户端**必须**在 ClientHelloOuter 中发送 GREASE "pre_shared_key" 扩展, 以使网络看起来好像扩展被正确协商.

The client generates the extension payload by constructing an `OfferedPsks`
structure (see {{RFC8446, Section 4.2.11}}) as follows. For each PSK identity
advertised in the ClientHelloInner, the client generates a random PSK identity
with the same length. It also generates a random, 32-bit, unsigned integer to
use as the `obfuscated_ticket_age`. Likewise, for each inner PSK binder, the
client generates a random string of the same length.

客户端通过按如下方式构造 `OfferedPsks` 结构 (参见 {{RFC8446, Section 4.2.11}}) 来生成扩展有效载荷. 对于 ClientHelloInner 中公布的每个 PSK 身份, 客户端生成具有相同长度的随机 PSK 身份. 它还生成一个随机的 32 位无符号整数用作 `obfuscated_ticket_age`. 同样, 对于每个内部 PSK 绑定器, 客户端生成相同长度的随机字符串.

Per the rules of {{real-ech}}, the server is not permitted to resume a
connection in the outer handshake. If ECH is rejected and the client-facing
server replies with a "pre_shared_key" extension in its ServerHello, then the
client MUST abort the handshake with an "illegal_parameter" alert.

根据 {{real-ech}} 的规则, 不允许服务器在外部握手中恢复连接. 如果 ECH 被拒绝且面向客户端的服务器在其 ServerHello 中回复 "pre_shared_key" 扩展, 则客户端**必须**以 "illegal_parameter" 警报中止握手.

### Recommended Padding Scheme | 推荐的填充方案 {#padding}

If the ClientHelloInner is encrypted without padding, then the length of
the `ClientHelloOuter.payload` can leak information about `ClientHelloInner`.
In order to prevent this the `EncodedClientHelloInner` structure
has a padding field. This section describes a deterministic mechanism for
computing the required amount of padding based on the following
observation: individual extensions can reveal sensitive information through
their length. Thus, each extension in the inner ClientHello may require
different amounts of padding. This padding may be fully determined by the
client's configuration or may require server input.

如果 ClientHelloInner 在没有填充的情况下加密, 则 `ClientHelloOuter.payload` 的长度可能会泄露有关 `ClientHelloInner` 的信息. 为了防止这种情况, `EncodedClientHelloInner` 结构有一个填充字段. 本节描述了基于以下观察的计算所需填充量的确定性机制：单个扩展可以通过其长度泄露敏感信息. 因此, 内部 ClientHello 中的每个扩展可能需要不同数量的填充. 此填充可能完全由客户端的配置确定, 或者可能需要服务器输入.

By way of example, clients typically support a small number of application
profiles. For instance, a browser might support HTTP with ALPN values
["http/1.1", "h2"] and WebRTC media with ALPNs ["webrtc", "c-webrtc"]. Clients
SHOULD pad this extension by rounding up to the total size of the longest ALPN
extension across all application profiles. The target padding length of most
ClientHello extensions can be computed in this way.

举例来说, 客户端通常支持少数应用程序配置文件. 例如, 浏览器可能支持带有 ALPN 值 ["http/1.1", "h2"] 的 HTTP 和带有 ALPN ["webrtc", "c-webrtc"] 的 WebRTC 媒体. 客户端应该通过四舍五入到所有应用程序配置文件中最长 ALPN 扩展的总大小来填充此扩展. 大多数 ClientHello 扩展的目标填充长度可以通过这种方式计算.

In contrast, clients do not know the longest SNI value in the client-facing
server's anonymity set without server input. Clients SHOULD use the ECHConfig's
`maximum_name_length` field as follows, where L is the `maximum_name_length`
value.

相比之下, 客户端在没有服务器输入的情况下不知道面向客户端的服务器匿名集中最长的 SNI 值. 客户端应该使用 ECHConfig 的 `maximum_name_length` 字段, 如下所示, 其中 L 是 `maximum_name_length` 值.

1. If the ClientHelloInner contained a "server_name" extension with a name of
   length D, add max(0, L - D) bytes of padding.

   如果 ClientHelloInner 包含带有长度为 D 的名称的"server_name"扩展, 则添加 max(0, L - D) 字节的填充.
2. If the ClientHelloInner did not contain a "server_name" extension (e.g., if
   the client is connecting to an IP address), add L + 9 bytes of padding. This
   is the length of a "server_name" extension with an L-byte name.

   如果 ClientHelloInner 不包含"server_name"扩展 (例如, 如果客户端连接到 IP 地址) , 则添加 L + 9 字节的填充. 这是带有 L 字节名称的"server_name"扩展的长度.

Finally, the client SHOULD pad the entire message as follows:

最后, 客户端**必须**按如下方式填充整个消息：

1. Let L be the length of the EncodedClientHelloInner with all the padding
   computed so far.

   设 L 为到目前为止计算的所有填充的 EncodedClientHelloInner 的长度.
2. Let N = 31 - ((L - 1) % 32) and add N bytes of padding.

   设 N = 31 - ((L - 1) % 32) 并添加 N 字节的填充.

This rounds the length of EncodedClientHelloInner up to a multiple of 32 bytes,
reducing the set of possible lengths across all clients.

这将 EncodedClientHelloInner 的长度四舍五入到 32 字节的倍数, 减少了所有客户端的可能长度集合.

In addition to padding ClientHelloInner, clients and servers will also need to
pad all other handshake messages that have sensitive-length fields. For example,
if a client proposes ALPN values in ClientHelloInner, the server-selected value
will be returned in an EncryptedExtension, so that handshake message also needs
to be padded using TLS record layer padding.

除了填充 ClientHelloInner 外, 客户端和服务器还需要填充所有其他具有敏感长度字段的握手消息. 例如, 如果客户端在 ClientHelloInner 中提议 ALPN 值, 服务器选择的值将在 EncryptedExtension 中返回, 因此该握手消息也需要使用 TLS 记录层填充进行填充.

### Determining ECH Acceptance | 确定 ECH 是否被接受 {#determining-ech-acceptance}

As described in {{server-behavior}}, the server may either accept ECH and use
ClientHelloInner or reject it and use ClientHelloOuter. This is determined by
the server's initial message.

如 {{server-behavior}} 中所述, 服务器可能接受 ECH 并使用 ClientHelloInner, 或拒绝它并使用 ClientHelloOuter. 这由服务器的初始消息确定.

If the message does not negotiate TLS 1.3 or higher, the server has rejected
ECH. Otherwise, it is either a ServerHello or HelloRetryRequest.

如果消息不协商 TLS 1.3 或更高版本, 服务器已拒绝 ECH. 否则, 它是 ServerHello 或 HelloRetryRequest.

If the message is a ServerHello, the client computes `accept_confirmation` as
described in {{backend-server}}. If this value matches the last 8 bytes of
`ServerHello.random`, the server has accepted ECH. Otherwise, it has rejected
ECH.

如果消息是 ServerHello, 客户端按照 {{backend-server}} 中的描述计算 `accept_confirmation`. 如果此值匹配 `ServerHello.random` 的最后 8 字节, 服务器已接受 ECH. 否则, 它已拒绝 ECH.

If the message is a HelloRetryRequest, the client checks for the
"encrypted_client_hello" extension. If none is found, the server has rejected
ECH. Otherwise, if it has a length other than 8, the client aborts the handshake
with a "decode_error" alert. Otherwise, the client computes
`hrr_accept_confirmation` as described in {{backend-server-hrr}}. If this value
matches the extension payload, the server has accepted ECH. Otherwise, it has
rejected ECH.

如果消息是 HelloRetryRequest, 客户端检查 "encrypted_client_hello" 扩展. 如果没有找到, 服务器已拒绝 ECH. 否则, 如果它的长度不是 8, 客户端以 "decode_error" 警报中止握手. 否则, 客户端按照 {{backend-server-hrr}} 中的描述计算 `hrr_accept_confirmation`. 如果此值匹配扩展有效载荷, 服务器已接受 ECH. 否则, 它已拒绝 ECH.

If the server accepts ECH, the client handshakes with ClientHelloInner as
described in {{accepted-ech}}. Otherwise, the client handshakes with
ClientHelloOuter as described in {{rejected-ech}}.

如果服务器接受 ECH, 客户端按照 {{accepted-ech}} 中的描述与 ClientHelloInner 握手. 否则, 客户端按照 {{rejected-ech}} 中的描述与 ClientHelloOuter 握手.

### Handshaking with ClientHelloInner | 使用 ClientHelloInner 握手 {#accepted-ech}

If the server accepts ECH, the client proceeds with the connection as in
{{RFC8446}}, with the following modifications:

如果服务器接受 ECH, 客户端按照 {{RFC8446}} 继续连接, 但有以下修改：

The client behaves as if it had sent ClientHelloInner as the ClientHello. That
is, it evaluates the handshake using the ClientHelloInner's preferences, and,
when computing the transcript hash ({{Section 4.4.1 of RFC8446}}), it uses
ClientHelloInner as the first ClientHello.

客户端的行为就像它发送了 ClientHelloInner 作为 ClientHello. 也就是说, 它使用 ClientHelloInner 的偏好评估握手, 并且在计算 Transcript-Hash ({{Section 4.4.1 of RFC8446}}) 时, 它使用 ClientHelloInner 作为第一个 ClientHello.

If the server responds with a HelloRetryRequest, the client computes the updated
ClientHello message as follows:

如果服务器响应 HelloRetryRequest, 客户端按如下方式计算更新的 ClientHello 消息：

1. It computes a second ClientHelloInner based on the first ClientHelloInner, as
   in {{Section 4.1.4 of RFC8446}}. The ClientHelloInner's
   "encrypted_client_hello" extension is left unmodified.

   它基于第一个 ClientHelloInner 计算第二个 ClientHelloInner, 如 {{Section 4.1.4 of RFC8446}} 中所述. ClientHelloInner 的 "encrypted_client_hello" 扩展保持不变.

1. It constructs EncodedClientHelloInner as described in {{encoding-inner}}.

   它按照 {{encoding-inner}} 中的描述构造 EncodedClientHelloInner.

1. It constructs a second partial ClientHelloOuterAAD message. This message MUST
   be syntactically valid. The extensions MAY be copied from the original
   ClientHelloOuter unmodified, or omitted. If not sensitive, the client MAY
   copy updated extensions from the second ClientHelloInner for compression.

   它构造第二个部分 ClientHelloOuterAAD 消息. 此消息**必须**在语法上有效. 扩展**可以**从原始 ClientHelloOuter 未修改地复制, 或省略. 如果不敏感, 客户端**可以**从第二个 ClientHelloInner 复制更新的扩展进行压缩.

1. It encrypts EncodedClientHelloInner as described in
   {{encrypting-clienthello}}, using the second partial ClientHelloOuterAAD, to
   obtain a second ClientHelloOuter. It reuses the original HPKE encryption
   context computed in {{real-ech}} and uses the empty string for `enc`.

   它按照 {{encrypting-clienthello}} 中的描述加密 EncodedClientHelloInner, 使用第二个部分 ClientHelloOuterAAD, 以获得第二个 ClientHelloOuter. 它重用在 {{real-ech}} 中计算的原始 HPKE 加密上下文, 并对 `enc` 使用空字符串.

   The HPKE context maintains a sequence number, so this operation internally
   uses a fresh nonce for each AEAD operation. Reusing the HPKE context avoids
   an attack described in {{flow-hrr-hijack}}.

   HPKE 上下文维护了一个序列号, 因此此操作内部地为每个 AEAD 操作使用了新的随机数. 重用 HPKE 上下文避免了 {{flow-hrr-hijack}} 中描述的攻击.

The client then sends the second ClientHelloOuter to the server. However, as
above, it uses the second ClientHelloInner for preferences, and both the
ClientHelloInner messages for the transcript hash. Additionally, it checks the
resulting ServerHello for ECH acceptance as in {{determining-ech-acceptance}}.
If the ServerHello does not also indicate ECH acceptance, the client MUST
terminate the connection with an "illegal_parameter" alert.

然后客户端向服务器发送第二个 ClientHelloOuter. 类似地, 使用第二个 ClientHelloInner 的偏好(执行握手), 并将 ClientHelloInner 消息用于 Transcript-Hash. 此外, 它按照 {{determining-ech-acceptance}} 中的方式检查相应响应的 ServerHello 是否接受了 ECH. 如果 ServerHello 依然提示未接受 ECH, 客户端**必须**以 "illegal_parameter" 警报终止连接.

### Handshaking with ClientHelloOuter | 使用 ClientHelloOuter 握手 {#rejected-ech}

If the server rejects ECH, the client proceeds with the handshake,
authenticating for ECHConfig.contents.public_name as described in
{{auth-public-name}}. If authentication or the handshake fails, the client MUST
return a failure to the calling application. It MUST NOT use the retry
configurations. It MUST NOT treat this as a secure signal to
disable ECH.

如果服务器拒绝 ECH, 客户端继续握手, 按照 {{auth-public-name}} 中的描述为 ECHConfig.contents.public_name 进行身份验证. 如果身份验证或握手失败, 客户端**必须**向调用者返回失败. 它**绝不能**使用重试配置. 它**绝不能**将此视为禁用 ECH 的安全信号.

If the server supplied an "encrypted_client_hello" extension in its
EncryptedExtensions message, the client MUST check that it is syntactically
valid and the client MUST abort the connection with a "decode_error" alert
otherwise. If an earlier TLS version was negotiated, the client MUST NOT enable
the False Start optimization {{RFC7918}} for this handshake. If both
authentication and the handshake complete successfully, the client MUST perform
the processing described below then abort the connection with an "ech_required"
alert before sending any application data to the server.

如果服务器在其 EncryptedExtensions 消息中提供了 "encrypted_client_hello" 扩展, 客户端必须检查它在语法上是否有效, 否则客户端必须以 "decode_error" 警报中止连接. 如果协商了较早的 TLS 版本, 客户端不得为此握手启用 False Start 优化 {{RFC7918}}. 如果身份验证和握手都成功完成, 客户端必须执行下面描述的处理, 然后在向服务器发送任何应用数据之前以 "ech_required" 警报中止连接.

If the server provided "retry_configs" and if at least one of the
values contains a version supported by the client, the client can
regard the ECH configuration as securely replaced by the server. It
SHOULD retry the handshake with a new transport connection, using the
retry configurations supplied by the server.

如果服务器提供了 "retry_configs", 并且如果至少一个值包含客户端支持的版本, 客户端可以将 ECH 配置视为被服务器安全替换. 它**必须**使用服务器提供的重试配置, 用新的传输连接重试握手.

Clients can implement a new transport connection in a way that best
suits their deployment. For example, clients can reuse the same server
IP address when establishing the new transport connection or they can
choose to use a different IP address if provided with options from
DNS. ECH does not mandate any specific implementation choices when
establishing this new connection.

客户端可以以最适合其部署的方式实现新的传输连接. 例如, 客户端可以在建立新传输连接时重用相同的服务器 IP 地址, 或者如果 DNS 提供了选项, 它们可以选择使用不同的 IP 地址. ECH 在建立此新连接时不强制任何特定的实现选择.

The retry configurations are meant to be used for retried connections. Further
use of retry configurations could yield a tracking vector. In settings where
the client will otherwise already let the server track the client, e.g.,
because the client will send cookies to the server in parallel connections,
using the retry configurations for these parallel connections does not
introduce a new tracking vector.

重试配置旨在用于重试连接. 进一步使用重试配置可能产生跟踪向量. 在客户端将以其他方式让服务器跟踪客户端的设置中, 例如, 因为客户端将在并行连接中向服务器发送 cookie, 为这些并行连接使用重试配置不会引入新的跟踪向量.

If none of the values provided in "retry_configs" contains a supported
version, the server did not supply an "encrypted_client_hello"
extension in its EncryptedExtensions message, or an earlier TLS
version was negotiated, the client can regard ECH as securely disabled
by the server, and it SHOULD retry the handshake with a new transport
connection and ECH disabled.

如果 "retry_configs" 中提供的值都不包含支持的版本, 服务器没有在其 EncryptedExtensions 消息中提供 "encrypted_client_hello" 扩展, 或者协商了较早的 TLS 版本, 客户端可以将 ECH 视为被服务器安全禁用, 它应该用新的传输连接、禁用 ECH 重试握手.

Clients SHOULD NOT accept "retry_config" in response to a connection
initiated in response to a "retry_config".  Sending a "retry_config"
in this situation is a signal that the server is misconfigured, e.g.,
the server might have multiple inconsistent configurations so that the
client reached a node with configuration A in the first connection and
a node with configuration B in the second. Note that this guidance
does not apply to the cases in the previous paragraph where the server
has securely disabled ECH.

客户端**绝不能**接受响应由 "retry_config" 启动的连接的 "retry_config". 在这种情况下发送 "retry_config" 是服务器配置错误的信号, 例如, 服务器可能有多个不一致的配置, 因此客户端在第一次连接中到达配置 A 的节点, 在第二次连接中到达配置 B 的节点. 请注意, 此指导不适用于前一段中服务器已安全禁用 ECH 的情况.

If a client does not retry, it MUST report an error to the calling
application.

如果客户端不重试, 它**必须**向调用应用程序报告错误.

### Authenticating for the Public Name | 为公共名称进行身份验证 {#auth-public-name}

When the server rejects ECH, it continues with the handshake using the plaintext
"server_name" extension instead (see {{server-behavior}}). Clients that offer
ECH then authenticate the connection with the public name, as follows:

当服务器拒绝 ECH 时, 它继续使用明文 "server_name" 扩展进行握手 (参见 {{server-behavior}}) . 然后提供 ECH 的客户端使用公共名称验证连接, 如下所示：

- The client MUST verify that the certificate is valid for
  ECHConfig.contents.public_name. If invalid, it MUST abort the connection with
  the appropriate alert.

  客户端**必须**验证证书对 ECHConfig.contents.public_name 有效. 如果无效, 它**必须**以适当的警报中止连接.

- If the server requests a client certificate, the client MUST respond with an
  empty Certificate message, denoting no client certificate.

  如果服务器请求客户端证书, 客户端**必须**以空的 Certificate 消息响应, 表示没有客户端证书.

In verifying the client-facing server certificate, the client MUST
interpret the public name as a DNS-based reference identity
{{!RFC6125}}. Clients that incorporate DNS names and IP addresses into
the same syntax (e.g. {{Section 7.4 of ?RFC3986}} and {{WHATWG-IPV4}})
MUST reject names that would be interpreted as IPv4 addresses.
Clients that enforce this by checking ECHConfig.contents.public_name
do not need to repeat the check when processing ECH rejection.

在验证面向客户端的服务器证书时, 客户端**必须**将公共名称解释为基于 DNS 的参考身份 (reference identity) {{!RFC6125}}. 将 DNS 名称和 IP 地址合并对待的客户端 (例如 {{Section 7.4 of ?RFC3986}} 以及 {{WHATWG-IPV4}}) 必须拒绝将被解释为 IPv4 地址的名称. 通过检查 ECHConfig.contents.public_name 强制执行此操作的客户端在处理 ECH 拒绝时不需要重复检查.

Note that authenticating a connection for the public name does not authenticate
it for the origin. The TLS implementation MUST NOT report such connections as
successful to the application. It additionally MUST ignore all session tickets
and session IDs presented by the server. These connections are only used to
trigger retries, as described in {{rejected-ech}}. This may be implemented, for
instance, by reporting a failed connection with a dedicated error code.

请注意, 为公共名称验证了连接不代表为源服务器验证了连接. TLS 实现**绝不能**将此类连接报告为对应用程序成功. 它还**必须**忽略服务器提供的所有会话票据和会话 ID. 这些连接仅用于触发重试, 如 {{rejected-ech}} 中所述. 例如, 这可以通过使用专用错误代码报告失败的连接来实现.

Prior to attempting a connection, a client SHOULD validate the `ECHConfig`.
Clients SHOULD ignore any
`ECHConfig` structure with a public_name that is not a valid host name in
preferred name syntax (see {{Section 2 of ?DNS-TERMS=RFC9499}}).  That is, to be
valid, the public_name needs to be a dot-separated sequence of LDH labels, as
defined in {{Section 2.3.1 of !RFC5890}}, where:

在尝试连接之前, 客户端**必须**验证 `ECHConfig`. 客户端**必须**忽略任何具有 public_name 不是首选名称语法 (preferred name syntax) 定义下有效主机名的 `ECHConfig` 结构 (参见 {{Section 2 of ?DNS-TERMS=RFC9499}}) . 也就是说, 要有效, public_name 需要是 LDH 标签的点分隔序列, 如 {{Section 2.3.1 of !RFC5890}} 中定义的, 其中：

* the sequence does not begin or end with an ASCII dot, and

  序列不以 ASCII 点开始或结束, 并且
* all labels are at most 63 octets.

  所有标签最多 63 个八位字节.

Clients additionally SHOULD ignore the structure if the final LDH
label either consists of all ASCII digits (i.e. '0' through '9') or is
"0x" or "0X" followed by some, possibly empty, sequence of ASCII
hexadecimal digits (i.e. '0' through '9', 'a' through 'f', and 'A'
through 'F'). This avoids public_name values that may be interpreted
as IPv4 literals.

如果最终 LDH 标签由所有 ASCII 数字 (即 '0' 到 '9') 组成, 或者是"0x"或"0X"后跟一些可能为空的 ASCII 十六进制数字序列 (即 '0' 到 '9'、'a' 到 'f' 和 'A' 到 'F') , 客户端**必须**忽略该结构. 这避免了可能被解释为 IPv4 文字的 public_name 值.

### Impact of Retry on Future Connections | 重试对未来连接的影响 {#impact-of-retry}

Clients MAY use information learned from a rejected ECH for future
connections to avoid repeatedly connecting to the same server and
being forced to retry. However, they MUST handle ECH rejection for
those connections as if it were a fresh connection, rather than
enforcing the single retry limit from {{rejected-ech}}. The reason
for this requirement is that if the server sends a "retry_config"
and then immediately rejects the resulting connection, it is
most likely misconfigured. However, if the server sends a "retry_config"
and then the client tries to use that to connect some time
later, it is possible that the server has changed
its configuration again and is now trying to recover.

客户端**可以**使用从被拒绝的 ECH 中获取的信息用于未来连接, 以避免重复连接到同一服务器并被迫重试. 但是, 它们**必须**处理这些连接的拒绝 ECH, 就像它是新连接一样, 而不是强制执行 {{rejected-ech}} 中的单次重试限制. 此要求的原因是, 如果服务器发送 "retry_config" 然后立即拒绝连接, 它很可能配置错误. 但是, 如果服务器发送 "retry_config" 然后客户端稍后尝试使用它进行连接, 服务器可能已再次更改其配置并现在正在尝试恢复.

Any persisted information MUST be associated with the ECHConfig source
used to bootstrap the connection, such as a DNS SVCB ServiceMode record
{{ECH-IN-DNS}}. Clients MUST limit any sharing of persisted ECH-related
state to connections that use the same ECHConfig source. Otherwise, it
might become possible for the client to have the wrong public name for
the server, making recovery impossible.

任何持久化信息**必须**与用于引导连接的 ECHConfig 源, 例如 DNS SVCB ServiceMode 记录 {{ECH-IN-DNS}}, 相关联. 客户端**必须**将任何持久化 ECH 相关状态的共享限制为使用相同 ECHConfig 源的连接. 否则, 客户端可能为服务器拥有错误的公共名称, 使恢复变得不可能.

ECHConfigs learned from ECH rejection can be used as a tracking
vector. Clients SHOULD impose the same lifetime and scope restrictions
that they apply to other server-based
tracking vectors such as PSKs.

从拒绝 ECH 中获得的 ECHConfigs 可以作跟踪向量 (而存在隐私风险). 客户端**必须**对其他源自服务器的跟踪向量 (如 PSK) 施加相同的生命周期和范围限制.

In general, the safest way for clients to minimize ECH retries is to
comply with any freshness rules (e.g., DNS TTLs) imposed by the ECH
configuration.

一般来说, 客户端最小化 ECH 重试的最安全方法是遵守 ECH 配置施加的任何新鲜度规则 (例如, DNS TTL) .

## GREASE ECH {#grease-ech}

The GREASE ECH mechanism allows a connection between an ECH-capable client
and a non-ECH server to appear to use ECH, thus reducing the extent to
which ECH connections stick out (see {{dont-stick-out}}).

GREASE ECH 机制允许支持 ECH 的客户端和不支持 ECH 的服务器之间的连接看起来使用 ECH, 从而减少 ECH 连接突出的程度 (参见 {{dont-stick-out}}) .

### Client Greasing | 客户端 Greasing {#client-greasing}

If the client attempts to connect to a server and does not have an ECHConfig
structure available for the server, it SHOULD send a GREASE {{?RFC8701}}
"encrypted_client_hello" extension in the first ClientHello as follows:

如果客户端尝试连接到服务器并且没有可用于服务器的 ECHConfig 结构, 它**必须**在第一个 ClientHello 中发送 GREASE {{?RFC8701}} "encrypted_client_hello" 扩展, 如下所示：

- Set the `config_id` field to a random byte.

  将 `config_id` 字段设置为随机字节.

- Set the `cipher_suite` field to a supported HpkeSymmetricCipherSuite. The
  selection SHOULD vary to exercise all supported configurations, but MAY be
  held constant for successive connections to the same server in the same
  session.

  将 `cipher_suite` 字段设置为支持的 HpkeSymmetricCipherSuite. 选择**必须**变化以测试所有支持的配置, 但对于同一会话中到同一服务器的连续连接可以保持常量.

- Set the `enc` field to a randomly-generated valid encapsulated public key
  output by the HPKE KEM.

  将 `enc` 字段设置为由 HPKE KEM 输出的随机生成的有效封装公钥.

- Set the `payload` field to a randomly-generated string of L+C bytes, where C
  is the ciphertext expansion of the selected AEAD scheme and L is the size of
  the EncodedClientHelloInner the client would compute when offering ECH, padded
  according to {{padding}}.

  将 `payload` 字段设置为 L+C 字节的随机生成的字符串, 其中 C 是所选 AEAD 方案的密文扩展, L 是客户端在提供 ECH 时将计算的 EncodedClientHelloInner 的大小, 根据 {{padding}} 填充.

If sending a second ClientHello in response to a HelloRetryRequest, the
client copies the entire "encrypted_client_hello" extension from the first
ClientHello. The identical value will reveal to an observer that the value of
"encrypted_client_hello" was fake, but this only occurs if there is a
HelloRetryRequest.

如果响应 HelloRetryRequest 发送第二个 ClientHello, 客户端从第一个 ClientHello 复制整个 "encrypted_client_hello" 扩展. 相同的值将向观察者透露 "encrypted_client_hello" 的值是假的, 但这仅在 HelloRetryRequest 时发生.

If the server sends an "encrypted_client_hello" extension in either
HelloRetryRequest or EncryptedExtensions, the client MUST check the extension
syntactically and abort the connection with a "decode_error" alert if it is
invalid. It otherwise ignores the extension. It MUST NOT save the
"retry_configs" value in EncryptedExtensions.

如果服务器在 HelloRetryRequest 或 EncryptedExtensions 中发送 "encrypted_client_hello" 扩展, 客户端必须在语法上检查扩展, 如果无效则以 "decode_error" 警报中止连接. 否则它忽略扩展. 它不得保存 EncryptedExtensions 中的 "retry_configs" 值.

Offering a GREASE extension is not considered offering an encrypted ClientHello
for purposes of requirements in {{real-ech}}. In particular, the client
MAY offer to resume sessions established without ECH.

提供 GREASE 扩展不被视为为 {{real-ech}} 中的要求提供加密的 ClientHello. 特别是, 客户端可以提供恢复在没有 ECH 的情况下建立的会话.

### Server Greasing | 服务器 Greasing {#server-greasing}

{{config-extensions-iana}} describes a set of Reserved extensions
which will never be registered. These can be used by servers to
"grease" the contents of the ECH configuration, as inspired by
{{?RFC8701}}. This helps ensure clients process ECH extensions
correctly. When constructing ECH configurations, servers SHOULD
randomly select from reserved values with the high-order bit
clear. Correctly-implemented client will ignore those extensions.

{{config-extensions-iana}} 描述了一组永远不会注册的保留扩展. 这些可以被服务器用来 "grease" ECH 配置的内容, 受 {{?RFC8701}} 启发. 这有助于确保客户端正确处理 ECH 扩展. 在构造 ECH 配置时, 服务器**必须**从高位清除的保留值中随机选择. 正确实现的客户端将忽略这些扩展.

The reserved values with the high-order bit set are mandatory, as
defined in {{config-extensions}}. Servers SHOULD randomly select from
these values and include them in extraneous ECH configurations.
Correctly-implemented clients will ignore these configurations because
they do not recognize the mandatory extension.  Servers SHOULD ensure
that any client using these configurations encounters a warning or error
message.  This can be accomplished in several ways, including:

高位设置的保留值是强制性的, 如 {{config-extensions}} 中定义的. 服务器**必须**从这些值中随机选择并将它们包含在多余的 ECH 配置中. 正确实现的客户端将忽略这些配置, 因为它们不识别强制扩展. 服务器**必须**确保使用这些配置的任何客户端遇到警告或错误消息. 这可以通过几种方式实现, 包括：

* By giving the extraneous configurations distinctive config IDs or
  public names, and rejecting the TLS connection or inserting an
  application-level warning message when these are observed.

  通过给多余的配置独特的 config ID 或公共名称, 并在观察到这些时拒绝 TLS 连接或插入应用程序级警告消息.

* By giving the extraneous configurations an invalid public
  key and a public name not associated with the server, so that
  the initial ClientHelloOuter will not be decryptable and
  the server cannot perform the recovery flow described
  in {{rejected-ech}}.

  通过给多余的配置无效的公钥和与服务器无关的公共名称, 使初始 ClientHelloOuter 无法解密, 服务器无法执行 {{rejected-ech}} 中描述的恢复流程.

# Server Behavior | 服务器行为 {#server-behavior}

As described in {{topologies}}, servers can play two roles, either as
the client-facing server or as the back-end server.
Depending on the server role, the `ECHClientHello` will be different:

如 {{topologies}} 中所述, 服务器可以扮演两个角色, 要么作为面向客户端的服务器, 要么作为后端服务器. 根据服务器角色, `ECHClientHello` 将不同：

* A client-facing server expects a `ECHClientHello.type` of `outer`, and
  proceeds as described in {{client-facing-server}} to extract a
  ClientHelloInner, if available.

  面向客户端的服务器期望 `ECHClientHello.type` 为 `outer`, 并按照 {{client-facing-server}} 中的描述进行, 以提取 ClientHelloInner (如果可用) .

* A backend server expects a `ECHClientHello.type` of `inner`, and
  proceeds as described in {{backend-server}}.

  后端服务器期望 `ECHClientHello.type` 为 `inner`, 并按照 {{backend-server}} 中的描述进行.

In split mode, a client-facing server which receives a `ClientHello`
with `ECHClientHello.type` of `inner` MUST abort with an
"illegal_parameter" alert. Similarly, in split mode, a backend server
which receives a `ClientHello` with `ECHClientHello.type` of `outer`
MUST abort with an "illegal_parameter" alert.

在异址模式中, 接收到 `ECHClientHello.type` 为 `inner` 的 `ClientHello` 的面向客户端的服务器**必须**以 "illegal_parameter" 警报中止. 同样, 在异址模式中, 接收到 `ECHClientHello.type` 为 `outer` 的 `ClientHello` 的后端服务器**必须**以 "illegal_parameter" 警报中止.

In shared mode, a server plays both roles, first decrypting the
`ClientHelloOuter` and then using the contents of the
`ClientHelloInner`.  A shared mode server which receives a
`ClientHello` with `ECHClientHello.type` of `inner` MUST abort with an
"illegal_parameter" alert, because such a `ClientHello` should never
be received directly from the network.

在同址模式中, 服务器扮演两个角色, 首先解密 `ClientHelloOuter`, 然后使用 `ClientHelloInner` 的内容. 接收到 `ECHClientHello.type` 为 `inner` 的 `ClientHello` 的同址模式服务器**必须**以 "illegal_parameter" 警报中止, 因为此类 `ClientHello` 永远不应该直接从网络接收.

If `ECHClientHello.type` is not a valid `ECHClientHelloType`, then
the server MUST abort with an "illegal_parameter" alert.

如果 `ECHClientHello.type` 不是有效的 `ECHClientHelloType`, 则服务器必须以 "illegal_parameter" 警报中止.

If the "encrypted_client_hello" is not present, then the server completes the
handshake normally, as described in {{RFC8446}}.

如果 "encrypted_client_hello" 不存在, 则服务器按照 {{RFC8446}} 中的描述正常完成握手.

## Client-Facing Server | 面向客户端的服务器 {#client-facing-server}

Upon receiving an "encrypted_client_hello" extension in an initial
ClientHello, the client-facing server determines if it will accept ECH, prior
to negotiating any other TLS parameters. Note that successfully decrypting the
extension will result in a new ClientHello to process, so even the client's TLS
version preferences may have changed.

在初始 ClientHello 中收到 "encrypted_client_hello" 扩展后, 面向客户端的服务器在协商任何其他 TLS 参数之前确定是否接受 ECH. 请注意, 成功解密扩展将导致要处理的新 ClientHello, 因此甚至客户端的 TLS 版本偏好也可能已更改.

First, the server collects a set of candidate ECHConfig values. This list is
determined by one of the two following methods:

首先, 服务器收集一组候选 ECHConfig 值. 此列表由以下两种方法之一确定：

1. Compare ECHClientHello.config_id against identifiers of each known ECHConfig
   and select the ones that match, if any, as candidates.

   将 ECHClientHello.config_id 与每个已知 ECHConfig 的标识符进行比较, 并选择匹配的 (如果有) 作为候选.
2. Collect all known ECHConfig values as candidates, with trial decryption
   below determining the final selection.

   收集所有已知的 ECHConfig 值作为候选, 下面的试验解密确定最终选择.

Some uses of ECH, such as local discovery mode, may randomize the
ECHClientHello.config_id since it can be used as a tracking vector. In such
cases, the second method SHOULD be used for matching the ECHClientHello to a
known ECHConfig. See {{ignored-configs}}. Unless specified by the application
profile or otherwise externally configured, implementations MUST use the first
method.

ECH 的某些用途, 如本地发现模式, 可能会随机化 ECHClientHello.config_id, 因为它可以用作跟踪向量. 在这种情况下, **必须**使用第二种方法将 ECHClientHello 匹配到已知的 ECHConfig. 参见 {{ignored-configs}}. 除非由应用程序配置文件指定或以其他方式外部配置, 实现**必须**使用第一种方法.

The server then iterates over the candidate ECHConfig values, attempting to
decrypt the "encrypted_client_hello" extension as follows.

然后服务器遍历候选 ECHConfig 值, 尝试按如下方式解密 "encrypted_client_hello" 扩展.

The server verifies that the ECHConfig supports the cipher suite indicated by
the ECHClientHello.cipher_suite and that the version of ECH indicated by the
client matches the ECHConfig.version. If not, the server continues to the next
candidate ECHConfig.

服务器验证 ECHConfig 支持由 ECHClientHello.cipher_suite 指示的密码套件, 并且客户端指示的 ECH 版本与 ECHConfig.version 匹配. 如果不匹配, 服务器继续到下一个候选 ECHConfig.

Next, the server decrypts ECHClientHello.payload, using the private key skR
corresponding to ECHConfig, as follows:

接下来, 服务器使用对应于 ECHConfig 的私钥 skR 解密 ECHClientHello.payload, 如下所示：

~~~
    context = SetupBaseR(ECHClientHello.enc, skR,
                         "tls ech" || 0x00 || ECHConfig)
    EncodedClientHelloInner = context.Open(ClientHelloOuterAAD,
                                         ECHClientHello.payload)
~~~

ClientHelloOuterAAD is computed from ClientHelloOuter as described in
{{authenticating-outer}}. The `info` parameter to SetupBaseR is the
concatenation "tls ech", a zero byte, and the serialized ECHConfig. If
decryption fails, the server continues to the next candidate ECHConfig.
Otherwise, the server reconstructs ClientHelloInner from
EncodedClientHelloInner, as described in {{encoding-inner}}. It then stops
iterating over the candidate ECHConfig values.

ClientHelloOuterAAD 从 ClientHelloOuter 计算, 如 {{authenticating-outer}} 中所述. SetupBaseR 的 `info` 参数是连接 "tls ech"、零字节和序列化的 ECHConfig. 如果解密失败, 服务器继续到下一个候选 ECHConfig. 当解密成功, 服务器从 EncodedClientHelloInner 重构 ClientHelloInner, 如 {{encoding-inner}} 中所述. 然后它停止遍历候选 ECHConfig 值.

Once the server has chosen the correct ECHConfig, it MAY verify that the value
in the ClientHelloOuter "server_name" extension matches the value of
ECHConfig.contents.public_name, and abort with an "illegal_parameter" alert if
these do not match. This optional check allows the server to limit ECH
connections to only use the public SNI values advertised in its ECHConfigs.
The server MUST be careful not to unnecessarily reject connections if the same
ECHConfig id or keypair is used in multiple ECHConfigs with distinct public
names.

一旦服务器选择了正确的 ECHConfig, 它**可以**验证 ClientHelloOuter "server_name" 扩展中的值是否与 ECHConfig.contents.public_name 的值匹配, 如果这些不匹配, 则以 "illegal_parameter" 警报中止. 此可选检查允许服务器将 ECH 连接限制为仅使用其 ECHConfigs 中公布的公共 SNI 值. 如果在具有不同公共名称的多个 ECHConfigs 中使用相同的 ECHConfig id 或密钥对, 服务器必须小心不要不必要地拒绝连接.

Upon determining the ClientHelloInner, the client-facing server checks that the
message includes a well-formed "encrypted_client_hello" extension of type
`inner` and that it does not offer TLS 1.2 or below. If either of these checks
fails, the client-facing server MUST abort with an "illegal_parameter" alert.

确定 ClientHelloInner 后, 面向客户端的服务器检查消息是否包含格式良好的类型为 `inner` 的 "encrypted_client_hello" 扩展, 以及它是否不提供 TLS 1.2 或以下版本. 如果这些检查中的任何一个失败, 面向客户端的服务器必须以 "illegal_parameter" 警报中止.

If these checks succeed, the client-facing server then forwards the
ClientHelloInner to the appropriate backend server, which proceeds as in
{{backend-server}}. If the backend server responds with a HelloRetryRequest, the
client-facing server forwards it, decrypts the client's second ClientHelloOuter
using the procedure in {{client-facing-server-hrr}}, and forwards the resulting
second ClientHelloInner. The client-facing server forwards all other TLS
messages between the client and backend server unmodified.

如果这些检查成功, 面向客户端的服务器然后将 ClientHelloInner 转发给适当的后端服务器, 后端服务器按照 {{backend-server}} 中的方式进行. 如果后端服务器响应 HelloRetryRequest, 面向客户端的服务器转发它, 使用 {{client-facing-server-hrr}} 中的过程解密客户端的第二个 ClientHelloOuter, 并转发结果的第二个 ClientHelloInner. 面向客户端的服务器在客户端和后端服务器之间未修改地转发所有其他 TLS 消息.

Otherwise, if all candidate ECHConfig values fail to decrypt the extension, the
client-facing server MUST ignore the extension and proceed with the connection
using ClientHelloOuter, with the following modifications:

否则, 如果所有候选 ECHConfig 值都无法解密扩展, 面向客户端的服务器必须忽略扩展并使用 ClientHelloOuter 继续连接, 但有以下修改：

* If sending a HelloRetryRequest, the server MAY include an
  "encrypted_client_hello" extension with a payload of 8 random bytes; see
  {{dont-stick-out}} for details.

  如果发送 HelloRetryRequest, 服务器**可以**包含一个带有8个随机字节载荷的 "encrypted_client_hello" 扩展；详见 {{dont-stick-out}}.

* If the server is configured with any ECHConfigs, it MUST include the
  "encrypted_client_hello" extension in its EncryptedExtensions with the
  "retry_configs" field set to one or more ECHConfig structures with up-to-date
  keys. Servers MAY supply multiple ECHConfig values of different versions.
  This allows a server to support multiple versions at once.

  如果服务器配置了任何 ECHConfigs, 它**必须**在其 EncryptedExtensions 中包含 "encrypted_client_hello" 扩展, 将 "retry_configs" 字段设置为一个或多个具有最新密钥的 ECHConfig 结构. 服务器**可以**提供不同版本的多个 ECHConfig 值. 这允许服务器同时支持多个版本.

Note that decryption failure could indicate a GREASE ECH extension (see
{{grease-ech}}), so it is necessary for servers to proceed with the connection
and rely on the client to abort if ECH was required. In particular, the
unrecognized value alone does not indicate a misconfigured ECH advertisement
({{misconfiguration}}). Instead, servers can measure occurrences of the
"ech_required" alert to detect this case.

请注意, 解密失败可能表示(客户端提供了) GREASE ECH 扩展 (参见 {{grease-ech}}) , 因此服务器有必要继续连接并依赖客户端在需要 ECH 时中止. 特别是, 仅仅无法识别的值并不表示 ECH 公布配置错误 ({{misconfiguration}}) . 相反, 服务器可以测量 "ech_required" 警报的出现次数来检测这种情况.

### Sending HelloRetryRequest | 发送 HelloRetryRequest {#client-facing-server-hrr}

After sending or forwarding a HelloRetryRequest, the client-facing server does
not repeat the steps in {{client-facing-server}} with the second
ClientHelloOuter. Instead, it continues with the ECHConfig selection from the
first ClientHelloOuter as follows:

在发送或转发 HelloRetryRequest 后, 面向客户端的服务器不会使用第二个 ClientHelloOuter 重复 {{client-facing-server}} 中的步骤. 相反, 它会继续使用第一个 ClientHelloOuter 中的 ECHConfig 选择, 如下所述：

If the client-facing server accepted ECH, it checks the second ClientHelloOuter
also contains the "encrypted_client_hello" extension. If not, it MUST abort the
handshake with a "missing_extension" alert. Otherwise, it checks that
ECHClientHello.cipher_suite and ECHClientHello.config_id are unchanged, and that
ECHClientHello.enc is empty. If not, it MUST abort the handshake with an
"illegal_parameter" alert.

如果面向客户端的服务器接受了 ECH, 它会检查第二个 ClientHelloOuter 是否也包含 "encrypted_client_hello" 扩展. 如果没有, 它**必须**使用 "missing_extension" 警报中止握手. 否则, 它会检查 ECHClientHello.cipher_suite 和 ECHClientHello.config_id 是否未发生变化, 并且 ECHClientHello.enc 是否为空. 如果不是, 它**必须**使用 "illegal_parameter" 警报中止握手.

Finally, it decrypts the new ECHClientHello.payload as a second message with the
previous HPKE context:

最后, 它使用之前的 HPKE 上下文将新的 ECHClientHello.payload 作为第二条消息解密：

~~~
    EncodedClientHelloInner = context.Open(ClientHelloOuterAAD,
                                         ECHClientHello.payload)
~~~

ClientHelloOuterAAD is computed as described in {{authenticating-outer}}, but
using the second ClientHelloOuter. If decryption fails, the client-facing
server MUST abort the handshake with a "decrypt_error" alert. Otherwise, it
reconstructs the second ClientHelloInner from the new EncodedClientHelloInner
as described in {{encoding-inner}}, using the second ClientHelloOuter for
any referenced extensions.

ClientHelloOuterAAD 的计算如 {{authenticating-outer}} 中所述, 但使用第二个 ClientHelloOuter. 如果解密失败, 面向客户端的服务器必须使用 "decrypt_error" 警报中止握手. 否则, 它会根据 {{encoding-inner}} 中所述, 从新的 EncodedClientHelloInner 重建第二个 ClientHelloInner, 使用第二个 ClientHelloOuter 来处理任何引用的扩展.

The client-facing server then forwards the resulting ClientHelloInner to the
backend server. It forwards all subsequent TLS messages between the client and
backend server unmodified.

然后, 面向客户端的服务器将结果 ClientHelloInner 转发给后端服务器. 它会将客户端和后端服务器之间所有后续 TLS 消息不经修改地转发.

If the client-facing server rejected ECH, or if the first ClientHello did not
include an "encrypted_client_hello" extension, the client-facing server
proceeds with the connection as usual. The server does not decrypt the
second ClientHello's ECHClientHello.payload value, if there is one.
Moreover, if the server is configured with any ECHConfigs, it MUST include the
"encrypted_client_hello" extension in its EncryptedExtensions with the
"retry_configs" field set to one or more ECHConfig structures with up-to-date
keys, as described in {{client-facing-server}}.

如果面向客户端的服务器拒绝了 ECH, 或者第一个 ClientHello 未包含 "encrypted_client_hello" 扩展, 则面向客户端的服务器会像往常一样继续连接. 服务器不会解密第二个 ClientHello 的 ECHClientHello.payload 值 (如果存在) . 此外, 如果服务器配置了任何 ECHConfig, 它必须在其 EncryptedExtensions 中包含 "encrypted_client_hello" 扩展, 并将 "retry_configs" 字段设置为一个或多个带有最新密钥的 ECHConfig 结构, 如 {{client-facing-server}} 中所述.

Note that a client-facing server that forwards the first ClientHello cannot
include its own "cookie" extension if the backend server sends a
HelloRetryRequest.  This means that the client-facing server either needs to
maintain state for such a connection or it needs to coordinate with the backend
server to include any information it requires to process the second ClientHello.

请注意, 转发第一个 ClientHello 的面向客户端的服务器不能在后端服务器发送 HelloRetryRequest 时包含自己的 "cookie" 扩展. 这意味着面向客户端的服务器要么需要为此类连接维护状态, 要么需要与后端服务器协调, 以包含处理第二个 ClientHello 所需的信息.

## Backend Server | 后端服务器 {#backend-server}

Upon receipt of an "encrypted_client_hello" extension of type `inner` in a
ClientHello, if the backend server negotiates TLS 1.3 or higher, then it MUST
confirm ECH acceptance to the client by computing its ServerHello as described
here.

在收到 ClientHello 中类型为 `inner` 的 "encrypted_client_hello" 扩展时, 如果后端服务器协商 TLS 1.3 或更高版本, 则它**必须**按照此处所述计算其 ServerHello, 向客户端确认 ECH 已被接受.

The backend server embeds in ServerHello.random a string derived from the inner
handshake. It begins by computing its ServerHello as usual, except the last 8
bytes of ServerHello.random are set to zero. It then computes the transcript
hash for ClientHelloInner up to and including the modified ServerHello, as
described in {{RFC8446, Section 4.4.1}}. Let transcript_ech_conf denote the
output. Finally, the backend server overwrites the last 8 bytes of the
ServerHello.random with the following string:

后端服务器在 ServerHello.random 中嵌入一个依据握手过程信息派生的字符串. 它首先像往常一样计算其 ServerHello, 但 ServerHello.random 的最后 8 字节设置为零. 然后, 它计算从 ClientHelloInner 到包括修改后的 ServerHello 的 Transcript-Hash, 如 {{RFC8446, Section 4.4.1}} 中所述. 让 transcript_ech_conf 表示输出. 最后, 后端服务器用以下字符串覆盖 ServerHello.random 的最后 8 字节：

~~~
   accept_confirmation = HKDF-Expand-Label(
      HKDF-Extract(0, ClientHelloInner.random),
      "ech accept confirmation",
      transcript_ech_conf,
      8)
~~~

where HKDF-Expand-Label is defined in {{RFC8446, Section 7.1}}, "0" indicates a
string of Hash.length bytes set to zero, and Hash is the hash function used to
compute the transcript hash. In DTLS, the modified version of HKDF-Expand-Label
defined in {{RFC9147, Section 5.9}} is used instead.

其中 HKDF-Expand-Label 定义于 {{RFC8446, Section 7.1}}, "0" 表示一串设置为零的 Hash.length 字节, 而 Hash 是用于计算 Transcript-Hash 的哈希函数. 在 DTLS 中, 使用 {{RFC9147, Section 5.9}} 中定义的 HKDF-Expand-Label 的修改版本.

The backend server MUST NOT perform this operation if it negotiated TLS 1.2 or
below. Note that doing so would overwrite the downgrade signal for TLS 1.3 (see
{{RFC8446, Section 4.1.3}}).

如果后端服务器协商了 TLS 1.2 或更低版本, 则它**绝不能**执行此操作. 请注意, 这样做会覆盖 TLS 1.3 的降级信号 (参见 {{RFC8446, Section 4.1.3}}) .

### Sending HelloRetryRequest | 发送 HelloRetryRequest {#backend-server-hrr}

When the backend server sends HelloRetryRequest in response to the ClientHello,
it similarly confirms ECH acceptance by adding a confirmation signal to its
HelloRetryRequest. But instead of embedding the signal in the
HelloRetryRequest.random (the value of which is specified by {{RFC8446}}), it
sends the signal in an extension.

当后端服务器响应 ClientHello 发送 HelloRetryRequest 时, 它同样通过向其 HelloRetryRequest 添加确认信号来确认 ECH 接受. 但它不是将信号嵌入 HelloRetryRequest.random (其值由 {{RFC8446}} 指定) , 而是将信号发送在扩展中.

The backend server begins by computing HelloRetryRequest as usual, except that
it also contains an "encrypted_client_hello" extension with a payload of 8 zero
bytes. It then computes the transcript hash for the first ClientHelloInner,
denoted ClientHelloInner1, up to and including the modified HelloRetryRequest.
Let transcript_hrr_ech_conf denote the output. Finally, the backend server
overwrites the payload of the "encrypted_client_hello" extension with the
following string:

后端服务器首先像往常一样计算 HelloRetryRequest, 但它还包含一个 "encrypted_client_hello" 扩展, 置零其 payload. 然后, 它计算第一个 ClientHelloInner (表示为 ClientHelloInner1) 的 Transcript-Hash, 直至包括修改后的 HelloRetryRequest. 让 transcript_hrr_ech_conf 表示输出. 最后, 后端服务器用以下字符串覆盖 "encrypted_client_hello" 扩展的 payload：

~~~
   hrr_accept_confirmation = HKDF-Expand-Label(
      HKDF-Extract(0, ClientHelloInner1.random),
      "hrr ech accept confirmation",
      transcript_hrr_ech_conf,
      8)
~~~

In the subsequent ServerHello message, the backend server sends the
accept_confirmation value as described in {{backend-server}}.

在随后的 ServerHello 消息中, 后端服务器按照 {{backend-server}} 中所述发送 accept_confirmation 值.

# Deployment Considerations | 部署注意事项 {#deployment}

The design of ECH as specified in this document necessarily requires changes
to client, client-facing server, and backend server. Coordination between
client-facing and backend server requires care, as deployment mistakes
can lead to compatibility issues. These are discussed in {{compat-issues}}.

本文件中指定的 ECH 设计必然需要对客户端、面向客户端的服务器和后端服务器进行更改. 面向客户端的服务器与后端服务器之间的协调需要谨慎, 因为部署错误可能导致兼容性问题. 这些问题在 {{compat-issues}} 中进行了讨论.

Beyond coordination difficulties, ECH deployments may also induce challenges
for use cases of information that ECH protects. In particular,
use cases which depend on this unencrypted information may no longer work
as desired. This is elaborated upon in {{no-sni}}.

除了协调困难之外, ECH 部署还可能为使用到 ECH 保护的那些信息的案例带来问题. 特别是, 那些依赖原未加密信息的用例可能无法按预期工作. 这在 {{no-sni}} 中进行了详细阐述.

## Compatibility Issues | 兼容性问题 {#compat-issues}

Unlike most TLS extensions, placing the SNI value in an ECH extension is not
interoperable with existing servers, which expect the value in the existing
plaintext extension. Thus server operators SHOULD ensure servers understand a
given set of ECH keys before advertising them. Additionally, servers SHOULD
retain support for any previously-advertised keys for the duration of their
validity.

与其他大多数 TLS 扩展不同, 将 SNI 值放置在 ECH 扩展中与现有服务器不兼容, 这些服务器期望该值位于现有的明文扩展中. 因此, 服务器运营商**必须**确保服务器在发布 ECH 密钥集之前理解这些密钥. 此外, 服务器**必须**在其有效期内保留对先前发布的密钥的支持.

However, in more complex deployment scenarios, this may be difficult to fully
guarantee. Thus this protocol was designed to be robust in case of
inconsistencies between systems that advertise ECH keys and servers, at the cost
of extra round-trips due to a retry. Two specific scenarios are detailed below.

然而, 在更复杂的部署场景中, 这可能难以完全保证. 因此, 该协议被设计为在发布 ECH 密钥的系统和(实际的)服务器之间存在不一致的情况下保持鲁棒性, 代价是由于重试而产生额外的往返. 下面详细说明了两个具体场景.

### Misconfiguration and Deployment Concerns | 配置错误和部署问题 {#misconfiguration}

It is possible for ECH advertisements and servers to become inconsistent. This
may occur, for instance, from DNS misconfiguration, caching issues, or an
incomplete rollout in a multi-server deployment. This may also occur if a server
loses its ECH keys, or if a deployment of ECH must be rolled back on the server.

已发布(的) ECH (配置)和(实际)服务器(所接受的)可能变得不一致. 例如, 这可能由于 DNS 配置错误、缓存问题或多服务器部署中的不完整推出而发生. 如果服务器丢失其 ECH 密钥, 或者必须在服务器上回滚 ECH 部署, 也可能发生这种情况.

The retry mechanism repairs inconsistencies, provided the TLS server
has a certificate for the public name. If server and advertised keys
mismatch, the server will reject ECH and respond with
"retry_configs". If the server does
not understand
the "encrypted_client_hello" extension at all, it will ignore it as required by
{{Section 4.1.2 of RFC8446}}. Provided the server can present a certificate
valid for the public name, the client can safely retry with updated settings,
as described in {{rejected-ech}}.

重试机制可以修复不一致性, 前提是 TLS 服务器具有公共名称的证书. 如果服务器和宣传的密钥不匹配, 服务器将拒绝 ECH 并响应 "retry_configs". 如果服务器根本不理解 "encrypted_client_hello" 扩展, 它将按照 {{Section 4.1.2 of RFC8446}} 的要求忽略它. 只要服务器能够提供适用于公共名称的证书, 客户端就可以安全地使用新配置重试, 如 {{rejected-ech}} 中所述.

Unless ECH is disabled as a result of successfully establishing a connection to
the public name, the client MUST NOT fall back to using unencrypted
ClientHellos, as this allows a network attacker to disclose the contents of this
ClientHello, including the SNI. It MAY attempt to use another server from the
DNS results, if one is provided.

除非由于成功建立到公共名称的连接而禁用 ECH, 否则客户端**绝不能**回退到使用未加密的 ClientHello, 因为这允许网络攻击者获得此 ClientHello 的内容, 包括 SNI. 客户端**可以**尝试使用 DNS 结果中的另一个服务器, 如果有的话.

In order to ensure that the retry mechanism works successfully servers
SHOULD ensure that every endpoint which might receive a TLS connection
is provisioned with an appropriate certificate for the public name.
This is especially important during periods of server reconfiguration
when different endpoints might have different configurations.

为了确保重试机制成功工作, 服务器**必须**确保每个可能接收 TLS 连接的端点都配备了适当的公共名称证书. 这在服务器重新配置期间尤其重要, 因为不同的端点可能具有不同的配置.

### Middleboxes | 中间盒 {#middleboxes}

The requirements in {{RFC8446, Section 9.3}} which require proxies to
act as conforming TLS client and server provide interoperability
with TLS-terminating proxies even in cases where the server supports
ECH but the proxy does not, as detailed below.

{{RFC8446, Section 9.3}} 要求中间代理为符合规范的 TLS 客户端和服务器, 即使在服务器支持 ECH 但中间代理不支持的情况下, 也能提供与代理 TLS 终止的互操作性, 详细说明如下.

The proxy must ignore unknown parameters, and
generate its own ClientHello containing only parameters it understands. Thus,
when presenting a certificate to the client or sending a ClientHello to the
server, the proxy will act as if connecting to the ClientHelloOuter
server_name, which SHOULD match the public name (see {{real-ech}}), without
echoing the "encrypted_client_hello" extension.

中间代理必须忽略未知参数, 并生成自己的 ClientHello, 仅包含它理解的参数. 因此, 当向客户端提供证书或向服务器发送 ClientHello 时, 代理将表现得好像连接到 ClientHelloOuter (中的) server_name, 这应该与公共名称匹配 (见 {{real-ech}}) , 而不回显 "encrypted_client_hello" 扩展.

Depending on whether the client is configured to accept the proxy's certificate
as authoritative for the public name, this may trigger the retry logic described
in {{rejected-ech}} or result in a connection failure. A proxy which is not
authoritative for the public name cannot forge a signal to disable ECH.

因客户端是否配置为接受代理的证书作为公共名称的权威证书而异, 这可能触发 {{rejected-ech}} 中描述的重试逻辑或导致连接失败. 对公共名称的非官方代理无法伪造 ECH 已被禁用的信号.

## Deployment Impact | 部署影响 {#no-sni}

Some use cases which depend on information ECH encrypts may break with the
deployment of ECH. The extent of breakage depends on a number of external
factors, including, for example, whether ECH can be disabled, whether or not
the party disabling ECH is trusted to do so, and whether or not client
implementations will fall back to TLS without ECH in the event of disablement.

一些依赖于 ECH (所加密了的)信息的使用场景可能会因 ECH 的部署而中断. 中断的程度取决于许多外部因素, 例如, 是否可以禁用 ECH, 禁用 ECH 的一方是否受信任, 以及在禁用的情况下客户端实现是否会回退到没有 ECH 的 TLS.

Depending on implementation details and deployment settings, use cases
which depend on plaintext TLS information may require fundamentally different
approaches to continue working. For example, in managed enterprise settings,
one approach may be to disable ECH entirely via group policy and for
client implementations to honor this action. Server deployments which
depend on SNI -- e.g., for load balancing -- may no longer function properly
without updates; the nature of those updates is out of scope of this
specification.

根据实现细节和部署设置, 依赖于明文 TLS 信息的使用场景可能需要(和当前措施)完全不同的方法才能继续工作. 例如, 在托管企业设置中, 一种方法可能是通过组策略完全禁用 ECH, 并让客户端实现遵守此操作. 依赖于 SNI 的服务器部署, 例如用于负载平衡, 如果没有更新可能不再正常工作；这些更新的性质超出了本规范的范围.

In the context of {{rejected-ech}}, another approach may be to
intercept and decrypt client TLS connections. The feasibility of alternative
solutions is specific to individual deployments.

在 {{rejected-ech}} 的上下文中, 另一种方法可能是拦截和解密客户端TLS连接. 替代解决方案的可行性特定于个别部署.

# Compliance Requirements | 合规要求 {#compliance}

In the absence of an application profile standard specifying otherwise,
a compliant ECH application MUST implement the following HPKE cipher suite:

在没有指定其他应用配置文件标准的情况下, 符合规范的 ECH 应用程序必须实现以下 HPKE 密码套件：

- KEM: DHKEM(X25519, HKDF-SHA256) (see {{Section 7.1 of HPKE}})
- KDF: HKDF-SHA256 (see {{Section 7.2 of HPKE}})
- AEAD: AES-128-GCM (see {{Section 7.3 of HPKE}})

# Security Considerations

This section contains security considerations for ECH.

本节包含 ECH 的安全注意事项.

## Security and Privacy Goals {#goals}

ECH considers two types of attackers: passive and active. Passive attackers can
read packets from the network, but they cannot perform any sort of active
behavior such as probing servers or querying DNS. A middlebox that filters based
on plaintext packet contents is one example of a passive attacker. In contrast,
active attackers can also write packets into the network for malicious purposes,
such as interfering with existing connections, probing servers, and querying
DNS. In short, an active attacker corresponds to the conventional threat model
{{?RFC3552}} for TLS 1.3 {{RFC8446}}.

ECH 考虑两种类型的攻击者: 被动攻击者和主动攻击者. 被动攻击者可以从网络中读取数据包, 但他们无法执行任何主动行为, 如探测服务器或查询 DNS. 基于明文数据包内容进行过滤的中间盒是被动攻击者的一个例子. 相比之下, 主动攻击者还可以向网络中写入数据包用于恶意目的, 如干扰现有连接、探测服务器和查询DNS. 简而言之, 主动攻击者对应于 TLS 1.3 {{RFC8446}} 的传统威胁模型 {{?RFC3552}}.

Passive and active attackers can exist anywhere in the network, including
between the client and client-facing server, as well as between the
client-facing and backend servers when running ECH in Split Mode. However,
for Split Mode in particular, ECH makes two additional assumptions:

被动和主动攻击者可以存在于网络中的任何位置, 包括客户端和面向客户端的服务器之间, 以及在 "异址模式" 下运行 ECH 时面向客户端的服务器和后端服务器之间. 然而, 特别是对于 "异址模式", ECH 做出了两个额外的假设:

1. The channel between each client-facing and each backend server is
authenticated such that the backend server only accepts messages from trusted
client-facing servers. The exact mechanism for establishing this authenticated
channel is out of scope for this document.
   
   每个面向客户端的服务器与每个后端服务器之间的通道是经过身份验证的, 使得后端服务器只接受来自受信任的面向客户端服务器的消息. 建立这个经过身份验证的通道的确切机制超出了本文档的范围.
1. The attacker cannot correlate messages between client and client-facing
server with messages between client-facing and backend server. Such correlation
could allow an attacker to link information unique to a backend server, such as
their server name or IP address, with a client's encrypted ClientHelloInner.
Correlation could occur through timing analysis of messages across the
client-facing server, or via examining the contents of messages sent between
client-facing and backend servers. The exact mechanism for preventing this sort
of correlation is out of scope for this document.

   攻击者无法将客户端与面向客户端的服务器之间的消息与面向客户端服务器与后端服务器之间的消息进行关联. 这种关联可能允许攻击者将后端服务器特有的信息 (如其服务器名称或IP地址) 与客户端的加密 ClientHelloInner 链接起来. 关联可能通过跨面向客户端服务器的消息时序分析发生, 或通过检查面向客户端服务器与后端服务器之间发送的消息内容发生. 防止这种关联的确切机制超出了本文档的范围.

Given this threat model, the primary goals of ECH are as follows.

鉴于这种威胁模型, ECH 的主要目标如下.

1. Security preservation. Use of ECH does not weaken the security properties of
   TLS without ECH.

   安全性保护. 使用 ECH 不会削弱没有 ECH 的 TLS 的安全属性.
1. Handshake privacy. TLS connection establishment to a server name
   within an anonymity set is indistinguishable from a connection to
   any other server name within the anonymity set. (The anonymity set
   is defined in {{intro}}.)

   握手隐私. 与匿名集内服务器名称的 TLS 连接建立与匿名集内任何其他服务器名称的连接无法区分. (匿名集在 {{intro}} 中定义.)
1. Downgrade resistance. An attacker cannot downgrade a connection that
   attempts to use ECH to one that does not use ECH.

   降级抵抗. 攻击者无法将尝试使用 ECH 的连接降级为不使用 ECH 的连接.

These properties were formally proven in {{ECH-Analysis}}.

这些属性在 {{ECH-Analysis}} 中得到了正式证明.

With regards to handshake privacy, client-facing server configuration
determines the size of the anonymity set. For example, if a
client-facing server uses distinct ECHConfig values for each server
name, then each anonymity set has size k = 1. Client-facing servers
SHOULD deploy ECH in such a way so as to maximize the size of the
anonymity set where possible. This means client-facing servers should
use the same ECHConfig for as many server names as possible. An
attacker can distinguish two server names that have different
ECHConfig values based on the ECHClientHello.config_id value.

关于握手隐私, 面向客户端的服务器配置决定了匿名集的大小. 例如, 如果面向客户端的服务器为每个服务器名称使用不同的 ECHConfig 值, 那么每个匿名集的大小为 k = 1. 面向客户端的服务器应该以尽可能最大化匿名集大小的方式部署 ECH. 这意味着面向客户端的服务器应该为尽可能多的服务器名称使用相同的ECHConfig. 攻击者可以基于 ECHClientHello.config_id 值区分具有不同 ECHConfig 值的两个服务器名称.

This also means public information in a TLS handshake should be
consistent across server names. For example, if a client-facing server
services many backend origin server names, only one of which supports some
cipher suite, it may be possible to identify that server name based on the
contents of unencrypted handshake message. Similarly, if a backend
origin reuses KeyShare values, then that provides a unique identifier
for that server.

这也意味着 TLS 握手中的公开信息应该在服务器名称之间保持一致. 例如, 如果面向客户端的服务器为许多后端源服务器提供服务, 其中只有一个支持某个密码套件, 则可能基于未加密握手消息的内容识别该服务器名称. 类似地, 如果后端源重用 KeyShare, 那么这为该服务器提供了唯一标识符.

Beyond these primary security and privacy goals, ECH also aims to hide, to some
extent, the fact that it is being used at all. Specifically, the GREASE ECH
extension described in {{grease-ech}} does not change the security properties of
the TLS handshake at all. Its goal is to provide "cover" for the real ECH
protocol ({{real-ech}}), as a means of addressing the "do not stick out"
requirements of {{?RFC8744}}. See {{dont-stick-out}} for details.

除了这些主要的安全和隐私目标外, ECH 还旨在在一定程度上隐藏其正在被使用的事实. 具体来说, {{grease-ech}} 中描述的 GREASE ECH 扩展完全不改变TLS握手的安全属性. 其目标是为真实的ECH协议 ({{real-ech}}) 提供 "掩护", 作为满足 {{?RFC8744}} 的 "不突出" 要求的手段. 详见 {{dont-stick-out}}.


## Unauthenticated and Plaintext DNS | 未认证的或明文的 DNS {#plaintext-dns}

ECH supports delivery of configurations through the DNS using SVCB or HTTPS
records, without requiring any verifiable authenticity or provenance
information {{ECH-IN-DNS}}. This means that any attacker which can inject
DNS responses or poison DNS caches, which is a common scenario in
client access networks, can supply clients with fake ECH configurations (so
that the client encrypts data to them) or strip the ECH configurations from
the response. However, in the face of an attacker that controls DNS,
no encryption scheme can work because the attacker can replace the IP
address, thus blocking client connections, or substitute a unique IP
address for each DNS name that was looked up.  Thus, using DNS records
without additional authentication does not make the situation significantly
worse.

ECH 支持通过 DNS 使用 SVCB 或 HTTPS 记录来传递配置, 无任何可供验证的真实性或来源信息 {{ECH-IN-DNS}}. 这意味着任何能够注入 DNS 响应或污染 DNS 缓存的攻击者 (这在客户端接入网络中是常见场景) 都可以向客户端提供虚假的 ECH 配置 (使客户端向他们加密数据) 或从响应中剥离 ECH 配置. 然而, 面对控制 DNS 的攻击者, 任何加密方案都无法工作, 因为攻击者可以替换 IP 地址, 从而阻止客户端连接, 或为每个查找的 DNS 名称替换唯一的 IP 地址. 因此, 使用没有额外认证的 DNS 记录并不会使情况显著恶化.

Clearly, DNSSEC (if the client validates and hard fails) is a defense
against this form of attack, but encrypted DNS transport is also a
defense against DNS attacks by attackers on the local network, which
is a common case where ClientHello and SNI encryption are
desired. Moreover, as noted in the introduction, SNI encryption is
less useful without encryption of DNS queries in transit.

显然, DNSSEC (如果客户端验证并硬失败) 是对这种攻击形式的防御, 但加密的 DNS 传输也是对本地网络攻击者发起的 DNS 攻击的防御, 这是希望进行 ClientHello 和 SNI 加密的常见情况. 此外, 如引言中所述, 如果没有对传输中 DNS 查询的加密, SNI 加密就不那么有用.

## Client Tracking | 客户端跟踪

A malicious client-facing server could distribute unique, per-client ECHConfig
structures as a way of tracking clients across subsequent connections. On-path
adversaries which know about these unique keys could also track clients in this
way by observing TLS connection attempts.

恶意的面向客户端的服务器可能会分发独特的、针对每个客户端的 ECHConfig 结构, 作为跟踪客户端后续连接的方式. 知晓这些独特密钥的中间人也可以通过观察 TLS 连接尝试以这种方式跟踪客户端.

The cost of this type of attack scales linearly with the desired number of
target clients. Moreover, DNS caching behavior makes targeting individual users
for extended periods of time, e.g., using per-client ECHConfig structures
delivered via HTTPS RRs with high TTLs, challenging. Clients can help mitigate
this problem by flushing any DNS or ECHConfig state upon changing networks
(this may not be possible if clients use the operating system resolver
rather than doing their own resolution).

这种类型攻击的成本与期望的目标客户端数量呈线性增长. 此外, DNS 缓存行为使得长期针对个别用户变得困难, 例如, 使用通过具有高 TTL 的 HTTPS RRs 交付的针对每个客户端的 ECHConfig 结构. 客户端可以通过在更换网络时清除任何 DNS 或 ECHConfig 状态来帮助缓解这个问题（如果客户端使用操作系统解析器而不是进行自己的解析, 这可能无法实现）.

ECHConfig rotation rate is also an issue for non-malicious servers,
which may want to rotate keys frequently to limit exposure if the key
is compromised. Rotating too frequently limits the client anonymity
set. In practice, servers which service many server names and thus
have high loads are the best candidates to be client-facing servers
and so anonymity sets will typically involve many connections even
with fairly fast rotation intervals.

ECHConfig 轮换率对于非恶意服务器也是一个问题, 这些服务器可能希望频繁轮换密钥以限制密钥被泄露时的暴露. 轮换过于频繁会限制客户端匿名集. 在实践中, 服务许多服务器名称且因此具有高负载的服务器是成为面向客户端服务器的最佳候选者, 因此即使在相当快的轮换间隔下, 匿名集通常也会涉及许多连接.

## Ignored Configuration Identifiers and Trial Decryption | 忽略配置标识符和试验解密 {#ignored-configs}

Ignoring configuration identifiers may be useful in scenarios where clients and
client-facing servers do not want to reveal information about the client-facing
server in the "encrypted_client_hello" extension. In such settings, clients send
a randomly generated config_id in the ECHClientHello. Servers in these settings
must perform trial decryption since they cannot identify the client's chosen ECH
key using the config_id value. As a result, ignoring configuration
identifiers may exacerbate DoS attacks. Specifically, an adversary may send
malicious ClientHello messages, i.e., those which will not decrypt with any
known ECH key, in order to force wasteful decryption. Servers that support this
feature should, for example, implement some form of rate limiting mechanism to
limit the potential damage caused by such attacks.

忽略配置标识符在客户端和面向客户端的服务器不希望在 "encrypted_client_hello" 扩展中透露面向客户端服务器信息的场景中可能很有用. 在这种设置中, 客户端在 ECHClientHello 中发送随机生成的 config_id. 这些设置中的服务器必须执行试验解密, 因为它们无法使用 config_id 值识别客户端选择的 ECH 密钥. 因此, 忽略配置标识符可能会加剧 DoS 攻击. 具体来说, 攻击者可能发送恶意 ClientHello 消息, 即那些无法用任何已知 ECH 密钥解密的消息, 以强制进行浪费性解密. 支持此功能的服务器应该, 例如, 实现某种形式的速率限制机制来限制此类攻击造成的潜在损害.

Unless specified by the application using (D)TLS or externally configured,
implementations MUST NOT use this mode.

除非使用(D)TLS的应用程序明确指定或外部配置, 否则实现**绝不能**使用此模式.

## Outer ClientHello | 外层 ClientHello {#outer-clienthello}

Any information that the client includes in the ClientHelloOuter is visible to
passive observers. The client SHOULD NOT send values in the ClientHelloOuter
which would reveal a sensitive ClientHelloInner property, such as the true
server name. It MAY send values associated with the public name in the
ClientHelloOuter.

客户端在 ClientHelloOuter 中包含的任何信息对被动观察者都是可见的. 客户端**绝不能**在 ClientHelloOuter 中发送会透露敏感 ClientHelloInner 属性 (如真实服务器名称) 的值. 它**可以**在 ClientHelloOuter 中发送与公共名称相关的值.

In particular, some extensions require the client send a server-name-specific
value in the ClientHello. These values may reveal information about the
true server name. For example, the "cached_info" ClientHello extension
{{?RFC7924}} can contain the hash of a previously observed server certificate.
The client SHOULD NOT send values associated with the true server name in the
ClientHelloOuter. It MAY send such values in the ClientHelloInner.

特别是, 某些扩展要求客户端在 ClientHello 中发送特定于服务器名称的值. 这些值可能透露有关真实服务器名称的信息. 例如, "cached_info" ClientHello 扩展 {{?RFC7924}} 可以包含先前观察到的服务器证书的哈希值. 客户端不应在 ClientHelloOuter 中发送与真实服务器名称相关的值. 它可以在 ClientHelloInner 中发送此类值.

A client may also use different preferences in different contexts. For example,
it may send different ALPN lists to different servers or in different
application contexts. A client that treats this context as sensitive SHOULD NOT
send context-specific values in ClientHelloOuter.

客户端也可能在不同上下文中使用不同的首选项. 例如, 它可能向不同服务器或在不同应用程序上下文中发送不同的 ALPN 列表. 将此上下文视为敏感信息的客户端不应在 ClientHelloOuter 中发送特定于上下文的值.

Values which are independent of the true server name, or other information the
client wishes to protect, MAY be included in ClientHelloOuter. If they match
the corresponding ClientHelloInner, they MAY be compressed as described in
{{encoding-inner}}. However, note that the payload length reveals information
about which extensions are compressed, so inner extensions which only sometimes
match the corresponding outer extension SHOULD NOT be compressed.

独立于真实服务器名称或客户端希望保护的其他信息的值可以包含在 ClientHelloOuter 中. 如果它们与相应的 ClientHelloInner 匹配, 可以按 {{encoding-inner}} 中描述的方式进行压缩. 但是, 请注意, 载荷长度会透露有关哪些扩展被压缩的信息, 因此仅有时与相应外部扩展匹配的内部扩展不应被压缩.

Clients MAY include additional extensions in ClientHelloOuter to avoid
signaling unusual behavior to passive observers, provided the choice of value
and value itself are not sensitive. See {{dont-stick-out}}.

客户端可以在 ClientHelloOuter 中包含额外的扩展以避免向被动观察者发出异常行为信号, 前提是值的选择和值本身不敏感. 参见 {{dont-stick-out}}.

## Inner ClientHello | 内层 ClientHello {#inner-clienthello}

Values which depend on the contents of ClientHelloInner, such as the
true server name, can influence how client-facing servers process this message.
In particular, timing side channels can reveal information about the contents
of ClientHelloInner. Implementations should take such side channels into
consideration when reasoning about the privacy properties that ECH provides.

依赖于 ClientHelloInner 内容的值, 如真实服务器名称, 可能影响面向客户端的服务器如何处理此消息. 特别是, 时序侧信道可能透露有关 ClientHelloInner 内容的信息. 实现在推理 ECH 提供的隐私属性时应考虑此类侧信道.

## Related Privacy Leaks | 相关隐私泄漏

ECH requires encrypted DNS to be an effective privacy protection mechanism.
However, verifying the server's identity from the Certificate message,
particularly when using the X509 CertificateType, may result in additional
network traffic that may reveal the server identity. Examples of this traffic
may include requests for revocation information, such as OCSP or CRL traffic, or
requests for repository information, such as authorityInformationAccess. It may
also include implementation-specific traffic for additional information sources
as part of verification.

ECH 需要加密 DNS 才能成为有效的隐私保护机制. 但是, 从 Certificate 消息验证服务器身份, 特别是使用 X509 CertificateType 时, 可能导致可能透露服务器身份的额外网络流量. 此类流量的示例可能包括对撤销信息的请求, 如 OCSP 或 CRL 流量, 或对存储库信息的请求, 如 authorityInformationAccess. 它还可能包括特定于实现的流量, 用于作为验证一部分的额外信息源.

Implementations SHOULD avoid leaking information that may identify the server.
Even when sent over an encrypted transport, such requests may result in indirect
exposure of the server's identity, such as indicating a specific CA or service
being used. To mitigate this risk, servers SHOULD deliver such information
in-band when possible, such as through the use of OCSP stapling, and clients
SHOULD take steps to minimize or protect such requests during certificate
validation.

实现应避免泄漏可能识别服务器的信息. 即使通过加密传输发送, 此类请求也可能导致服务器身份的间接暴露, 例如指示正在使用的特定 CA 或服务. 为了减轻此风险, 服务器应在可能时在带内传递此类信息, 例如 OCSP 装订, 客户端应采取措施在证书验证期间最小化或保护此类请求.

Attacks that rely on non-ECH traffic to infer server identity in an ECH
connection are out of scope for this document. For example, a client that
connects to a particular host prior to ECH deployment may later resume a
connection to that same host after ECH deployment. An adversary that observes
this can deduce that the ECH-enabled connection was made to a host that the
client previously connected to and which is within the same anonymity set.

依赖非 ECH 流量来推断 ECH 连接中服务器身份的攻击超出了本文档的范围. 例如,在 ECH 部署之前连接到特定主机的客户端可能在 ECH 部署后恢复到同一主机的连接. 观察到这一点的攻击者可以推断 ECH 启用的连接是向客户端先前连接的主机建立的,并且该主机在同一匿名集内.

## Cookies

{{Section 4.2.2 of RFC8446}} defines a cookie value that servers may send in
HelloRetryRequest for clients to echo in the second ClientHello. While ECH
encrypts the cookie in the second ClientHelloInner, the backend server's
HelloRetryRequest is unencrypted.This means differences in cookies between
backend servers, such as lengths or cleartext components, may leak information
about the server identity.

{{Section 4.2.2 of RFC8446}} 定义了服务器可能在 HelloRetryRequest 中发送供客户端在第二个 ClientHello 中回显的 cookie 值. 虽然 ECH 在第二个 ClientHelloInner 中加密 cookie, 但后端服务器的 HelloRetryRequest 是未加密的. 这意味着后端服务器之间 cookie 的差异, 如长度或明文组件, 可能泄漏有关服务器身份的信息.

Backend servers in an anonymity set SHOULD NOT reveal information in the cookie
which identifies the server. This may be done by handling HelloRetryRequest
statefully, thus not sending cookies, or by using the same cookie construction
for all backend servers.

匿名集中的后端服务器**绝不能**在 cookie 中透露识别服务器的信息. 这可以通过有状态地处理 HelloRetryRequest (因此不发送cookie) 或对所有后端服务器使用相同的 cookie 构造来实现.

Note that, if the cookie includes a key name, analogous to {{Section 4 of
?RFC5077}}, this may leak information if different backend servers issue
cookies with different key names at the time of the connection. In particular,
if the deployment operates in Split Mode, the backend servers may not share
cookie encryption keys. Backend servers may mitigate this by either handling
key rotation with trial decryption, or coordinating to match key names.

请注意,如果 cookie 包含密钥名称, 类似于 {{Section 4 of ?RFC5077}}, 如果不同后端服务器在连接时使用不同密钥名称发出 cookie, 这可能泄漏信息. 特别是, 如果部署在分离模式下运行, 后端服务器可能不共享 cookie 加密密钥. 后端服务器可以通过试验解密处理密钥轮换或协调匹配密钥名称来缓解这一问题.

## Attacks Exploiting Acceptance Confirmation | 利用接受确认的攻击

To signal acceptance, the backend server overwrites 8 bytes of its
ServerHello.random with a value derived from the ClientHelloInner.random. (See
{{backend-server}} for details.) This behavior increases the likelihood of the
ServerHello.random colliding with the ServerHello.random of a previous session,
potentially reducing the overall security of the protocol. However, the
remaining 24 bytes provide enough entropy to ensure this is not a practical
avenue of attack.

为了发出接受信号, 后端服务器用从 ClientHelloInner.random 派生的值覆盖其 ServerHello.random 的 8 个字节. (详见 {{backend-server}}.) 此行为增加了 ServerHello.random 与先前会话的 ServerHello.random 发生冲突的可能性,可 能降低协议的整体安全性. 但是, 剩余的24字节提供了足够的熵来确保这不是实际的攻击途径.

On the other hand, the probability that two 8-byte strings are the same is
non-negligible. This poses a modest operational risk. Suppose the client-facing
server terminates the connection (i.e., ECH is rejected or bypassed): if the
last 8 bytes of its ServerHello.random coincide with the confirmation signal,
then the client will incorrectly presume acceptance and proceed as if the
backend server terminated the connection. However, the probability of a false
positive occurring for a given connection is only 1 in 2^64. This value is
smaller than the probability of network connection failures in practice.

另一方面, 两个 8 字节字符串相同的概率是不可忽略的. 这带来了适度的操作风险. 假设面向客户端的服务器终止连接 (即,ECH被拒绝或绕过): 如果其 ServerHello.random 的最后 8 字节与确认信号重合, 那么客户端将错误地假定接受并继续进行, 就好像后端服务器终止连接一样. 但是, 给定连接出现误报的概率仅为 2^64 分之一. 此值小于实际网络连接故障的概率.

Note that the same bytes of the ServerHello.random are used to implement
downgrade protection for TLS 1.3 (see {{RFC8446, Section 4.1.3}}). These
mechanisms do not interfere because the backend server only signals ECH
acceptance in TLS 1.3 or higher.

请注意, ServerHello.random 的相同字节用于为 TLS 1.3 实现降级保护 (参见 {{RFC8446, Section 4.1.3}}). 这些机制不会干扰, 因为后端服务器仅在 TLS 1.3 或更高版本中发出ECH接受信号.

## Comparison Against Criteria | 与标准对比

{{?RFC8744}} lists several requirements for SNI encryption.
In this section, we re-iterate these requirements and assess the ECH design
against them.

{{?RFC8744}} 列出了 SNI 加密的几个要求. 在本节中, 我们重申这些要求并根据它们评估 ECH 设计.

### Mitigate Cut-and-Paste Attacks | 缓解剪切粘贴攻击

Since servers process either ClientHelloInner or ClientHelloOuter, and because
ClientHelloInner.random is encrypted, it is not possible for an attacker to "cut
and paste" the ECH value in a different Client Hello and learn information from
ClientHelloInner.

由于服务器处理 ClientHelloInner 或 ClientHelloOuter, 并且因为 ClientHelloInner.random 是加密的, 攻击者无法在不同的 Client Hello中 "剪切粘贴" ECH 值并从 ClientHelloInner 中学习信息.

### Avoid Widely Shared Secrets | 避免广泛共享机密

This design depends upon DNS as a vehicle for semi-static public key
distribution. Server operators may partition their private keys
however they see fit provided each server behind an IP address has the
corresponding private key to decrypt a key. Thus, when one ECH key is
provided, sharing is optimally bound by the number of hosts that share
an IP address. Server operators may further limit sharing of private
keys by publishing different DNS records containing ECHConfig values
with different public keys using a short TTL.

此设计依赖 DNS 作为半静态公钥分发的载体. 服务器运营商可以随意分区其私钥, 只要 IP 地址后面的每个服务器都有相应的私钥来解密密钥. 因此, 当提供一个 ECH 密钥时, 共享最佳情况下受共享 IP 地址的主机数量限制. 服务器运营商可以通过使用短 TTL 发布包含具有不同公钥的 ECHConfig 值的不同 DNS 记录来进一步限制私钥的共享.

### SNI-Based Denial-of-Service Attacks | 基于 SNI 的拒绝服务攻击

This design requires servers to decrypt ClientHello messages with ECHClientHello
extensions carrying valid digests. Thus, it is possible for an attacker to force
decryption operations on the server. This attack is bound by the number of valid
transport connections an attacker can open.

此设计要求服务器解密携带有效摘要的 ECHClientHello 扩展的 ClientHello 消息. 因此, 攻击者可能强制服务器进行解密操作. 此攻击受攻击者可以打开的有效传输连接数量限制.

### Do Not Stick Out | 不要突出 {#dont-stick-out}

As a means of reducing the impact of network ossification, {{?RFC8744}}
recommends SNI-protection mechanisms be designed in such a way that network
operators do not differentiate connections using the mechanism from connections
not using the mechanism. To that end, ECH is designed to resemble a standard
TLS handshake as much as possible. The most obvious difference is the extension
itself: as long as middleboxes ignore it, as required by {{!RFC8446}}, the rest
of the handshake is designed to look very much as usual.

作为减少网络僵化影响的手段, {{?RFC8744}} 建议 SNI 保护机制的设计方式使网络运营商不会区分使用该机制的连接和不使用该机制的连接. 为此, ECH 被设计为尽可能类似标准 TLS 握手. 最明显的区别是扩展本身: 只要中间件忽略它 (如{{!RFC8446}}所要求), 握手的其余部分被设计为看起来非常正常.

The GREASE ECH protocol described in {{grease-ech}} provides a low-risk way to
evaluate the deployability of ECH. It is designed to mimic the real ECH protocol
({{real-ech}}) without changing the security properties of the handshake. The
underlying theory is that if GREASE ECH is deployable without triggering
middlebox misbehavior, and real ECH looks enough like GREASE ECH, then ECH
should be deployable as well. Thus, the strategy for mitigating network
ossification is to deploy GREASE ECH widely enough to disincentivize
differential treatment of the real ECH protocol by the network.

{{grease-ech}} 中描述的 GREASE ECH 协议提供了评估 ECH 可部署性的低风险方法. 它被设计为模仿真实 ECH 协议 ({{real-ech}}) 而不改变握手的安全属性. 基本理论是, 如果 GREASE ECH 可部署而不触发中间件错误行为, 并且真实 ECH 看起来足够像 GREASE ECH, 那么 ECH 也应该是可部署的. 因此, 缓解网络僵化的策略是广泛部署 GREASE ECH, 以阻止网络对真实 ECH 协议的差别对待.

Ensuring that networks do not differentiate between real ECH and GREASE ECH may
not be feasible for all implementations. While most middleboxes will not treat
them differently, some operators may wish to block real ECH usage but allow
GREASE ECH. This specification aims to provide a baseline security level that
most deployments can achieve easily, while providing implementations enough
flexibility to achieve stronger security where possible. Minimally, real ECH is
designed to be indifferentiable from GREASE ECH for passive adversaries with
following capabilities:

确保网络不区分真实 ECH 和 GREASE ECH 对所有实现可能不可行. 虽然大多数中间件不会区别对待它们, 但一些运营商可能希望阻止真实 ECH 使用但允许 GREASE ECH. 此规范旨在提供大多数部署可以轻松实现的基线安全级别, 同时为实现提供足够的灵活性以在可能的情况下实现更强的安全性. 最低限度,真实 ECH 被设计为对具有以下能力的被动攻击者与 GREASE ECH 无法区分:

1. The attacker does not know the ECHConfigList used by the server.

   攻击者不知道服务器使用的 ECHConfigList.
1. The attacker keeps per-connection state only. In particular, it does not
   track endpoints across connections.

   攻击者仅保持每连接状态. 特别是, 它不跨连接跟踪端点.

Moreover, real ECH and GREASE ECH are designed so that the following features
do not noticeably vary to the attacker, i.e., they are not distinguishers:

此外, 真实 ECH 和 GREASE ECH 被设计为以下特征对攻击者不明显变化, 即它们不是可供区分的特征:

1. the code points of extensions negotiated in the clear, and their order;

   明文协商的扩展的代码点及其顺序;
1. the length of messages; and

   消息的长度; 以及
1. the values of plaintext alert messages.

   明文警报消息的值.

This leaves a variety of practical differentiators out-of-scope. including,
though not limited to, the following:

这使得各种实际区分器超出范围 (即采用其他方法进行区分). 包括但不限于以下内容:

1. the value of the configuration identifier;

   配置标识符的值;
1. the value of the outer SNI;

   外部 SNI 的值;

   (译者注: 最典型的是 Cloudflare 的 ECH 均采用 cloudflare-ech.com 作为外部 SNI, 会直接被阻断)
1. the TLS version negotiated, which may depend on ECH acceptance;

   协商的 TLS 版本,可能取决于 ECH 是否被接受;
1. client authentication, which may depend on ECH acceptance; and

   客户端身份验证, 可能取决于 ECH 是否被接受; 以及
1. HRR issuance, which may depend on ECH acceptance.

   HRR 发布, 可能取决于 ECH 是否被接受.

These can be addressed with more sophisticated implementations, but some
mitigations require coordination between the client and server, and even
across different client and server implementations. These mitigations are
out-of-scope for this specification.

这些可以通过更复杂的实现来解决, 但一些缓解措施需要客户端和服务器之间的协调, 甚至跨不同的客户端和服务器实现. 这些缓解措施超出了本规范的范围.

### Maintain Forward Secrecy | 维护前向保密

This design does not provide forward secrecy for the inner ClientHello
because the server's ECH key is static.  However, the window of
exposure is bound by the key lifetime. It is RECOMMENDED that servers
rotate keys regularly.

此设计不为内层 ClientHello 提供前向保密, 因为服务器的 ECH 密钥是静态的. 但是, 暴露窗口受密钥生命周期限制. **建议**服务器定期轮换密钥.

### Enable Multi-party Security Contexts | 启用多方安全上下文

This design permits servers operating in Split Mode to forward connections
directly to backend origin servers. The client authenticates the identity of
the backend origin server, thereby allowing the backend origin server
to hide behind the client-facing server without the client-facing
server decrypting and reencrypting the connection.

此设计允许在分离模式下运行的服务器直接将连接转发到后端源服务器. 客户端验证后端源服务器的身份, 从而允许后端源服务器隐藏在面向客户端的服务器后面, 而面向客户端的服务器无需解密和重新加密连接.

Conversely, if the DNS records used for configuration are
authenticated, e.g., via DNSSEC,
spoofing a client-facing server operating in Split Mode is not
possible. See {{plaintext-dns}} for more details regarding plaintext
DNS.

此外, 如果用于配置的 DNS 记录经过身份验证, 例如通过 DNSSEC, 则无法伪造在分离模式下运行的面向客户端的服务器. 有关明文 DNS 的更多详细信息, 参见 {{plaintext-dns}}.

Authenticating the ECHConfig structure naturally authenticates the included
public name. This also authenticates any retry signals from the client-facing
server because the client validates the server certificate against the public
name before retrying.

验证 ECHConfig 结构自然验证包含的公共名称. 这也验证来自面向客户端服务器的任何重试信号, 因为客户端在重试之前根据公共名称验证服务器证书.

### Support Multiple Protocols | 支持多种协议

This design has no impact on application layer protocol negotiation. It may
affect connection routing, server certificate selection, and client certificate
verification. Thus, it is compatible with multiple application and transport
protocols. By encrypting the entire ClientHello, this design additionally
supports encrypting the ALPN extension.

此设计对应用层协议协商没有影响. 它可能影响连接路由, 服务器证书选择和客户端证书验证. 因此, 它与多种应用程序和传输协议兼容. 通过加密整个 ClientHello, 此设计还支持加密 ALPN 扩展.

## Padding Policy | 填充策略

Variations in the length of the ClientHelloInner ciphertext could leak
information about the corresponding plaintext. {{padding}} describes a
RECOMMENDED padding mechanism for clients aimed at reducing potential
information leakage.

ClientHelloInner 密文长度的变化可能泄漏有关相应明文的信息. {{padding}} 描述了旨在减少潜在信息泄漏的客户端推荐填充机制.

## Active Attack Mitigations | 主动攻击缓解

This section describes the rationale for ECH properties and mechanics as
defenses against active attacks. In all the attacks below, the attacker is
on-path between the target client and server. The goal of the attacker is to
learn private information about the inner ClientHello, such as the true SNI
value.

本节描述 ECH 属性和机制作为对主动攻击防御的基本原理. 在下面的所有攻击中, 攻击者位于目标客户端和服务器之间的路径上. 攻击者的目标是了解有关内部 ClientHello 的私有信息, 如真实 SNI 值.

### Client Reaction Attack Mitigation | 客户端反应攻击缓解 {#flow-client-reaction}

This attack uses the client's reaction to an incorrect certificate as an oracle.
The attacker intercepts a legitimate ClientHello and replies with a ServerHello,
Certificate, CertificateVerify, and Finished messages, wherein the Certificate
message contains a "test" certificate for the domain name it wishes to query. If
the client decrypted the Certificate and failed verification (or leaked
information about its verification process by a timing side channel), the
attacker learns that its test certificate name was incorrect. As an example,
suppose the client's SNI value in its inner ClientHello is "example.com," and
the attacker replied with a Certificate for "test.com". If the client produces a
verification failure alert because of the mismatch faster than it would due to
the Certificate signature validation, information about the name leaks. Note
that the attacker can also withhold the CertificateVerify message. In that
scenario, a client which first verifies the Certificate would then respond
similarly and leak the same information.

这种攻击利用客户端对错误证书的反应作为预言机. 攻击者拦截合法的 ClientHello 并回复 ServerHello、Certificate、CertificateVerify 和 Finished 消息, 其中 Certificate 消息包含其希望查询的域名的 "测试" 证书. 如果客户端解密了 Certificate 并验证失败 (或通过时间侧信道泄露了其验证过程的信息), 攻击者就知道其测试证书名称是错误的. 举个例子,, 假设客户端内部 ClientHello 中的 SNI 值是 "example.com", 而攻击者回复了 "test.com" 的 Certificate. 如果客户端由于不匹配而产生验证失败警报的速度比由于 Certificate 签名验证而产生的速度更快, 则名称信息会泄露. 注意, 攻击者也可以扣留 CertificateVerify 消息. 在这种情况下, 首先验证Certificate的客户端会做出类似响应并泄露相同信息.

~~~
 Client                         Attacker               Server
   ClientHello
   + key_share
   + ech         ------>      (intercept)     -----> X (drop)

                             ServerHello
                             + key_share
                   {EncryptedExtensions}
                   {CertificateRequest*}
                          {Certificate*}
                    {CertificateVerify*}
                 <------
   Alert
                 ------>
~~~
{: #flow-diagram-client-reaction title="Client reaction attack"}

ClientHelloInner.random prevents this attack. In particular, since the attacker
does not have access to this value, it cannot produce the right transcript and
handshake keys needed for encrypting the Certificate message. Thus, the client
will fail to decrypt the Certificate and abort the connection.

ClientHelloInner.random 阻止了这种攻击. 特别是, 由于攻击者无法访问这个值, 它无法产生加密 Certificate 消息所需的正确记录和握手密钥. 因此, 客户端将无法解密 Certificate 并中止连接.

### HelloRetryRequest Hijack Mitigation | HelloRetryRequest 劫持缓解 {#flow-hrr-hijack}

This attack aims to exploit server HRR state management to recover information
about a legitimate ClientHello using its own attacker-controlled ClientHello.
To begin, the attacker intercepts and forwards a legitimate ClientHello with an
"encrypted_client_hello" (ech) extension to the server, which triggers a
legitimate HelloRetryRequest in return. Rather than forward the retry to the
client, the attacker attempts to generate its own ClientHello in response based
on the contents of the first ClientHello and HelloRetryRequest exchange with the
result that the server encrypts the Certificate to the attacker. If the server
used the SNI from the first ClientHello and the key share from the second
(attacker-controlled) ClientHello, the Certificate produced would leak the
client's chosen SNI to the attacker.

这种攻击旨在利用服务器 HRR 状态管理来使用其自己的攻击者控制的 ClientHello 恢复关于合法 ClientHello 的信息. 首先, 攻击者拦截并转发带有 "encrypted_client_hello" (ech) 扩展的合法 ClientHello 到服务器, 这触发了合法的 HelloRetryRequest 作为回应. 攻击者不是将重试转发给客户端, 而是尝试基于第一个 ClientHello 和 HelloRetryRequest 交换的内容生成自己的 ClientHello 作为响应, 结果是服务器将 Certificate 加密给攻击者. 如果服务器使用第一个 ClientHello 中的 SNI 和第二个 (攻击者控制的) ClientHello 中的 key_share, 产生的 Certificate 将向攻击者泄露客户端选择的 SNI.

~~~
 Client                         Attacker                   Server
   ClientHello
   + key_share
   + ech         ------>       (forward)        ------->
                                              HelloRetryRequest
                                                    + key_share
                              (intercept)       <-------

                              ClientHello
                              + key_share'
                              + ech'           ------->
                                                    ServerHello
                                                    + key_share
                                          {EncryptedExtensions}
                                          {CertificateRequest*}
                                                 {Certificate*}
                                           {CertificateVerify*}
                                                     {Finished}
                                                <-------
                         (process server flight)
~~~
{: #flow-diagram-hrr-hijack title="HelloRetryRequest hijack attack"}

This attack is mitigated by using the same HPKE context for both ClientHello
messages. The attacker does not possess the context's keys, so it cannot
generate a valid encryption of the second inner ClientHello.

这种攻击通过对两个 ClientHello 消息使用相同的 HPKE 上下文来缓解. 攻击者不拥有上下文的密钥, 因此无法生成第二个内层 ClientHello 的合法密文.

If the attacker could manipulate the second ClientHello, it might be possible
for the server to act as an oracle if it required parameters from the first
ClientHello to match that of the second ClientHello. For example, imagine the
client's original SNI value in the inner ClientHello is "example.com", and the
attacker's hijacked SNI value in its inner ClientHello is "test.com". A server
which checks these for equality and changes behavior based on the result can be
used as an oracle to learn the client's SNI.

如果攻击者能够操纵第二个 ClientHello, 如果服务器要求第一个 ClientHello 的参数与第二个 ClientHello 的参数匹配, 服务器可能会充当预言机. 例如, 假设客户端内部 ClientHello 中的原始SNI值是 "example.com", 而攻击者在其内部 ClientHello 中劫持的 SNI 值是 "test.com". 检查这些值是否相等并根据结果改变行为的服务器可以用作预言机来学习客户端的 SNI.

### ClientHello Malleability Mitigation | ClientHello 可塑性缓解 {#flow-clienthello-malleability}

This attack aims to leak information about secret parts of the encrypted
ClientHello by adding attacker-controlled parameters and observing the server's
response. In particular, the compression mechanism described in
{{encoding-inner}} references parts of a potentially attacker-controlled
ClientHelloOuter to construct ClientHelloInner, or a buggy server may
incorrectly apply parameters from ClientHelloOuter to the handshake.

这种攻击旨在通过添加攻击者控制的参数并观察服务器的响应来泄露关于已加密 ClientHello 机密部分的信息. 特别是, {{encoding-inner}} 中描述的压缩机制引用潜在攻击者控制的 ClientHelloOuter 的部分来构造 ClientHelloInner, 或有错误的服务器可能错误地将 ClientHelloOuter 的参数应用于握手.

To begin, the attacker first interacts with a server to obtain a resumption
ticket for a given test domain, such as "example.com". Later, upon receipt of a
ClientHelloOuter, it modifies it such that the server will process the
resumption ticket with ClientHelloInner. If the server only accepts resumption
PSKs that match the server name, it will fail the PSK binder check with an
alert when ClientHelloInner is for "example.com" but silently ignore the PSK
and continue when ClientHelloInner is for any other name. This introduces an
oracle for testing encrypted SNI values.

首先, 攻击者首先与服务器交互以获得给定测试域的恢复票据, 例如 "example.com". 稍后, 在接收到 ClientHelloOuter 时, 它修改它使得服务器将使用 ClientHelloInner 处理恢复票据. 如果服务器只接受与服务器名称匹配的恢复 PSK, 当 ClientHelloInner 是 "example.com" 时它将因 PSK binder 检查失败而发出警报, 但当 ClientHelloInner 是任何其他名称时会静默忽略 PSK 并继续. 这为测试加密 SNI 值引入了预言机.

~~~
      Client              Attacker                       Server

                                    handshake and ticket
                                       for "example.com"
                                       <-------->

      ClientHello
      + key_share
      + ech
         + ech_outer_extensions(pre_shared_key)
      + pre_shared_key
                  -------->
                        (intercept)
                        ClientHello
                        + key_share
                        + ech
                           + ech_outer_extensions(pre_shared_key)
                        + pre_shared_key'
                                          -------->
                                                         Alert
                                                         -or-
                                                   ServerHello
                                                            ...
                                                      Finished
                                          <--------
~~~
{: #tls-clienthello-malleability title="Message flow for malleable ClientHello"}

This attack may be generalized to any parameter which the server varies by
server name, such as ALPN preferences.

这种攻击可能推广到服务器按服务器名称变化的任何参数, 例如 ALPN 偏好.

ECH mitigates this attack by only negotiating TLS parameters from
ClientHelloInner and authenticating all inputs to the ClientHelloInner
(EncodedClientHelloInner and ClientHelloOuter) with the HPKE AEAD. See
{{authenticating-outer}}. The decompression process in {{encoding-inner}}
forbids "encrypted_client_hello" in OuterExtensions. This ensures the
unauthenticated portion of ClientHelloOuter is not incorporated into
ClientHelloInner.
An earlier iteration of this specification only
encrypted and authenticated the "server_name" extension, which left the overall
ClientHello vulnerable to an analogue of this attack.

ECH 通过仅从 ClientHelloInner 协商TLS参数并使用 HPKE AEAD 认证 ClientHelloInner 的所有输入 (EncodedClientHelloInner 和 ClientHelloOuter) 来缓解这种攻击. 见 {{authenticating-outer}}. {{encoding-inner}} 中的解压过程禁止 OuterExtensions 中的 "encrypted_client_hello". 这确保ClientHelloOuter的未认证部分不会合并到 ClientHelloInner 中. 本规范的早期版本只加密和认证 "server_name" 扩展, 这使整个 ClientHello 容易受到这种攻击的类似攻击.

### ClientHelloInner Packet Amplification Mitigation | ClientHelloInner 数据包放大缓解 {#decompression-amp}

Client-facing servers must decompress EncodedClientHelloInners. A malicious
attacker may craft a packet which takes excessive resources to decompress
or may be much larger than the incoming packet:

面向客户端的服务器必须解压 EncodedClientHelloInners. 恶意攻击者可能制作需要过多资源来解压或可能比传入数据包大得多的数据包:

* If looking up a ClientHelloOuter extension takes time linear in the number of
  extensions, the overall decoding process would take O(M\*N) time, where
  M is the number of extensions in ClientHelloOuter and N is the
  size of OuterExtensions.

  如果查找 ClientHelloOuter 扩展需要与扩展数量成线性关系的时间, 整个解码过程将需要 O(M\*N) 时间, 其中 M 是 ClientHelloOuter 中的扩展数量, N 是 
  OuterExtensions 的大小.

* If the same ClientHelloOuter extension can be copied multiple times,
  an attacker could cause the client-facing server to construct a large
  ClientHelloInner by including a large extension in ClientHelloOuter,
  of length L, and an OuterExtensions list referencing N copies of that
  extension. The client-facing server would then use O(N\*L) memory in
  response to O(N+L) bandwidth from the client. In split-mode, an
  O(N\*L) sized packet would then be transmitted to the
  backend server.

  如果同一个 ClientHelloOuter 扩展可以被复制多次, 攻击者可能导致面向客户端的服务器通过在 ClientHelloOuter 中包含长度为 L 的大扩展, 以及引用该扩展 N 个副本的 OuterExtensions 列表来构造大的 ClientHelloInner. 面向客户端的服务器然后会使用 O(N\*L) 内存来响应来自客户端的 O(N+L) 带宽. 在分离模式下, O(N\*L) 大小的数据包会传输到后端服务器.

ECH mitigates this attack by requiring that OuterExtensions be referenced in
order, that duplicate references be rejected, and by recommending that
client-facing servers use a linear scan to perform decompression. These
requirements are detailed in {{encoding-inner}}.

ECH通过要求OuterExtensions按顺序引用, 拒绝重复引用, 以及建议面向客户端的服务器使用线性扫描来执行解压来缓解这种攻击. 这些要求在{{encoding-inner}}中详细说明.

# IANA Considerations

## Update of the TLS ExtensionType Registry

IANA is requested to create the following entries in the existing registry for
ExtensionType (defined in {{!RFC8446}}):

要求 IANA 增加以下拓展类型 (定义于 {{!RFC8446}}):

1. encrypted_client_hello(0xfe0d), with "TLS 1.3" column values set to
   "CH, HRR, EE", "DTLS-Only" column set to "N", and "Recommended" column set
   to "Yes".

   encrypted_client_hello(0xfe0d), "TLS 1.3" 栏为 "CH, HRR, EE", "DTLS-Only" 栏为 "N", "Recommended" 栏为 "Yes".
1. ech_outer_extensions(0xfd00), with the "TLS 1.3" column values set to "CH",
   "DTLS-Only" column set to "N", "Recommended" column set to "Yes", and the
   "Comment" column set to "Only appears in inner CH."

   ech_outer_extensions(0xfd00), "TLS 1.3" 栏为 "CH", "DTLS-Only" 栏为 "N", "Recommended" 栏为 "Yes", "Comment" 栏为 "Only appears in inner CH. (仅在 CH 出现)".

## Update of the TLS Alert Registry {#alerts}

IANA is requested to create an entry, ech_required(121) in the existing registry
for Alerts (defined in {{!RFC8446}}), with the "DTLS-OK" column set to
"Y".

要求 IANA 增加 ech_required(121) 警报 (定义于 {{!RFC8446}}), "DTLS-OK" 项设置为 "Y".

## ECH Configuration Extension Registry {#config-extensions-iana}

IANA is requested to create a new "ECHConfig Extension" registry in a new
"TLS Encrypted Client Hello (ECH) Configuration Extensions" page. New
registrations need to list the following attributes:

要求 IANA 增加 "TLS Encrypted Client Hello (ECH) Configuration Extensions" 页, 记录 "ECHConfig Extension", 包含下列属性:

Value:
: The two-byte identifier for the ECHConfigExtension, i.e., the
ECHConfigExtensionType
: ECHConfigExtension 二字节标识符, 即 ECHConfigExtensionType

Extension Name:
: Name of the ECHConfigExtension
: ECHConfigExtension 名称

Recommended:
: A "Y" or "N" value indicating if the extension is TLS WG recommends that the
extension be supported. This column is assigned a value of "N" unless
explicitly requested. Adding a value with a value of "Y" requires Standards
Action {{RFC8126}}.
: 一个 "Y" 或 "N" 值, 表示扩展是否为 TLS 工作组建议支持的扩展. 除非明确请求, 否则此列被赋值为 "N". 添加值为 "Y" 的条目需要标准行动 {{RFC8126}}.

Reference:
: The specification where the ECHConfigExtension is defined
: 此 ECHConfigExtension 的定义位置

Notes:
: Any notes associated with the entry
: 有关该项的注意事项
{: spacing="compact"}

New entries in the "ECHConfig Extension" registry are subject to the
Specification Required registration policy ({{!RFC8126, Section
4.6}}), with the policies described in {{!RFC8447, Section 17}}. IANA
[shall add/has added] the following note to the TLS ECHConfig Extension
registry:

"ECHConfig Extension" 中的新条目需要遵循规范要求注册策略 ({{!RFC8126, Section 4.6}}), 以及 {{!RFC8447, Section 17}} 中描述的策略. IANA [shall add/has added] 以下说明到 TLS ECHConfig Extension 注册表:

   Note:  The role of the designated expert is described in RFC 8447.
      The designated expert [RFC8126] ensures that the specification is
      publicly available.  It is sufficient to have an Internet-Draft
      (that is posted and never published as an RFC) or a document from
      another standards body, industry consortium, university site, etc.
      The expert may provide more in depth reviews, but their approval
      should not be taken as an endorsement of the extension.

   注意: 指定专家的职责在 RFC 8447 中有所描述. 指定的专家 [RFC8126] 确保规范是公开可用的. 拥有互联网草案 (已发布但从未作为 RFC 发布) 或来自其他标准机构、行业联盟、大学站点等的文档就足够了. 专家可以提供更深入的审查, 但他们的批准不应被视为对扩展的认可.

This document defines several Reserved values for ECH configuration extensions
to be used for "greasing" as described in {{server-greasing}}.

本文档为 ECH 配置扩展定义了几个保留值, 用于 {{server-greasing}} 中描述的 "greasing".

The initial contents for this registry consists of multiple reserved values,
with the following attributes, which are repeated for each registration:

此注册表的初始内容包含多个保留值, 具有以下属性, 每个注册都会重复这些属性:

Value:
: 0x0000, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A,
0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA

Extension Name:
: RESERVED

Recommended:
: Y

Reference:
: This document

Notes:
: Grease entries.
{: spacing="compact"}

--- back

# Linear-time Outer Extension Processing | 线性时间外层拓展处理 {#linear-outer-extensions}

The following procedure processes the "ech_outer_extensions" extension (see
{{encoding-inner}}) in linear time, ensuring that each referenced extension
in the ClientHelloOuter is included at most once:

通过以下步骤实现对 "ech_outer_extensions" 扩展 (见 {{encoding-inner}}) 的线性时间处理, 确保引用了 ClientHelloOuter 中扩展的扩展最多只出现一次:

1. Let I be initialized to zero and N be set to the number of extensions
in ClientHelloOuter.

   记 I 为零, N 为 ClientHelloOuter 中的扩展数量.

1. For each extension type, E, in OuterExtensions:

   逐个处理 OuterExtensions 中(所记录的被省去的)拓展 (拓展类型记为 E):

   * If E is "encrypted_client_hello", abort the connection with an
     "illegal_parameter" alert and terminate this procedure.

     如果 E 是 "encrypted_client_hello", 则以 "illegal_parameter" 警报中止连接并终止此过程.

   * While I is less than N and the I-th extension of
     ClientHelloOuter does not have type E, increment I.

     如果 I 小于 N 且 ClientHelloOuter 的第 I 个扩展类型不是 E, 则递增 I.

   * If I is equal to N, abort the connection with an "illegal_parameter"
     alert and terminate this procedure.

     如果 I 等于 N, 则以 "illegal_parameter" 警报中止连接并终止此过程.

   * Otherwise, the I-th extension of ClientHelloOuter has type E. Copy
     it to the EncodedClientHelloInner and increment I.

     否则, ClientHelloOuter 中第 I 个拓展的类型即为 E, 复制到 EncodedClientHelloInner 并递增 I.

# Acknowledgements

This document draws extensively from ideas in {{?I-D.kazuho-protected-sni}}, but
is a much more limited mechanism because it depends on the DNS for the
protection of the ECH key. Richard Barnes, Christian Huitema, Patrick McManus,
Matthew Prince, Nick Sullivan, Martin Thomson, and David Benjamin also provided
important ideas and contributions.

该文档在很大程度上借鉴了 {{?I-D.kazuho-protected-sni}} 中的想法, 但由于该方案依赖 DNS 来保护 ECH 密钥, 因此其机制更为有限. Richard Barnes、Christian Huitema、Patrick McManus、Matthew Prince、Nick Sullivan、Martin Thomson 和 David Benjamin 也提供了重要的想法和贡献.

# Change Log

> **RFC Editor's Note:** Please remove this section prior to publication of a
> final version of this document.

Issue and pull request numbers are listed with a leading octothorp.

## Since draft-ietf-tls-esni-16

- Keep-alive

## Since draft-ietf-tls-esni-15

- Add CCS2022 reference and summary (#539)

## Since draft-ietf-tls-esni-14

- Keep-alive

## Since draft-ietf-tls-esni-13

- Editorial improvements

## Since draft-ietf-tls-esni-12

- Abort on duplicate OuterExtensions (#514)

- Improve EncodedClientHelloInner definition (#503)

- Clarify retry configuration usage (#498)

- Expand on config_id generation implications (#491)

- Server-side acceptance signal extension GREASE (#481)

- Refactor overview, client implementation, and middlebox
  sections (#480, #478, #475, #508)

- Editorial iprovements (#485, #488, #490, #495, #496, #499, #500,
  #501, #504, #505, #507, #510, #511)

## Since draft-ietf-tls-esni-11

- Move ClientHello padding to the encoding (#443)

- Align codepoints (#464)

- Relax OuterExtensions checks for alignment with RFC8446 (#467)

- Clarify HRR acceptance and rejection logic (#470)

- Editorial improvements (#468, #465, #462, #461)

## Since draft-ietf-tls-esni-10

- Make HRR confirmation and ECH acceptance explicit (#422, #423)

- Relax computation of the acceptance signal (#420, #449)

- Simplify ClientHelloOuterAAD generation (#438, #442)

- Allow empty enc in ECHClientHello (#444)

- Authenticate ECHClientHello extensions position in ClientHelloOuterAAD (#410)

- Allow clients to send a dummy PSK and early_data in ClientHelloOuter when
  applicable (#414, #415)

- Compress ECHConfigContents (#409)

- Validate ECHConfig.contents.public_name (#413, #456)

- Validate ClientHelloInner contents (#411)

- Note split-mode challenges for HRR (#418)

- Editorial improvements (#428, #432, #439, #445, #458, #455)

## Since draft-ietf-tls-esni-09

- Finalize HPKE dependency (#390)

- Move from client-computed to server-chosen, one-byte config
  identifier (#376, #381)

- Rename ECHConfigs to ECHConfigList (#391)

- Clarify some security and privacy properties (#385, #383)
