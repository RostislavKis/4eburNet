#ifndef EBURNET_CONFIG_H
#define EBURNET_CONFIG_H

/*
 * Compile-time feature flags.
 * Значения устанавливаются через CFLAGS в Makefile:
 *   -DCONFIG_EBURNET_VLESS=1
 * Если флаг не задан — включается по умолчанию (все фичи on).
 */

/* Протоколы */
#ifndef CONFIG_EBURNET_VLESS
#define CONFIG_EBURNET_VLESS 1
#endif

#ifndef CONFIG_EBURNET_TROJAN
#define CONFIG_EBURNET_TROJAN 1
#endif

#ifndef CONFIG_EBURNET_SS
#define CONFIG_EBURNET_SS 1
#endif

#ifndef CONFIG_EBURNET_AWG
#define CONFIG_EBURNET_AWG 1
#endif

/* DNS расширения */
#ifndef CONFIG_EBURNET_FAKE_IP
#define CONFIG_EBURNET_FAKE_IP 1
#endif

#ifndef CONFIG_EBURNET_DOH
#define CONFIG_EBURNET_DOH 1
#endif

/* Proxy providers (подписки) */
#ifndef CONFIG_EBURNET_PROXY_PROVIDERS
#define CONFIG_EBURNET_PROXY_PROVIDERS 1
#endif

/* SNI sniffer */
#ifndef CONFIG_EBURNET_SNIFFER
#define CONFIG_EBURNET_SNIFFER 1
#endif

/* DNS-over-QUIC (требует wolfSSL --enable-quic, не поддерживается на MICRO) */
#ifndef CONFIG_EBURNET_DOQ
#define CONFIG_EBURNET_DOQ 0
#endif

#endif /* EBURNET_CONFIG_H */
