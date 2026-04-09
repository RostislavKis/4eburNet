#ifndef PHOENIX_CONFIG_H
#define PHOENIX_CONFIG_H

/*
 * Compile-time feature flags.
 * Значения устанавливаются через CFLAGS в Makefile:
 *   -DCONFIG_PHOENIX_VLESS=1
 * Если флаг не задан — включается по умолчанию (все фичи on).
 */

/* Протоколы */
#ifndef CONFIG_PHOENIX_VLESS
#define CONFIG_PHOENIX_VLESS 1
#endif

#ifndef CONFIG_PHOENIX_TROJAN
#define CONFIG_PHOENIX_TROJAN 1
#endif

#ifndef CONFIG_PHOENIX_SS
#define CONFIG_PHOENIX_SS 1
#endif

#ifndef CONFIG_PHOENIX_AWG
#define CONFIG_PHOENIX_AWG 1
#endif

/* DNS расширения */
#ifndef CONFIG_PHOENIX_FAKE_IP
#define CONFIG_PHOENIX_FAKE_IP 1
#endif

#ifndef CONFIG_PHOENIX_DOH
#define CONFIG_PHOENIX_DOH 1
#endif

/* Proxy providers (подписки) */
#ifndef CONFIG_PHOENIX_PROXY_PROVIDERS
#define CONFIG_PHOENIX_PROXY_PROVIDERS 1
#endif

/* SNI sniffer */
#ifndef CONFIG_PHOENIX_SNIFFER
#define CONFIG_PHOENIX_SNIFFER 1
#endif

#endif /* PHOENIX_CONFIG_H */
