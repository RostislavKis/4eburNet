/*
 * geo_compile.h — компилятор .lst → .gbin для geo баз
 * Для использования в unit-тестах: скомпилировать с -DGEO_COMPILE_LIB
 */

#ifndef GEO_COMPILE_H
#define GEO_COMPILE_H

#include <stdint.h>

/*
 * geo_compile_file — скомпилировать .lst в бинарный .gbin формат.
 *   in_path:  путь к входному .lst файлу
 *   out_path: путь к выходному .gbin файлу (атомарная запись через .tmp)
 *   region:   0=UNKNOWN 1=RU 2=CN 3=US 99=OTHER
 *   cat_type: 0=GENERIC 1=ADS 2=TRACKERS 3=THREATS
 * Возвращает 0 при успехе, 1 при ошибке.
 */
int geo_compile_file(const char *in_path, const char *out_path,
                     uint32_t region, uint32_t cat_type);

#endif /* GEO_COMPILE_H */
