/*
 * strongSwan GM Crypto Plugin
 *
 * Registers SM2/SM3/SM4 algorithms with strongSwan's crypto framework,
 * enabling IKEv2 key exchange and ESP SA negotiation using Chinese
 * national cryptographic standards.
 *
 * strongSwan plugin interface: library/libstrongswan/plugins/plugin.h
 */
#ifndef GM_PLUGIN_H
#define GM_PLUGIN_H

#include <library.h>
#include <plugins/plugin.h>

/**
 * Plugin name
 */
#define GM_PLUGIN_NAME "gm"

/**
 * Create the GM crypto plugin instance.
 */
plugin_t *gm_plugin_create(void);

#endif /* GM_PLUGIN_H */
