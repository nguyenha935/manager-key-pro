// Package plugin implements the CPA plugin ABI. This is the main entry point the
// host calls — all other packages are wired together here.
package plugin

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	cliproxy_host_call_fn call;
	cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);

static const cliproxy_host_api* stored_host;

static void store_host_api(const cliproxy_host_api* host) {
	stored_host = host;
}
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"log"
	"unsafe"
)

const abiVersion uint32 = 1

var app *App // set by plugin.register

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if plugin == nil {
		return 1
	}
	C.store_host_api(host)
	plugin.abi_version = C.uint32_t(abiVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	// Panicking here would take the whole host down, so recover and log.
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[mkp] panic in %s: %v", C.GoString(method), rec)
			writeResponse(response, errorEnvelope("plugin_error", "internal error"))
		}
	}()
	if method == nil {
		writeResponse(response, errorEnvelope("invalid_method", "method is required"))
		return 1
	}
	var payload []byte
	if request != nil && requestLen > 0 {
		payload = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	raw, errHandle := handleMethod(C.GoString(method), payload)
	if errHandle != nil {
		writeResponse(response, errorEnvelope("plugin_error", errHandle.Error()))
		return 1
	}
	writeResponse(response, raw)
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, size C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
	_ = size
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {
	if app != nil {
		if errClose := app.Close(); errClose != nil {
			log.Printf("[mkp] shutdown: %v", errClose)
		}
	}
}

func handleMethod(method string, payload []byte) ([]byte, error) {
	switch method {
	case "plugin.register":
		return handleRegister(payload)
	case "plugin.reconfigure":
		return handleReconfigure(payload)
	case "frontend_auth.identifier":
		return okEnvelopeJSON(`{"identifier":"manager-key-pro"}`)
	case "frontend_auth.authenticate":
		return handleAuthenticate(payload)
	case "request.intercept_before":
		return handleInterceptBefore(payload)
	case "request.intercept_after":
		return handleInterceptAfter(payload)
	case "management.register":
		return managementRegister()
	case "management.handle":
		return handleManagement(payload)
	case "usage.handle":
		return handleUsage(payload)
	case "request.complete":
		return handleComplete(payload)
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *envelopeError  `json:"error,omitempty"`
}

type envelopeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func okEnvelopeJSON(result string) ([]byte, error) {
	return json.Marshal(envelope{OK: true, Result: json.RawMessage(result)})
}

func errorEnvelope(code, message string) []byte {
	raw, _ := json.Marshal(envelope{OK: false, Error: &envelopeError{Code: code, Message: message}})
	return raw
}

func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}

func handleRegister(payload []byte) ([]byte, error) {
	log.Printf("[mkp] handleRegister called")
	var req struct {
		SchemaVersion int    `json:"schema_version"`
		ConfigYAML    string `json:"config_yaml"`
	}
	if errUnmarshal := json.Unmarshal(payload, &req); errUnmarshal != nil {
		return nil, fmt.Errorf("unmarshal register: %w", errUnmarshal)
	}
	// Parse the config YAML delivered by CPA and boot once.
	if app == nil {
		log.Printf("[mkp] booting app...")
		cfg, errCfg := parseConfigYAML(req.ConfigYAML)
		if errCfg != nil {
			return nil, fmt.Errorf("parse config: %w", errCfg)
		}
		var errBoot error
		app, errBoot = Boot(Config{
			DBPath:    cfg.DBPath,
			SecretKey: cfg.EncryptionKey,
		})
		if errBoot != nil {
			return nil, fmt.Errorf("boot: %w", errBoot)
		}
		log.Printf("[mkp] boot complete: db=%s log_mode=%s", cfg.DBPath, cfg.LogMode)
	}
	reg := map[string]any{
		"schema_version": 1,
		"metadata": map[string]any{
			"Name":             "manager-key-pro",
			"Version":          "0.0.1",
			"Author":           "nguyenha935",
			"GitHubRepository": "https://github.com/nguyenha935/manager-key-pro",
			"ConfigFields":     []any{},
		},
		"capabilities": map[string]any{
			"frontend_auth_provider":   true,
			"request_interceptor":      true,
			"usage_plugin":             true,
			"request_lifecycle_plugin": true,
			"management_api":           true,
		},
	}
	raw, errMarshal := json.Marshal(reg)
	if errMarshal != nil {
		return nil, fmt.Errorf("marshal registration: %w", errMarshal)
	}
	return okEnvelopeJSON(string(raw))
}

func handleReconfigure(payload []byte) ([]byte, error) {
	// Reconfiguration must return the full registration envelope again
	// (same as plugin.register). The PoC proved an empty result makes the host
	// drop the capabilities (invalid metadata or no capabilities) and none of
	// the hooks get called after that.
	return handleRegister(payload)
}
