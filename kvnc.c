#define UNICODE
#define COBJMACROS
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_DEPRECATE
#include <initguid.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windowsx.h>

#include <intrin.h>
#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>

#ifdef _DEBUG
#  define Assert(cond) do { if (!(cond)) __debugbreak(); } while (0)
#  define HR(hr) Assert(SUCCEEDED(hr))
#else
#  define Assert(cond) (void)(cond)
#  define HR(hr) hr
#endif

#pragma comment (lib, "onecore")
#pragma comment (lib, "kernel32")
#pragma comment (lib, "user32")
#pragma comment (lib, "ws2_32")

#define GET2BE(ptr)				_byteswap_ushort(*(uint16_t*)(ptr))
#define GET4BE(ptr)				_byteswap_ulong(*(uint32_t*)(ptr))
#define SET2BE(ptr, value)		*(uint16_t*)(ptr) = _byteswap_ushort(value)
#define SET4BE(ptr, value)		*(uint32_t*)(ptr) = _byteswap_ulong(value)

// ringbuffer

typedef struct {
	uint8_t* data;
	size_t size;
	size_t read;
	size_t write;
} RingBuffer;

static void rb_init(RingBuffer* rb, size_t size)
{
	uint8_t* ptr1 = VirtualAlloc2(NULL, NULL, 2 * size, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS, NULL, 0);
	uint8_t* ptr2 = ptr1 + size;
	Assert(ptr1);

	BOOL ok = VirtualFree(ptr1, size, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
	Assert(ok);

	HANDLE section = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, (DWORD)(size >> 32), (DWORD)size, NULL);
	Assert(section);

	uint8_t* view1 = MapViewOfFile3(section, NULL, ptr1, 0, size, MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, NULL, 0);
	Assert(view1);

	uint8_t* view2 = MapViewOfFile3(section, NULL, ptr2, 0, size, MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, NULL, 0);
	Assert(view2);

	CloseHandle(section);

	rb->data = ptr1;
	rb->size = size;
	rb->read = 0;
	rb->write = 0;
}

static void rb_done(RingBuffer* rb)
{
	UnmapViewOfFile(rb->data);
	UnmapViewOfFile(rb->data + rb->size);
	VirtualFree(rb->data, 0, MEM_RELEASE);
}

static size_t rb_get_available(const RingBuffer* rb)		{ return rb->write - rb->read; }
static size_t rb_get_free(const RingBuffer* rb)				{ return rb->size - rb_get_available(rb); }
static bool rb_is_empty(const RingBuffer* rb)				{ return rb_get_available(rb) == 0; }
static bool rb_is_full(const RingBuffer* rb)				{ return rb_get_free(rb) == 0; }
static void* rb_read_begin(RingBuffer* rb)					{ return rb->data + (rb->read & (rb->size - 1)); }
static void* rb_write_begin(RingBuffer* rb)					{ return rb->data + (rb->write & (rb->size - 1)); }
static void rb_read_end(RingBuffer* rb, size_t size)
{
	Assert(size <= rb_get_available(rb));
	rb->read += size;
}
static void rb_write_end(RingBuffer* rb, size_t size)
{
	Assert(size <= rb_get_free(rb));
	rb->write += size;
}

// VNC protocol constants

// supported VNC version
static const char RFB_VERSION[12] = "RFB 003.008\n";

// vnc authentication types
#define RFB_SECURITY_VENCRYPT 19

// vencrypt auth version
#define RFB_VENCRYPT_VERSION_MAJOR 0
#define RFB_VENCRYPT_VERSION_MINOR 2

// vencrypt subtypes
#define RFB_VENCRYPT_PLAIN 256
#define RFB_VENCRYPT_TLS_PLAIN 259
#define RFB_VENCRYPT_X509_PLAIN 262

// client -> server messages
#define RFB_FRAMEBUFFER_UPDATE_REQUEST	3
#define RFB_SET_ENCODINGS				2
#define RFB_POINTER_EVENT				3
#define RFB_KEY_EVENT					4
#define RFB_CLIENT_CUT_TEXT				6
#define RFB_QEMU_CLIENT_MESSAGE			255

// server -> client messages
#define RFB_FRAMEBUFFER_UPDATE 0

// supported encodings
#define RFB_ENCODING_TIGHT				7
#define RFB_ENCODING_OPENH264			50
#define RFB_ENCODING_TIGHT_JPEG			-23
#define RFB_ENCODING_DESKTOP_SIZE		-223
#define RFB_ENCODING_DESKTOP_NAME		-307
#define RFB_ENCODING_QEMU_LEDS			-261
#define RFB_ENCODING_QEMU_EXTENDED_KEY	-258

// expected pixel format
static const uint8_t RFB_PIXEL_FORMAT[16] = { 32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0 };

// supported encodings
static const int16_t RFB_ENCODINGS[] = {
	RFB_ENCODING_OPENH264,
	RFB_ENCODING_TIGHT,
	RFB_ENCODING_TIGHT_JPEG,
	RFB_ENCODING_DESKTOP_SIZE,
	RFB_ENCODING_DESKTOP_NAME,
	RFB_ENCODING_QEMU_LEDS,
	RFB_ENCODING_QEMU_EXTENDED_KEY,
};

// state

typedef enum {
	NET_STATE_VERSION,
	NET_STATE_SECURITY,
	NET_STATE_VENCRYPT_VERSION,
	NET_STATE_VENCRYPT_ACK,
	NET_STATE_VENCRYPT_SUBTYPE,
	NET_STATE_SECURITY_RESULT,
	NET_STATE_SERVER_INIT,
	NET_STATE_CONNECTED,
	NET_STATE_DISCONNECTED,
} NetState;

typedef struct {
	HWND window;

	HANDLE thread;
	HANDLE stop;

	SOCKET sock;
	NetState net;
	bool sending;
	RingBuffer recv;
	RingBuffer send;
	OVERLAPPED ov_recv;
	OVERLAPPED ov_send;
} State;

#define WM_STATE_SEND (WM_USER + 1)
#define WM_STATE_RECV (WM_USER + 2)

static void state_disconnect(State* state)
{
	state->net = NET_STATE_DISCONNECTED;

	SetEvent(state->stop);
	WaitForSingleObject(state->thread, INFINITE);
	CloseHandle(state->thread);

	shutdown(state->sock, SD_BOTH);
	closesocket(state->sock);
}

static void state_error(State* state, int socket_error, const char* message, ...)
{
	wchar_t wmsg[1024];
	MultiByteToWideChar(CP_UTF8, 0, message, -1, wmsg, 1024);

	wchar_t wbuf1[1024];

	va_list args;
	va_start(args, message);
	_vsnwprintf(wbuf1, ARRAYSIZE(wbuf1), wmsg, args);
	va_end(args);

	wchar_t wbuf2[1024];

	wchar_t* wbuf = wbuf1;
	if (socket_error)
	{
		wchar_t wsockmsg[1024];
		FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM, NULL, socket_error, 0, wsockmsg, ARRAYSIZE(wsockmsg), NULL);

		_snwprintf(wbuf2, ARRAYSIZE(wbuf2), L"%ls\n\n%ls", wbuf1, wsockmsg);
		wbuf = wbuf2;
	}

	MessageBoxW(state->window, wbuf, L"kvnc", MB_ICONERROR);
	state_disconnect(state);
}

static DWORD CALLBACK state_thread(LPVOID arg)
{
	State* state = arg;

	HANDLE events[] = { state->stop, state->ov_send.hEvent, state->ov_recv.hEvent };
	for (;;)
	{
		DWORD wait = WaitForMultipleObjects(ARRAYSIZE(events), events, FALSE, INFINITE);
		if (wait == WAIT_OBJECT_0)
		{
			return 0;
		}
		else if (wait == WAIT_OBJECT_0 + 1)
		{
			PostMessageW(state->window, WM_STATE_SEND, 0, 0);
		}
		else if (wait == WAIT_OBJECT_0 + 2)
		{
			PostMessageW(state->window, WM_STATE_RECV, 0, 0);
		}
		else
		{
			Assert(!"waiting for events failed");
		}
	}
}

static void state_init(State* state)
{
	rb_init(&state->recv, 4 * 1024 * 1024);
	rb_init(&state->send, 4096);

	ZeroMemory(&state->ov_recv, sizeof(state->ov_recv));
	state->ov_recv.hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
	Assert(state->ov_recv.hEvent);

	ZeroMemory(&state->ov_send, sizeof(state->ov_send));
	state->ov_send.hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
	Assert(state->ov_send.hEvent);

	state->stop = CreateEventW(NULL, FALSE, FALSE, NULL);
	Assert(state->stop);
}

static void state_send_end(State* state)
{
	Assert(state->net != NET_STATE_DISCONNECTED);
	Assert(state->sending);

	DWORD transferred;
	DWORD flags;
	BOOL ok = WSAGetOverlappedResult(state->sock, &state->ov_send, &transferred, TRUE, &flags);
	Assert(ok && transferred > 0);

	state->sending = false;

	Assert(transferred <= rb_get_available(&state->send));
	rb_read_end(&state->send, transferred);
}

static void state_send_begin(State* state)
{
	Assert(state->net != NET_STATE_DISCONNECTED);
	Assert(!state->sending);

	size_t used = rb_get_available(&state->send);
	if (used == 0)
	{
		return;
	}

	WSABUF buffer = { .buf = rb_read_begin(&state->send), .len = (ULONG)used };
	DWORD error = WSASend(state->sock, &buffer, 1, NULL, 0, &state->ov_send, NULL);
	if (error == SOCKET_ERROR)
	{
		error = WSAGetLastError();
		if (error != WSA_IO_PENDING)
		{
			state_error(state, error, "Failed to send data to server!");
			return;
		}
	}
	state->sending = true;
}

static void state_recv_end(State* state)
{
	if (state->net == NET_STATE_DISCONNECTED)
	{
		return;
	}

	DWORD transferred;
	DWORD flags;
	BOOL ok = WSAGetOverlappedResult(state->sock, &state->ov_recv, &transferred, TRUE, &flags);
	Assert(ok);

	if (transferred == 0)
	{
		MessageBoxW(state->window, L"Server closed connection", L"kvnc", MB_ICONEXCLAMATION);
		state_disconnect(state);
		return;
	}

	rb_write_end(&state->recv, transferred);
}

static void state_recv_begin(State* state)
{
	if (state->net == NET_STATE_DISCONNECTED)
	{
		return;
	}

	size_t count = rb_get_free(&state->recv);
	if (count == 0)
	{
		state_error(state, 0, "Too much invalid data received from server!");
		return;
	}

	WSABUF buffer = { .buf = rb_write_begin(&state->recv), .len = (ULONG)count };
	DWORD flags = 0;
	DWORD transferred;
	int error = WSARecv(state->sock, &buffer, 1, &transferred, &flags, &state->ov_recv, NULL);
	if (error == SOCKET_ERROR)
	{
		error = WSAGetLastError();
		if (error != WSA_IO_PENDING)
		{
			state_error(state, error, "Failed to receive data from server!");
			return;
		}
	}
}

static void state_connect(State* state, const wchar_t* host, const wchar_t* port)
{
	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	Assert(sock != INVALID_SOCKET);

	// todo: allow to cancel connection
	BOOL ok = WSAConnectByNameW(sock, (LPWSTR)host, (LPWSTR)port, NULL, NULL, NULL, NULL, NULL, NULL);
	if (!ok)
	{
		state_error(state, WSAGetLastError(), "Cannot connect to %ls:%ls", host, port);
		closesocket(sock);
		return;
	}

	state->sock = sock;
	ResetEvent(state->ov_recv.hEvent);
	ResetEvent(state->ov_send.hEvent);
	ResetEvent(state->stop);
	state_recv_begin(state);

	state->thread = CreateThread(NULL, 0, &state_thread, state, 0, NULL);
}

static bool state_update_version(State* state)
{
	if (rb_get_available(&state->recv) < sizeof(RFB_VERSION))
	{
		return false;
	}

	const uint8_t* server_version = rb_read_begin(&state->recv);
	if (memcmp(server_version, RFB_VERSION, sizeof(RFB_VERSION)) != 0)
	{
		state_error(state, 0, "Received unsupported VNC version!");
		return false;
	}
	rb_read_end(&state->recv, sizeof(RFB_VERSION));

	uint8_t* client_version = rb_write_begin(&state->send);
	memcpy(client_version, RFB_VERSION, sizeof(RFB_VERSION));
	rb_write_end(&state->send, sizeof(RFB_VERSION));

	state->net = NET_STATE_SECURITY;
	state_send_begin(state);
	return true;
}

static bool state_update_security(State* state)
{
	size_t available = rb_get_available(&state->recv);
	if (available < 1)
	{
		return false;
	}

	const uint8_t* security = rb_read_begin(&state->recv);
	size_t count = security[0];
	size_t expected = 1 + count;
	if (available < expected)
	{
		return false;
	}

	bool ok = false;
	for (size_t i = 0; i < count; i++)
	{
		if (security[1 + i] == RFB_SECURITY_VENCRYPT)
		{
			ok = true;
			break;
		}
	}
	if (!ok)
	{
		state_error(state, 0, "VeNCrypt authentication not available!");
		return false;
	}
	rb_read_end(&state->recv, expected);

	uint8_t* chosen_security = rb_write_begin(&state->send);
	chosen_security[0] = RFB_SECURITY_VENCRYPT;
	rb_write_end(&state->send, 1);

	state->net = NET_STATE_VENCRYPT_VERSION;
	state_send_begin(state);
	return true;
}

static bool state_update_vencrypt_version(State* state)
{
	if (rb_get_available(&state->recv) < 2)
	{
		return false;
	}

	const uint8_t* server_version = rb_read_begin(&state->recv);
	if (server_version[0] != RFB_VENCRYPT_VERSION_MAJOR && server_version[1] != RFB_VENCRYPT_VERSION_MINOR)
	{
		state_error(state, 0, "Unsupported VeNCrypt version!");
		return false;
	}
	rb_read_end(&state->recv, 2);

	uint8_t* client_version = rb_write_begin(&state->send);
	client_version[0] = RFB_VENCRYPT_VERSION_MAJOR;
	client_version[1] = RFB_VENCRYPT_VERSION_MINOR;
	rb_write_end(&state->send, 2);

	state->net = NET_STATE_VENCRYPT_ACK;
	state_send_begin(state);
	return true;
}

static bool state_update_vencrypt_ack(State* state)
{
	if (rb_get_available(&state->recv) < 1)
	{
		return false;
	}

	const uint8_t* ack = rb_read_begin(&state->recv);
	if (ack[0] != 0)
	{
		state_error(state, 0, "VeNCrypt version handshake failed!");
		return false;
	}
	rb_read_end(&state->recv, 1);

	state->net = NET_STATE_VENCRYPT_SUBTYPE;
	return true;
}

static bool state_update_vencrypt_subtype(State* state)
{
	size_t available = rb_get_available(&state->recv);
	if (available < 1)
	{
		return false;
	}

	const uint8_t* security = rb_read_begin(&state->recv);
	size_t count = security[0];
	size_t expected = 1 + 4 * count;
	if (available < expected)
	{
		return false;
	}

	bool ok = false;
	for (size_t i = 0; i < count; i++)
	{
		if (GET4BE(&security[1 + 4 * i]) == RFB_VENCRYPT_PLAIN)
		{
			ok = true;
			break;
		}
	}
	if (!ok)
	{
		state_error(state, 0, "Unsupported VeNCrypt authentication subtype!");
		return false;
	}
	rb_read_end(&state->recv, expected);

	uint32_t username_len = 5;
	uint32_t password_len = 5;
	char username[5] = "admin";
	char password[5] = "admin";

	uint8_t* auth = rb_write_begin(&state->send);
	SET4BE(auth, RFB_VENCRYPT_PLAIN);		auth += sizeof(uint32_t);
	SET4BE(auth, username_len);				auth += sizeof(uint32_t);
	SET4BE(auth, password_len);				auth += sizeof(uint32_t);
	memcpy(auth, username, username_len);	auth += username_len;
	memcpy(auth, password, password_len);	auth += password_len;
	rb_write_end(&state->send, 4 + 4 + 4 + username_len + password_len);

	state->net = NET_STATE_SECURITY_RESULT;
	state_send_begin(state);
	return true;
}

static bool state_update_security_result(State* state)
{
	size_t available = rb_get_available(&state->recv);
	if (available < sizeof(uint32_t))
	{
		return false;
	}

	const uint8_t* recv = rb_read_begin(&state->recv);
	uint32_t result = GET4BE(&recv[0]);
	if (result != 0)
	{
		if (available < 2 * sizeof(uint32_t))
		{
			return false;
		}
		size_t reason_len = GET4BE(&recv[4]);
		if (available < 2 * sizeof(uint32_t) + reason_len)
		{
			return false;
		}
		const char* reason = (const char*)&recv[8];

		state_error(state, 0, "Authentication failed:\n%s", reason);
		return false;
	}
	rb_read_end(&state->recv, sizeof(result));

	uint8_t* shared = rb_write_begin(&state->send);
	shared[0] = 0;
	rb_write_end(&state->send, 1);

	state->net = NET_STATE_SERVER_INIT;
	state_send_begin(state);
	return true;
}

static bool state_update_server_init(State* state)
{
	size_t available = rb_get_available(&state->recv);
	size_t expected = 2 + 2 + 16 + 4;
	if (available < expected)
	{
		return false;
	}

	const uint8_t* recv = rb_read_begin(&state->recv);
	size_t name_len = GET4BE(&recv[2 + 2 + 16]);
	expected += name_len;
	if (available < expected)
	{
		return false;
	}
	if (memcmp(RFB_PIXEL_FORMAT, &recv[4], sizeof(RFB_PIXEL_FORMAT)) != 0)
	{
		state_error(state, 0, "Unsupported pixel format!");
		return false;
	}
	int width = GET2BE(&recv[0]);
	int height = GET2BE(&recv[2]);
	const char* name = (char*)&recv[2 + 2 + 16 + 4];

	// TODO
	wchar_t title[1024];
	int wlen = MultiByteToWideChar(CP_UTF8, 0, name, (int)name_len, title, ARRAYSIZE(title));
	title[wlen] = 0;
	SetWindowTextW(state->window, title);

	rb_read_end(&state->recv, expected);

	uint8_t* enc = rb_write_begin(&state->send);
	*enc++ = RFB_SET_ENCODINGS;
	*enc++ = 0;
	SET2BE(enc, ARRAYSIZE(RFB_ENCODINGS));
	enc += sizeof(uint16_t);
	for (size_t i = 0; i < ARRAYSIZE(RFB_ENCODINGS); i++)
	{
		SET4BE(enc, RFB_ENCODINGS[i]);
		enc += 4;
	}
	rb_write_end(&state->send, 1 + 1 + 2 + 4 * ARRAYSIZE(RFB_ENCODINGS));

	// temporary
	uint8_t* update = rb_write_begin(&state->send);
	update[0] = RFB_FRAMEBUFFER_UPDATE_REQUEST;
	update[1] = 0;
	SET2BE(&update[2], 0); // x
	SET2BE(&update[4], 0); // y
	SET2BE(&update[6], width); // w
	SET2BE(&update[8], height); // h
	rb_write_end(&state->send, 1 + 1 + 2 + 2 + 2 + 2);

	state->net = NET_STATE_CONNECTED;
	state_send_begin(state);
	return true;
}

static bool state_update_connected(State* state)
{
	size_t available = rb_get_available(&state->recv);
	if (available < 1)
	{
		return false;
	}

	const uint8_t* recv = rb_read_begin(&state->recv);
	int message = recv[0]; recv += 2;
	if (message != RFB_FRAMEBUFFER_UPDATE)
	{
		state_error(state, 0, "Unsupported message received!");
		return false;
	}

	size_t expected = 1 + 1 + 2;
	if (available < expected)
	{
		return false;
	}

	int rects = GET2BE(recv); recv += 2;
	if (rects != 1)
	{
		state_error(state, 0, "Expected only one rectangle in update message!");
		return false;
	}

	expected += 2 + 2 + 2 + 2 + 4;
	if (available < expected)
	{
		return false;
	}

	int x = GET2BE(recv); recv += 2;
	int y = GET2BE(recv); recv += 2;
	int w = GET2BE(recv); recv += 2;
	int h = GET2BE(recv); recv += 2;
	int encoding = GET4BE(recv); recv += 4;

	if (encoding == RFB_ENCODING_TIGHT)
	{
		if (x != 0 || y != 0) // w/h
		{
			state_error(state, 0, "Unsupported update message received - bad x/y/width/height values in Tight encoding!");
			return false;
		}

		expected += 1 + 1;
		uint8_t control = *recv++;
		if (available < expected)
		{
			return false;
		}

		if ((control & 0xf0) != 0x90)
		{
			state_error(state, 0, "Unsupported update message received - only jpeg format in Tight encoding is supported!");
			return false;
		}

		uint8_t byte = *recv++;
		size_t length = (size_t)(byte & 0x7f);
		if (byte & 0x80)
		{
			expected += 1;
			if (available < expected)
			{
				return false;
			}

			byte = *recv++;
			length |= (size_t)(byte & 0x7f) << 7;
			if (byte & 0x80)
			{
				expected += 1;
				if (available < expected)
				{
					return false;
				}

				byte = *recv++;
				length |= (size_t)byte << 14;
			}
		}

		expected += length;
		if (available < expected)
		{
			return false;
		}

		const uint8_t* data = recv;
		// TODO
	}
	else if (encoding == RFB_ENCODING_OPENH264)
	{
		if (x != 0 || y != 0) // w/h
		{
			state_error(state, 0, "Unsupported update message received - bad x/y/width/height values in Open H.264 encoding!");
			return false;
		}

		expected += 4 + 4;
		if (available < expected)
		{
			return false;
		}

		uint32_t length = GET4BE(recv); recv += 4;
		uint32_t flags = GET4BE(recv); recv += 4;

		expected += length;
		if (available < expected)
		{
			return false;
		}

		const uint8_t* data = recv;
		// TODO
	}
	else if (encoding == RFB_ENCODING_DESKTOP_SIZE)
	{
		// TODO: use w/h
	}
	else if (encoding == RFB_ENCODING_QEMU_EXTENDED_KEY)
	{
		// TODO
	}
	else if (encoding == RFB_ENCODING_QEMU_LEDS)
	{
		expected += 1;
		if (available < expected)
		{
			return false;
		}

		uint8_t state = *recv;
		// TODO

	}
	else if (encoding == RFB_ENCODING_DESKTOP_NAME)
	{
		expected += 4;
		if (available < expected)
		{
			return false;
		}

		uint32_t name_len = GET4BE(recv); recv += 4;
		expected += name_len;
		if (available < expected)
		{
			return false;
		}

		const char* name = (char*)recv;
		// TODO
	}
	else
	{
		state_error(state, 0, "Unsupported update message received - bad encoding %d value!", encoding);
		return false;
	}
	rb_read_end(&state->recv, expected);

	return true;
}

static const bool (*state_update[])(State* state) =
{
	[NET_STATE_VERSION]				= &state_update_version,
	[NET_STATE_SECURITY]			= &state_update_security,
	[NET_STATE_VENCRYPT_VERSION]	= &state_update_vencrypt_version,
	[NET_STATE_VENCRYPT_ACK]		= &state_update_vencrypt_ack,
	[NET_STATE_VENCRYPT_SUBTYPE]	= &state_update_vencrypt_subtype,
	[NET_STATE_SECURITY_RESULT]		= &state_update_security_result,
	[NET_STATE_SERVER_INIT]			= &state_update_server_init,
	[NET_STATE_CONNECTED]			= &state_update_connected,
};

// window messages

static LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
	if (message == WM_CREATE)
	{
		State* state = ((CREATESTRUCT*)lparam)->lpCreateParams;
		state->window = window;
		SetWindowLongPtr(window, GWLP_USERDATA, (LONG_PTR)state);
		return 0;
	}

	State* state = (void*)GetWindowLongPtr(window, GWLP_USERDATA);
	if (!state)
	{
		return DefWindowProcW(window, message, wparam, lparam);
	}

	switch (message)
	{
	case WM_DESTROY:
		PostQuitMessage(0);
		return 0;

	case WM_STATE_SEND:
		state_send_end(state);
		state_send_begin(state);
		return 0;

	case WM_STATE_RECV:
		state_recv_end(state);
		while (state_update[state->net](state)) {}
		state_recv_begin(state);
		return 0;
	}

	return DefWindowProcW(window, message, wparam, lparam);
}

// main

void WinMainCRTStartup()
{
	WSADATA wsa;
	int err = WSAStartup(MAKEWORD(2, 2), &wsa);
	Assert(err == 0 && "failed to initialize windows sockets");

	WNDCLASSEXW wc =
	{
		.cbSize = sizeof(wc),
		.lpfnWndProc = &window_proc,
		.hInstance = GetModuleHandleW(NULL),
		.lpszClassName = L"kvnc",
	};
	ATOM atom = RegisterClassExW(&wc);
	Assert(atom && "failed to register window class");

	State state;
	state_init(&state);

	HWND window = CreateWindowExW(
		0, wc.lpszClassName, L"kvnc", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
		CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
		NULL, NULL, wc.hInstance, &state);
	Assert(window && "failed to create window");

	state_connect(&state, L"pikvm-server", L"5900");

	for (;;)
	{
		MSG message;
		BOOL ok = GetMessageW(&message, NULL, 0, 0);
		Assert(ok >= 0 && "get message failed");
		if (ok == 0)
		{
			ExitProcess(0);
		}
		TranslateMessage(&message);
		DispatchMessageW(&message);
	}
}
