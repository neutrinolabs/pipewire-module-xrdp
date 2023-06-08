/**
 * xrdp pipewire module
 *
 * This is a modified version of src/modules/module-pipe-tunnel.c
 * from pipewire 0.3.64
 */

/* PipeWire
 *
 * Copyright © 2021 Sanchayan Maity <sanchayan@asymptotic.io>
 * Copyright © 2022 Wim Taymans
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <limits.h>
#include <math.h>
#include <time.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <spa/utils/result.h>
#include <spa/utils/string.h>
#include <spa/utils/json.h>
#include <spa/utils/ringbuffer.h>
#include <spa/utils/dll.h>
#include <spa/debug/types.h>
#include <spa/pod/builder.h>
#include <spa/param/audio/format-utils.h>
#include <spa/param/latency-utils.h>
#include <spa/param/audio/raw.h>

#include <pipewire/impl.h>
#include <pipewire/i18n.h>

/** \page page_module_pipe_tunnel PipeWire Module: Unix Pipe Tunnel
 *
 * The pipe-tunnel module provides a source or sink that tunnels all audio to
 * a unix pipe.
 *
 * ## Module Options
 *
 * - `tunnel.mode`: the desired tunnel to create. (Default `playback`)
 * - `pipe.filename`: the filename of the pipe.
 * - `stream.props`: Extra properties for the local stream.
 *
 * When `tunnel.mode` is `capture`, a capture stream on the default source is
 * created. Samples read from the pipe will be the contents of the captured source.
 *
 * When `tunnel.mode` is `sink`, a sink node is created. Samples read from the
 * pipe will be the samples played on the sink.
 *
 * When `tunnel.mode` is `playback`, a playback stream on the default sink is
 * created. Samples written to the pipe will be played on the sink.
 *
 * When `tunnel.mode` is `source`, a source node is created. Samples written to
 * the pipe will be made available to streams connected to the source.
 *
 * When `pipe.filename` is not given, a default fifo in `/tmp/fifo_input` or
 * `/tmp/fifo_output` will be created that can be written and read respectively,
 * depending on the selected `tunnel.mode`.
 *
 * ## General options
 *
 * Options with well-known behavior.
 *
 * - \ref PW_KEY_REMOTE_NAME
 * - \ref PW_KEY_AUDIO_FORMAT
 * - \ref PW_KEY_AUDIO_RATE
 * - \ref PW_KEY_AUDIO_CHANNELS
 * - \ref SPA_KEY_AUDIO_POSITION
 * - \ref PW_KEY_NODE_LATENCY
 * - \ref PW_KEY_NODE_NAME
 * - \ref PW_KEY_NODE_DESCRIPTION
 * - \ref PW_KEY_NODE_GROUP
 * - \ref PW_KEY_NODE_VIRTUAL
 * - \ref PW_KEY_MEDIA_CLASS
 * - \ref PW_KEY_TARGET_OBJECT to specify the remote name or serial id to link to
 *
 * When not otherwise specified, the pipe will accept or produce a
 * 16 bits, stereo, 48KHz sample stream.
 *
 * ## Example configuration of a pipe playback stream
 *
 *\code{.unparsed}
 * context.modules = [
 * {   name = libpipewire-module-pipe-tunnel
 *     args = {
 *         tunnel.mode = playback
 *         # Set the pipe name to tunnel to
 *         pipe.filename = "/tmp/fifo_output"
 *         #audio.format=<sample format>
 *         #audio.rate=<sample rate>
 *         #audio.channels=<number of channels>
 *         #audio.position=<channel map>
 *         #target.object=<remote target node>
 *         stream.props = {
 *             # extra sink properties
 *         }
 *     }
 * }
 * ]
 *\endcode
 */

#define NAME "xrdp-pipewire"

#define DEFAULT_FORMAT "S16"
#define DEFAULT_RATE 44100
#define DEFAULT_CHANNELS 2
#define DEFAULT_POSITION "[ FL FR ]"

PW_LOG_TOPIC_STATIC(mod_topic, "mod." NAME);
#define PW_LOG_TOPIC_DEFAULT mod_topic

#define MODULE_USAGE	"[ remote.name=<remote> ] "				\
			"[ sink.node.latency=<latency for sink> ] "		\
			"[ target.object=<remote node target name> ] "		\
			"[ audio.format=<sample format> ] "			\
			"[ audio.rate=<sample rate> ] "				\
			"[ audio.channels=<number of channels> ] "		\
			"[ audio.position=<channel map> ] "			\
			"[ sink.stream.props=<properties for sink> ] "		\
			"[ source.stream.props=<properties for source> ] "


/* commands to xrdp_chansrv_audio_in_socket (xrdp/sesman/chansrv/sound.h)*/
#define PA_CMD_START_REC    1
#define PA_CMD_STOP_REC     2
#define PA_CMD_SEND_DATA    3

static const struct spa_dict_item module_props[] = {
	{ PW_KEY_MODULE_AUTHOR, "Wim Taymans <wim.taymans@gmail.com>" },
	{ PW_KEY_MODULE_DESCRIPTION, "Create a xrdp pipewire interface" },
	{ PW_KEY_MODULE_USAGE, MODULE_USAGE },
	{ PW_KEY_MODULE_VERSION, pw_get_headers_version() },
};

struct impl {
	struct pw_context *context;  // common
	uint32_t destroy_work_id;  // common

#define MODE_XRDP_SINK		1
#define MODE_XRDP_SOURCE	2
#define MODE_BOTH	(MODE_XRDP_SINK | MODE_XRDP_SOURCE)
	uint32_t mode;
	struct pw_properties *props_sink;
	struct pw_properties *props_source;

	struct pw_impl_module *module;  // common

	struct spa_hook module_listener;  // common

	struct pw_core *core;  // common
	struct spa_hook core_proxy_listener;  // common
	struct spa_hook core_listener;  // common

	char *filename_sink;
	char *filename_source;
	int fd_sink;
	int fd_source;
	uint64_t failed_connect_time;

	struct pw_properties *stream_props_sink;
	struct pw_properties *stream_props_source;
	struct pw_stream *stream_sink;
	struct pw_stream *stream_source;
	struct spa_hook stream_listener_sink;
	struct spa_hook stream_listener_source;
	struct spa_audio_info_raw info;  // common
	uint32_t frame_size;  // only source

	unsigned int do_disconnect:1;  // common
	uint32_t leftover_count;  // only source
	uint8_t *leftover;  // only source

	int want_src_data;  // only source
	unsigned int unloading:1;  // common
	struct pw_work_queue *work;  // common
	int display_num; // for debug
};

static void do_unload_module(void *obj, void *data, int res, uint32_t id)
{
	struct impl *impl = data;
	pw_impl_module_destroy(impl->module);
}

static void unload_module(struct impl *impl)
{
	if (!impl->unloading) {
		impl->unloading = true;
		pw_work_queue_add(impl->work, impl, 0, do_unload_module, impl);
	}
}

static void stream_destroy_sink(void *d)
{
	struct impl *impl = d;
	spa_hook_remove(&impl->stream_listener_sink);
	impl->stream_sink = NULL;
}

static void stream_destroy_source(void *d)
{
	struct impl *impl = d;
	spa_hook_remove(&impl->stream_listener_source);
	impl->stream_source = NULL;
}

struct header {
    int code;
    int bytes;
};

static int get_display_num_from_display(const char *display_text) {
    int mode = 0;
    int disp_index = 0;
    char disp[16] = { 0 };

    if (display_text == NULL)
        return 0;

    for (size_t index = 0; display_text[index] != 0 && index < sizeof(disp) ; index++) {
        if (display_text[index] == ':')
            mode = 1;
        else if (display_text[index] == '.')
            break;
        else if (mode == 1)
            disp[disp_index++] = display_text[index];
    }

    disp[disp_index] = 0;
    return atoi(disp);
}

static int lsend(int fd, char *data, int bytes) {
    int sent = 0;
    while (sent < bytes) {
        int error = send(fd, data + sent, bytes - sent, MSG_NOSIGNAL);
        if (error < 1)
            return error;
        sent += error;
    }
    return sent;
}

static int lrecv(int fd, char *data, int bytes) {
    int recved = 0;
    while (recved < bytes) {
        int error = recv(fd, data + recved, bytes - recved, 0);
        if (error < 1)
            return error;
        recved += error;
    }
    return recved;
}

static int close_send_sink(struct impl *impl) {
    pw_log_info("close_send_sink");
    if (impl->fd_sink != -1) {
		struct header h;
		h.code = 1;
		h.bytes = 8;
	    if (lsend(impl->fd_sink, (char*)(&h), 8) != 8) {
    	    pw_log_debug("close_send: send failed");
        	close(impl->fd_sink);
	        impl->fd_sink = -1;
    	    return 0;
	    } else {
    	    pw_log_debug("close_send: sent header ok");
		}
    }

    return 8;
}

static int close_send_source(struct impl *impl) {
    pw_log_info("close_send_source");
    if (impl->fd_source != -1) {
		/* we don't want source data anymore */
		char stop_rec[] = { 0, 0, 0, 0, 11, 0, 0, 0, PA_CMD_STOP_REC, 0, 0 };
		if (lsend(impl->fd_source, stop_rec, 11) != 11) {
			close(impl->fd_source);
			impl->fd_source = -1;
		}
		impl->want_src_data = 0;
		pw_log_debug("###### stopped recording");
	}

    return 8;
}

static void stream_state_changed_sink(void *d, enum pw_stream_state old,
		enum pw_stream_state state, const char *error)
{
	struct impl *impl = d;
	switch (state) {
	case PW_STREAM_STATE_ERROR:
	case PW_STREAM_STATE_UNCONNECTED:
		//pw_impl_module_schedule_destroy(impl->module);
		unload_module(impl);
		break;
	case PW_STREAM_STATE_PAUSED:
		close_send_sink(impl);
		break;
	case PW_STREAM_STATE_STREAMING:
		break;
	default:
		break;
	}
    pw_log_debug("stream_state_changed:%s", pw_stream_state_as_string (state));
}

static void stream_state_changed_source(void *d, enum pw_stream_state old,
		enum pw_stream_state state, const char *error)
{
	struct impl *impl = d;
	switch (state) {
	case PW_STREAM_STATE_ERROR:
	case PW_STREAM_STATE_UNCONNECTED:
		//pw_impl_module_schedule_destroy(impl->module);
		unload_module(impl);
		break;
	case PW_STREAM_STATE_PAUSED:
		close_send_source(impl);
		break;
	case PW_STREAM_STATE_STREAMING:
		break;
	default:
		break;
	}
    pw_log_debug("stream_state_changed:%s", pw_stream_state_as_string (state));
}

static void set_socket_path(struct impl *impl) {
	const char *socket_path;
    char default_socket_path[128];

    const char *socket_dir;
    const char *socket_name;

    socket_dir = getenv("XRDP_SOCKET_PATH");
    if (socket_dir == NULL || socket_dir[0] == '\0') {
		return;
	}
    impl->display_num = get_display_num_from_display(getenv("DISPLAY"));

    socket_name = getenv("XRDP_PULSE_SINK_SOCKET");
    if (socket_name == NULL || socket_name[0] == '\0') {
		return;

		//pw_log_debug("Could not obtain xrdp_socket from environment.");
		//snprintf(default_socket_name, sizeof(default_socket_name)-1,
		//		"xrdp_chansrv_audio_out_socket_%d", impl->display_num);
       	//socket_name = default_socket_name;
   	}
	snprintf(default_socket_path, sizeof(default_socket_path)-1, "%s/%s", socket_dir, socket_name);
	socket_path = default_socket_path;

    pw_log_info("set_sink_socket. socket path:%s", socket_path);

	impl->filename_sink = strdup(socket_path);

    socket_name = getenv("XRDP_PULSE_SOURCE_SOCKET");
    if (socket_name == NULL || socket_name[0] == '\0') {
		return;

		//pw_log_debug("Could not obtain xrdp_socket from environment.");
		//snprintf(default_socket_name, sizeof(default_socket_name)-1,
		//		"xrdp_chansrv_audio_out_socket_%d", impl->display_num);
       	//socket_name = default_socket_name;
   	}
	snprintf(default_socket_path, sizeof(default_socket_path)-1, "%s/%s", socket_dir, socket_name);
	socket_path = default_socket_path;

    pw_log_info("set_source_socket. socket path:%s", socket_path);

	impl->filename_source = strdup(socket_path);
}

static int conect_xrdp_socket(struct impl *impl, char *filename) {
    struct sockaddr_un s = { 0 };
    struct timespec tm;

    if (impl->failed_connect_time != 0) {
        clock_gettime(CLOCK_MONOTONIC, &tm);
        //pw_log_debug("wait 1sec when connect error occurred. waiting %lld nS", (tm.tv_sec * 1000000000LL + tm.tv_nsec) - impl->failed_connect_time);
        if ((tm.tv_sec * 1000000000LL + tm.tv_nsec) - impl->failed_connect_time < 1000000000LL) {
            return -1;
        }
    }

    /* connect to xrdp unix domain socket */
    int fd = socket(PF_LOCAL, SOCK_STREAM, 0);
    s.sun_family = AF_UNIX;
    strncpy(s.sun_path, filename, sizeof(s.sun_path)-1);
    pw_log_info("trying to connect to %s", s.sun_path);

    if (connect(fd, (struct sockaddr *)&s, sizeof(struct sockaddr_un)) != 0) {
        pw_log_debug("Connect failed");
        close(fd);
        clock_gettime(CLOCK_MONOTONIC, &tm);
        impl->failed_connect_time = tm.tv_sec * 1000000000LL + tm.tv_nsec;
        fd = -1;
    } else {
        impl->failed_connect_time = 0;
        pw_log_info("Connected ok fd %d", fd);
    }
    return fd;
}

static void playback_stream_process(void *data)
{
	struct impl *impl = data;
	struct pw_buffer *buf;
	ssize_t written_all = 0;
	uint32_t size_all = 0;

	if ((buf = pw_stream_dequeue_buffer(impl->stream_sink)) == NULL) {
		pw_log_debug("out of buffers: %m");
		return;
	}

    if (impl->fd_sink == -1) {
        if ((impl->fd_sink = conect_xrdp_socket(impl, impl->filename_sink)) == -1)
            goto error;
	}

	for (uint32_t i = 0; i < buf->buffer->n_datas; i++) {
        uint32_t size, offs;
        struct spa_data *d;
        d = &buf->buffer->datas[i];

        offs = SPA_MIN(d->chunk->offset, d->maxsize);
        size = SPA_MIN(d->chunk->size, d->maxsize - offs);

        size_all += size;
    }
    struct header h;
    h.code = 0;
    h.bytes = 8 + size_all;
    if (lsend(impl->fd_sink, (char*)(&h), 8) != 8) {
        pw_log_warn("data_send: send failed");
        close(impl->fd_sink);
        impl->fd_sink = -1;
        goto error;
    } else {
        //pw_log_debug("data_send: sent header ok bytes %d", size_all);
    }

	for (uint32_t i = 0; i < buf->buffer->n_datas; i++) {
        uint32_t size, offs;
        ssize_t written;
        struct spa_data *d;
        d = &buf->buffer->datas[i];

        offs = SPA_MIN(d->chunk->offset, d->maxsize);
        size = SPA_MIN(d->chunk->size, d->maxsize - offs);

        written = lsend(impl->fd_sink, SPA_MEMBER(d->data, offs, void), size);
        written_all += written;
        if (written != size) {
            pw_log_warn("Failed to write to xrdp sink");
            close(impl->fd_sink);
            impl->fd_sink = -1;
            goto error;
        }
	}

error:
	pw_stream_queue_buffer(impl->stream_sink, buf);

    if (written_all != size_all) {
        //pw_log_warn("data_send: send failed sent %ld bytes %d", written_all, size_all);
    } else {
        //pw_log_warn("data_send: send OK n_datas:%d sent %ld bytes %d", buf->buffer->n_datas, written_all, size_all);
    }
}

static void capture_stream_process(void *data)
{
	struct impl *impl = data;
	struct pw_buffer *buf;
	struct spa_data *d;
	uint32_t req;
	ssize_t nread = 0;

	if ((buf = pw_stream_dequeue_buffer(impl->stream_source)) == NULL) {
		pw_log_debug("out of buffers: %m");
		return;
	}

	d = &buf->buffer->datas[0];

	if ((req = buf->requested * impl->frame_size) == 0)
		req = 4096 * impl->frame_size;

	req = SPA_MIN(req, d->maxsize);

	d->chunk->offset = 0;
	d->chunk->stride = impl->frame_size;
	d->chunk->size = SPA_MIN(req, impl->leftover_count);
	memcpy(d->data, impl->leftover, d->chunk->size);
	req -= d->chunk->size;

	uint32_t bytes = 0;
    unsigned char ubuf[10];

	if (impl->fd_source == -1) {
	    if ((impl->fd_source = conect_xrdp_socket(impl, impl->filename_source)) == -1)
	        goto nodata;
	}

	if (!impl->want_src_data) {
		char start_rec[] = { 0, 0, 0, 0, 11, 0, 0, 0, PA_CMD_START_REC, 0, 0 };

		if (lsend(impl->fd_source, start_rec, 11) != 11) {
			close(impl->fd_source);
			impl->fd_source = -1;
			goto nodata;
		}
		impl->want_src_data = 1;
		pw_log_debug("###### started recording");
	}

	/* ask for more data */
	char send_data[] = { 0, 0, 0, 0, 11, 0, 0, 0, PA_CMD_SEND_DATA, (unsigned char) req, (unsigned char) ((req >> 8) & 0xff) };

	if (lsend(impl->fd_source, send_data, 11) != 11) {
		close(impl->fd_source);
		impl->fd_source = -1;
		impl->want_src_data = 0;
		goto nodata;
	}

	/* read length of data available */
	if (lrecv(impl->fd_source, (char *) ubuf, 2) != 2) {
		close(impl->fd_source);
		impl->fd_source = -1;
		impl->want_src_data = 0;
		goto nodata;
	}
	bytes = ((ubuf[1] << 8) & 0xff00) | (ubuf[0] & 0xff);

	if (bytes == 0)
		goto nodata;

	/* get data */
	nread = lrecv(impl->fd_source, SPA_PTROFF(d->data, d->chunk->size, void), /*req*/bytes);
	if (nread < 0) {
		close(impl->fd_source);
		impl->fd_source = -1;
		impl->want_src_data = 0;
		pw_log_warn("failed to read from pipe (%s): %s",
					impl->filename_source, strerror(errno));
	} else {
		d->chunk->size += nread;
	}
nodata:
    //pw_log_debug("nread:%ld. req:%d. %s", nread, req, req == bytes ? "":"req != bytes");

	impl->leftover_count = d->chunk->size % impl->frame_size;
	d->chunk->size -= impl->leftover_count;
	memcpy(impl->leftover, SPA_PTROFF(d->data, d->chunk->size, void), impl->leftover_count);

	pw_stream_queue_buffer(impl->stream_source, buf);
}

static const struct pw_stream_events playback_stream_events = {
	PW_VERSION_STREAM_EVENTS,
	.destroy = stream_destroy_sink,
	.state_changed = stream_state_changed_sink,
	.process = playback_stream_process
};

static const struct pw_stream_events capture_stream_events = {
	PW_VERSION_STREAM_EVENTS,
	.destroy = stream_destroy_source,
	.state_changed = stream_state_changed_source,
	.process = capture_stream_process
};

static int create_stream(struct impl *impl)
{
	int res;
	uint32_t n_params;
	const struct spa_pod *params[1];
	uint8_t buffer[1024];
	struct spa_pod_builder b;

	// sink
	if (impl->mode & MODE_XRDP_SINK) {
		impl->stream_sink = pw_stream_new(impl->core, "xrdp-sink", impl->stream_props_sink);
		impl->stream_props_sink = NULL;

		if (impl->stream_sink == NULL)
			return -errno;

		pw_stream_add_listener(impl->stream_sink,
				&impl->stream_listener_sink,
				&playback_stream_events, impl);
	}

	//source
	if (impl->mode & MODE_XRDP_SOURCE) {
		impl->stream_source = pw_stream_new(impl->core, "xrdp-source", impl->stream_props_source);
		impl->stream_props_source = NULL;

		if (impl->stream_source == NULL)
			return -errno;

		pw_stream_add_listener(impl->stream_source,
				&impl->stream_listener_source,
				&capture_stream_events, impl);
	}

	n_params = 0;
	spa_pod_builder_init(&b, buffer, sizeof(buffer));
	params[n_params++] = spa_format_audio_raw_build(&b,
		SPA_PARAM_EnumFormat, &impl->info);

	if (impl->mode & MODE_XRDP_SINK) {
		if ((res = pw_stream_connect(impl->stream_sink,
				PW_DIRECTION_INPUT,
				PW_ID_ANY,
				PW_STREAM_FLAG_AUTOCONNECT |
				PW_STREAM_FLAG_MAP_BUFFERS |
				PW_STREAM_FLAG_RT_PROCESS,
				params, n_params)) < 0)
			return res;
	}

	if (impl->mode & MODE_XRDP_SOURCE) {
		if ((res = pw_stream_connect(impl->stream_source,
				PW_DIRECTION_OUTPUT,
				PW_ID_ANY,
				PW_STREAM_FLAG_AUTOCONNECT |
				PW_STREAM_FLAG_MAP_BUFFERS |
				PW_STREAM_FLAG_RT_PROCESS,
				params, n_params)) < 0)
			return res;
	}

	return 0;
}

static void core_error(void *data, uint32_t id, int seq, int res, const char *message)
{
	struct impl *impl = data;

	pw_log_error("error id:%u seq:%d res:%d (%s): %s",
			id, seq, res, spa_strerror(res), message);

	if (id == PW_ID_CORE && res == -EPIPE)
		//pw_impl_module_schedule_destroy(impl->module);
		unload_module(impl);
}

static const struct pw_core_events core_events = {
	PW_VERSION_CORE_EVENTS,
	.error = core_error,
};

static void core_destroy(void *d)
{
	struct impl *impl = d;
	spa_hook_remove(&impl->core_listener);
	impl->core = NULL;
	//pw_impl_module_schedule_destroy(impl->module);
	unload_module(impl);
}

static const struct pw_proxy_events core_proxy_events = {
	.destroy = core_destroy,
};

static void impl_destroy(struct impl *impl)
{
    close_send_sink(impl);
    close_send_source(impl);

	if (impl->stream_sink)
		pw_stream_destroy(impl->stream_sink);
	if (impl->core && impl->do_disconnect)
		pw_core_disconnect(impl->core);

	if (impl->filename_sink) {
		free(impl->filename_sink);
		impl->filename_sink = NULL;
	}
	if (impl->fd_sink >= 0)
		close(impl->fd_sink);

	pw_properties_free(impl->stream_props_sink);
	pw_properties_free(impl->props_sink);

	if (impl->stream_source)
		pw_stream_destroy(impl->stream_source);

	if (impl->filename_source) {
		free(impl->filename_source);
		impl->filename_source = NULL;
	}
	if (impl->fd_source >= 0)
		close(impl->fd_source);

	pw_properties_free(impl->stream_props_source);
	pw_properties_free(impl->props_source);

	free(impl->leftover);
	free(impl);
}

static void module_destroy(void *data)
{
	struct impl *impl = data;
	spa_hook_remove(&impl->module_listener);
	impl_destroy(impl);
}

static const struct pw_impl_module_events module_events = {
	PW_VERSION_IMPL_MODULE_EVENTS,
	.destroy = module_destroy,
};

static uint32_t channel_from_name(const char *name)
{
	int i;
	for (i = 0; spa_type_audio_channel[i].name; i++) {
		if (spa_streq(name, spa_debug_type_short_name(spa_type_audio_channel[i].name)))
			return spa_type_audio_channel[i].type;
	}
	return SPA_AUDIO_CHANNEL_UNKNOWN;
}

static void parse_position(struct spa_audio_info_raw *info, const char *val, size_t len)
{
	struct spa_json it[2];
	char v[256];

	spa_json_init(&it[0], val, len);
        if (spa_json_enter_array(&it[0], &it[1]) <= 0)
                spa_json_init(&it[1], val, len);

	info->channels = 0;
	while (spa_json_get_string(&it[1], v, sizeof(v)) > 0 &&
	    info->channels < SPA_AUDIO_MAX_CHANNELS) {
		info->position[info->channels++] = channel_from_name(v);
	}
}

static inline uint32_t format_from_name(const char *name, size_t len)
{
	int i;
	for (i = 0; spa_type_audio_format[i].name; i++) {
		if (strncmp(name, spa_debug_type_short_name(spa_type_audio_format[i].name), len) == 0)
			return spa_type_audio_format[i].type;
	}
	return SPA_AUDIO_FORMAT_UNKNOWN;
}

static void parse_audio_info(const struct pw_properties *props, struct spa_audio_info_raw *info)
{
	const char *str;

	spa_zero(*info);
	if ((str = pw_properties_get(props, PW_KEY_AUDIO_FORMAT)) == NULL)
		str = DEFAULT_FORMAT;
	info->format = format_from_name(str, strlen(str));

	info->rate = pw_properties_get_uint32(props, PW_KEY_AUDIO_RATE, info->rate);
	if (info->rate == 0)
		info->rate = DEFAULT_RATE;

	info->channels = pw_properties_get_uint32(props, PW_KEY_AUDIO_CHANNELS, info->channels);
	info->channels = SPA_MIN(info->channels, SPA_AUDIO_MAX_CHANNELS);
	if ((str = pw_properties_get(props, SPA_KEY_AUDIO_POSITION)) != NULL)
		parse_position(info, str, strlen(str));
	if (info->channels == 0)
		parse_position(info, DEFAULT_POSITION, strlen(DEFAULT_POSITION));
}

static int calc_frame_size(const struct spa_audio_info_raw *info)
{
	int res = info->channels;
	switch (info->format) {
	case SPA_AUDIO_FORMAT_U8:
	case SPA_AUDIO_FORMAT_S8:
	case SPA_AUDIO_FORMAT_ALAW:
	case SPA_AUDIO_FORMAT_ULAW:
		return res;
	case SPA_AUDIO_FORMAT_S16:
	case SPA_AUDIO_FORMAT_S16_OE:
	case SPA_AUDIO_FORMAT_U16:
		return res * 2;
	case SPA_AUDIO_FORMAT_S24:
	case SPA_AUDIO_FORMAT_S24_OE:
	case SPA_AUDIO_FORMAT_U24:
		return res * 3;
	case SPA_AUDIO_FORMAT_S24_32:
	case SPA_AUDIO_FORMAT_S24_32_OE:
	case SPA_AUDIO_FORMAT_S32:
	case SPA_AUDIO_FORMAT_S32_OE:
	case SPA_AUDIO_FORMAT_U32:
	case SPA_AUDIO_FORMAT_U32_OE:
	case SPA_AUDIO_FORMAT_F32:
	case SPA_AUDIO_FORMAT_F32_OE:
		return res * 4;
	case SPA_AUDIO_FORMAT_F64:
	case SPA_AUDIO_FORMAT_F64_OE:
		return res * 8;
	default:
		return 0;
	}
}

static void copy_props(struct pw_properties *stream_props, struct pw_properties *props, const char *key)
{
	const char *str;
	if ((str = pw_properties_get(props, key)) != NULL) {
		if (pw_properties_get(stream_props, key) == NULL)
			pw_properties_set(stream_props, key, str);
	}
}

SPA_EXPORT
int pipewire__module_init(struct pw_impl_module *module, const char *args)
{
	struct pw_context *context = pw_impl_module_get_context(module);
	struct pw_properties *props = NULL;
	struct impl *impl;
	const char *str;
	int res;

	PW_LOG_TOPIC_INIT(mod_topic);

	impl = calloc(1, sizeof(struct impl));
	if (impl == NULL)
		return -errno;

	impl->fd_sink = -1;
	impl->fd_source = -1;
	impl->filename_sink = NULL;
	impl->filename_source = NULL;

	impl->module = module;
	impl->context = context;
	impl->work = pw_context_get_work_queue(context);

	pw_log_debug("module %p: new %s", impl, args);

	if (args == NULL)
		args = "";

	props = pw_properties_new_string(args);
	if (props == NULL) {
		res = -errno;
		pw_log_error( "can't create properties: %m");
		goto error;
	}
	impl->props_sink = props;

	impl->stream_props_sink = pw_properties_new(NULL, NULL);
	if (impl->stream_props_sink == NULL) {
		res = -errno;
		pw_log_error( "can't create properties: %m");
		goto error;
	}

	// sink
	if (pw_properties_get(props, PW_KEY_NODE_VIRTUAL) == NULL)
		pw_properties_set(props, PW_KEY_NODE_VIRTUAL, "true");
	if (pw_properties_get(props, PW_KEY_NODE_NETWORK) == NULL)
		pw_properties_set(props, PW_KEY_NODE_NETWORK, "true");
	if (pw_properties_get(props, PW_KEY_MEDIA_CLASS) == NULL)
		pw_properties_set(props, PW_KEY_MEDIA_CLASS, "Audio/Sink");

	if ((str = pw_properties_get(props, "sink.stream.props")) != NULL) {
		impl->mode |= MODE_XRDP_SINK;
		pw_properties_update_string(impl->stream_props_sink, str, strlen(str));
	}

	copy_props(impl->stream_props_sink, props, PW_KEY_AUDIO_FORMAT);
	copy_props(impl->stream_props_sink, props, PW_KEY_AUDIO_RATE);
	copy_props(impl->stream_props_sink, props, PW_KEY_AUDIO_CHANNELS);
	copy_props(impl->stream_props_sink, props, SPA_KEY_AUDIO_POSITION);
	copy_props(impl->stream_props_sink, props, PW_KEY_NODE_NAME);
	copy_props(impl->stream_props_sink, props, PW_KEY_NODE_DESCRIPTION);
	copy_props(impl->stream_props_sink, props, PW_KEY_NODE_GROUP);
//	copy_props(impl->stream_props_sink, props, PW_KEY_NODE_LATENCY);
	copy_props(impl->stream_props_sink, props, PW_KEY_NODE_VIRTUAL);
	copy_props(impl->stream_props_sink, props, PW_KEY_NODE_NETWORK);
	copy_props(impl->stream_props_sink, props, PW_KEY_MEDIA_CLASS);

	parse_audio_info(impl->stream_props_sink, &impl->info);

	if (impl->info.rate != 0 &&
	    pw_properties_get(props, PW_KEY_NODE_RATE) == NULL)
		pw_properties_setf(props, PW_KEY_NODE_RATE,
				"1/%u", impl->info.rate);

	copy_props(impl->stream_props_sink, props, PW_KEY_NODE_RATE);

	if ((str = pw_properties_get(props, "sink.node.latency")) != NULL)
		pw_properties_setf(props, PW_KEY_NODE_LATENCY,	"%s/%u", str, impl->info.rate);
	copy_props(impl->stream_props_sink, props, PW_KEY_NODE_LATENCY);

	// source
	props = pw_properties_new_string(args);
	if (props == NULL) {
		res = -errno;
		pw_log_error( "can't create properties: %m");
		goto error;
	}
	impl->props_source = props;

	impl->stream_props_source = pw_properties_new(NULL, NULL);
	if (impl->stream_props_source == NULL) {
		res = -errno;
		pw_log_error( "can't create properties: %m");
		goto error;
	}

	if (pw_properties_get(props, PW_KEY_NODE_VIRTUAL) == NULL)
		pw_properties_set(props, PW_KEY_NODE_VIRTUAL, "true");
	if (pw_properties_get(props, PW_KEY_NODE_NETWORK) == NULL)
		pw_properties_set(props, PW_KEY_NODE_NETWORK, "true");
	if (pw_properties_get(props, PW_KEY_MEDIA_CLASS) == NULL)
		pw_properties_set(props, PW_KEY_MEDIA_CLASS, "Audio/Source");

	if ((str = pw_properties_get(props, "source.stream.props")) != NULL) {
		impl->mode |= MODE_XRDP_SOURCE;
		pw_properties_update_string(impl->stream_props_source, str, strlen(str));
	}

	copy_props(impl->stream_props_source, props, PW_KEY_AUDIO_FORMAT);
	copy_props(impl->stream_props_source, props, PW_KEY_AUDIO_RATE);
	copy_props(impl->stream_props_source, props, PW_KEY_AUDIO_CHANNELS);
	copy_props(impl->stream_props_source, props, SPA_KEY_AUDIO_POSITION);
	copy_props(impl->stream_props_source, props, PW_KEY_NODE_NAME);
	copy_props(impl->stream_props_source, props, PW_KEY_NODE_DESCRIPTION);
	copy_props(impl->stream_props_source, props, PW_KEY_NODE_GROUP);
	copy_props(impl->stream_props_source, props, PW_KEY_NODE_LATENCY);
	copy_props(impl->stream_props_source, props, PW_KEY_NODE_VIRTUAL);
	copy_props(impl->stream_props_source, props, PW_KEY_NODE_NETWORK);
	copy_props(impl->stream_props_source, props, PW_KEY_MEDIA_CLASS);

	parse_audio_info(impl->stream_props_source, &impl->info);

	impl->frame_size = calc_frame_size(&impl->info);
	if (impl->frame_size == 0) {
		pw_log_error("unsupported audio format:%d channels:%d",
				impl->info.format, impl->info.channels);
		res = -EINVAL;
		goto error;
	}
	if (impl->info.rate != 0 &&
	    pw_properties_get(props, PW_KEY_NODE_RATE) == NULL)
		pw_properties_setf(props, PW_KEY_NODE_RATE,
				"1/%u", impl->info.rate);

	copy_props(impl->stream_props_source, props, PW_KEY_NODE_RATE);

	impl->leftover = calloc(1, impl->frame_size);
	if (impl->leftover == NULL) {
		res = -errno;
		pw_log_error("can't alloc leftover buffer: %m");
		goto error;
	}

	if (!impl->mode) {
		res = -EINVAL;
		goto error;
	}

	impl->core = pw_context_get_object(impl->context, PW_TYPE_INTERFACE_Core);
	if (impl->core == NULL) {
		str = pw_properties_get(props, PW_KEY_REMOTE_NAME);
		impl->core = pw_context_connect(impl->context,
				pw_properties_new(
					PW_KEY_REMOTE_NAME, str,
					NULL),
				0);
		impl->do_disconnect = true;
	}
	if (impl->core == NULL) {
		res = -errno;
		pw_log_error("can't connect: %m");
		goto error;
	}

	pw_proxy_add_listener((struct pw_proxy*)impl->core,
			&impl->core_proxy_listener,
			&core_proxy_events, impl);
	pw_core_add_listener(impl->core,
			&impl->core_listener,
			&core_events, impl);

	set_socket_path(impl);

  	if ((res = create_stream(impl)) < 0)
		goto error;

	pw_impl_module_add_listener(module, &impl->module_listener, &module_events, impl);

	pw_impl_module_update_properties(module, &SPA_DICT_INIT_ARRAY(module_props));

	return 0;

error:
	impl_destroy(impl);
	return res;
}
