
	/* $Id: mca_net.c,v 1.20 2008/06/02 15:21:27 anight Exp $ */
	/* (c) Andrei Nigmatulin, 2007 */

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>

#include <mca.h>
#include <mca_private.h>

static int socket_set_blocked(int fd, int blocked)
{
	int flags = fcntl(fd, F_GETFL);

	if (flags < 0) return -1;

	if (blocked) {
		flags &= ~O_NONBLOCK;
	}
	else {
		flags |= O_NONBLOCK;
	}

	return fcntl(fd, F_SETFL, flags);
}

static int socket_get_last_error(int s)
{
	int e = 0;
	socklen_t l = sizeof(e);
	getsockopt(s, SOL_SOCKET, SO_ERROR, &e, &l);
	return e;
}

static int _mca_connect(mca *m, struct sockaddr *sa, socklen_t sa_len)
{
	int c;

	m->sock = socket(sa->sa_family, SOCK_STREAM, 0);

	if (m->sock < 0) {
		return MCA_ERROR;
	}

	if (0 > socket_set_blocked(m->sock, 0)) {
		return MCA_ERROR;
	}

	c = connect(m->sock, sa, sa_len);

	if (c == 0) {
		m->state = MCA_STATE_READING_HANDSHAKE;
		return MCA_OK;
	}

	if (c == -1 && errno == EINPROGRESS) {
		m->state = MCA_STATE_CONNECTING;
		return MCA_OK;
	}

	return MCA_ERROR;
}

int mca_connect_unix(mca *m, char *unix_socket)
{
	struct sockaddr_un sa_un;

	memset(&sa_un, 0, sizeof(sa_un));

	strncpy(sa_un.sun_path, unix_socket, sizeof(sa_un.sun_path) - 1);
	sa_un.sun_family = AF_UNIX;
	sa_un.sun_path[sizeof(sa_un.sun_path) - 1] = '\0';

	return _mca_connect(m, (struct sockaddr *) &sa_un, sizeof(struct sockaddr_un));
}

int mca_connect_inet(mca *m, char *host, int port)
{
	struct sockaddr_in sa_in;

	memset(&sa_in, 0, sizeof(sa_in));

	sa_in.sin_addr.s_addr = inet_addr(host);

	if (sa_in.sin_addr.s_addr == INADDR_NONE) {
		mca_set_error(m, 0, "No resolve support yet, sorry");
		return MCA_ERROR_USER;
	}

	sa_in.sin_family = AF_INET;
	sa_in.sin_port = port ? htons(port) : MYSQL_DEFAULT_PORT;

	return _mca_connect(m, (struct sockaddr *) &sa_in, sizeof(struct sockaddr_in));
}

static int mca_read(int s, char *buf, size_t *offset, size_t len)
{
	int c = 0;

	len -= *offset;
	buf += *offset;

	while (len > 0) {
		c = recv(s, buf, len, 0);

		if (c == -1 && errno == EINTR) {
			continue;
		}

		if (c > 0) {
			buf += c;
			len -= c;
			*offset += c;
			continue;
		}

		break;
	}

	return c;
}

static int mca_write(int s, char *buf, size_t *offset, size_t len)
{
	int c = 0;

	len -= *offset;
	buf += *offset;

	while (len > 0) {
		c = send(s, buf, len, 0);

		if (c == -1 && errno == EINTR) {
			continue;
		}

		if (c > 0) {
			buf += c;
			len -= c;
			*offset += c;
			continue;
		}

		break;
	}

	return c;
}

void mca_packet_read_reset(mca *m)
{
	memset(m->read_hdr_buf, 0, NET_HEADER_SIZE);

	m->read_hdr_off = 0;

	m->read_packet_buf = 0;
	m->read_packet_off = 0;
	m->read_packet_len = 0;
}

int mca_packet_write_alloc(mca *m, size_t s)
{
	m->write_packet_off = 0;
	m->write_packet_len = 0;

	m->write_packet_buf = mca_alloc_buf(m, NET_HEADER_SIZE + s);

	if (!m->write_packet_buf) {
		mca_set_error(m, 0, "Out of memory");
		return MCA_ERROR;
	}

	return MCA_OK;
}

int mca_packet_read(mca *m)
{
	int c;

	if (m->read_hdr_off < NET_HEADER_SIZE) {

		c = mca_read(m->sock, m->read_hdr_buf, &m->read_hdr_off, NET_HEADER_SIZE);

		if (c == -1 && errno != EAGAIN) {
			mca_set_error(m, 1, "mca_packet_read(): hdr read error");
			return MCA_ERROR;
		}

		if (c == 0) {
			mca_set_error(m, 0, "mca_packet_read(): connection closed while reading header");
			return MCA_ERROR;
		}

		if (m->read_hdr_off == NET_HEADER_SIZE) {
			m->read_packet_len = ((unsigned char *) m->read_hdr_buf)[0] |
						((unsigned char *) m->read_hdr_buf)[1] << 8 |
						((unsigned char *) m->read_hdr_buf)[2] << 16;

			if ((unsigned char) m->read_hdr_buf[3] != m->packet_id) {
				mca_set_error(m, 0, "mca_packet_read(): packet out of order: %d (expected %d)",
						(unsigned char) m->read_hdr_buf[3], m->packet_id);
				return MCA_ERROR;
			}

			m->read_packet_buf = mca_alloc_buf(m, NET_HEADER_SIZE + m->read_packet_len + 1);

			if (!m->read_packet_buf) {
				mca_set_error(m, 0, "Out of memory");
				return MCA_ERROR;
			}

			++m->packet_id;

			memcpy(m->read_packet_buf, m->read_hdr_buf, NET_HEADER_SIZE);
		}
		else {
			return MCA_EAGAIN;
		}
	}

	if (m->read_packet_len) {

		c = mca_read(m->sock, NET_HEADER_SIZE + m->read_packet_buf, &m->read_packet_off, m->read_packet_len);

		if (c == -1 && errno != EAGAIN) {
			mca_set_error(m, 1, "mca_packet_read(): packet read_error");
			return MCA_ERROR;
		}

		if (c == 0) {
			mca_set_error(m, 0, "mca_packet_read(): connection closed while reading packet body");
			return MCA_ERROR;
		}

		if (m->read_packet_off < m->read_packet_len) {
			return MCA_EAGAIN;
		}

	}

	m->read_packet_buf[NET_HEADER_SIZE + m->read_packet_len] = '\0';

	return MCA_OK;
}

int mca_packet_write(mca *m)
{
	int c;

	c = mca_write(m->sock, m->write_packet_buf, &m->write_packet_off, m->write_packet_len);

	if (c == -1 && errno != EAGAIN) {
		mca_set_error(m, 1, "mca_packet_write(): write error");
		return MCA_ERROR;
	}

	if (c == 0) {
		mca_set_error(m, 0, "mca_packet_write(): connection closed while writing packet");
		return MCA_ERROR;
	}

	if (m->write_packet_off < m->write_packet_len) {
		return MCA_EAGAIN;
	}

	return MCA_OK;
}
