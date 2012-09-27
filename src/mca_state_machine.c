
	/* $Id: mca_state_machine.c,v 1.27 2008/11/05 09:05:01 tony Exp $ */
	/* (c) Andrei Nigmatulin, 2007 */

#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <sys/time.h>
#include <sys/types.h>
#include <event.h>

#include <mca.h>
#include <mca_private.h>


#define debugger() asm("int $3\n")

static void mca_event_handler(int fd, short which, void *arg);

void mca_ev_update(mca *m, int e, struct timeval *tv)
{
	if (m->ev_active) {
		event_del(&m->ev);
	}
	if (e) {
		event_set(&m->ev, m->sock, e, mca_event_handler, m);
		event_add(&m->ev, (tv && tv->tv_sec == 0 && tv->tv_usec == 0) ? 0 : tv);
	}
	m->ev_active = e;
}

static int mca_do_io(mca *m)
{
	switch (m->state) {

		case MCA_STATE_READING_HANDSHAKE :
		case MCA_STATE_READING_AUTH_RESULT :
		case MCA_STATE_READING_RESULT :
		case MCA_STATE_READING_RESULT_FLDESC :
		case MCA_STATE_READING_RESULT_ROWS :

			return mca_packet_read(m);

		case MCA_STATE_WRITING_HANDSHAKE :
		case MCA_STATE_WRITING_QUERY :

			return mca_packet_write(m);

		default : /* should not happen */

			debugger();

			return MCA_ERROR;
	}
}

static void mca_do_cpu(mca *m)
{
	switch (m->state) {

		case MCA_STATE_READING_HANDSHAKE :

			m->state = mca_handshake_process(m);

			break;

		case MCA_STATE_READING_AUTH_RESULT :

			m->state = mca_handshake_process2(m);

			break;

		case MCA_STATE_READING_RESULT :

			m->state = mca_result_process(m);
			if (m->state == MCA_STATE_READING_RESULT_FLDESC) {
				mca_packet_read_reset(m);
			}

			break;

		case MCA_STATE_READING_RESULT_FLDESC :

			m->state = mca_result_process_fldesc(m);
			if (m->state == MCA_STATE_READING_RESULT_FLDESC) {
				mca_packet_read_reset(m);
			}

			break;

		case MCA_STATE_READING_RESULT_ROWS :

			m->state = mca_result_process_row(m);

			break;

		case MCA_STATE_WRITING_HANDSHAKE :

			m->state = MCA_STATE_READING_AUTH_RESULT;
			mca_packet_read_reset(m);

			break;

		case MCA_STATE_WRITING_QUERY :

			m->state = MCA_STATE_READING_RESULT;
			mca_packet_read_reset(m);

			break;

		default : /* should not happen */

			debugger();
	}

}

static void mca_update_event(mca *m)
{

	if (m->is_suspended) {
		return;
	}

	switch (m->state) {

		case MCA_STATE_READING_HANDSHAKE :
		case MCA_STATE_READING_AUTH_RESULT :
		case MCA_STATE_READING_RESULT :
		case MCA_STATE_READING_RESULT_FLDESC :
		case MCA_STATE_READING_RESULT_ROWS :
			mca_ev_update(m, EV_READ | EV_PERSIST, &m->read_timeout);
			break;

		case MCA_STATE_WRITING_HANDSHAKE :
		case MCA_STATE_WRITING_QUERY :
			mca_ev_update(m, EV_WRITE | EV_PERSIST, &m->write_timeout);
			break;

		case MCA_STATE_CONNECTING :
			mca_ev_update(m, EV_WRITE | EV_PERSIST, &m->connect_timeout);
			break;

		default :

			break;
	}

}

void mca_ev_activate(mca *m, int e)
{
	mca_ev_update(m, e | EV_PERSIST, e == EV_READ ? &m->read_timeout : &m->write_timeout);
	event_active(&m->ev, e, 1);
}

static void mca_event_handler(int fd, short which, void *arg)
{
	mca *m = arg;
	int do_exit = 0;

	m->in_handler = 1;

	if (which == EV_TIMEOUT) {

		switch (m->state) {

			case MCA_STATE_CONNECTING :

				mca_set_error(m, 0, "Connection timed out");
				break;

			default:

				mca_set_error(m, 0, "I/o timeout");
				break;

		}

		m->state = MCA_STATE_ERROR;

	}

	while (!do_exit) {

		switch (m->state) {

			case MCA_STATE_NONE :

				do_exit = 1;
				break;

			case MCA_STATE_ERROR :

				mca_cb(m, ERROR);
				if (m->state == MCA_STATE_ERROR) {
					mca_ev_update(m, 0, 0);
					do_exit = 1;
				}
				break;

			case MCA_STATE_READY :

				m->packet_id = 0;
				mca_cb(m, READY);
				if (m->state == MCA_STATE_READY) {
					mca_ev_update(m, 0, 0);
					do_exit = 1;
				}
				break;

			case MCA_STATE_READY_FLDESC :

				mca_cb(m, READY_FLDESC);
				if (m->state == MCA_STATE_READY_FLDESC) {
					if (m->is_suspended) {
						do_exit = 1;
						break;
					}
				}
				else {
					break;
				}
				mca_packet_read_reset(m);
				m->state = MCA_STATE_READING_RESULT_ROWS;
				break;

			case MCA_STATE_READY_ROW :

				mca_cb(m, READY_ROW);
				if (m->state == MCA_STATE_READY_ROW) {
					if (m->is_suspended) {
						do_exit = 1;
						break;
					}
				}
				else {
					m->row_parsed = 0;
					break;
				}
				m->row_parsed = 0;
				mca_packet_read_reset(m);
				m->state = MCA_STATE_READING_RESULT_ROWS;
				break;

			case MCA_STATE_CONNECTING :

				if (which == EV_WRITE) {
					mca_packet_read_reset(m);
					m->state = MCA_STATE_READING_HANDSHAKE;
				}
				else {
					do_exit = 1;
				}
				break;

			case MCA_STATE_CLOSING :

				mca_close(m);
				do_exit = 1;
				break;

			case MCA_STATE_READING_HANDSHAKE :
			case MCA_STATE_WRITING_HANDSHAKE :
			case MCA_STATE_READING_AUTH_RESULT :
			case MCA_STATE_WRITING_QUERY :
			case MCA_STATE_READING_RESULT :
			case MCA_STATE_READING_RESULT_FLDESC :
			case MCA_STATE_READING_RESULT_ROWS :

				switch (mca_do_io(m)) {

					case MCA_OK :

						mca_do_cpu(m);

						break;

					case MCA_EAGAIN :

						do_exit = 1;
						break;

					case MCA_ERROR :

						m->state = MCA_STATE_ERROR;
						break;
				}
				break;

			default : /* should not happen */

				debugger();
		}

	}

	if (m->state == MCA_STATE_CLOSING) {
		mca_free(m);
		return;
	}

	mca_update_event(m);

	m->in_handler = 0;
}

