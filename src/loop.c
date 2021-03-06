/*
Copyright (c) 2009-2018 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.
 
The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.
 
Contributors:
   Roger Light - initial implementation and documentation.
   Tatsuzo Osawa - Add epoll.
*/

#define _GNU_SOURCE

#include <config.h>

#include <assert.h>
#ifndef WIN32
#ifdef WITH_EPOLL
#include <sys/epoll.h>
#define MAX_EVENTS 1000
#endif
#include <poll.h>
#include <unistd.h>
#else
#include <process.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#ifndef WIN32
#  include <sys/socket.h>
#endif
#include <time.h>

#ifdef WITH_WEBSOCKETS
#  include <libwebsockets.h>
#endif

#include "mosquitto_broker_internal.h"
#include "memory_mosq.h"
#include "packet_mosq.h"
#include "send_mosq.h"
#include "sys_tree.h"
#include "time_mosq.h"
#include "util_mosq.h"

extern bool flag_reload;
#ifdef WITH_PERSISTENCE
extern bool flag_db_backup;
#endif
extern bool flag_tree_print;
extern int run;

#ifdef WITH_EPOLL
static void loop_handle_reads_writes(struct mosquitto_db *db, mosq_sock_t sock, uint32_t events);
#else
static void loop_handle_reads_writes(struct mosquitto_db *db, struct pollfd *pollfds);
#endif

#ifdef WITH_WEBSOCKETS
static void temp__expire_websockets_clients(struct mosquitto_db *db)
{
	struct mosquitto *context, *ctxt_tmp;
	static time_t last_check = 0;
	time_t now = mosquitto_time();
	char *id;

	if(now - last_check > 60){
		HASH_ITER(hh_id, db->contexts_by_id, context, ctxt_tmp){
			if(context->wsi && context->sock != INVALID_SOCKET){
				if(context->keepalive && now - context->last_msg_in > (time_t)(context->keepalive)*3/2){
					if(db->config->connection_messages == true){
						if(context->id){
							id = context->id;
						}else{
							id = "<unknown>";
						}
						log__printf(NULL, MOSQ_LOG_NOTICE, "Client %s has exceeded timeout, disconnecting.", id);
					}
					/* Client has exceeded keepalive*1.5 */
					do_disconnect(db, context);
				}
			}
		}
		last_check = mosquitto_time();
	}
}
#endif

int mosquitto_main_loop(struct mosquitto_db *db, mosq_sock_t *listensock, int listensock_count, int listener_max)
{
	printf("################: %x\n", db->contexts_by_id);

#ifdef WITH_SYS_TREE
	time_t start_time = mosquitto_time();
#endif
#ifdef WITH_PERSISTENCE
	time_t last_backup = mosquitto_time();
#endif
	time_t now = 0;
	time_t now_time;
	int time_count;
	int fdcount;
	struct mosquitto *context = NULL, *ctxt_tmp =  NULL;
#ifndef WIN32
	sigset_t sigblock, origsig;
#endif
	int i;
#ifdef WITH_EPOLL
	int j;
	struct epoll_event ev, events[MAX_EVENTS];
#else
	struct pollfd *pollfds = NULL;
	int pollfd_index;
	int pollfd_max;
#endif
#ifdef WITH_BRIDGE
	mosq_sock_t bridge_sock;
	int rc;
#endif
#ifdef WITH_CLUSTER
	struct mosquitto__node *node;
	struct mosquitto *node_context;
#endif
	time_t expiration_check_time = 0;
	char *id;

#ifndef WIN32
	sigemptyset(&sigblock);
	sigaddset(&sigblock, SIGINT);
	sigaddset(&sigblock, SIGTERM);
	sigaddset(&sigblock, SIGUSR1);
	sigaddset(&sigblock, SIGUSR2);
	sigaddset(&sigblock, SIGHUP);
#endif

#ifndef WITH_EPOLL
#ifdef WIN32
	pollfd_max = _getmaxstdio();
#else
	pollfd_max = sysconf(_SC_OPEN_MAX);
#endif

	pollfds = mosquitto__malloc(sizeof(struct pollfd)*pollfd_max);
	if(!pollfds){
		log__printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		return MOSQ_ERR_NOMEM;
	}
#endif

	if(db->config->persistent_client_expiration > 0){
		expiration_check_time = time(NULL) + 3600;
	}

#ifdef WITH_EPOLL
	db->epollfd = 0;
	if ((db->epollfd = epoll_create(MAX_EVENTS)) == -1) {
		log__printf(NULL, MOSQ_LOG_ERR, "Error in epoll creating: %s", strerror(errno));
		return MOSQ_ERR_UNKNOWN;
	}
	memset(&ev, 0, sizeof(struct epoll_event));
	memset(&events, 0, sizeof(struct epoll_event)*MAX_EVENTS);
	for(i=0; i<listensock_count; i++){
		ev.data.fd = listensock[i];
		ev.events = EPOLLIN;
		if (epoll_ctl(db->epollfd, EPOLL_CTL_ADD, listensock[i], &ev) == -1) {
			log__printf(NULL, MOSQ_LOG_ERR, "Error in epoll initial registering: %s", strerror(errno));
			(void)close(db->epollfd);
			db->epollfd = 0;
			return MOSQ_ERR_UNKNOWN;
		}
	}
#ifdef WITH_BRIDGE
	HASH_ITER(hh_sock, db->contexts_by_sock, context, ctxt_tmp){
		if(context->bridge){
			ev.data.fd = context->sock;
			ev.events = EPOLLIN;
			context->events = EPOLLIN;
			if (epoll_ctl(db->epollfd, EPOLL_CTL_ADD, context->sock, &ev) == -1) {
				log__printf(NULL, MOSQ_LOG_ERR, "Error in epoll initial registering bridge: %s", strerror(errno));
				(void)close(db->epollfd);
				db->epollfd = 0;
				return MOSQ_ERR_UNKNOWN;
			}
		}
	}
#endif
#endif

#ifdef WITH_CLUSTER
	log__printf(NULL, MOSQ_LOG_INFO, "[CLUSTER] totally %d remote nodes configured:", db->config->node_count);
	for(i=0; i<db->config->node_count; i++){
		node = &db->config->nodes[i];
		if(!node) continue;
		log__printf(NULL, MOSQ_LOG_INFO, "[CLUSTER] Node(%d):%s, ip:%s, port:%d, local_clientid:%s, remote_clientid:%s, remote_username:%s, remote_password:%s, keepalive:%d", 
										i+1, node->name, node->address, node->port,node->local_clientid,node->remote_clientid, node->remote_username, node->remote_password, node->keepalive);
	}

	
#endif

	while(run){
		context__free_disused(db);
#ifdef WITH_SYS_TREE
		if(db->config->sys_interval > 0){
			sys_tree__update(db, db->config->sys_interval, start_time);
		}
#endif

#ifndef WITH_EPOLL
		memset(pollfds, -1, sizeof(struct pollfd)*pollfd_max);

		pollfd_index = 0;
		for(i=0; i<listensock_count; i++){
			pollfds[pollfd_index].fd = listensock[i];
			pollfds[pollfd_index].events = POLLIN;
			pollfds[pollfd_index].revents = 0;
			pollfd_index++;
		}
#endif

#ifdef WITH_CLUSTER
		now = mosquitto_time();

		if(db->cluster_retain_delay > 0){
			mosquitto_handle_retain(db ,now);
		}

		for(i=0; i<db->config->node_count; i++){
			node = &(db->config->nodes[i]);
			if(!node->context)
				node__new(db, node);
		}

		for(i=0; i<db->node_context_count; i++){
			node_context = db->node_contexts[i];
			if(!node_context)
				continue;
			if(node_context->state == mosq_cs_connected && node_context->node->handshaked &&
				node_context->ping_t && now - node_context->ping_t >= (time_t)(node_context->keepalive)*3/2){
			    log__printf(NULL, MOSQ_LOG_ERR, "[HANDSHAKE] Remote node(OS): %s maybe crashed, close node and reconnect later.",
												node_context->node->name);
				node_context->ping_t = 0;
				node_context->node->handshaked = false;
				printf("%d\n", __LINE__);
				do_disconnect(db, node_context);
				continue;
			}
			if(node_context->state == mosq_cs_connected && node_context->node->handshaked && 
				node_context->keepalive && (now >= node_context->next_pingreq)){
				if(send__pingreq(node_context)){
					log__printf(NULL, MOSQ_LOG_ERR, "[HANDSHAKE] Failed in send PINGREQ with node: %s, close node and reconnect later.",
													node_context->node->name);
					printf("%d\n", __LINE__);
					do_disconnect(db, node_context);
				}
				node_context->next_pingreq += node_context->keepalive;
				continue;
			}
			if(now >= node_context->node->attemp_reconnect &&
				!node_context->node->handshaked && node_context->sock == INVALID_SOCKET){
				if(!node__try_connect(db, node_context, now)){
#ifndef WITH_EPOLL
					pollfds[pollfd_index].fd = listensock[i];
					pollfds[pollfd_index].events = POLLIN;
					pollfds[pollfd_index].revents = 0;
					pollfd_index++;
#else
					ev.data.fd = node_context->sock;
					ev.events = EPOLLIN;
					node_context->events = EPOLLIN|EPOLLOUT;
					if(epoll_ctl(db->epollfd, EPOLL_CTL_ADD, node_context->sock, &ev) == -1) {
						log__printf(NULL, MOSQ_LOG_ERR, "Error in epoll initial registering node: %s.", strerror(errno));
					}	
#endif
				}
			}
			if(node_context->sock != INVALID_SOCKET && 
				!node_context->node->handshaked && now >= node_context->node->check_handshake){
				if(!node__check_connect(db, node_context, now)){
#ifndef WITH_EPOLL
					pollfds[pollfd_index].fd = listensock[i];
					pollfds[pollfd_index].events = POLLIN|EPOLLOUT;
					pollfds[pollfd_index].revents = 0;
					pollfd_index++;
#else
					ev.data.fd = node_context->sock;
					ev.events = EPOLLIN;
					node_context->events = EPOLLIN;
					if(epoll_ctl(db->epollfd, EPOLL_CTL_ADD, node_context->sock, &ev) == -1) {
						log__printf(NULL, MOSQ_LOG_ERR, "Error in epoll initial registering node: %s.", strerror(errno));
					}	
#endif
				}else{
					//
				}
				continue;
			}
			
		}
#endif

		now_time = time(NULL);

		time_count = 0;
		HASH_ITER(hh_sock, db->contexts_by_sock, context, ctxt_tmp){
			if(time_count > 0){
				time_count--;
			}else{
				time_count = 1000;
				now = mosquitto_time();
			}
			context->pollfd_index = -1;

			if(context->sock != INVALID_SOCKET){
#ifdef WITH_BRIDGE
				if(context->bridge){
					mosquitto__check_keepalive(db, context);
					if(context->bridge->round_robin == false
							&& context->bridge->cur_address != 0
							&& now > context->bridge->primary_retry){

						if(net__try_connect(context, context->bridge->addresses[0].address, context->bridge->addresses[0].port, &bridge_sock, NULL, false) <= 0){
							COMPAT_CLOSE(bridge_sock);
							net__socket_close(db, context);
							context->bridge->cur_address = context->bridge->address_count-1;
						}
					}
				}
#endif

				/* Local bridges and nodes never time out in this fashion. */
				if(!(context->keepalive)
						|| context->bridge
#ifdef WITH_CLUSTER
						|| context->is_node
#endif
						|| now - context->last_msg_in < (time_t)(context->keepalive)*3/2){

					if(db__message_write(db, context) == MOSQ_ERR_SUCCESS){
#ifdef WITH_EPOLL
						if(context->current_out_packet || context->state == mosq_cs_connect_pending || context->ws_want_write){
							if(!(context->events & EPOLLOUT)) {
								ev.data.fd = context->sock;
								ev.events = EPOLLIN | EPOLLOUT;
								if(epoll_ctl(db->epollfd, EPOLL_CTL_ADD, context->sock, &ev) == -1) {
									if((errno != EEXIST)||(epoll_ctl(db->epollfd, EPOLL_CTL_MOD, context->sock, &ev) == -1)) {
											log__printf(NULL, MOSQ_LOG_DEBUG, "Error in epoll re-registering to EPOLLOUT: %s", strerror(errno));
									}
								}
								context->events = EPOLLIN | EPOLLOUT;
							}
							context->ws_want_write = false;
						}
						else{
							if(context->events & EPOLLOUT) {
								ev.data.fd = context->sock;
								ev.events = EPOLLIN;
								if(epoll_ctl(db->epollfd, EPOLL_CTL_ADD, context->sock, &ev) == -1) {
									if((errno != EEXIST)||(epoll_ctl(db->epollfd, EPOLL_CTL_MOD, context->sock, &ev) == -1)) {
											log__printf(NULL, MOSQ_LOG_DEBUG, "Error in epoll re-registering to EPOLLIN: %s", strerror(errno));
									}
								}
								context->events = EPOLLIN;
							}
						}
#else
						pollfds[pollfd_index].fd = context->sock;
						pollfds[pollfd_index].events = POLLIN;
						pollfds[pollfd_index].revents = 0;
						if(context->current_out_packet || context->state == mosq_cs_connect_pending || context->ws_want_write){
							pollfds[pollfd_index].events |= POLLOUT;
							context->ws_want_write = false;
						}
						context->pollfd_index = pollfd_index;
						pollfd_index++;
#endif
					}else{
						printf("%d\n", __LINE__);
						do_disconnect(db, context);
					}
				}else{
					if(db->config->connection_messages == true){
						if(context->id){
							id = context->id;
						}else{
							id = "<unknown>";
						}
						log__printf(NULL, MOSQ_LOG_NOTICE, "Client %s has exceeded timeout, disconnecting.", id);
					}
					/* Client has exceeded keepalive*1.5 */
					printf("%d\n", __LINE__);
					do_disconnect(db, context);
				}
			}
		}

#ifdef WITH_BRIDGE
		time_count = 0;
		for(i=0; i<db->bridge_count; i++){
			if(!db->bridges[i]) continue;

			context = db->bridges[i];

			if(context->sock == INVALID_SOCKET){
				if(time_count > 0){
					time_count--;
				}else{
					time_count = 1000;
					now = mosquitto_time();
				}
				/* Want to try to restart the bridge connection */
				if(!context->bridge->restart_t){
					context->bridge->restart_t = now+context->bridge->restart_timeout;
					context->bridge->cur_address++;
					if(context->bridge->cur_address == context->bridge->address_count){
						context->bridge->cur_address = 0;
					}
					if(context->bridge->round_robin == false && context->bridge->cur_address != 0){
						context->bridge->primary_retry = now + 5;
					}
				}else{
					if((context->bridge->start_type == bst_lazy && context->bridge->lazy_reconnect)
							|| (context->bridge->start_type == bst_automatic && now > context->bridge->restart_t)){
						context->bridge->restart_t = 0;
#if defined(__GLIBC__) && defined(WITH_ADNS)
						if(context->adns){
							/* Waiting on DNS lookup */
							rc = gai_error(context->adns);
							if(rc == EAI_INPROGRESS){
								/* Just keep on waiting */
							}else if(rc == 0){
								rc = bridge__connect_step2(db, context);
								if(rc == MOSQ_ERR_SUCCESS){
#ifdef WITH_EPOLL
									ev.data.fd = context->sock;
									ev.events = EPOLLIN;
									if(context->current_out_packet){
										ev.events |= EPOLLOUT;
									}
									if(epoll_ctl(db->epollfd, EPOLL_CTL_ADD, context->sock, &ev) == -1) {
										if((errno != EEXIST)||(epoll_ctl(db->epollfd, EPOLL_CTL_MOD, context->sock, &ev) == -1)) {
												log__printf(NULL, MOSQ_LOG_DEBUG, "Error in epoll re-registering bridge: %s", strerror(errno));
										}
									}else{
										context->events = ev.events;
									}
#else
									pollfds[pollfd_index].fd = context->sock;
									pollfds[pollfd_index].events = POLLIN;
									pollfds[pollfd_index].revents = 0;
									if(context->current_out_packet){
										pollfds[pollfd_index].events |= POLLOUT;
									}
									context->pollfd_index = pollfd_index;
									pollfd_index++;
#endif
								}else{
									context->bridge->cur_address++;
									if(context->bridge->cur_address == context->bridge->address_count){
										context->bridge->cur_address = 0;
									}
								}
							}else{
								/* Need to retry */
								if(context->adns->ar_result){
									freeaddrinfo(context->adns->ar_result);
								}
								mosquitto__free(context->adns);
								context->adns = NULL;
							}
						}else{
							rc = bridge__connect_step1(db, context);
							if(rc){
								context->bridge->cur_address++;
								if(context->bridge->cur_address == context->bridge->address_count){
									context->bridge->cur_address = 0;
								}
							}
						}
#else
						{
							rc = bridge__connect(db, context);
							if(rc == MOSQ_ERR_SUCCESS){
#ifdef WITH_EPOLL
								ev.data.fd = context->sock;
								ev.events = EPOLLIN;
								if(context->current_out_packet){
									ev.events |= EPOLLOUT;
								}
								if(epoll_ctl(db->epollfd, EPOLL_CTL_ADD, context->sock, &ev) == -1) {
									if((errno != EEXIST)||(epoll_ctl(db->epollfd, EPOLL_CTL_MOD, context->sock, &ev) == -1)) {
											log__printf(NULL, MOSQ_LOG_DEBUG, "Error in epoll re-registering bridge: %s", strerror(errno));
									}
								}else{
									context->events = ev.events;
								}
#else
								pollfds[pollfd_index].fd = context->sock;
								pollfds[pollfd_index].events = POLLIN;
								pollfds[pollfd_index].revents = 0;
								if(context->current_out_packet){
									pollfds[pollfd_index].events |= POLLOUT;
								}
								context->pollfd_index = pollfd_index;
								pollfd_index++;
#endif
							}else{
								context->bridge->cur_address++;
								if(context->bridge->cur_address == context->bridge->address_count){
									context->bridge->cur_address = 0;
								}
							}
						}
#endif
					}
				}
			}
		}
#endif
		now_time = time(NULL);
		if(db->config->persistent_client_expiration > 0 && now_time > expiration_check_time){
			HASH_ITER(hh_id, db->contexts_by_id, context, ctxt_tmp){
				if(context->sock == INVALID_SOCKET && context->clean_session == 0){
					/* This is a persistent client, check to see if the
					 * last time it connected was longer than
					 * persistent_client_expiration seconds ago. If so,
					 * expire it and clean up.
					 */
					if(now_time > context->disconnect_t+db->config->persistent_client_expiration){
						if(context->id){
							id = context->id;
						}else{
							id = "<unknown>";
						}
						log__printf(NULL, MOSQ_LOG_NOTICE, "Expiring persistent client %s due to timeout.", id);
						G_CLIENTS_EXPIRED_INC();
						context->clean_session = true;
						context->state = mosq_cs_expiring;
						printf("%d\n", __LINE__);
						do_disconnect(db, context);
					}
				}
			}
			expiration_check_time = time(NULL) + 3600;
		}

#ifndef WIN32
		sigprocmask(SIG_SETMASK, &sigblock, &origsig);
#ifdef WITH_EPOLL
		fdcount = epoll_wait(db->epollfd, events, MAX_EVENTS, 100);
#else
		fdcount = poll(pollfds, pollfd_index, 100);
#endif
		sigprocmask(SIG_SETMASK, &origsig, NULL);
#else
		fdcount = WSAPoll(pollfds, pollfd_index, 100);
#endif
#ifdef WITH_EPOLL	
		switch(fdcount){
		case -1:
			if(errno != EINTR){
			log__printf(NULL, MOSQ_LOG_ERR, "Error in epoll waiting: %s.", strerror(errno));
			}
			break;
		case 0:
			break;
		default:
			printf("98765432100000: %d\n", fdcount);
			for(i=0; i<fdcount; i++){
				for(j=0; j<listensock_count; j++){
					if (events[i].data.fd == listensock[j]) {
						if (events[i].events & (EPOLLIN | EPOLLPRI)){
							printf("98765432100000\n");
							while((ev.data.fd = net__socket_accept(db, listensock[j])) != -1){
								ev.events = EPOLLIN;
								if (epoll_ctl(db->epollfd, EPOLL_CTL_ADD, ev.data.fd, &ev) == -1) {
									log__printf(NULL, MOSQ_LOG_ERR, "Error in epoll accepting: %s", strerror(errno));
								}
								context = NULL;
								HASH_FIND(hh_sock, db->contexts_by_sock, &(ev.data.fd), sizeof(mosq_sock_t), context);
								if(!context) {
									log__printf(NULL, MOSQ_LOG_ERR, "Error in epoll accepting: no context");
								}
								context->events = EPOLLIN;
							}
						}
						break;
					}
				}
				if (j == listensock_count) {
					loop_handle_reads_writes(db, events[i].data.fd, events[i].events);
				}
			}
		}
#else

		if(fdcount == -1){
			log__printf(NULL, MOSQ_LOG_ERR, "Error in poll: %s.", strerror(errno));
		}else{
			loop_handle_reads_writes(db, pollfds);

			for(i=0; i<listensock_count; i++){
				if(pollfds[i].revents & (POLLIN | POLLPRI)){
						printf("98765431\n");
					while(net__socket_accept(db, listensock[i]) != -1){
						printf("123456789\n");
					}
				}
			}
		}
#endif
#ifdef WITH_PERSISTENCE
		if(db->config->persistence && db->config->autosave_interval){
			if(db->config->autosave_on_changes){
				if(db->persistence_changes >= db->config->autosave_interval){
					persist__backup(db, false);
					db->persistence_changes = 0;
				}
			}else{
				if(last_backup + db->config->autosave_interval < mosquitto_time()){
					persist__backup(db, false);
					last_backup = mosquitto_time();
				}
			}
		}
#endif

#ifdef WITH_PERSISTENCE
		if(flag_db_backup){
			persist__backup(db, false);
			flag_db_backup = false;
		}
#endif
		if(flag_reload){
			log__printf(NULL, MOSQ_LOG_INFO, "Reloading config.");
			config__read(db->config, true);
			mosquitto_security_cleanup(db, true);
			mosquitto_security_init(db, true);
			mosquitto_security_apply(db);
			log__close(db->config);
			log__init(db->config);
			flag_reload = false;
		}
		if(flag_tree_print){
			sub__tree_print(db->subs, 0);
			flag_tree_print = false;
		}
#ifdef WITH_WEBSOCKETS
		for(i=0; i<db->config->listener_count; i++){
			/* Extremely hacky, should be using the lws provided external poll
			 * interface, but their interface has changed recently and ours
			 * will soon, so for now websockets clients are second class
			 * citizens. */
			if(db->config->listeners[i].ws_context){
				libwebsocket_service(db->config->listeners[i].ws_context, 0);
			}
		}
		if(db->config->have_websockets_listener){
			temp__expire_websockets_clients(db);
		}
#endif
	}

#ifdef WITH_EPOLL
	(void) close(db->epollfd);
	db->epollfd = 0;
#else
	mosquitto__free(pollfds);
#endif
	
	return MOSQ_ERR_SUCCESS;
}

void do_disconnect(struct mosquitto_db *db, struct mosquitto *context)
{
	printf("loop.c start do_disconnect\n");
	char *id;
#ifdef WITH_EPOLL
	struct epoll_event ev;
#endif
	printf("0\n");
	if(context->state == mosq_cs_disconnected){
		return;
	}
	printf("1\n");
#ifdef WITH_CLUSTER
	printf("2\n");
	if(context->is_node)
		node__disconnect(db, context);
	if(!context->is_node && !context->is_peer && !context->save_subs && context->clean_session)
		mosquitto_cluster_client_disconnect(db, context);
	if(context->is_peer)
		sub__clean_session(db, context);
	printf("3\n");
#endif
#ifdef WITH_WEBSOCKETS
	printf("4\n");
	if(context->wsi){
		if(context->state != mosq_cs_disconnecting){
			context->state = mosq_cs_disconnect_ws;
		}
		if(context->wsi){
			libwebsocket_callback_on_writable(context->ws_context, context->wsi);
		}
		if(context->sock != INVALID_SOCKET){
			HASH_DELETE(hh_sock, db->contexts_by_sock, context);
#ifdef WITH_EPOLL
			if (epoll_ctl(db->epollfd, EPOLL_CTL_DEL, context->sock, &ev) == -1) {
				log__printf(NULL, MOSQ_LOG_DEBUG, "Error in epoll disconnecting websockets: %s", strerror(errno));
			}
#endif		
			context->sock = INVALID_SOCKET;
			context->pollfd_index = -1;
		}
	}else;
	printf("5\n");
#endif
	printf("6\n");
	{
		if(db->config->connection_messages == true){
			if(context->id){
				id = context->id;
			}else{
				id = "<unknown>";
			}
			if(context->state != mosq_cs_disconnecting){
				log__printf(NULL, MOSQ_LOG_NOTICE, "Socket error on client %s, disconnecting.", id);
			}else{
				log__printf(NULL, MOSQ_LOG_NOTICE, "Client %s disconnected.", id);
			}
		}
		printf("6.1\n");
#ifdef WITH_EPOLL
		if (context->sock != INVALID_SOCKET && epoll_ctl(db->epollfd, EPOLL_CTL_DEL, context->sock, &ev) == -1) {
			log__printf(NULL, MOSQ_LOG_DEBUG, "Error in epoll disconnecting: %s", strerror(errno));
		}
		printf("6.2\n");
#endif
		context__disconnect(db, context);
		printf("6.3\n");
#ifdef WITH_BRIDGE
		if(context->clean_session && !context->bridge){
#else
		if(context->clean_session){
#endif
			context__add_to_disused(db, context);
			printf("6.3.1\n");
			if(context->id){
				printf("6.3.2: %x, %x\n", db->contexts_by_id, context);
				HASH_DELETE(hh_id, db->contexts_by_id, context);
				printf("6.3.3\n");
				printf("%x\n", context->id);
				mosquitto__free(context->id);
				printf("6.3.4\n");
				context->id = NULL;
				printf("6.3.5\n");
			}
			printf("6.4\n");
		}
		context->state = mosq_cs_disconnected;
		printf("6.5\n");
	}
	printf("7\n");
}


#ifdef WITH_EPOLL
static void loop_handle_reads_writes(struct mosquitto_db *db, mosq_sock_t sock, uint32_t events)
#else
static void loop_handle_reads_writes(struct mosquitto_db *db, struct pollfd *pollfds)
#endif
{
	struct mosquitto *context;
#ifndef WITH_EPOLL
	struct mosquitto *ctxt_tmp;
#endif
	int err;
	socklen_t len;

#ifdef WITH_EPOLL
	int i;
	context = NULL;
	HASH_FIND(hh_sock, db->contexts_by_sock, &sock, sizeof(mosq_sock_t), context);
	if(!context) {
		return;
	}
	for (i=0;i<1;i++) {
#else
	HASH_ITER(hh_sock, db->contexts_by_sock, context, ctxt_tmp){
		if(context->pollfd_index < 0){
			continue;
		}

		assert(pollfds[context->pollfd_index].fd == context->sock);
#endif

#ifdef WITH_WEBSOCKETS
		if(context->wsi){
			struct lws_pollfd wspoll;
#ifdef WITH_EPOLL
			wspoll.fd = context->sock;
			wspoll.events = context->events;
			wspoll.revents = events;
#else
			wspoll.fd = pollfds[context->pollfd_index].fd;
			wspoll.events = pollfds[context->pollfd_index].events;
			wspoll.revents = pollfds[context->pollfd_index].revents;
#endif
			lws_service_fd(lws_get_context(context->wsi), &wspoll);
			continue;
		}
#endif

#ifdef WITH_TLS
#ifdef WITH_EPOLL
		if(events & EPOLLOUT ||
#else
		if(pollfds[context->pollfd_index].revents & POLLOUT ||
#endif
				context->want_write ||
				(context->ssl && context->state == mosq_cs_new)){
#else
#ifdef WITH_EPOLL
		if(events & EPOLLOUT){
#else			
		if(pollfds[context->pollfd_index].revents & POLLOUT){
#endif
#endif
			if(context->state == mosq_cs_connect_pending){
				len = sizeof(int);
				if(!getsockopt(context->sock, SOL_SOCKET, SO_ERROR, (char *)&err, &len)){
					if(err == 0){
						context->state = mosq_cs_new;
					}
				}else{
					do_disconnect(db, context);
					continue;
				}
			}
			if(packet__write(context)){
				do_disconnect(db, context);
				continue;
			}
		}
	}

#ifdef WITH_EPOLL
	context = NULL;
	HASH_FIND(hh_sock, db->contexts_by_sock, &sock, sizeof(mosq_sock_t), context);
	if(!context) {
		return;
	}
	for (i=0;i<1;i++) {
#else
	HASH_ITER(hh_sock, db->contexts_by_sock, context, ctxt_tmp){
		if(context->pollfd_index < 0){
			continue;
		}
#endif
#ifdef WITH_WEBSOCKETS
		if(context->wsi){
			// Websocket are already handled above
			continue;
		}
#endif

#ifdef WITH_TLS
#ifdef WITH_EPOLL
		if(events & EPOLLIN ||
#else
		if(pollfds[context->pollfd_index].revents & POLLIN ||
#endif
				(context->ssl && context->state == mosq_cs_new)){
#else
#ifdef WITH_EPOLL
		if(events & EPOLLIN){
#else
		if(pollfds[context->pollfd_index].revents & POLLIN){
#endif
#endif
			printf("88888888888888\n");
			do{
				if(packet__read(db, context)){
					printf("loop1 packet_read down\n");
					do_disconnect(db, context);
					printf("loop1 do_disconnect down\n");
					continue; 
					//return -1;
				}
			}while(SSL_DATA_PENDING(context));
			printf("88888888######8888888\n");
		}
#ifdef WITH_EPOLL
		if(events & (EPOLLERR | EPOLLHUP)){
#else
		if(context->pollfd_index >= 0 && pollfds[context->pollfd_index].revents & (POLLERR | POLLNVAL | POLLHUP)){
#endif
			do_disconnect(db, context);
			continue;
		}
	}

	return 0;
}



