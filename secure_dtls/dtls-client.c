
#include <contiki.h>
#include <contiki-net.h>
#include <contiki-lib.h>
#include <net/dtls/dtls.h>
#include <string.h>
#include "lib/mmem.h"
#define SEND_INTERVAL 1 * CLOCK_CONF_SECOND
#define CLOSE_INTERVAL 120 * CLOCK_CONF_SECOND

PROCESS(dtls_client_test_process, "DTLS client");
AUTOSTART_PROCESSES(&dtls_client_test_process);
static Connection* connection;
static struct etimer et;
static struct etimer et2;
static char* hello_msg = "Hello World";
static uip_ipaddr_t ipaddr;
static void dtls_handler(process_event_t ev, process_data_t data){
	if (ev == dtls_event){
		if (dtls_rehandshake()){
			etimer_stop(&et);
		} else
		if (dtls_connected()){
			connection = (Connection*)data;
			etimer_set(&et, SEND_INTERVAL);
			DTLS_Write(connection, hello_msg, 11);
		} else if (dtls_newdata()){
			dtls_appdata[dtls_applen] = 0;
		}
	} else if (ev == PROCESS_EVENT_TIMER){
		if (etimer_expired(&et)){
			DTLS_Write(connection, hello_msg, 11);
			etimer_reset(&et);
		}
		if (etimer_expired(&et2)){
			DTLS_Close(connection);
			etimer_stop(&et);
			etimer_stop(&et2);
		}
	}


}
static void set_connection_address(uip_ipaddr_t *ipaddr)
{
	// use uip_ip6addr to set the address of the server to connect to
}

PROCESS_THREAD(dtls_client_test_process, ev, data)
{
  PROCESS_BEGIN();
	
	set_connection_address(&ipaddr);
	etimer_set(&et, CLOCK_CONF_SECOND*10);
  	PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_TIMER);
  	etimer_set(&et2, CLOSE_INTERVAL);
	DTLS_Connect(&ipaddr, 4433);
	while(1){
		PROCESS_YIELD();
		dtls_handler(ev, data);
	}
  PROCESS_END();
}
