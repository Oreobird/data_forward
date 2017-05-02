/********************************************************
*
* FILE NAME  :   dac_forward.h
* VERSION    :   1.0
* DESCRIPTION:   door access control module
*
* AUTHOR     :   zhongguanshi <zhongguanshi@evergrande.cn>
* CREATE DATE:   05/04/2017
*
*********************************************************/


#ifndef _DAC_FORWARD_H
#define _DAC_FORWARD_H

struct target_dev {
    unsigned char mac_addr[6];
    __be32 ip_addr;
};

#define CTL_PORT 20200
#define VIDEO_PORT 20000
#define AUDIO_PORT 15004
#define ALARM_SEND_PORT 20300
#define ALARM_RCV_PORT 20302
#define NETLINK_DAC 25


#endif
