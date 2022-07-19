/*
* uart_pads.c- Sigmastar
*
* Copyright (C) 2018 Sigmastar Technology Corp.
*
* Author: richard.guo <richard.guo@sigmastar.com.tw>
*
* This software is licensed under the terms of the GNU General Public
* License version 2, as published by the Free Software Foundation, and
* may be copied, distributed, and modified under those terms.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
*/

#include <linux/serial.h>

#include "ms_uart.h"
#include "gpio.h"

int ms_uart_get_padmux(int tx_pad, u8 *padmux, u8 *pad_mode)
{
    int ret = 0;

    switch(tx_pad)
    {
        case PAD_FUART_CTS:
            *padmux=MUX_FUART;
            *pad_mode=0x1;
            break;

        case PAD_FUART_RX:
            *padmux=MUX_FUART;
            *pad_mode=0x2;
            break;

        case PAD_TTL1:
            *padmux=MUX_FUART;
            *pad_mode=0x3;
            break;

        case PAD_TTL21:
            *padmux=MUX_FUART;
            *pad_mode=0x4;
            break;

        case PAD_GPIO1:
            *padmux=MUX_FUART;
            *pad_mode=0x5;
            break;

        case PAD_GPIO5:
            *padmux=MUX_FUART;
            *pad_mode=0x6;
            break;

        case PAD_SD_D0:
            *padmux=MUX_FUART;
            *pad_mode=0x7;
            break;

        case PAD_UART0_TX:
            *padmux=MUX_UART0;
            *pad_mode=0x1;
            break;

        case PAD_FUART_RTS:
            *padmux=MUX_UART0;
            *pad_mode=0x2;
            break;

        case PAD_TTL13:
            *padmux=MUX_UART0;
            *pad_mode=0x3;
            break;

        case PAD_GPIO9:
            *padmux=MUX_UART0;
            *pad_mode=0x4;
            break;

        case PAD_UART1_TX:
            *padmux=MUX_UART1;
            *pad_mode=0x1;
            break;

        case PAD_TTL15:
            *padmux=MUX_UART1;
            *pad_mode=0x2;
            break;

        case PAD_GPIO14:
            *padmux=MUX_UART1;
            *pad_mode=0x3;
            break;

        case PAD_GPIO11:
            *padmux=MUX_UART1;
            *pad_mode=0x4;
            break;

        case PAD_FUART_TX:
            *padmux=MUX_UART2;
            *pad_mode=0x1;
            break;

        case PAD_GPIO8:
            *padmux=MUX_UART2;
            *pad_mode=0x2;
            break;

        case PAD_VSYNC_OUT:
            *padmux=MUX_UART2;
            *pad_mode=0x3;
            break;

        case PAD_SD_D2:
            *padmux=MUX_UART2;
            *pad_mode=0x4;
            break;

        default:
            ret = -1;
            break;
    }

    return ret;
}