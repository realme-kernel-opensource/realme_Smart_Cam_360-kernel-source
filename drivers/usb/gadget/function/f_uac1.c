/*
 * f_audio.c -- USB Audio class function driver
  *
 * Copyright (C) 2008 Bryan Wu <cooloney@kernel.org>
 * Copyright (C) 2008 Analog Devices, Inc
 *
 * Enter bugs at http://blackfin.uclinux.org/
 *
 * Licensed under the GPL-2 or later.
 */

#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/atomic.h>

#include "u_uac1.h"

static int generic_set_cmd(struct usb_audio_control *con, u8 cmd, int value);
static int generic_get_cmd(struct usb_audio_control *con, u8 cmd);

#define USB_OUT_IT_ID	1
#define IO_OUT_OT_ID	2
//#define USB_FU_ID	3
#define IO_IN_IT_ID	3
#define USB_IN_OT_ID	4

/*
 * DESCRIPTORS ... most are static, but strings and full
 * configuration descriptors are built on demand.
 */

/*
 * We have three interfaces - one AudioControl and two AudioStreaming
 *
 * The driver implements a simple UAC_1 topology.
 * USB-OUT -> IT_1 -> OT_2 -> ALSA_Capture
 * ALSA_Playback -> IT_3 -> OT_4 -> USB-IN
 */
#define F_AUDIO_AC_INTERFACE		0
/* this two index for interface ,no id */
#define F_AUDIO_AS_OUT_INTERFACE	0
#define F_AUDIO_AS_IN_INTERFACE		1
/* Number of streaming interfaces */
#define F_AUDIO_NUM_INTERFACES		2

/* B.3.1  Standard AC Interface Descriptor */
static struct usb_interface_descriptor ac_interface_desc = {
	.bLength =		USB_DT_INTERFACE_SIZE,
	.bDescriptorType =	USB_DT_INTERFACE,
	.bNumEndpoints =	0,
	.bInterfaceClass =	USB_CLASS_AUDIO,
	.bInterfaceSubClass =	USB_SUBCLASS_AUDIOCONTROL,
};

/*
 * The number of AudioStreaming and MIDIStreaming interfaces
 * in the Audio Interface Collection
 */
DECLARE_UAC_AC_HEADER_DESCRIPTOR(1);
#define UAC_DT_AC_HEADER_LENGTH_1	UAC_DT_AC_HEADER_SIZE(1)
/* 1 input terminal, 1 output terminal */
#define UAC_DT_TOTAL_LENGTH_1 (UAC_DT_AC_HEADER_LENGTH_1 \
	+ UAC_DT_INPUT_TERMINAL_SIZE + UAC_DT_OUTPUT_TERMINAL_SIZE)
/* B.3.2  Class-Specific AC Interface Descriptor */
static struct uac1_ac_header_descriptor_1 ac_header_desc_1 = {
	.bLength =		UAC_DT_AC_HEADER_LENGTH_1,
	.bDescriptorType =	USB_DT_CS_INTERFACE,
	.bDescriptorSubtype =	UAC_HEADER,
	.bcdADC =		cpu_to_le16(0x0100),
	.wTotalLength =		cpu_to_le16(UAC_DT_TOTAL_LENGTH_1),
	.bInCollection =	1,
	.baInterfaceNr = {
	/* Interface number of the first AudioStream interface */
	/*
		[0] =		F_AUDIO_AS_OUT_INTERFACE / F_AUDIO_AS_IN_INTERFACE,
	 */
	}
};

#if defined(CONFIG_SS_GADGET) ||defined(CONFIG_SS_GADGET_MODULE)
DECLARE_UAC_AC_HEADER_DESCRIPTOR(2);
#define UAC_DT_AC_HEADER_LENGTH_2	UAC_DT_AC_HEADER_SIZE(2)
/* 2 input terminal, 2 output terminal */
#define UAC_DT_TOTAL_LENGTH_2 (UAC_DT_AC_HEADER_LENGTH_2 \
	+ 2*UAC_DT_INPUT_TERMINAL_SIZE + 2*UAC_DT_OUTPUT_TERMINAL_SIZE)
/* B.3.2  Class-Specific AC Interface Descriptor */
static struct uac1_ac_header_descriptor_2 ac_header_desc_2 = {
	.bLength =		UAC_DT_AC_HEADER_LENGTH_2,
	.bDescriptorType =	USB_DT_CS_INTERFACE,
	.bDescriptorSubtype =	UAC_HEADER,
	.bcdADC =		cpu_to_le16(0x0100),
	.wTotalLength =		cpu_to_le16(UAC_DT_TOTAL_LENGTH_2),
	.bInCollection =	2,
	.baInterfaceNr = {
	/* Interface number of the first AudioStream interface */
	/*
		[0] =		F_AUDIO_AS_OUT_INTERFACE,
		[1] =		F_AUDIO_AS_IN_INTERFACE,
	 */
	}
};
#endif
static struct uac_input_terminal_descriptor usb_out_it_desc = {
	.bLength =		UAC_DT_INPUT_TERMINAL_SIZE,
	.bDescriptorType =	USB_DT_CS_INTERFACE,
	.bDescriptorSubtype =	UAC_INPUT_TERMINAL,
	.bTerminalID =		USB_OUT_IT_ID,
	.wTerminalType =	cpu_to_le16(UAC_TERMINAL_STREAMING),
	.bAssocTerminal =	IO_OUT_OT_ID,
	.wChannelConfig =	cpu_to_le16(0x3),
};

static struct uac1_output_terminal_descriptor io_out_ot_desc = {
	.bLength		= UAC_DT_OUTPUT_TERMINAL_SIZE,
	.bDescriptorType	= USB_DT_CS_INTERFACE,
	.bDescriptorSubtype	= UAC_OUTPUT_TERMINAL,
	.bTerminalID		= IO_OUT_OT_ID,
	.wTerminalType		= cpu_to_le16(UAC_OUTPUT_TERMINAL_SPEAKER),
	.bAssocTerminal		= USB_OUT_IT_ID,
	.bSourceID		= USB_OUT_IT_ID,
};
/* add more control dynamically */
static struct usb_audio_control playback_mute_control = {
	.list = LIST_HEAD_INIT(playback_mute_control.list),
	.name = "Playback Mute Control",
	.type = UAC_FU_MUTE,
	/* Todo: add real Mute control code */
	.set = generic_set_cmd,
	.get = generic_get_cmd,
};
static struct usb_audio_control playback_volume_control = {
	.list = LIST_HEAD_INIT(playback_volume_control.list),
	.name = "Playback Volume Control",
	.type = UAC_FU_VOLUME,
	/* Todo: add real Volume control code */
	.set = generic_set_cmd,
	.get = generic_get_cmd,
};
static struct usb_audio_control playback_sample_freq_control = {
	.list = LIST_HEAD_INIT(playback_sample_freq_control.list),
	.name = "Playback Sampling Frequency Control",
	.type = UAC_EP_CS_ATTR_SAMPLE_RATE,
	.set  = generic_set_cmd,
	.get  = generic_get_cmd,
};
static struct usb_audio_control_selector playback_fu_controls = {
	.list = LIST_HEAD_INIT(playback_fu_controls.list),
	.name = "Playback Function Unit Controls",
};
#if defined(CONFIG_SS_GADGET) ||defined(CONFIG_SS_GADGET_MODULE)
static struct uac_input_terminal_descriptor io_in_it_desc = {
	.bLength		= UAC_DT_INPUT_TERMINAL_SIZE,
	.bDescriptorType	= USB_DT_CS_INTERFACE,
	.bDescriptorSubtype	= UAC_INPUT_TERMINAL,
	.bTerminalID		= IO_IN_IT_ID,
	.wTerminalType		= cpu_to_le16(UAC_INPUT_TERMINAL_MICROPHONE),
	.bAssocTerminal		= USB_IN_OT_ID,
	.bNrChannels		= 1,
	.wChannelConfig		= cpu_to_le16(0x3),
};

static struct uac1_output_terminal_descriptor usb_in_ot_desc = {
	.bLength		= UAC_DT_OUTPUT_TERMINAL_SIZE,
	.bDescriptorType	= USB_DT_CS_INTERFACE,
	.bDescriptorSubtype	= UAC_OUTPUT_TERMINAL,
	.bTerminalID =		USB_IN_OT_ID,
	.wTerminalType =	cpu_to_le16(UAC_TERMINAL_STREAMING),
	.bAssocTerminal =	IO_IN_IT_ID,
	.bSourceID =		IO_IN_IT_ID,
};
/* add more control dynamically */
static struct usb_audio_control capture_mute_control = {
	.list = LIST_HEAD_INIT(capture_mute_control.list),
	.name = "Capture Mute Control",
	.type = UAC_FU_MUTE,
	/* Todo: add real Mute control code */
	.set = generic_set_cmd,
	.get = generic_get_cmd,
};
static struct usb_audio_control capture_volume_control = {
	.list = LIST_HEAD_INIT(capture_volume_control.list),
	.name = "Capture Volume Control",
	.type = UAC_FU_VOLUME,
	/* Todo: add real Volume control code */
	.set = generic_set_cmd,
	.get = generic_get_cmd,
};
static struct usb_audio_control capture_sample_freq_control = {
	.list = LIST_HEAD_INIT(capture_sample_freq_control.list),
	.name = "Capture Sampling Frequency Control",
	.type = UAC_EP_CS_ATTR_SAMPLE_RATE,
	.set  = generic_set_cmd,
	.get  = generic_get_cmd,
};
static struct usb_audio_control_selector capture_fu_controls = {
	.list = LIST_HEAD_INIT(capture_fu_controls.list),
	.name = "Capture Feature Unit Controls",
};
#endif
/* B.4.1  Standard AS Interface Descriptor */
static struct usb_interface_descriptor as_out_interface_alt_0_desc = {
	.bLength =		USB_DT_INTERFACE_SIZE,
	.bDescriptorType =	USB_DT_INTERFACE,
	.bAlternateSetting =	0,
	.bNumEndpoints =	0,
	.bInterfaceClass =	USB_CLASS_AUDIO,
	.bInterfaceSubClass =	USB_SUBCLASS_AUDIOSTREAMING,
};
static struct usb_interface_descriptor as_out_interface_alt_1_desc = {
	.bLength =		USB_DT_INTERFACE_SIZE,
	.bDescriptorType =	USB_DT_INTERFACE,
	.bAlternateSetting =	1,
	.bNumEndpoints =	1,
	.bInterfaceClass =	USB_CLASS_AUDIO,
	.bInterfaceSubClass =	USB_SUBCLASS_AUDIOSTREAMING,
};
#if defined(CONFIG_SS_GADGET) ||defined(CONFIG_SS_GADGET_MODULE)
static struct usb_interface_descriptor as_in_interface_alt_0_desc = {
	.bLength =		USB_DT_INTERFACE_SIZE,
	.bDescriptorType =	USB_DT_INTERFACE,
	.bAlternateSetting =	0,
	.bNumEndpoints =	0,
	.bInterfaceClass =	USB_CLASS_AUDIO,
	.bInterfaceSubClass =	USB_SUBCLASS_AUDIOSTREAMING,
};
static struct usb_interface_descriptor as_in_interface_alt_1_desc = {
	.bLength =		USB_DT_INTERFACE_SIZE,
	.bDescriptorType =	USB_DT_INTERFACE,
	.bAlternateSetting =	1,
	.bNumEndpoints =	1,
	.bInterfaceClass =	USB_CLASS_AUDIO,
	.bInterfaceSubClass =	USB_SUBCLASS_AUDIOSTREAMING,
};
#endif
/* B.4.2  Class-Specific AS Interface Descriptor */
static struct uac1_as_header_descriptor as_out_header_desc = {
	.bLength =		UAC_DT_AS_HEADER_SIZE,
	.bDescriptorType =	USB_DT_CS_INTERFACE,
	.bDescriptorSubtype =	UAC_AS_GENERAL,
	.bTerminalLink =	USB_OUT_IT_ID,
	.bDelay =		1,
	.wFormatTag =		cpu_to_le16(UAC_FORMAT_TYPE_I_PCM),
};

#if defined(CONFIG_SS_GADGET) ||defined(CONFIG_SS_GADGET_MODULE)
static struct uac1_as_header_descriptor as_in_header_desc = {
	.bLength =		UAC_DT_AS_HEADER_SIZE,
	.bDescriptorType =	USB_DT_CS_INTERFACE,
	.bDescriptorSubtype =	UAC_AS_GENERAL,
	.bTerminalLink =	USB_IN_OT_ID,
	.bDelay =		1,
	.wFormatTag =		cpu_to_le16(UAC_FORMAT_TYPE_I_PCM),
};
#endif

DECLARE_UAC_FORMAT_TYPE_I_DISCRETE_DESC(1);

static struct uac_format_type_i_discrete_descriptor_1 as_out_type_i_desc = {
	.bLength =		UAC_FORMAT_TYPE_I_DISCRETE_DESC_SIZE(1),
	.bDescriptorType =	USB_DT_CS_INTERFACE,
	.bDescriptorSubtype =	UAC_FORMAT_TYPE,
	.bFormatType =		UAC_FORMAT_TYPE_I,
	.bSubframeSize =	2,
	.bBitResolution =	16,
	.bSamFreqType =		1,
};

/* Standard ISO OUT Endpoint Descriptor */
static struct usb_endpoint_descriptor as_out_ep_desc  = {
	.bLength =		USB_DT_ENDPOINT_AUDIO_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,
	.bEndpointAddress =	USB_DIR_OUT,
	.bmAttributes =		USB_ENDPOINT_SYNC_ADAPTIVE
				| USB_ENDPOINT_XFER_ISOC,
	.wMaxPacketSize	=	cpu_to_le16(UAC1_OUT_EP_MAX_PACKET_SIZE),
	.bInterval =		4,
};

/* Class-specific AS ISO OUT Endpoint Descriptor */
static struct uac_iso_endpoint_descriptor as_iso_out_desc = {
	.bLength =		UAC_ISO_ENDPOINT_DESC_SIZE,
	.bDescriptorType =	USB_DT_CS_ENDPOINT,
	.bDescriptorSubtype =	UAC_EP_GENERAL,
	.bmAttributes = 	1,
	.bLockDelayUnits =	1,
	.wLockDelay =		__constant_cpu_to_le16(1),
};

#if defined(CONFIG_SS_GADGET) ||defined(CONFIG_SS_GADGET_MODULE)
static struct uac_format_type_i_discrete_descriptor_1 as_in_type_i_desc = {
	.bLength =		UAC_FORMAT_TYPE_I_DISCRETE_DESC_SIZE(1),
	.bDescriptorType =	USB_DT_CS_INTERFACE,
	.bDescriptorSubtype =	UAC_FORMAT_TYPE,
	.bFormatType =		UAC_FORMAT_TYPE_I,
	.bSubframeSize =	2,
	.bBitResolution =	16,
	.bSamFreqType =		1,
};

/* Standard ISO OUT Endpoint Descriptor */
static struct usb_endpoint_descriptor as_in_ep_desc  = {
	.bLength =		USB_DT_ENDPOINT_AUDIO_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,
	.bEndpointAddress =	USB_DIR_IN,
	.bmAttributes =		USB_ENDPOINT_SYNC_ASYNC
				| USB_ENDPOINT_XFER_ISOC,
	.wMaxPacketSize	=	cpu_to_le16(UAC1_IN_EP_MAX_PACKET_SIZE),
	.bInterval =		4,
};

/* Class-specific AS ISO OUT Endpoint Descriptor */
static struct uac_iso_endpoint_descriptor as_iso_in_desc = {
	.bLength =		UAC_ISO_ENDPOINT_DESC_SIZE,
	.bDescriptorType =	USB_DT_CS_ENDPOINT,
	.bDescriptorSubtype =	UAC_EP_GENERAL,
	.bmAttributes =		1,
	.bLockDelayUnits =	0,
	.wLockDelay =		0,
};
#endif
static struct usb_interface_assoc_descriptor
audio_iad_descriptor = {
    .bLength           =    sizeof(audio_iad_descriptor),
    .bDescriptorType   =    USB_DT_INTERFACE_ASSOCIATION,
    .bFirstInterface   =    0, /* updated at bind */
    .bInterfaceCount   =    3,
    .bFunctionClass    =    USB_CLASS_AUDIO,
    .bFunctionSubClass =    0,
    .bFunctionProtocol =    UAC_VERSION_1,
};

static struct usb_descriptor_header *f_audio_desc_0[] = {
	(struct usb_descriptor_header *)&audio_iad_descriptor,
	(struct usb_descriptor_header *)&ac_interface_desc,
	(struct usb_descriptor_header *)&ac_header_desc_1,

	(struct usb_descriptor_header *)&usb_out_it_desc,
	(struct usb_descriptor_header *)&io_out_ot_desc,

	(struct usb_descriptor_header *)&as_out_interface_alt_0_desc,
	(struct usb_descriptor_header *)&as_out_interface_alt_1_desc,
	(struct usb_descriptor_header *)&as_out_header_desc,

	(struct usb_descriptor_header *)&as_out_type_i_desc,

	(struct usb_descriptor_header *)&as_out_ep_desc,
	(struct usb_descriptor_header *)&as_iso_out_desc,
	NULL,
};

#if defined(CONFIG_SS_GADGET) ||defined(CONFIG_SS_GADGET_MODULE)
static struct usb_descriptor_header *f_audio_desc_1[] = {
	(struct usb_descriptor_header *)&audio_iad_descriptor,
	(struct usb_descriptor_header *)&ac_interface_desc,
	(struct usb_descriptor_header *)&ac_header_desc_1,

	(struct usb_descriptor_header *)&io_in_it_desc,
	(struct usb_descriptor_header *)&usb_in_ot_desc,

	(struct usb_descriptor_header *)&as_in_interface_alt_0_desc,
	(struct usb_descriptor_header *)&as_in_interface_alt_1_desc,
	(struct usb_descriptor_header *)&as_in_header_desc,

	(struct usb_descriptor_header *)&as_in_type_i_desc,

	(struct usb_descriptor_header *)&as_in_ep_desc,
	(struct usb_descriptor_header *)&as_iso_in_desc,
	NULL,
};

static struct usb_descriptor_header *f_audio_desc_2[] = {
	(struct usb_descriptor_header *)&audio_iad_descriptor,
	(struct usb_descriptor_header *)&ac_interface_desc,
	(struct usb_descriptor_header *)&ac_header_desc_2,

	(struct usb_descriptor_header *)&usb_out_it_desc,
	(struct usb_descriptor_header *)&io_out_ot_desc,
	(struct usb_descriptor_header *)&io_in_it_desc,
	(struct usb_descriptor_header *)&usb_in_ot_desc,

	(struct usb_descriptor_header *)&as_out_interface_alt_0_desc,
	(struct usb_descriptor_header *)&as_out_interface_alt_1_desc,
	(struct usb_descriptor_header *)&as_out_header_desc,

	(struct usb_descriptor_header *)&as_out_type_i_desc,

	(struct usb_descriptor_header *)&as_out_ep_desc,
	(struct usb_descriptor_header *)&as_iso_out_desc,

	(struct usb_descriptor_header *)&as_in_interface_alt_0_desc,
	(struct usb_descriptor_header *)&as_in_interface_alt_1_desc,
	(struct usb_descriptor_header *)&as_in_header_desc,

	(struct usb_descriptor_header *)&as_in_type_i_desc,

	(struct usb_descriptor_header *)&as_in_ep_desc,
	(struct usb_descriptor_header *)&as_iso_in_desc,
	NULL,
};
#endif

enum {
	STR_AC_IF,
	STR_USB_OUT_IT,
	STR_USB_OUT_IT_CH_NAMES,
	STR_IO_OUT_OT,
	STR_AS_OUT_IF_ALT0,
	STR_AS_OUT_IF_ALT1,
	STR_IO_IN_IT,
	STR_IO_IN_IT_CH_NAMES,
	STR_USB_IN_OT,
	STR_AS_IN_IF_ALT0,
	STR_AS_IN_IF_ALT1,
};

static struct usb_string strings_uac1[] = {
	[STR_AC_IF].s = "AC Interface",
	[STR_USB_OUT_IT].s = "Playback Input terminal",
	[STR_USB_OUT_IT_CH_NAMES].s = "Playback Channels",
	[STR_IO_OUT_OT].s = "Playback Output terminal",
	[STR_AS_OUT_IF_ALT0].s = "Playback Inactive",
	[STR_AS_OUT_IF_ALT1].s = "Playback Active",
	[STR_IO_IN_IT].s = "Capture Input terminal",
	[STR_IO_IN_IT_CH_NAMES].s = "Capture Channels",
	[STR_USB_IN_OT].s = "Capture Output terminal",
	[STR_AS_IN_IF_ALT0].s = "Capture Inactive",
	[STR_AS_IN_IF_ALT1].s = "Capture Active",
	{ },
};


static struct usb_gadget_strings str_uac1 = {
	.language = 0x0409,	/* en-us */
	.strings = strings_uac1,
};

static struct usb_gadget_strings *uac1_strings[] = {
	&str_uac1,
	NULL,
};

/*
 * This function is an ALSA sound card following USB Audio Class Spec 1.0.
 */

/*-------------------------------------------------------------------------*/
struct f_audio_buf {
	u8 *buf;
	int actual;
	struct list_head list;
};

static struct f_audio_buf *f_audio_buffer_alloc(int buf_size)
{
	struct f_audio_buf *copy_buf;

	copy_buf = kzalloc(sizeof *copy_buf, GFP_ATOMIC);
	if (!copy_buf)
		return ERR_PTR(-ENOMEM);

	copy_buf->buf = kzalloc(buf_size, GFP_ATOMIC);
	if (!copy_buf->buf) {
		kfree(copy_buf);
		return ERR_PTR(-ENOMEM);
	}

	return copy_buf;
}

static void f_audio_buffer_free(struct f_audio_buf *audio_buf)
{
	kfree(audio_buf->buf);
	kfree(audio_buf);
}
/*-------------------------------------------------------------------------*/

struct f_audio {
	struct gaudio			card;

	/* endpoints handle full and/or high speeds */
	struct usb_ep			*out_ep;
	struct usb_ep			*in_ep;

	spinlock_t			playback_lock;
	spinlock_t			capture_lock;
	spinlock_t			capture_req_lock;
	struct f_audio_buf *playback_copy_buf;
	struct work_struct playback_work;
	struct work_struct capture_work;
	struct list_head playback_play_queue;//store buf playback to audio
	struct list_head capture_play_queue; //store buf capture from audio
	struct list_head capture_req_free;//store req request, total in_req_count
	u8     alt_intf[F_AUDIO_NUM_INTERFACES];

	/* Control Set command */
	struct list_head cs;
	u8 set_cmd;
	struct usb_audio_control *set_con;
};

static inline struct f_audio *func_to_audio(struct usb_function *f)
{
	return container_of(f, struct f_audio, card.func);
}

static inline struct f_uac1_opts *fi_to_opts(const struct usb_function_instance *fi)
{
	return container_of(fi,struct f_uac1_opts, func_inst);
}

 inline struct f_audio *capture_work_to_audio(struct work_struct *w)
{
	return container_of(w, struct f_audio,capture_work);
}

/*-------------------------------------------------------------------------*/

#if defined(CONFIG_SS_GADGET) ||defined(CONFIG_SS_GADGET_MODULE)
static void f_audio_capture_work(struct work_struct *data)
{
	struct usb_request *req = NULL;
	struct f_audio *audio = capture_work_to_audio(data);
	struct f_audio_buf *capture_buf,*copy_buf = NULL;
	struct f_uac1_opts *opts = fi_to_opts(audio->card.func.fi);
	int audio_capture_buf_size = opts->audio_capture_buf_size;
	unsigned long flags;
	unsigned int copy_size, left_size, in_req_buf_size = opts->in_req_buf_size;
	struct usb_ep *ep = audio->in_ep;
	int res = 0, ret = 0;

	pr_debug("%s Started\n", __func__);

	spin_lock_irqsave(&audio->capture_lock, flags);
	if (!list_empty(&audio->capture_play_queue)) {
		spin_unlock_irqrestore(&audio->capture_lock, flags);
		pr_debug("%s !! buffer already filled\n", __func__);
	} else {
		spin_unlock_irqrestore(&audio->capture_lock, flags);

		capture_buf = f_audio_buffer_alloc(audio_capture_buf_size);
		if (capture_buf <= 0) {
			pr_err("%s: buffer alloc failed\n", __func__);
			return;
		}
		res = u_audio_capture(&audio->card,
				capture_buf->buf,
				audio_capture_buf_size);

		if (res) {
			pr_err("copying failed");
			f_audio_buffer_free(capture_buf);
			schedule_work(&audio->capture_work);
			return;
		}

		spin_lock_irqsave(&audio->capture_lock, flags);
		list_add_tail(&capture_buf->list, &audio->capture_play_queue);
		spin_unlock_irqrestore(&audio->capture_lock, flags);
	}

	/* Queue request now */
	while(1) {
		/* Get A Free Request */
		spin_lock_irqsave(&audio->capture_req_lock, flags);
		if (list_empty(&audio->capture_req_free)) {
			spin_unlock_irqrestore(&audio->capture_req_lock, flags);
			return;
		}
		req = list_first_entry(&audio->capture_req_free, struct usb_request,list);
		list_del(&req->list);
		spin_unlock_irqrestore(&audio->capture_req_lock, flags);

		/* Get a capture buf */
		spin_lock_irqsave(&audio->capture_lock, flags);
		if (list_empty(&audio->capture_play_queue)) {
			schedule_work(&audio->capture_work);
			spin_unlock_irqrestore(&audio->capture_lock, flags);
			goto requeue;
		}

		copy_buf = list_first_entry(&audio->capture_play_queue,
		struct f_audio_buf, list);
		if (copy_buf == NULL) {
			schedule_work(&audio->capture_work);
			spin_unlock_irqrestore(&audio->capture_lock, flags);
			goto requeue;
		}

		left_size = audio_capture_buf_size - copy_buf->actual;
		copy_size = min(left_size, in_req_buf_size);
		memcpy(req->buf, copy_buf->buf + copy_buf->actual, copy_size);
		req->length = copy_size;
		copy_buf->actual += copy_size;
		if (audio_capture_buf_size <= copy_buf->actual) {
			list_del(&copy_buf->list);
			f_audio_buffer_free(copy_buf);
			schedule_work(&audio->capture_work);
		}
		spin_unlock_irqrestore(&audio->capture_lock, flags);
		ret = usb_ep_queue(ep, req, GFP_ATOMIC);
		if(ret < 0) {
			printk(KERN_INFO "Failed to queue request (%d).\n", ret);
			usb_ep_set_halt(ep);
			goto requeue;
		}
	}

requeue:
	spin_lock_irqsave(&audio->capture_req_lock, flags);
	list_add_tail(&req->list, &audio->capture_req_free);
	spin_unlock_irqrestore(&audio->capture_req_lock, flags);
}
#endif

static void f_audio_playback_work(struct work_struct *data)
{
	struct f_audio *audio = container_of(data, struct f_audio,
					playback_work);
	struct f_audio_buf *play_buf;

	spin_lock_irq(&audio->playback_lock);
	if (list_empty(&audio->playback_play_queue)) {
		spin_unlock_irq(&audio->playback_lock);
		return;
	}
	play_buf = list_first_entry(&audio->playback_play_queue,
			struct f_audio_buf, list);
	list_del(&play_buf->list);
	spin_unlock_irq(&audio->playback_lock);

	u_audio_playback(&audio->card, play_buf->buf, play_buf->actual);
	f_audio_buffer_free(play_buf);
}

static int f_audio_in_ep_complete(struct usb_ep *ep, struct usb_request *req)
{
	struct f_audio *audio = req->context;
	struct f_audio_buf *copy_buf = NULL;
	struct f_uac1_opts *opts = fi_to_opts(audio->card.func.fi);
	int audio_capture_buf_size = opts->audio_capture_buf_size;
	unsigned long flags;
	unsigned int copy_size, left_size, in_req_buf_size = opts->in_req_buf_size;
	int err = 0;

	spin_lock_irqsave(&audio->capture_lock, flags);
	if (list_empty(&audio->capture_play_queue)) {
		pr_debug("capture_play_queue is Empty\n");
		schedule_work(&audio->capture_work);
		spin_unlock_irqrestore(&audio->capture_lock, flags);
		goto requeue;
	}

	copy_buf = list_first_entry(&audio->capture_play_queue,
			struct f_audio_buf, list);

	left_size = audio_capture_buf_size - copy_buf->actual;
	copy_size = min(left_size, in_req_buf_size);
	memcpy(req->buf, copy_buf->buf + copy_buf->actual, copy_size);
	req->length = copy_size;
	copy_buf->actual += copy_size;
	if (audio_capture_buf_size <= copy_buf->actual) {
		list_del(&copy_buf->list);
		f_audio_buffer_free(copy_buf);
		schedule_work(&audio->capture_work);
	}
	spin_unlock_irqrestore(&audio->capture_lock, flags);
	err = usb_ep_queue(ep, req, GFP_ATOMIC);
	if (err) {
		pr_err("Failed to queue %s req: err - %d\n", ep->name, err);
		goto requeue;
	}

	return 0;
requeue:
	spin_lock_irqsave(&audio->capture_req_lock, flags);
	list_add_tail(&req->list, &audio->capture_req_free);
	spin_unlock_irqrestore(&audio->capture_req_lock, flags);
	return err;
}
static int f_audio_out_ep_complete(struct usb_ep *ep, struct usb_request *req)
{
	struct f_audio *audio = req->context;
	struct usb_composite_dev *cdev = audio->card.func.config->cdev;
	struct f_audio_buf *playback_copy_buf = audio->playback_copy_buf;
	struct f_uac1_opts *opts;
	int audio_playback_buf_size;
	int err;

	opts = container_of(audio->card.func.fi, struct f_uac1_opts,
			func_inst);
	audio_playback_buf_size = opts->audio_playback_buf_size;

	if (!playback_copy_buf)
		return -EINVAL;

	/* Copy buffer is full, add it to the playback_play_queue */
	if (audio_playback_buf_size - playback_copy_buf->actual < req->actual) {
		list_add_tail(&playback_copy_buf->list, &audio->playback_play_queue);
		schedule_work(&audio->playback_work);
		playback_copy_buf = f_audio_buffer_alloc(audio_playback_buf_size);
		if (IS_ERR(playback_copy_buf))
			return -ENOMEM;
	}

	memcpy(playback_copy_buf->buf + playback_copy_buf->actual, req->buf, req->actual);
	playback_copy_buf->actual += req->actual;
	audio->playback_copy_buf = playback_copy_buf;

	err = usb_ep_queue(ep, req, GFP_ATOMIC);
	if (err)
		ERROR(cdev, "%s queue req: %d\n", ep->name, err);

	return 0;

}

static void f_audio_complete(struct usb_ep *ep, struct usb_request *req)
{
	struct f_audio *audio = req->context;
	int status = req->status;
	u32 data = 0;
	struct usb_ep *out_ep = audio->out_ep,*in_ep = audio->in_ep;

	switch (status) {

	case 0:				/* normal completion? */
		if (ep == out_ep)
			f_audio_out_ep_complete(ep, req);
		else if (ep == in_ep) {
			f_audio_in_ep_complete(ep, req);
		}
		else if (audio->set_con) {
			memcpy(&data, req->buf, req->length);
			audio->set_con->set(audio->set_con, audio->set_cmd,
					le16_to_cpu(data));
			audio->set_con = NULL;
		}
		break;
	default:
		break;
	}
}

static int audio_set_intf_req(struct usb_function *f,
		const struct usb_ctrlrequest *ctrl)
{
	struct f_audio		*audio = func_to_audio(f);
	struct usb_composite_dev *cdev = f->config->cdev;
	struct usb_request	*req = cdev->req;
	u8			id = ((le16_to_cpu(ctrl->wIndex) >> 8) & 0xFF);
	u16			len = le16_to_cpu(ctrl->wLength);
	u16			w_value = le16_to_cpu(ctrl->wValue);
	u8			con_sel = (w_value >> 8) & 0xFF;
	u8			cmd = (ctrl->bRequest & 0x0F);
	struct usb_audio_control_selector *cs;
	struct usb_audio_control *con;

	DBG(cdev, "bRequest 0x%x, w_value 0x%04x, len %d, entity %d\n",
			ctrl->bRequest, w_value, len, id);

	list_for_each_entry(cs, &audio->cs, list) {
		if (cs->id == id) {
			list_for_each_entry(con, &cs->control, list) {
				if (con->type == con_sel) {
					audio->set_con = con;
					break;
				}
			}
			break;
		}
	}

	audio->set_cmd = cmd;
	req->context = audio;
	req->complete = f_audio_complete;

	return len;
}

static int audio_get_intf_req(struct usb_function *f,
		const struct usb_ctrlrequest *ctrl)
{
	struct f_audio		*audio = func_to_audio(f);
	struct usb_composite_dev *cdev = f->config->cdev;
	struct usb_request	*req = cdev->req;
	int			value = -EOPNOTSUPP;
	u8			id = ((le16_to_cpu(ctrl->wIndex) >> 8) & 0xFF);
	u16			len = le16_to_cpu(ctrl->wLength);
	u16			w_value = le16_to_cpu(ctrl->wValue);
	u8			con_sel = (w_value >> 8) & 0xFF;
	u8			cmd = (ctrl->bRequest & 0x0F);
	struct usb_audio_control_selector *cs;
	struct usb_audio_control *con;

	DBG(cdev, "bRequest 0x%x, w_value 0x%04x, len %d, entity %d\n",
			ctrl->bRequest, w_value, len, id);

	list_for_each_entry(cs, &audio->cs, list) {
		if (cs->id == id) {
			list_for_each_entry(con, &cs->control, list) {
				if (con->type == con_sel && con->get) {
					value = con->get(con, cmd);
					break;
				}
			}
			break;
		}
	}

	req->context = audio;
	req->complete = f_audio_complete;
	len = min_t(size_t, sizeof(value), len);
	memcpy(req->buf, &value, len);

	return len;
}

static int audio_set_endpoint_req(struct usb_function *f,
		const struct usb_ctrlrequest *ctrl)
{
	struct usb_composite_dev *cdev = f->config->cdev;
	int			value = -EOPNOTSUPP;
	u16			ep = le16_to_cpu(ctrl->wIndex);
	u16			len = le16_to_cpu(ctrl->wLength);
	u16			w_value = le16_to_cpu(ctrl->wValue);

	DBG(cdev, "bRequest 0x%x, w_value 0x%04x, len %d, endpoint %d\n",
			ctrl->bRequest, w_value, len, ep);

	switch (ctrl->bRequest) {
	case UAC_SET_CUR:
		value = len;
		break;

	case UAC_SET_MIN:
		break;

	case UAC_SET_MAX:
		break;

	case UAC_SET_RES:
		break;

	case UAC_SET_MEM:
		break;

	default:
		break;
	}

	return value;
}

static int audio_get_endpoint_req(struct usb_function *f,
		const struct usb_ctrlrequest *ctrl)
{
	struct usb_composite_dev *cdev = f->config->cdev;
	int value = -EOPNOTSUPP;
	u8 ep = ((le16_to_cpu(ctrl->wIndex) >> 8) & 0xFF);
	u16 len = le16_to_cpu(ctrl->wLength);
	u16 w_value = le16_to_cpu(ctrl->wValue);

	DBG(cdev, "bRequest 0x%x, w_value 0x%04x, len %d, endpoint %d\n",
			ctrl->bRequest, w_value, len, ep);

	switch (ctrl->bRequest) {
	case UAC_GET_CUR:
	case UAC_GET_MIN:
	case UAC_GET_MAX:
	case UAC_GET_RES:
		value = len;
		break;
	case UAC_GET_MEM:
		break;
	default:
		break;
	}

	return value;
}

static int
f_audio_setup(struct usb_function *f, const struct usb_ctrlrequest *ctrl)
{
	struct usb_composite_dev *cdev = f->config->cdev;
	struct usb_request	*req = cdev->req;
	int			value = -EOPNOTSUPP;
	u16			w_index = le16_to_cpu(ctrl->wIndex);
	u16			w_value = le16_to_cpu(ctrl->wValue);
	u16			w_length = le16_to_cpu(ctrl->wLength);

	/* composite driver infrastructure handles everything; interface
	 * activation uses set_alt().
	 */
	DBG(cdev, "control req%02x.%02x v%04x i%04x l%d\n",
		ctrl->bRequestType, ctrl->bRequest,
		w_value, w_index, w_length);

	switch (ctrl->bRequestType) {
	case USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE:
	DBG(cdev,"USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE\n");
		value = audio_set_intf_req(f, ctrl);
		break;

	case USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE:
	DBG(cdev,"USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE\n");
		value = audio_get_intf_req(f, ctrl);
		break;

	case USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_ENDPOINT:
	DBG(cdev,"USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_ENDPOINT\n");
		value = audio_set_endpoint_req(f, ctrl);
		break;

	case USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_ENDPOINT:
	DBG(cdev,"USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE\n");
		value = audio_get_endpoint_req(f, ctrl);
		break;

	default:
		ERROR(cdev, "invalid control req%02x.%02x v%04x i%04x l%d\n",
			ctrl->bRequestType, ctrl->bRequest,
			w_value, w_index, w_length);
	}

	/* respond with data transfer or status phase? */
	if (value >= 0) {
		DBG(cdev, "audio req%02x.%02x v%04x i%04x l%d\n",
			ctrl->bRequestType, ctrl->bRequest,
			w_value, w_index, w_length);
		req->zero = 0;
		req->length = value;
		value = usb_ep_queue(cdev->gadget->ep0, req, GFP_ATOMIC);
		if (value < 0)
			ERROR(cdev, "audio response on err %d\n", value);
	}

	/* device either stalls (value < 0) or reports success */
	return value;
}

static int f_audio_get_alt(struct usb_function *f, unsigned intf)
{
	struct f_audio		*audio = func_to_audio(f);
	struct f_uac1_opts *opts;

	opts = container_of(f->fi, struct f_uac1_opts, func_inst);

#if defined(CONFIG_SS_GADGET) ||defined(CONFIG_SS_GADGET_MODULE)
	if ((ENABLE_MICROPHONE == opts->audio_play_mode) ||
	    (ENABLE_MIC_AND_SPK == opts->audio_play_mode &&
	     intf == ac_header_desc_2.baInterfaceNr[F_AUDIO_AS_IN_INTERFACE]))
	{
		return audio->alt_intf[F_AUDIO_AS_IN_INTERFACE];
	}
	if ((ENABLE_SPEAKER == opts->audio_play_mode) ||
	    (ENABLE_MIC_AND_SPK == opts->audio_play_mode &&
	     intf == ac_header_desc_2.baInterfaceNr[F_AUDIO_AS_OUT_INTERFACE]))
#endif
	{
		return audio->alt_intf[F_AUDIO_AS_OUT_INTERFACE];
	}

	return 0;
}

static int f_audio_set_alt(struct usb_function *f, unsigned intf, unsigned alt)
{
	struct f_audio		*audio = func_to_audio(f);
	struct usb_composite_dev *cdev = f->config->cdev;
	struct usb_request *req;
	struct f_uac1_opts *opts;
	struct usb_ep *out_ep = audio->out_ep;
	int out_req_buf_size, out_req_count, audio_playback_buf_size;
#if defined(CONFIG_SS_GADGET) ||defined(CONFIG_SS_GADGET_MODULE)
	struct usb_ep *in_ep = audio->in_ep;
	int in_req_buf_size, in_req_count, audio_capture_buf_size;
	unsigned long flags;
#endif
	int i = 0, err = 0;

	INFO(cdev, "uac1 intf %d, alt %d\n", intf, alt);

	opts = container_of(f->fi, struct f_uac1_opts, func_inst);
	out_req_buf_size = opts->out_req_buf_size;
	out_req_count = opts->out_req_count;
	audio_playback_buf_size = opts->audio_playback_buf_size;

#if defined(CONFIG_SS_GADGET) ||defined(CONFIG_SS_GADGET_MODULE)
	in_req_buf_size = opts->in_req_buf_size;
	in_req_count = opts->in_req_count;
	audio_capture_buf_size = opts->audio_capture_buf_size;

	if( (ENABLE_MICROPHONE == opts->audio_play_mode) ||
		   (ENABLE_MIC_AND_SPK == opts->audio_play_mode && intf == ac_header_desc_2.baInterfaceNr[F_AUDIO_AS_IN_INTERFACE]))
	{
		if (alt == 1) {
			err = config_ep_by_speed(cdev->gadget, f, in_ep);
			if (err)
				return err;

			usb_ep_enable(in_ep);

			for (i = 0; i < in_req_count && err == 0; i++) {
			/* Allocate a write buffer */
				req = usb_ep_alloc_request(in_ep, GFP_ATOMIC);
				if (!req) {
					pr_err("request allocation failed\n");
					return -ENOMEM;
				}
				req->buf = kzalloc(in_req_buf_size,GFP_ATOMIC);
				if (!req->buf)
					return -ENOMEM;

				req->length   = in_req_buf_size;
				req->context  = audio;
				req->complete = f_audio_complete;

				spin_lock_irqsave(&audio->capture_req_lock, flags);
				list_add_tail(&req->list, &audio->capture_req_free);
				spin_unlock_irqrestore(&audio->capture_req_lock, flags);
			}
			schedule_work(&audio->capture_work);

		} else {
			struct f_audio_buf *capture_buf;
			usb_ep_disable(in_ep);
			spin_lock_irqsave(&audio->capture_lock, flags);
			while (!list_empty(&audio->capture_play_queue)) {
				capture_buf = list_first_entry(
					&audio->capture_play_queue,
					struct f_audio_buf,list);
				list_del(&capture_buf->list);
				f_audio_buffer_free(capture_buf);
			}
			INIT_LIST_HEAD(&audio->capture_req_free);
			spin_unlock_irqrestore(&audio->capture_lock, flags);
		}
		audio->alt_intf[F_AUDIO_AS_IN_INTERFACE] = alt;
	} else if ((ENABLE_SPEAKER == opts->audio_play_mode) ||
		(ENABLE_MIC_AND_SPK == opts->audio_play_mode && intf == ac_header_desc_2.baInterfaceNr[F_AUDIO_AS_OUT_INTERFACE]))
#endif
	{
		if (alt == 1) {
			err = config_ep_by_speed(cdev->gadget, f, out_ep);
			if (err)
				return err;

			usb_ep_enable(out_ep);
			audio->playback_copy_buf = f_audio_buffer_alloc(audio_playback_buf_size);
			if (IS_ERR(audio->playback_copy_buf))
				return -ENOMEM;

			/*
			 * allocate a bunch of read buffers
			 * and queue them all at once.
			 */
			for (i = 0; i < out_req_count && err == 0; i++) {
				req = usb_ep_alloc_request(out_ep, GFP_ATOMIC);
				if (req) {
					req->buf = kzalloc(out_req_buf_size,
							GFP_ATOMIC);
					if (req->buf) {
						req->length = out_req_buf_size;
						req->context = audio;
						req->complete =
							f_audio_complete;
						err = usb_ep_queue(out_ep,
							req, GFP_ATOMIC);
						if (err)
							ERROR(cdev,
							"%s queue req: %d\n",
							out_ep->name, err);
					} else
						err = -ENOMEM;
				} else
					err = -ENOMEM;
			}

		} else {
			struct f_audio_buf *playback_copy_buf = audio->playback_copy_buf;
			if (playback_copy_buf) {
				list_add_tail(&playback_copy_buf->list,
						&audio->playback_play_queue);
				schedule_work(&audio->playback_work);
				audio->playback_copy_buf = NULL;
			}
		}
		audio->alt_intf[F_AUDIO_AS_OUT_INTERFACE] = alt;
	}
	return err;
}

static void f_audio_disable(struct usb_function *f)
{
	struct f_audio		*audio = func_to_audio(f);
	struct usb_composite_dev *cdev = f->config->cdev;

	DBG(cdev, "%s\n",__func__);

	(void)audio;
	(void)cdev;

	return;
}

/*-------------------------------------------------------------------------*/

static void f_audio_build_desc(struct f_audio *audio)
{
	struct gaudio *card = &audio->card;
	u8 *sam_freq;
	int rate;

	/* Set channel numbers */
	usb_out_it_desc.bNrChannels = u_audio_get_playback_channels(card);
	as_out_type_i_desc.bNrChannels = u_audio_get_playback_channels(card);
#if defined(CONFIG_SS_GADGET) ||defined(CONFIG_SS_GADGET_MODULE)
	io_in_it_desc.bNrChannels = u_audio_get_capture_channels(card);
	as_in_type_i_desc.bNrChannels = u_audio_get_capture_channels(card);
#endif
	/* Set sample rates */
	rate = u_audio_get_playback_rate(card);
	sam_freq = as_out_type_i_desc.tSamFreq[0];
	memcpy(sam_freq, &rate, 3);

#if defined(CONFIG_SS_GADGET) ||defined(CONFIG_SS_GADGET_MODULE)
	rate = u_audio_get_capture_rate(card);
	sam_freq = as_in_type_i_desc.tSamFreq[0];
	memcpy(sam_freq, &rate, 3);
#endif

	/* Todo: Set Sample bits and other parameters */

	return;
}

/* audio function driver setup/binding */
static int
f_audio_bind(struct usb_configuration *c, struct usb_function *f)
{
	struct usb_composite_dev *cdev = c->cdev;
	struct f_audio		*audio = func_to_audio(f);
	struct usb_string	*us;
	int			status;
	static struct usb_descriptor_header **f_audio_desc = NULL;
	struct usb_ep		*ep = NULL;
	struct f_uac1_opts	*audio_opts;

	audio_opts = container_of(f->fi, struct f_uac1_opts, func_inst);
	audio->card.gadget = c->cdev->gadget;
	/* set up ASLA audio devices */
	if (!audio_opts->bound) {
		status = gaudio_setup(&audio->card);
		if (status < 0)
			return status;
		audio_opts->bound = true;
	}
	/* Set Strings Desc & attach to releated desc*/
	us = usb_gstrings_attach(cdev, uac1_strings, ARRAY_SIZE(strings_uac1));
	if (IS_ERR(us))
		return PTR_ERR(us);
	ac_interface_desc.iInterface = us[STR_AC_IF].id;
	usb_out_it_desc.iTerminal = us[STR_USB_OUT_IT].id;
	usb_out_it_desc.iChannelNames = us[STR_USB_OUT_IT_CH_NAMES].id;
	io_out_ot_desc.iTerminal = us[STR_IO_OUT_OT].id;
	as_out_interface_alt_0_desc.iInterface = us[STR_AS_OUT_IF_ALT0].id;
	as_out_interface_alt_1_desc.iInterface = us[STR_AS_OUT_IF_ALT1].id;

#if defined(CONFIG_SS_GADGET) ||defined(CONFIG_SS_GADGET_MODULE)
	io_in_it_desc.iTerminal = us[STR_IO_IN_IT].id;
	io_in_it_desc.iChannelNames = us[STR_IO_IN_IT_CH_NAMES].id;
	usb_in_ot_desc.iTerminal = us[STR_USB_IN_OT].id;
	as_in_interface_alt_0_desc.iInterface = us[STR_AS_IN_IF_ALT0].id;
	as_in_interface_alt_1_desc.iInterface = us[STR_AS_IN_IF_ALT1].id;
#endif
	f_audio_build_desc(audio);

	/* allocate instance-specific interface IDs, and patch descriptors */
	status = usb_interface_id(c, f);
	if (status < 0)
		goto fail;
	ac_interface_desc.bInterfaceNumber = status;
	audio_iad_descriptor.bFirstInterface = status;

#if defined(CONFIG_SS_GADGET) ||defined(CONFIG_SS_GADGET_MODULE)
	if(ENABLE_SPEAKER == audio_opts->audio_play_mode ||
	   ENABLE_MIC_AND_SPK == audio_opts->audio_play_mode )
#endif
	{
		status = usb_interface_id(c, f);
		if (status < 0)
			goto fail;
		as_out_interface_alt_0_desc.bInterfaceNumber = status;
		as_out_interface_alt_1_desc.bInterfaceNumber = status;
		audio->alt_intf[F_AUDIO_AS_OUT_INTERFACE] = 0;
	}

#if defined(CONFIG_SS_GADGET) ||defined(CONFIG_SS_GADGET_MODULE)
	if(ENABLE_MIC_AND_SPK == audio_opts->audio_play_mode)
		ac_header_desc_2.baInterfaceNr[F_AUDIO_AS_OUT_INTERFACE] = status;
#endif

#if defined(CONFIG_SS_GADGET) ||defined(CONFIG_SS_GADGET_MODULE)
	if(ENABLE_MICROPHONE == audio_opts->audio_play_mode ||
	   ENABLE_MIC_AND_SPK == audio_opts->audio_play_mode )
	{
		status = usb_interface_id(c, f);
		if (status < 0)
			goto fail;
		as_in_interface_alt_0_desc.bInterfaceNumber = status;
		as_in_interface_alt_1_desc.bInterfaceNumber = status;
		audio->alt_intf[F_AUDIO_AS_IN_INTERFACE] = 0;
	}
#endif

#if defined(CONFIG_SS_GADGET) ||defined(CONFIG_SS_GADGET_MODULE)
	if(ENABLE_MIC_AND_SPK == audio_opts->audio_play_mode)
		ac_header_desc_2.baInterfaceNr[F_AUDIO_AS_IN_INTERFACE] = status;
	else
#endif
		ac_header_desc_1.baInterfaceNr[0] = status;

	status = -ENODEV;

	/* allocate instance-specific endpoints */
#if defined(CONFIG_SS_GADGET) ||defined(CONFIG_SS_GADGET_MODULE)
	if(ENABLE_SPEAKER == audio_opts->audio_play_mode ||
	  ENABLE_MIC_AND_SPK == audio_opts->audio_play_mode )
#endif
	{
		ep = usb_ep_autoconfig(cdev->gadget, &as_out_ep_desc);
		if (!ep)
			goto fail;
		audio->out_ep = ep;
		audio->out_ep->desc = &as_out_ep_desc;
	}

#if defined(CONFIG_SS_GADGET) ||defined(CONFIG_SS_GADGET_MODULE)
	if(ENABLE_MICROPHONE == audio_opts->audio_play_mode ||
	   ENABLE_MIC_AND_SPK == audio_opts->audio_play_mode )
	{
		ep = usb_ep_autoconfig(cdev->gadget, &as_in_ep_desc);
		if (!ep)
			goto fail;
		audio->in_ep = ep;
		audio->in_ep->desc = &as_in_ep_desc;
	}
#endif
	status = -ENOMEM;

	/* Finally Build the Descriptors */
#if defined(CONFIG_SS_GADGET) ||defined(CONFIG_SS_GADGET_MODULE)
	if(ENABLE_MICROPHONE == audio_opts->audio_play_mode) {
		audio_iad_descriptor.bInterfaceCount = 2;
		f_audio_desc = f_audio_desc_1;
	}
	else if(ENABLE_MIC_AND_SPK == audio_opts->audio_play_mode) {
		audio_iad_descriptor.bInterfaceCount = 3;
		f_audio_desc = f_audio_desc_2;
	} else if (ENABLE_SPEAKER == audio_opts->audio_play_mode)
#endif
	{
		audio_iad_descriptor.bInterfaceCount = 2;
		f_audio_desc = f_audio_desc_0;
	}

	/* copy descriptors, and track endpoint copies */
	status = usb_assign_descriptors(f, f_audio_desc, f_audio_desc, NULL,
					NULL);
	if (status)
		goto fail;
	return 0;

fail:
	gaudio_cleanup(&audio->card);
	return status;
}

/*-------------------------------------------------------------------------*/

static int generic_set_cmd(struct usb_audio_control *con, u8 cmd, int value)
{
	con->data[cmd] = value;

	return 0;
}

static int generic_get_cmd(struct usb_audio_control *con, u8 cmd)
{
	return con->data[cmd];
}
static int control_selector_init(struct f_audio *audio)
{
	INIT_LIST_HEAD(&audio->cs);
#if defined(CONFIG_SS_GADGET) ||defined(CONFIG_SS_GADGET_MODULE)
	list_add(&capture_fu_controls.list,&audio->cs);
#endif
	list_add(&playback_fu_controls.list,&audio->cs);

#if defined(CONFIG_SS_GADGET) ||defined(CONFIG_SS_GADGET_MODULE)
	INIT_LIST_HEAD(&capture_fu_controls.control);
	list_add(&capture_mute_control.list,
		     &capture_fu_controls.control);
	list_add(&capture_volume_control.list,
		     &capture_fu_controls.control);
#endif
	INIT_LIST_HEAD(&playback_fu_controls.control);
	list_add(&playback_mute_control.list,
		 &playback_fu_controls.control);
	list_add(&playback_volume_control.list,
		 &playback_fu_controls.control);

#if defined(CONFIG_SS_GADGET) ||defined(CONFIG_SS_GADGET_MODULE)
	capture_volume_control.data[UAC__CUR] = 0xffc0;
	capture_volume_control.data[UAC__MIN] = 0xe3a0;
	capture_volume_control.data[UAC__MAX] = 0xfff0;
	capture_volume_control.data[UAC__RES] = 0x0030;
#endif
	playback_volume_control.data[UAC__CUR] = 0xffc0;
	playback_volume_control.data[UAC__MIN] = 0xe3a0;
	playback_volume_control.data[UAC__MAX] = 0xfff0;
	playback_volume_control.data[UAC__RES] = 0x0030;

	return 0;
}
static inline struct f_uac1_opts *to_f_uac1_opts(struct config_item *item)
{
	return container_of(to_config_group(item), struct f_uac1_opts,
			    func_inst.group);
}

static void f_uac1_attr_release(struct config_item *item)
{
	struct f_uac1_opts *opts = to_f_uac1_opts(item);

	usb_put_function_instance(&opts->func_inst);
}

static struct configfs_item_operations f_uac1_item_ops = {
	.release	= f_uac1_attr_release,
};

#define UAC1_INT_ATTRIBUTE(name)					\
static ssize_t f_uac1_opts_##name##_show(struct config_item *item,	\
					 char *page)			\
{									\
	struct f_uac1_opts *opts = to_f_uac1_opts(item);		\
	int result;							\
									\
	mutex_lock(&opts->lock);					\
	result = sprintf(page, "%u\n", opts->name);			\
	mutex_unlock(&opts->lock);					\
									\
	return result;							\
}									\
									\
static ssize_t f_uac1_opts_##name##_store(struct config_item *item,		\
					  const char *page, size_t len)	\
{									\
	struct f_uac1_opts *opts = to_f_uac1_opts(item);		\
	int ret;							\
	u32 num;							\
									\
	mutex_lock(&opts->lock);					\
	if (opts->refcnt) {						\
		ret = -EBUSY;						\
		goto end;						\
	}								\
									\
	ret = kstrtou32(page, 0, &num);					\
	if (ret)							\
		goto end;						\
									\
	opts->name = num;						\
	ret = len;							\
									\
end:									\
	mutex_unlock(&opts->lock);					\
	return ret;							\
}									\
									\
CONFIGFS_ATTR(f_uac1_opts_, name)

UAC1_INT_ATTRIBUTE(out_req_buf_size);
UAC1_INT_ATTRIBUTE(out_req_count);
UAC1_INT_ATTRIBUTE(audio_playback_buf_size);

UAC1_INT_ATTRIBUTE(in_req_buf_size);
UAC1_INT_ATTRIBUTE(in_req_count);
UAC1_INT_ATTRIBUTE(audio_capture_buf_size);

#define UAC1_STR_ATTRIBUTE(name)					\
static ssize_t f_uac1_opts_##name##_show(struct config_item *item,	\
					 char *page)			\
{									\
	struct f_uac1_opts *opts = to_f_uac1_opts(item);		\
	int result;							\
									\
	mutex_lock(&opts->lock);					\
	result = sprintf(page, "%s\n", opts->name);			\
	mutex_unlock(&opts->lock);					\
									\
	return result;							\
}									\
									\
static ssize_t f_uac1_opts_##name##_store(struct config_item *item,	\
					  const char *page, size_t len)	\
{									\
	struct f_uac1_opts *opts = to_f_uac1_opts(item);		\
	int ret = -EBUSY;						\
	char *tmp;							\
									\
	mutex_lock(&opts->lock);					\
	if (opts->refcnt)						\
		goto end;						\
									\
	tmp = kstrndup(page, len, GFP_KERNEL);				\
	if (tmp) {							\
		ret = -ENOMEM;						\
		goto end;						\
	}								\
	if (opts->name##_alloc)						\
		kfree(opts->name);					\
	opts->name##_alloc = true;					\
	opts->name = tmp;						\
	ret = len;							\
									\
end:									\
	mutex_unlock(&opts->lock);					\
	return ret;							\
}									\
									\
CONFIGFS_ATTR(f_uac1_opts_, name)

UAC1_STR_ATTRIBUTE(fn_play);
UAC1_STR_ATTRIBUTE(fn_cap);
UAC1_STR_ATTRIBUTE(fn_cntl);

static struct configfs_attribute *f_uac1_attrs[] = {
	&f_uac1_opts_attr_out_req_buf_size,
	&f_uac1_opts_attr_out_req_count,
	&f_uac1_opts_attr_audio_playback_buf_size,
	&f_uac1_opts_attr_in_req_buf_size,
	&f_uac1_opts_attr_in_req_count,
	&f_uac1_opts_attr_audio_capture_buf_size,
	&f_uac1_opts_attr_fn_play,
	&f_uac1_opts_attr_fn_cap,
	&f_uac1_opts_attr_fn_cntl,
	NULL,
};

static struct config_item_type f_uac1_func_type = {
	.ct_item_ops	= &f_uac1_item_ops,
	.ct_attrs	= f_uac1_attrs,
	.ct_owner	= THIS_MODULE,
};

static void f_audio_free_inst(struct usb_function_instance *f)
{
	struct f_uac1_opts *opts;

	opts = container_of(f, struct f_uac1_opts, func_inst);
	if (opts->fn_play_alloc)
		kfree(opts->fn_play);
	if (opts->fn_cap_alloc)
		kfree(opts->fn_cap);
	if (opts->fn_cntl_alloc)
		kfree(opts->fn_cntl);
	kfree(opts);
}

static struct usb_function_instance *f_audio_alloc_inst(void)
{
	struct f_uac1_opts *opts;

	opts = kzalloc(sizeof(*opts), GFP_KERNEL);
	if (!opts)
		return ERR_PTR(-ENOMEM);

	mutex_init(&opts->lock);
	opts->func_inst.free_func_inst = f_audio_free_inst;

	config_group_init_type_name(&opts->func_inst.group, "",
				    &f_uac1_func_type);

	opts->out_req_buf_size = UAC1_OUT_EP_MAX_PACKET_SIZE;
	opts->out_req_count = UAC1_OUT_REQ_COUNT;
	opts->audio_playback_buf_size = UAC1_AUDIO_PLAYBACK_BUF_SIZE;

#if defined(CONFIG_SS_GADGET) ||defined(CONFIG_SS_GADGET_MODULE)
	opts->in_req_buf_size = UAC1_IN_EP_MAX_PACKET_SIZE;
	opts->in_req_count = UAC1_IN_REQ_COUNT;
	opts->audio_capture_buf_size = UAC1_AUDIO_CAPTURE_BUF_SIZE;
#endif

	opts->fn_play = FILE_PCM_PLAYBACK;
#if defined(CONFIG_SS_GADGET) ||defined(CONFIG_SS_GADGET_MODULE)
	opts->fn_cap = FILE_PCM_CAPTURE;
#endif
	opts->fn_cntl = FILE_CONTROL;
	return &opts->func_inst;
}

static void f_audio_free(struct usb_function *f)
{
	struct f_audio *audio = func_to_audio(f);
	struct f_uac1_opts *opts;

	gaudio_cleanup(&audio->card);
	opts = container_of(f->fi, struct f_uac1_opts, func_inst);
	kfree(audio);
	mutex_lock(&opts->lock);
	--opts->refcnt;
	mutex_unlock(&opts->lock);
}

static void f_audio_unbind(struct usb_configuration *c, struct usb_function *f)
{
	usb_free_all_descriptors(f);
}

static struct usb_function *f_audio_alloc(struct usb_function_instance *fi)
{
	struct f_audio *audio;
	struct f_uac1_opts *opts;

	/* allocate and initialize one new instance */
	audio = kzalloc(sizeof(*audio), GFP_KERNEL);
	if (!audio)
		return ERR_PTR(-ENOMEM);

	audio->card.func.name = "g_audio";

	opts = container_of(fi, struct f_uac1_opts, func_inst);
	mutex_lock(&opts->lock);
	++opts->refcnt;
	mutex_unlock(&opts->lock);
	INIT_LIST_HEAD(&audio->playback_play_queue);
	INIT_LIST_HEAD(&audio->capture_play_queue);
	spin_lock_init(&audio->playback_lock);
	spin_lock_init(&audio->capture_lock);

	INIT_LIST_HEAD(&audio->capture_req_free);
	spin_lock_init(&audio->capture_req_lock);

	audio->card.func.bind = f_audio_bind;
	audio->card.func.unbind = f_audio_unbind;
	audio->card.func.get_alt = f_audio_get_alt;
	audio->card.func.set_alt = f_audio_set_alt;
	audio->card.func.setup = f_audio_setup;
	audio->card.func.disable = f_audio_disable;
	audio->card.func.free_func = f_audio_free;

	control_selector_init(audio);

#if defined(CONFIG_SS_GADGET) ||defined(CONFIG_SS_GADGET_MODULE)
	if(ENABLE_MICROPHONE == opts->audio_play_mode)
		INIT_WORK(&audio->capture_work, f_audio_capture_work);
	else if(ENABLE_MIC_AND_SPK == opts->audio_play_mode)
	{
		INIT_WORK(&audio->playback_work, f_audio_playback_work);
		INIT_WORK(&audio->capture_work, f_audio_capture_work);
	}
	else if (ENABLE_SPEAKER == opts->audio_play_mode)
#endif
		INIT_WORK(&audio->playback_work, f_audio_playback_work);

	return &audio->card.func;
}

DECLARE_USB_FUNCTION_INIT(uac1, f_audio_alloc_inst, f_audio_alloc);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bryan Wu");
