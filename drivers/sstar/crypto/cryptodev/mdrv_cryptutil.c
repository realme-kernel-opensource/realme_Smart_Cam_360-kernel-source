/*
* mdrv_cryptutil.c- Sigmastar
*
* Copyright (C) 2018 Sigmastar Technology Corp.
*
* Author: edie.chen <edie.chen@sigmastar.com.tw>
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
#include <crypto/scatterwalk.h>
#include <linux/scatterlist.h>
#include "mdrv_cryptutil.h"

/* These were taken from Maxim Levitsky's patch to lkml.
 */
struct scatterlist *sg_advance(struct scatterlist *sg, int consumed)
{
	while (consumed >= sg->length) {
		consumed -= sg->length;

		sg = sg_next(sg);
		if (!sg)
			break;
	}

	WARN_ON(!sg && consumed);

	if (!sg)
		return NULL;

	sg->offset += consumed;
	sg->length -= consumed;

	if (sg->offset >= PAGE_SIZE) {
		struct page *page =
			nth_page(sg_page(sg), sg->offset / PAGE_SIZE);
		sg_set_page(sg, page, sg->length, sg->offset % PAGE_SIZE);
	}

	return sg;
}

/**
 * sg_copy - copies sg entries from sg_from to sg_to, such
 * as sg_to covers first 'len' bytes from sg_from.
 */
int sg_copy(struct scatterlist *sg_from, struct scatterlist *sg_to, int len)
{
	while (len > sg_from->length) {
		len -= sg_from->length;

		sg_set_page(sg_to, sg_page(sg_from),
				sg_from->length, sg_from->offset);

		sg_to = sg_next(sg_to);
		sg_from = sg_next(sg_from);

		if (len || (!sg_from || !sg_to))
			return -ENOMEM;
	}

	if (len)
		sg_set_page(sg_to, sg_page(sg_from),
				len, sg_from->offset);
	sg_mark_end(sg_to);
	return 0;
}